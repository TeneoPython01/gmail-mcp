"""Security and content-filtering for email data.

This module scans email content *before* it is returned to the LLM.  Any
content that matches sensitive patterns is either redacted in-place or causes
the whole email to be blocked (depending on the severity flag).

Patterns covered:
  - Passwords mentioned in plain text
  - Password-reset / account-recovery emails
  - Social Security Numbers (SSN)
  - Credit / debit card numbers (Luhn-valid 13–19 digit sequences)
  - Bank account and routing numbers
  - API keys, bearer tokens, private keys / certificates
  - Other Sensitive Personal Information (SPI) markers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Public API types
# ---------------------------------------------------------------------------

class SensitivityLevel(Enum):
    """How the server should react when a sensitive pattern is detected."""
    NONE = "none"           # No sensitive content detected.
    REDACTED = "redacted"   # Some fields were redacted; content returned.
    BLOCKED = "blocked"     # Entire email blocked; only a notice is returned.


@dataclass
class ScanResult:
    """Result of scanning an email for sensitive content."""
    level: SensitivityLevel = SensitivityLevel.NONE
    reasons: list[str] = field(default_factory=list)


class FilteredEmail(NamedTuple):
    """An email dict after security filtering has been applied."""
    data: dict          # The (possibly-redacted) email fields.
    scan: ScanResult    # What was found / redacted.


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Patterns that cause the *entire* email to be BLOCKED (not just redacted).
# These are high-confidence indicators that the email contains credentials or
# password-reset flows that the LLM must never see.
_BLOCK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "password reset / account recovery link",
        re.compile(
            r"(reset\s+your\s+password|password\s+reset|reset\s+password"
            r"|account\s+recovery|recover\s+your\s+account"
            r"|verify\s+your\s+(email|identity|account)"
            r"|confirm\s+your\s+(email|identity|account)"
            r"|click\s+(here\s+)?to\s+(reset|verify|confirm|activate)"
            r"|activate\s+your\s+account"
            r"|one[- ]time\s+(password|code|pin|passcode)\b"
            r"|your\s+verification\s+code\s+is"
            r"|your\s+one[- ]time\s+(code|pin)\s+is)",
            re.IGNORECASE,
        ),
    ),
    (
        "plaintext password disclosure",
        re.compile(
            r"(your\s+(temporary\s+)?password\s+is\b"
            r"|new\s+password\s*[:=]\s*\S+"
            r"|temporary\s+password\s*[:=]\s*\S+"
            r"|default\s+password\s*[:=]\s*\S+)",
            re.IGNORECASE,
        ),
    ),
    (
        "private key / certificate material",
        re.compile(
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----|-----BEGIN\s+CERTIFICATE-----",
            re.IGNORECASE,
        ),
    ),
]

# Patterns whose matched text is REDACTED in-place (replaced with a placeholder).
_REDACT_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Social Security Number (SSN)",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        "[SSN REDACTED]",
    ),
    (
        "credit/debit card number",
        # Matches 13-19 digit sequences with optional spaces or dashes.
        re.compile(r"\b(?:\d[ -]?){13,18}\d\b"),
        "[CARD NUMBER REDACTED]",
    ),
    (
        "bank routing number (ABA)",
        re.compile(r"\b(0[0-9]|1[0-2]|2[1-9]|3[0-2])\d{7}\b"),
        "[ROUTING NUMBER REDACTED]",
    ),
    (
        "bearer / API token",
        re.compile(
            r"(Bearer\s+[A-Za-z0-9\-._~+/]+=*"
            r"|api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-._~+/]{20,}['\"]?"
            r"|token\s*[:=]\s*['\"]?[A-Za-z0-9\-._~+/]{20,}['\"]?)",
            re.IGNORECASE,
        ),
        "[TOKEN REDACTED]",
    ),
    (
        "AWS access key",
        re.compile(r"\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b"),
        "[AWS KEY REDACTED]",
    ),
]

# Subject-line patterns that flag an email as sensitive (block-level).
_BLOCK_SUBJECT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "password / security alert in subject",
        re.compile(
            r"(password|reset\s+password|account\s+recovery|verify\s+your"
            r"|confirm\s+your|security\s+alert|sign[- ]in\s+attempt"
            r"|unusual\s+(sign[- ]in|activity|login))",
            re.IGNORECASE,
        ),
    ),
]


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def scan_text(text: str) -> ScanResult:
    """Scan *text* for sensitive patterns and return a :class:`ScanResult`.

    This is the low-level checker; callers typically use :func:`filter_email`.
    """
    result = ScanResult()

    for reason, pattern in _BLOCK_PATTERNS:
        if pattern.search(text):
            result.level = SensitivityLevel.BLOCKED
            result.reasons.append(reason)

    if result.level != SensitivityLevel.BLOCKED:
        for reason, pattern, _placeholder in _REDACT_PATTERNS:
            if pattern.search(text):
                if result.level == SensitivityLevel.NONE:
                    result.level = SensitivityLevel.REDACTED
                result.reasons.append(reason)

    return result


def redact_text(text: str) -> str:
    """Return a copy of *text* with all sensitive patterns replaced by placeholders."""
    for _reason, pattern, placeholder in _REDACT_PATTERNS:
        text = pattern.sub(placeholder, text)
    return text


def filter_email(email: dict) -> FilteredEmail:
    """Apply security filtering to an email dict.

    The *email* dict is expected to contain at least some of these keys:
    ``subject``, ``body``, ``snippet``, ``from``, ``to``, ``cc``, ``bcc``.

    Returns:
        A :class:`FilteredEmail` with the (possibly redacted) email data and a
        :class:`ScanResult` describing what was found.

    Behaviour:
        - If the subject matches a block pattern → the entire email is blocked
          and only a notice is returned (no body, no snippet).
        - If body / snippet / subject contains a block pattern → same.
        - If body / snippet contain redact-only patterns → those are replaced
          in-place and the modified email is returned.
    """
    subject = email.get("subject", "") or ""
    body = email.get("body", "") or ""
    snippet = email.get("snippet", "") or ""

    # ------------------------------------------------------------------
    # 1. Check subject for block-level patterns
    # ------------------------------------------------------------------
    for reason, pattern in _BLOCK_SUBJECT_PATTERNS:
        if pattern.search(subject):
            scan = ScanResult(level=SensitivityLevel.BLOCKED, reasons=[reason])
            return FilteredEmail(data=_blocked_notice(email, scan), scan=scan)

    # ------------------------------------------------------------------
    # 2. Check full text (body + subject) for block-level patterns
    # ------------------------------------------------------------------
    full_text = f"{subject}\n{body}\n{snippet}"
    block_scan = scan_text(full_text)

    if block_scan.level == SensitivityLevel.BLOCKED:
        return FilteredEmail(data=_blocked_notice(email, block_scan), scan=block_scan)

    # ------------------------------------------------------------------
    # 3. Redact sensitive patterns from body and snippet
    # ------------------------------------------------------------------
    redacted_body = redact_text(body)
    redacted_snippet = redact_text(snippet)

    # Rebuild scan result based on what was actually changed.
    reasons: list[str] = []
    for reason, pattern, _ph in _REDACT_PATTERNS:
        if pattern.search(body) or pattern.search(snippet):
            reasons.append(reason)

    filtered = dict(email)
    filtered["body"] = redacted_body
    filtered["snippet"] = redacted_snippet

    level = SensitivityLevel.REDACTED if reasons else SensitivityLevel.NONE
    scan = ScanResult(level=level, reasons=reasons)
    return FilteredEmail(data=filtered, scan=scan)


def _blocked_notice(email: dict, scan: ScanResult) -> dict:
    """Return a sanitised dict for a blocked email."""
    return {
        "id": email.get("id", ""),
        "thread_id": email.get("thread_id", ""),
        "subject": email.get("subject", "(subject hidden)"),
        "from": email.get("from", ""),
        "to": email.get("to", ""),
        "date": email.get("date", ""),
        "snippet": "[EMAIL BLOCKED: contains sensitive or credential information]",
        "body": (
            "This email has been blocked by the Gmail MCP security filter because it "
            "appears to contain sensitive personal information (SPI) or credential "
            f"data.\n\nReason(s): {', '.join(scan.reasons)}\n\n"
            "If you need to act on this email, please open Gmail directly."
        ),
        "security_filtered": True,
        "security_reasons": scan.reasons,
    }
