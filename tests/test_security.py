"""Tests for the security / content-filtering module."""

from __future__ import annotations

import pytest

from gmail_mcp.security import (
    SensitivityLevel,
    filter_email,
    redact_text,
    scan_text,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_email(**kwargs) -> dict:
    defaults = {
        "id": "abc123",
        "thread_id": "thread456",
        "subject": "Hello",
        "from": "alice@example.com",
        "to": "bob@example.com",
        "cc": "",
        "date": "Mon, 1 Jan 2024 00:00:00 +0000",
        "message_id": "<msg@example.com>",
        "in_reply_to": "",
        "snippet": "",
        "body": "",
        "label_ids": ["INBOX"],
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# scan_text – individual pattern checks
# ---------------------------------------------------------------------------

class TestScanText:
    def test_clean_text_returns_none_level(self):
        result = scan_text("Hi there, how are you?")
        assert result.level == SensitivityLevel.NONE
        assert result.reasons == []

    # Block-level patterns

    def test_detects_password_reset_link_phrase(self):
        result = scan_text("Please click here to reset your password.")
        assert result.level == SensitivityLevel.BLOCKED
        assert any("password" in r.lower() for r in result.reasons)

    def test_detects_one_time_password(self):
        result = scan_text("Your one-time password is 847291.")
        assert result.level == SensitivityLevel.BLOCKED

    def test_detects_account_recovery(self):
        result = scan_text("Use this link for account recovery.")
        assert result.level == SensitivityLevel.BLOCKED

    def test_detects_verify_your_email(self):
        result = scan_text("Please verify your email address.")
        assert result.level == SensitivityLevel.BLOCKED

    def test_detects_plaintext_password(self):
        result = scan_text("Your temporary password is: S3cr3tP@ss!")
        assert result.level == SensitivityLevel.BLOCKED

    def test_detects_private_key_pem(self):
        result = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...")
        assert result.level == SensitivityLevel.BLOCKED

    def test_detects_private_key_without_rsa(self):
        result = scan_text("-----BEGIN PRIVATE KEY-----\nMIIEow...")
        assert result.level == SensitivityLevel.BLOCKED

    # Redact-level patterns

    def test_detects_ssn(self):
        result = scan_text("My SSN is 123-45-6789.")
        assert result.level == SensitivityLevel.REDACTED
        assert any("ssn" in r.lower() or "social" in r.lower() for r in result.reasons)

    def test_detects_ssn_with_spaces(self):
        result = scan_text("SSN: 234 56 7890")
        assert result.level == SensitivityLevel.REDACTED

    def test_detects_credit_card(self):
        result = scan_text("Card: 4111 1111 1111 1111")
        assert result.level == SensitivityLevel.REDACTED
        assert any("card" in r.lower() for r in result.reasons)

    def test_detects_bearer_token(self):
        result = scan_text("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        assert result.level == SensitivityLevel.REDACTED

    def test_detects_aws_key(self):
        result = scan_text("Key: AKIAIOSFODNN7EXAMPLE")
        assert result.level == SensitivityLevel.REDACTED

    def test_detects_api_key_assignment(self):
        result = scan_text('api_key = "abcdefghijklmnopqrstuvwxyz12345678"')
        assert result.level == SensitivityLevel.REDACTED

    def test_block_takes_priority_over_redact(self):
        # Text with both a block-level pattern and a redact-level pattern.
        text = "Reset your password. My SSN is 123-45-6789."
        result = scan_text(text)
        assert result.level == SensitivityLevel.BLOCKED


# ---------------------------------------------------------------------------
# redact_text – in-place replacement
# ---------------------------------------------------------------------------

class TestRedactText:
    def test_ssn_is_redacted(self):
        out = redact_text("SSN: 123-45-6789 end")
        assert "123-45-6789" not in out
        assert "[SSN REDACTED]" in out

    def test_card_number_is_redacted(self):
        out = redact_text("Card 4111111111111111 here")
        assert "4111111111111111" not in out
        assert "[CARD NUMBER REDACTED]" in out

    def test_bearer_token_is_redacted(self):
        out = redact_text("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        assert "eyJhbGciOiJIUzI1NiJ9" not in out
        assert "[TOKEN REDACTED]" in out

    def test_aws_key_is_redacted(self):
        out = redact_text("AKIAIOSFODNN7EXAMPLE rest of text")
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "[AWS KEY REDACTED]" in out

    def test_clean_text_unchanged(self):
        text = "Nothing sensitive here."
        assert redact_text(text) == text

    def test_multiple_redactions_in_one_pass(self):
        text = "SSN: 234-56-7890 and card 4111111111111111 goodbye"
        out = redact_text(text)
        assert "234-56-7890" not in out
        assert "4111111111111111" not in out
        assert "[SSN REDACTED]" in out
        assert "[CARD NUMBER REDACTED]" in out


# ---------------------------------------------------------------------------
# filter_email – high-level email dict filtering
# ---------------------------------------------------------------------------

class TestFilterEmail:
    def test_clean_email_passes_through(self):
        email = _make_email(subject="Team meeting tomorrow", body="See you at 10am!")
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.NONE
        assert fe.data["body"] == "See you at 10am!"
        assert fe.data["subject"] == "Team meeting tomorrow"

    def test_password_reset_subject_blocks_email(self):
        email = _make_email(
            subject="Reset your password",
            body="Click the link below.",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED
        assert fe.data.get("security_filtered") is True
        # Body must not expose original content.
        assert "Click the link below" not in fe.data["body"]

    def test_password_reset_in_body_blocks_email(self):
        email = _make_email(
            subject="Hello",
            body="Click here to reset your password.",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED

    def test_otp_in_body_blocks_email(self):
        email = _make_email(
            subject="Your code",
            body="Your one-time code is 482910.",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED

    def test_ssn_in_body_is_redacted(self):
        email = _make_email(
            subject="Tax form",
            body="Your SSN is 321-54-9876 for our records.",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.REDACTED
        assert "321-54-9876" not in fe.data["body"]
        assert "[SSN REDACTED]" in fe.data["body"]

    def test_ssn_in_snippet_is_redacted(self):
        email = _make_email(
            subject="Tax form",
            body="Hi there",
            snippet="SSN 123-45-6789 confirmed",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.REDACTED
        assert "123-45-6789" not in fe.data["snippet"]

    def test_credit_card_in_body_is_redacted(self):
        email = _make_email(
            subject="Order confirmation",
            body="Charged card 4111 1111 1111 1111 for $49.99",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.REDACTED
        assert "4111" not in fe.data["body"] or "[CARD NUMBER REDACTED]" in fe.data["body"]

    def test_private_key_in_body_blocks_email(self):
        email = _make_email(
            subject="Keys",
            body="-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkq...",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED

    def test_blocked_email_has_security_fields(self):
        email = _make_email(subject="Verify your account", body="Confirm your email.")
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED
        assert "security_filtered" in fe.data
        assert fe.data["security_filtered"] is True
        assert isinstance(fe.data["security_reasons"], list)
        assert len(fe.data["security_reasons"]) > 0

    def test_blocked_email_preserves_metadata(self):
        email = _make_email(
            subject="Reset your password",
            body="Link here.",
            **{"from": "noreply@example.com", "to": "user@example.com"},
        )
        fe = filter_email(email)
        assert fe.data["from"] == "noreply@example.com"
        assert fe.data["to"] == "user@example.com"
        assert fe.data["id"] == "abc123"

    def test_clean_email_no_security_fields(self):
        email = _make_email(subject="Lunch plans", body="Tacos at noon?")
        fe = filter_email(email)
        assert not fe.data.get("security_filtered")

    def test_aws_key_in_body_is_redacted(self):
        email = _make_email(
            subject="Config",
            body="Use key AKIAIOSFODNN7EXAMPLE for access.",
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.REDACTED
        assert "AKIAIOSFODNN7EXAMPLE" not in fe.data["body"]

    def test_empty_email_passes(self):
        email = _make_email(subject="", body="", snippet="")
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.NONE

    def test_verify_your_email_subject_blocks(self):
        email = _make_email(subject="Verify your email", body="Click below.")
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED

    def test_security_alert_subject_blocks(self):
        email = _make_email(subject="Security alert: new sign-in", body="Was this you?")
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED
