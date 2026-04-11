"""Runtime configuration for the Gmail MCP server.

Settings are read from environment variables (with sensible defaults).

Environment variables
---------------------
GMAIL_BLOCKED_LABELS
    Comma-separated list of Gmail label names the LLM is **not** permitted to
    access (Feature 3 – label-based access control).  Labels are matched
    case-insensitively against both system label IDs (e.g. ``INBOX``) and
    user-defined label names.

    Example::

        GMAIL_BLOCKED_LABELS=finance,medical,work

GMAIL_DISABLED_TOOLS
    Comma-separated list of tool names that are disabled (Feature 4 –
    per-tool permission scopes).  Disabled tools return an error when called
    rather than executing.

    Example::

        GMAIL_DISABLED_TOOLS=send_email,trash_email,reply_to_email

GMAIL_REQUIRE_CONFIRMATION
    When set to ``1``, ``true``, or ``yes``, any tool that modifies state
    (send, reply, archive, trash, mark read/unread) returns a pending-action
    object instead of executing immediately (Feature 5 – confirmation-required
    mode).  A subsequent :func:`confirm_action` call is required to proceed.

    Example::

        GMAIL_REQUIRE_CONFIRMATION=true

GMAIL_AUDIT_LOG
    Path to the append-only audit log file (Feature 10 – audit logging).
    When set, every tool call is recorded with a timestamp, tool name,
    masked parameters, and the security filter result.  If unset, audit
    logging is disabled.

    Example::

        GMAIL_AUDIT_LOG=/var/log/gmail-mcp-audit.jsonl

GMAIL_MAX_BODY_CHARS
    Maximum number of characters to return from any single email body
    (Feature 13 – email body truncation).  Bodies longer than this limit are
    truncated and a notice is appended.  Set to ``0`` (the default) to disable
    truncation.

    Example::

        GMAIL_MAX_BODY_CHARS=10000

GMAIL_PATTERNS_FILE
    Path to a YAML file containing custom block / redact patterns
    (Feature 14 – regex pattern hot-reload).  The file is re-read whenever its
    modification time changes, so patterns can be updated without restarting
    the server.

    Example::

        GMAIL_PATTERNS_FILE=/etc/gmail-mcp/patterns.yaml
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class GmailMCPConfig:
    """Immutable runtime configuration for the Gmail MCP server."""

    # Feature 3: label names (lowercase) whose emails are blocked outright.
    blocked_labels: frozenset[str] = field(default_factory=frozenset)

    # Feature 4: tool names (lowercase) that are disabled entirely.
    disabled_tools: frozenset[str] = field(default_factory=frozenset)

    # Feature 5: when True, write operations require explicit confirmation.
    require_confirmation: bool = False

    # Feature 10: path to the append-only audit log file (empty = disabled).
    audit_log_path: str = ""

    # Feature 13: maximum email body characters (0 = no limit).
    max_body_chars: int = 0

    # Feature 14: path to a YAML file with custom block/redact patterns.
    patterns_file: str = ""

    @classmethod
    def from_env(cls) -> "GmailMCPConfig":
        """Build a :class:`GmailMCPConfig` from environment variables."""
        raw_labels = os.environ.get("GMAIL_BLOCKED_LABELS", "")
        blocked_labels: frozenset[str] = frozenset(
            lbl.strip().lower() for lbl in raw_labels.split(",") if lbl.strip()
        )

        raw_tools = os.environ.get("GMAIL_DISABLED_TOOLS", "")
        disabled_tools: frozenset[str] = frozenset(
            t.strip().lower() for t in raw_tools.split(",") if t.strip()
        )

        confirm_raw = os.environ.get("GMAIL_REQUIRE_CONFIRMATION", "").strip().lower()
        require_confirmation = confirm_raw in {"1", "true", "yes"}

        audit_log_path = os.environ.get("GMAIL_AUDIT_LOG", "").strip()

        max_body_raw = os.environ.get("GMAIL_MAX_BODY_CHARS", "0").strip()
        try:
            max_body_chars = max(0, int(max_body_raw))
        except ValueError:
            max_body_chars = 0

        patterns_file = os.environ.get("GMAIL_PATTERNS_FILE", "").strip()

        return cls(
            blocked_labels=blocked_labels,
            disabled_tools=disabled_tools,
            require_confirmation=require_confirmation,
            audit_log_path=audit_log_path,
            max_body_chars=max_body_chars,
            patterns_file=patterns_file,
        )


_config: GmailMCPConfig | None = None


def get_config() -> GmailMCPConfig:
    """Return the singleton config, loading it from the environment on first call."""
    global _config
    if _config is None:
        _config = GmailMCPConfig.from_env()
    return _config


def reset_config() -> None:
    """Reset the singleton so tests can reinitialise with fresh environment variables."""
    global _config
    _config = None
