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

        return cls(
            blocked_labels=blocked_labels,
            disabled_tools=disabled_tools,
            require_confirmation=require_confirmation,
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
