"""Gmail MCP server.

Exposes Gmail operations as MCP tools that an AI agent can call.

All email content is passed through the security filter in
:mod:`gmail_mcp.security` before being returned, so the LLM never sees raw
passwords, SSNs, credit-card numbers, API tokens, password-reset links, or
prompt-injection attempts.

Tools exposed:
  - list_emails
  - get_email
  - search_emails
  - send_email
  - reply_to_email
  - mark_as_read
  - mark_as_unread
  - archive_email
  - trash_email
  - confirm_action  (Feature 5 – confirmation-required mode)

Security features
-----------------
* **Label-based access control** (Feature 3): set ``GMAIL_BLOCKED_LABELS`` to
  a comma-separated list of label names whose emails will be blocked outright.
* **Per-tool permission scopes** (Feature 4): set ``GMAIL_DISABLED_TOOLS`` to
  a comma-separated list of tool names to disable.
* **Confirmation-required mode** (Feature 5): set
  ``GMAIL_REQUIRE_CONFIRMATION=true`` so that write operations return a
  pending-action object instead of executing immediately.  Call
  ``confirm_action`` with the returned ``pending_action_id`` to proceed.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import get_config
from .gmail_client import GmailClient
from .security import SensitivityLevel

# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Gmail MCP",
    instructions=(
        "You are connected to the user's Gmail account via the Gmail MCP server. "
        "You can read, search, send, reply to, and manage emails on the user's behalf. "
        "All email content is automatically filtered to remove sensitive personal "
        "information (SPI) such as SSNs, credit card numbers, passwords, "
        "password-reset links, and prompt-injection attempts before it reaches you. "
        "If an email is marked as 'security_filtered': true, it has been blocked "
        "because it contained credentials, sensitive data, or a prompt-injection "
        "attempt – do not attempt to circumvent this filter. "
        "If a write operation returns a 'pending_action_id', you MUST call "
        "confirm_action with that ID before the operation executes."
    ),
)

# Lazy-initialised client (created on first tool call so that auth only happens
# when a tool is actually invoked, not at import time).
_client: GmailClient | None = None

# Cache of Gmail label-id -> label-name, populated lazily on first label check.
_label_id_to_name: dict[str, str] | None = None

# Pending write actions awaiting confirmation (Feature 5).
# Maps action_id -> {"tool": str, "params": dict}
_pending_actions: dict[str, dict[str, Any]] = {}


def _get_client() -> GmailClient:
    global _client
    if _client is None:
        _client = GmailClient()
    return _client


def _get_blocked_label_ids() -> frozenset[str]:
    """Return the set of Gmail label IDs that are blocked (Feature 3).

    System labels (INBOX, SENT, …) have IDs equal to their uppercase names.
    User-defined labels are resolved via the Gmail labels API (cached).
    """
    global _label_id_to_name
    config = get_config()
    if not config.blocked_labels:
        return frozenset()

    # Build a combined set: system labels are matched by uppercased name.
    blocked_ids: set[str] = {name.upper() for name in config.blocked_labels}

    # Lazily resolve user-defined label names to their API IDs.
    if _label_id_to_name is None:
        try:
            client = _get_client()
            resp = (
                client._service.users().labels().list(userId="me").execute()
            )
            _label_id_to_name = {
                lbl["id"]: lbl["name"].lower()
                for lbl in resp.get("labels", [])
            }
        except Exception:
            _label_id_to_name = {}

    for lbl_id, lbl_name in _label_id_to_name.items():
        if lbl_name in config.blocked_labels:
            blocked_ids.add(lbl_id)

    return frozenset(blocked_ids)


def _check_label_access(email_data: dict) -> dict | None:
    """Return a blocked-notice dict if the email carries a restricted label, else None."""
    label_ids: list[str] = email_data.get("label_ids", [])
    blocked = _get_blocked_label_ids()
    if not blocked:
        return None
    hit = blocked.intersection(label_ids)
    if hit:
        matched_names = sorted(hit)
        return {
            "id": email_data.get("id", ""),
            "thread_id": email_data.get("thread_id", ""),
            "subject": "(subject hidden)",
            "from": email_data.get("from", ""),
            "date": email_data.get("date", ""),
            "snippet": "[EMAIL BLOCKED: restricted label]",
            "body": (
                "This email has been blocked by the Gmail MCP label-access policy "
                f"because it carries a restricted label: {', '.join(matched_names)}.\n\n"
                "If you need to act on this email, please open Gmail directly."
            ),
            "security_filtered": True,
            "security_reasons": [f"restricted label: {n}" for n in matched_names],
        }
    return None


def _check_tool_enabled(tool_name: str) -> dict | None:
    """Return an error dict if *tool_name* is disabled, else None (Feature 4)."""
    config = get_config()
    if tool_name.lower() in config.disabled_tools:
        return {
            "error": (
                f"The tool '{tool_name}' has been disabled by the server "
                "administrator.  Please contact the account owner if you believe "
                "this is a mistake."
            )
        }
    return None


def _create_pending_action(tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
    """Store a write operation as a pending action and return a notice (Feature 5)."""
    action_id = str(uuid.uuid4())
    _pending_actions[action_id] = {"tool": tool_name, "params": params}
    return {
        "pending_action_id": action_id,
        "action": tool_name,
        "params": params,
        "message": (
            f"Action '{tool_name}' is pending confirmation.  "
            f"Call confirm_action(action_id='{action_id}') to execute it, "
            "or discard it by doing nothing."
        ),
    }


def _format_email(fe_data: dict) -> dict[str, Any]:
    """Strip internal keys that are not useful to the LLM."""
    display = dict(fe_data)
    # Collapse empty fields to keep responses concise.
    return {k: v for k, v in display.items() if v not in ("", [], None)}


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_emails(
    max_results: int = 10,
    query: str = "",
    label: str = "INBOX",
) -> list[dict]:
    """List emails from the user's Gmail account.

    Args:
        max_results: Number of emails to return (1–100, default 10).
        query: Optional Gmail search query (e.g. "from:alice newer_than:7d").
        label: Gmail label to filter by (default "INBOX").
                Use "SENT" for sent mail, "SPAM" for spam, etc.

    Returns:
        A list of email objects.  Emails containing sensitive information are
        automatically redacted or replaced with a security notice.  Emails
        carrying a restricted label are blocked outright.
    """
    client = _get_client()
    label_ids = [label.upper()] if label else ["INBOX"]
    filtered_emails = client.list_emails(
        max_results=max_results,
        query=query,
        label_ids=label_ids,
    )
    results = []
    for fe in filtered_emails:
        blocked = _check_label_access(fe.data)
        results.append(_format_email(blocked if blocked is not None else fe.data))
    return results


@mcp.tool()
def get_email(email_id: str) -> dict:
    """Retrieve the full content of a single email by its ID.

    Args:
        email_id: The Gmail message ID (obtained from list_emails or search_emails).

    Returns:
        An email object.  If the email contains sensitive information it will be
        redacted or replaced with a security notice.  If the email carries a
        restricted label it is blocked outright.
    """
    client = _get_client()
    fe = client.get_email(email_id)
    blocked = _check_label_access(fe.data)
    return _format_email(blocked if blocked is not None else fe.data)


@mcp.tool()
def search_emails(
    query: str,
    max_results: int = 10,
) -> list[dict]:
    """Search emails using Gmail's query syntax.

    Common query operators:
      - ``from:alice@example.com``  – emails from Alice
      - ``to:me``                   – emails addressed to me
      - ``subject:invoice``         – subject contains "invoice"
      - ``newer_than:7d``           – received in the last 7 days
      - ``has:attachment``          – emails with attachments
      - ``is:unread``               – unread emails
      - ``label:work``              – emails with the "work" label

    Multiple operators can be combined, e.g.:
      ``"from:boss subject:urgent newer_than:3d"``

    Args:
        query: Gmail search query string.
        max_results: Maximum number of results to return (1–100, default 10).

    Returns:
        A list of matching email objects, security-filtered.  Emails carrying
        a restricted label are blocked outright.
    """
    client = _get_client()
    filtered_emails = client.search_emails(query=query, max_results=max_results)
    results = []
    for fe in filtered_emails:
        blocked = _check_label_access(fe.data)
        results.append(_format_email(blocked if blocked is not None else fe.data))
    return results


@mcp.tool()
def send_email(
    to: str,
    subject: str,
    body: str,
    cc: str = "",
    bcc: str = "",
) -> dict:
    """Send a new email from the user's Gmail account.

    Args:
        to: Recipient email address (or comma-separated list).
        subject: Email subject line.
        body: Plain-text email body.
        cc: Optional comma-separated CC addresses.
        bcc: Optional comma-separated BCC addresses.

    Returns:
        A dict containing the ``id`` and ``thread_id`` of the sent message, or
        a ``pending_action_id`` dict when confirmation-required mode is enabled.
    """
    err = _check_tool_enabled("send_email")
    if err is not None:
        return err
    config = get_config()
    params: dict[str, Any] = {
        "to": to, "subject": subject, "body": body, "cc": cc, "bcc": bcc,
    }
    if config.require_confirmation:
        return _create_pending_action("send_email", params)
    client = _get_client()
    return client.send_email(**params)


@mcp.tool()
def reply_to_email(email_id: str, body: str) -> dict:
    """Reply to an existing email.

    The reply is sent to the original sender with proper threading headers
    (``In-Reply-To``, ``References``) so it appears as a thread in Gmail.

    Args:
        email_id: The Gmail message ID of the email to reply to.
        body: The plain-text reply body.

    Returns:
        A dict containing the ``id`` and ``thread_id`` of the sent reply, or
        a ``pending_action_id`` dict when confirmation-required mode is enabled.
    """
    err = _check_tool_enabled("reply_to_email")
    if err is not None:
        return err
    config = get_config()
    params: dict[str, Any] = {"email_id": email_id, "body": body}
    if config.require_confirmation:
        return _create_pending_action("reply_to_email", params)
    client = _get_client()
    return client.reply_to_email(**params)


@mcp.tool()
def mark_as_read(email_id: str) -> dict:
    """Mark an email as read.

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict, or a ``pending_action_id`` dict when
        confirmation-required mode is enabled.
    """
    err = _check_tool_enabled("mark_as_read")
    if err is not None:
        return err
    config = get_config()
    if config.require_confirmation:
        return _create_pending_action("mark_as_read", {"email_id": email_id})
    client = _get_client()
    client.mark_as_read(email_id)
    return {"status": "ok", "email_id": email_id, "action": "marked_as_read"}


@mcp.tool()
def mark_as_unread(email_id: str) -> dict:
    """Mark an email as unread.

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict, or a ``pending_action_id`` dict when
        confirmation-required mode is enabled.
    """
    err = _check_tool_enabled("mark_as_unread")
    if err is not None:
        return err
    config = get_config()
    if config.require_confirmation:
        return _create_pending_action("mark_as_unread", {"email_id": email_id})
    client = _get_client()
    client.mark_as_unread(email_id)
    return {"status": "ok", "email_id": email_id, "action": "marked_as_unread"}


@mcp.tool()
def archive_email(email_id: str) -> dict:
    """Archive an email (remove it from the Inbox without deleting it).

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict, or a ``pending_action_id`` dict when
        confirmation-required mode is enabled.
    """
    err = _check_tool_enabled("archive_email")
    if err is not None:
        return err
    config = get_config()
    if config.require_confirmation:
        return _create_pending_action("archive_email", {"email_id": email_id})
    client = _get_client()
    client.archive_email(email_id)
    return {"status": "ok", "email_id": email_id, "action": "archived"}


@mcp.tool()
def trash_email(email_id: str) -> dict:
    """Move an email to Trash.

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict, or a ``pending_action_id`` dict when
        confirmation-required mode is enabled.
    """
    err = _check_tool_enabled("trash_email")
    if err is not None:
        return err
    config = get_config()
    if config.require_confirmation:
        return _create_pending_action("trash_email", {"email_id": email_id})
    client = _get_client()
    client.trash_email(email_id)
    return {"status": "ok", "email_id": email_id, "action": "trashed"}


@mcp.tool()
def confirm_action(action_id: str) -> dict:
    """Execute a pending write action that was deferred for confirmation.

    When the server is running in confirmation-required mode
    (``GMAIL_REQUIRE_CONFIRMATION=true``), any tool that modifies state returns
    a ``pending_action_id`` instead of executing immediately.  Pass that ID to
    this tool to authorise and execute the action.

    Args:
        action_id: The ``pending_action_id`` returned by the write tool.

    Returns:
        The result of the original write operation, or an error dict if the
        action ID is unknown or has already been executed / discarded.
    """
    action = _pending_actions.pop(action_id, None)
    if action is None:
        return {
            "error": (
                f"No pending action with id '{action_id}'.  "
                "It may have already been executed or discarded."
            )
        }

    tool_name = action["tool"]
    params: dict[str, Any] = action["params"]
    client = _get_client()

    if tool_name == "send_email":
        return client.send_email(**params)
    if tool_name == "reply_to_email":
        return client.reply_to_email(**params)

    # Label-modifying / state-changing single-message operations share the
    # same response shape: {status, email_id, action}.
    _LABEL_OPS: dict[str, tuple[Any, str]] = {
        "mark_as_read":   (client.mark_as_read,   "marked_as_read"),
        "mark_as_unread": (client.mark_as_unread, "marked_as_unread"),
        "archive_email":  (client.archive_email,  "archived"),
        "trash_email":    (client.trash_email,    "trashed"),
    }
    if tool_name in _LABEL_OPS:
        method, action_label = _LABEL_OPS[tool_name]
        method(params["email_id"])
        return {"status": "ok", "email_id": params["email_id"], "action": action_label}

    return {"error": f"Unknown pending action type: '{tool_name}'."}


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry-point for the Gmail MCP server."""
    parser = argparse.ArgumentParser(
        prog="gmail-mcp",
        description="Gmail MCP server – connect an LLM to your Gmail account.",
    )
    parser.add_argument(
        "--auth",
        action="store_true",
        help="Run the OAuth2 authorisation flow and exit (useful for first-time setup).",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio).",
    )
    args = parser.parse_args()

    if args.auth:
        # Trigger authentication and then exit.
        from .auth import get_credentials
        get_credentials()
        print("Authentication successful.  token.json has been saved.")
        sys.exit(0)

    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
