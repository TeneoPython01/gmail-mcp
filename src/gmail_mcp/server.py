"""Gmail MCP server.

Exposes Gmail operations as MCP tools that an AI agent can call.

All email content is passed through the security filter in
:mod:`gmail_mcp.security` before being returned, so the LLM never sees raw
passwords, SSNs, credit-card numbers, API tokens, or password-reset links.

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
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

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
        "information (SPI) such as SSNs, credit card numbers, passwords, and "
        "password-reset links before it reaches you. "
        "If an email is marked as 'security_filtered': true, it has been blocked "
        "because it contained credentials or sensitive data – do not attempt to "
        "circumvent this filter."
    ),
)

# Lazy-initialised client (created on first tool call so that auth only happens
# when a tool is actually invoked, not at import time).
_client: GmailClient | None = None


def _get_client() -> GmailClient:
    global _client
    if _client is None:
        _client = GmailClient()
    return _client


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
        automatically redacted or replaced with a security notice.
    """
    client = _get_client()
    label_ids = [label.upper()] if label else ["INBOX"]
    filtered_emails = client.list_emails(
        max_results=max_results,
        query=query,
        label_ids=label_ids,
    )
    return [_format_email(fe.data) for fe in filtered_emails]


@mcp.tool()
def get_email(email_id: str) -> dict:
    """Retrieve the full content of a single email by its ID.

    Args:
        email_id: The Gmail message ID (obtained from list_emails or search_emails).

    Returns:
        An email object.  If the email contains sensitive information it will be
        redacted or replaced with a security notice.
    """
    client = _get_client()
    fe = client.get_email(email_id)
    return _format_email(fe.data)


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
        A list of matching email objects, security-filtered.
    """
    client = _get_client()
    filtered_emails = client.search_emails(query=query, max_results=max_results)
    return [_format_email(fe.data) for fe in filtered_emails]


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
        A dict containing the ``id`` and ``thread_id`` of the sent message.
    """
    client = _get_client()
    result = client.send_email(to=to, subject=subject, body=body, cc=cc, bcc=bcc)
    return result


@mcp.tool()
def reply_to_email(email_id: str, body: str) -> dict:
    """Reply to an existing email.

    The reply is sent to the original sender with proper threading headers
    (``In-Reply-To``, ``References``) so it appears as a thread in Gmail.

    Args:
        email_id: The Gmail message ID of the email to reply to.
        body: The plain-text reply body.

    Returns:
        A dict containing the ``id`` and ``thread_id`` of the sent reply.
    """
    client = _get_client()
    result = client.reply_to_email(email_id=email_id, body=body)
    return result


@mcp.tool()
def mark_as_read(email_id: str) -> dict:
    """Mark an email as read.

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict.
    """
    client = _get_client()
    client.mark_as_read(email_id)
    return {"status": "ok", "email_id": email_id, "action": "marked_as_read"}


@mcp.tool()
def mark_as_unread(email_id: str) -> dict:
    """Mark an email as unread.

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict.
    """
    client = _get_client()
    client.mark_as_unread(email_id)
    return {"status": "ok", "email_id": email_id, "action": "marked_as_unread"}


@mcp.tool()
def archive_email(email_id: str) -> dict:
    """Archive an email (remove it from the Inbox without deleting it).

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict.
    """
    client = _get_client()
    client.archive_email(email_id)
    return {"status": "ok", "email_id": email_id, "action": "archived"}


@mcp.tool()
def trash_email(email_id: str) -> dict:
    """Move an email to Trash.

    Args:
        email_id: The Gmail message ID.

    Returns:
        A confirmation dict.
    """
    client = _get_client()
    client.trash_email(email_id)
    return {"status": "ok", "email_id": email_id, "action": "trashed"}


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
