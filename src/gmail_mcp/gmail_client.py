"""Gmail API client wrapper.

This module wraps the Google Gmail API into simple Python methods.  All email
content passes through the security filter in :mod:`gmail_mcp.security` before
being returned, so the LLM never sees raw sensitive data.

Attachment handling:
  Text is extracted from plain-text, PDF, and DOCX attachments and scanned by
  the same security filter used for email bodies.  Attachments whose text
  cannot be extracted (e.g. images) are included with metadata only.
"""

from __future__ import annotations

import base64
import email as _email_lib
import email.utils
import io
import logging
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .auth import get_credentials
from .security import FilteredEmail, filter_email

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional attachment-parsing libraries (graceful degradation if absent)
# ---------------------------------------------------------------------------

try:
    from pdfminer.high_level import extract_text as _pdf_extract_text  # type: ignore[import]
    _PDFMINER_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PDFMINER_AVAILABLE = False

try:
    import docx as _docx  # type: ignore[import]
    _DOCX_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DOCX_AVAILABLE = False

# MIME types that are structural/body parts, not file attachments.
_NON_ATTACHMENT_MIME_TYPES: frozenset[str] = frozenset({
    "text/plain",
    "text/html",
    "multipart/mixed",
    "multipart/alternative",
    "multipart/related",
})


class GmailClient:
    """A high-level Gmail client backed by the Gmail REST API.

    All content-returning methods apply :func:`~gmail_mcp.security.filter_email`
    before returning data so that sensitive information is never exposed to the
    caller (e.g. an LLM tool invocation).
    """

    def __init__(self) -> None:
        creds = get_credentials()
        self._service = build("gmail", "v1", credentials=creds)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_raw_message(self, msg_id: str, user_id: str = "me") -> dict[str, Any]:
        return (
            self._service.users()
            .messages()
            .get(userId=user_id, id=msg_id, format="full")
            .execute()
        )

    @staticmethod
    def _decode_body(payload: dict) -> str:
        """Recursively extract the plaintext body from a message payload."""
        mime_type = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data", "")

        if mime_type == "text/plain" and body_data:
            return base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")

        if mime_type == "text/html" and body_data:
            html = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
            # Strip HTML tags to get readable text.
            return re.sub(r"<[^>]+>", " ", html)

        parts = payload.get("parts", [])
        for part in parts:
            text = GmailClient._decode_body(part)
            if text:
                return text

        return ""

    @staticmethod
    def _extract_header(headers: list[dict], name: str) -> str:
        for h in headers:
            if h.get("name", "").lower() == name.lower():
                return h.get("value", "")
        return ""

    # ------------------------------------------------------------------
    # Attachment helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_attachment_parts(payload: dict) -> list[dict]:
        """Recursively collect attachment parts from a message payload."""
        parts: list[dict] = []
        filename = payload.get("filename", "")
        mime_type = payload.get("mimeType", "")
        body = payload.get("body", {})

        # A part is considered an attachment when it has a filename or an
        # explicit Content-Disposition of "attachment".
        if filename or (
            mime_type not in _NON_ATTACHMENT_MIME_TYPES
            and body.get("attachmentId")
        ):
            parts.append(payload)

        for sub in payload.get("parts", []):
            parts.extend(GmailClient._collect_attachment_parts(sub))
        return parts

    def _fetch_attachment_bytes(
        self, msg_id: str, part: dict, user_id: str
    ) -> bytes:
        """Return the raw bytes for a single attachment part."""
        body = part.get("body", {})
        attachment_id = body.get("attachmentId")

        if attachment_id:
            response = (
                self._service.users()
                .messages()
                .attachments()
                .get(userId=user_id, messageId=msg_id, id=attachment_id)
                .execute()
            )
            data = response.get("data", "")
        else:
            data = body.get("data", "")

        if not data:
            return b""
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _extract_text_from_bytes(mime_type: str, data: bytes) -> str:
        """Extract plain text from attachment bytes.

        Supports:
          - ``text/plain`` – decoded directly as UTF-8.
          - ``application/pdf`` – extracted via *pdfminer.six* (if installed).
          - ``application/vnd.openxmlformats-officedocument.wordprocessingml.document``
            (DOCX) – extracted via *python-docx* (if installed).

        All other MIME types return an empty string.
        """
        if mime_type == "text/plain":
            try:
                return data.decode("utf-8", errors="replace")
            except Exception:
                return ""

        if mime_type == "application/pdf":
            if not _PDFMINER_AVAILABLE:
                logger.debug("pdfminer.six not installed; skipping PDF text extraction")
                return ""
            try:
                return _pdf_extract_text(io.BytesIO(data)) or ""
            except Exception as exc:
                logger.debug("PDF text extraction failed: %s", exc)
                return ""

        if mime_type in (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/docx",
        ):
            if not _DOCX_AVAILABLE:
                logger.debug("python-docx not installed; skipping DOCX text extraction")
                return ""
            try:
                doc = _docx.Document(io.BytesIO(data))
                return "\n".join(p.text for p in doc.paragraphs)
            except Exception as exc:
                logger.debug("DOCX text extraction failed: %s", exc)
                return ""

        return ""

    def _parse_attachments(
        self, msg_id: str, raw: dict, user_id: str
    ) -> list[dict]:
        """Return a list of attachment dicts with extracted text for *raw*.

        Each dict contains:
          ``filename``, ``mime_type``, ``size``, and ``content`` (extracted
          text, or ``""`` if the type is not supported or extraction failed).
        """
        payload = raw.get("payload", {})
        att_parts = self._collect_attachment_parts(payload)
        attachments: list[dict] = []

        for part in att_parts:
            mime_type = part.get("mimeType", "")
            filename = part.get("filename", "")
            size = part.get("body", {}).get("size", 0)

            try:
                data_bytes = self._fetch_attachment_bytes(msg_id, part, user_id)
            except Exception as exc:
                logger.debug(
                    "Could not fetch attachment '%s' (msg %s): %s",
                    filename, msg_id, exc,
                )
                data_bytes = b""

            content = self._extract_text_from_bytes(mime_type, data_bytes)

            attachments.append(
                {
                    "filename": filename,
                    "mime_type": mime_type,
                    "size": size,
                    "content": content,
                }
            )

        return attachments

    def _parse_message(self, raw: dict) -> dict:
        """Convert a raw Gmail API message into a normalised dict."""
        headers = raw.get("payload", {}).get("headers", [])
        return {
            "id": raw.get("id", ""),
            "thread_id": raw.get("threadId", ""),
            "subject": self._extract_header(headers, "Subject"),
            "from": self._extract_header(headers, "From"),
            "to": self._extract_header(headers, "To"),
            "cc": self._extract_header(headers, "Cc"),
            "date": self._extract_header(headers, "Date"),
            "message_id": self._extract_header(headers, "Message-ID"),
            "in_reply_to": self._extract_header(headers, "In-Reply-To"),
            "snippet": raw.get("snippet", ""),
            "body": self._decode_body(raw.get("payload", {})),
            "label_ids": raw.get("labelIds", []),
        }

    # ------------------------------------------------------------------
    # Reading / searching
    # ------------------------------------------------------------------

    def list_emails(
        self,
        max_results: int = 10,
        query: str = "",
        label_ids: list[str] | None = None,
        user_id: str = "me",
    ) -> list[FilteredEmail]:
        """List emails, applying the security filter to each one.

        Args:
            max_results: Maximum number of messages to return (1–100).
            query: Optional Gmail search query (e.g. ``from:alice newer_than:7d``).
            label_ids: Gmail label IDs to restrict the search (default: ``["INBOX"]``).
            user_id: Gmail user ID (default ``"me"`` for the authenticated account).

        Returns:
            A list of :class:`~gmail_mcp.security.FilteredEmail` objects.
        """
        if label_ids is None:
            label_ids = ["INBOX"]

        max_results = max(1, min(max_results, 100))

        params: dict[str, Any] = {
            "userId": user_id,
            "maxResults": max_results,
            "labelIds": label_ids,
        }
        if query:
            params["q"] = query

        try:
            response = self._service.users().messages().list(**params).execute()
        except HttpError as exc:
            raise RuntimeError(f"Gmail API error: {exc}") from exc

        messages = response.get("messages", [])
        results: list[FilteredEmail] = []
        for msg in messages:
            raw = self._get_raw_message(msg["id"], user_id)
            parsed = self._parse_message(raw)
            parsed["attachments"] = self._parse_attachments(msg["id"], raw, user_id)
            results.append(filter_email(parsed))
        return results

    def get_email(self, email_id: str, user_id: str = "me") -> FilteredEmail:
        """Fetch a single email by its Gmail message ID.

        Args:
            email_id: The Gmail message ID (e.g. from :meth:`list_emails`).
            user_id: Gmail user ID.

        Returns:
            A :class:`~gmail_mcp.security.FilteredEmail`.
        """
        try:
            raw = self._get_raw_message(email_id, user_id)
        except HttpError as exc:
            raise RuntimeError(f"Gmail API error: {exc}") from exc
        parsed = self._parse_message(raw)
        parsed["attachments"] = self._parse_attachments(email_id, raw, user_id)
        return filter_email(parsed)

    def search_emails(
        self,
        query: str,
        max_results: int = 10,
        user_id: str = "me",
    ) -> list[FilteredEmail]:
        """Search emails using Gmail query syntax.

        Args:
            query: Gmail search query string (e.g. ``"from:boss subject:urgent"``).
            max_results: Maximum number of results to return (1–100).
            user_id: Gmail user ID.

        Returns:
            A list of :class:`~gmail_mcp.security.FilteredEmail` objects.
        """
        return self.list_emails(
            max_results=max_results,
            query=query,
            label_ids=[],
            user_id=user_id,
        )

    # ------------------------------------------------------------------
    # Sending / replying
    # ------------------------------------------------------------------

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        cc: str = "",
        bcc: str = "",
        user_id: str = "me",
    ) -> dict:
        """Send a new email.

        Args:
            to: Recipient email address (or comma-separated list).
            subject: Email subject line.
            body: Plain-text body.
            cc: Carbon-copy addresses (optional).
            bcc: Blind carbon-copy addresses (optional).
            user_id: Gmail user ID.

        Returns:
            A dict with ``id`` and ``thread_id`` of the sent message.
        """
        msg = MIMEMultipart()
        msg["To"] = to
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = cc
        if bcc:
            msg["Bcc"] = bcc
        msg.attach(MIMEText(body, "plain", "utf-8"))

        raw_bytes = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        try:
            sent = (
                self._service.users()
                .messages()
                .send(userId=user_id, body={"raw": raw_bytes})
                .execute()
            )
        except HttpError as exc:
            raise RuntimeError(f"Gmail API error: {exc}") from exc

        return {"id": sent.get("id", ""), "thread_id": sent.get("threadId", "")}

    def reply_to_email(
        self,
        email_id: str,
        body: str,
        user_id: str = "me",
    ) -> dict:
        """Reply to an existing email.

        The reply uses the original subject (prefixed with ``Re:`` if not already),
        sets the correct ``In-Reply-To`` and ``References`` headers, and sends to
        the original sender.

        Args:
            email_id: The Gmail message ID to reply to.
            body: Plain-text reply body.
            user_id: Gmail user ID.

        Returns:
            A dict with ``id`` and ``thread_id`` of the sent reply.
        """
        try:
            raw = self._get_raw_message(email_id, user_id)
        except HttpError as exc:
            raise RuntimeError(f"Gmail API error: {exc}") from exc

        parsed = self._parse_message(raw)
        original_from = parsed["from"]
        original_subject = parsed["subject"]
        original_message_id = parsed["message_id"]
        thread_id = parsed["thread_id"]

        reply_subject = (
            original_subject
            if original_subject.lower().startswith("re:")
            else f"Re: {original_subject}"
        )

        msg = MIMEMultipart()
        msg["To"] = original_from
        msg["Subject"] = reply_subject
        if original_message_id:
            msg["In-Reply-To"] = original_message_id
            msg["References"] = original_message_id
        msg.attach(MIMEText(body, "plain", "utf-8"))

        raw_bytes = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        try:
            sent = (
                self._service.users()
                .messages()
                .send(
                    userId=user_id,
                    body={"raw": raw_bytes, "threadId": thread_id},
                )
                .execute()
            )
        except HttpError as exc:
            raise RuntimeError(f"Gmail API error: {exc}") from exc

        return {"id": sent.get("id", ""), "thread_id": sent.get("threadId", "")}

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------

    def _modify_labels(
        self,
        email_id: str,
        add_labels: list[str],
        remove_labels: list[str],
        user_id: str = "me",
    ) -> None:
        try:
            self._service.users().messages().modify(
                userId=user_id,
                id=email_id,
                body={"addLabelIds": add_labels, "removeLabelIds": remove_labels},
            ).execute()
        except HttpError as exc:
            raise RuntimeError(f"Gmail API error: {exc}") from exc

    def mark_as_read(self, email_id: str, user_id: str = "me") -> None:
        """Remove the ``UNREAD`` label from an email."""
        self._modify_labels(email_id, [], ["UNREAD"], user_id)

    def mark_as_unread(self, email_id: str, user_id: str = "me") -> None:
        """Add the ``UNREAD`` label to an email."""
        self._modify_labels(email_id, ["UNREAD"], [], user_id)

    def archive_email(self, email_id: str, user_id: str = "me") -> None:
        """Remove an email from the INBOX (archive it)."""
        self._modify_labels(email_id, [], ["INBOX"], user_id)

    def trash_email(self, email_id: str, user_id: str = "me") -> None:
        """Move an email to Trash."""
        try:
            self._service.users().messages().trash(userId=user_id, id=email_id).execute()
        except HttpError as exc:
            raise RuntimeError(f"Gmail API error: {exc}") from exc
