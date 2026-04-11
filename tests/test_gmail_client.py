"""Tests for the GmailClient wrapper.

All Gmail API calls are mocked so no real credentials are needed.
"""

from __future__ import annotations

import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import MagicMock, patch

import pytest

from gmail_mcp.gmail_client import GmailClient
from gmail_mcp.security import SensitivityLevel


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _build_raw_message(
    msg_id: str = "msg1",
    thread_id: str = "thread1",
    subject: str = "Test Subject",
    from_: str = "alice@example.com",
    to: str = "bob@example.com",
    body_text: str = "Hello, world!",
    snippet: str = "Hello, world!",
    label_ids: list[str] | None = None,
) -> dict:
    """Return a minimal Gmail API message dict."""
    body_encoded = base64.urlsafe_b64encode(body_text.encode()).decode()
    return {
        "id": msg_id,
        "threadId": thread_id,
        "snippet": snippet,
        "labelIds": label_ids or ["INBOX"],
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "Subject", "value": subject},
                {"name": "From", "value": from_},
                {"name": "To", "value": to},
                {"name": "Date", "value": "Mon, 1 Jan 2024 00:00:00 +0000"},
                {"name": "Message-ID", "value": f"<{msg_id}@example.com>"},
            ],
            "body": {"data": body_encoded},
            "parts": [],
        },
    }


@pytest.fixture
def mock_service():
    """Return a mock Gmail API service and patch get_credentials + build."""
    with patch("gmail_mcp.gmail_client.get_credentials"), \
         patch("gmail_mcp.gmail_client.build") as mock_build:
        service = MagicMock()
        mock_build.return_value = service
        yield service


@pytest.fixture
def client(mock_service):
    """Return a GmailClient backed by a mock service."""
    return GmailClient()


# ---------------------------------------------------------------------------
# list_emails
# ---------------------------------------------------------------------------

class TestListEmails:
    def test_returns_filtered_emails(self, client, mock_service):
        raw = _build_raw_message(body_text="Meeting at 3pm", snippet="Meeting at 3pm")
        mock_service.users().messages().list().execute.return_value = {
            "messages": [{"id": "msg1"}]
        }
        mock_service.users().messages().get().execute.return_value = raw

        results = client.list_emails(max_results=5)

        assert len(results) == 1
        fe = results[0]
        assert fe.data["subject"] == "Test Subject"
        assert fe.scan.level == SensitivityLevel.NONE

    def test_empty_inbox_returns_empty_list(self, client, mock_service):
        mock_service.users().messages().list().execute.return_value = {"messages": []}

        results = client.list_emails()
        assert results == []

    def test_max_results_clamped_to_100(self, client, mock_service):
        mock_service.users().messages().list().execute.return_value = {}
        client.list_emails(max_results=200)
        call_kwargs = mock_service.users().messages().list.call_args
        assert call_kwargs.kwargs.get("maxResults", 100) <= 100

    def test_security_filtered_email_is_blocked(self, client, mock_service):
        raw = _build_raw_message(
            subject="Reset your password",
            body_text="Click here to reset your password.",
            snippet="Click here to reset",
        )
        mock_service.users().messages().list().execute.return_value = {
            "messages": [{"id": "msg1"}]
        }
        mock_service.users().messages().get().execute.return_value = raw

        results = client.list_emails()
        fe = results[0]
        assert fe.scan.level == SensitivityLevel.BLOCKED
        assert fe.data.get("security_filtered") is True


# ---------------------------------------------------------------------------
# get_email
# ---------------------------------------------------------------------------

class TestGetEmail:
    def test_get_email_returns_filtered_email(self, client, mock_service):
        raw = _build_raw_message(body_text="See you soon!")
        mock_service.users().messages().get().execute.return_value = raw

        fe = client.get_email("msg1")
        assert fe.data["id"] == "msg1"
        assert fe.data["body"] == "See you soon!"
        assert fe.scan.level == SensitivityLevel.NONE

    def test_get_email_with_ssn_is_redacted(self, client, mock_service):
        raw = _build_raw_message(body_text="Your SSN is 123-45-6789 ok?")
        mock_service.users().messages().get().execute.return_value = raw

        fe = client.get_email("msg1")
        assert fe.scan.level == SensitivityLevel.REDACTED
        assert "123-45-6789" not in fe.data["body"]
        assert "[SSN REDACTED]" in fe.data["body"]


# ---------------------------------------------------------------------------
# send_email
# ---------------------------------------------------------------------------

class TestSendEmail:
    def test_send_email_calls_api(self, client, mock_service):
        mock_service.users().messages().send().execute.return_value = {
            "id": "sent1",
            "threadId": "thread1",
        }

        result = client.send_email(
            to="bob@example.com",
            subject="Hello",
            body="Hi Bob!",
        )

        assert result["id"] == "sent1"
        assert result["thread_id"] == "thread1"
        mock_service.users().messages().send.assert_called()

    def test_send_email_with_cc_bcc(self, client, mock_service):
        mock_service.users().messages().send().execute.return_value = {
            "id": "sent2",
            "threadId": "thread2",
        }

        result = client.send_email(
            to="bob@example.com",
            subject="Test",
            body="Body",
            cc="carol@example.com",
            bcc="dave@example.com",
        )
        assert result["id"] == "sent2"


# ---------------------------------------------------------------------------
# reply_to_email
# ---------------------------------------------------------------------------

class TestReplyToEmail:
    def test_reply_adds_re_prefix(self, client, mock_service):
        raw = _build_raw_message(subject="Meeting notes", body_text="See agenda.")
        mock_service.users().messages().get().execute.return_value = raw
        mock_service.users().messages().send().execute.return_value = {
            "id": "reply1",
            "threadId": "thread1",
        }

        result = client.reply_to_email("msg1", body="Thanks for sharing!")
        assert result["id"] == "reply1"

        # Verify the sent message has Re: prefix.
        send_call_body = mock_service.users().messages().send.call_args.kwargs["body"]
        raw_sent = base64.urlsafe_b64decode(send_call_body["raw"]).decode()
        assert "Re: Meeting notes" in raw_sent

    def test_reply_does_not_duplicate_re_prefix(self, client, mock_service):
        raw = _build_raw_message(subject="Re: Meeting notes", body_text="See agenda.")
        mock_service.users().messages().get().execute.return_value = raw
        mock_service.users().messages().send().execute.return_value = {
            "id": "reply2",
            "threadId": "thread1",
        }

        client.reply_to_email("msg1", body="Ack")
        send_call_body = mock_service.users().messages().send.call_args.kwargs["body"]
        raw_sent = base64.urlsafe_b64decode(send_call_body["raw"]).decode()
        assert "Re: Re:" not in raw_sent


# ---------------------------------------------------------------------------
# mark_as_read / mark_as_unread / archive_email / trash_email
# ---------------------------------------------------------------------------

class TestManagement:
    def test_mark_as_read(self, client, mock_service):
        mock_service.users().messages().modify().execute.return_value = {}
        client.mark_as_read("msg1")
        call_kwargs = mock_service.users().messages().modify.call_args.kwargs
        assert "UNREAD" in call_kwargs["body"]["removeLabelIds"]

    def test_mark_as_unread(self, client, mock_service):
        mock_service.users().messages().modify().execute.return_value = {}
        client.mark_as_unread("msg1")
        call_kwargs = mock_service.users().messages().modify.call_args.kwargs
        assert "UNREAD" in call_kwargs["body"]["addLabelIds"]

    def test_archive_email(self, client, mock_service):
        mock_service.users().messages().modify().execute.return_value = {}
        client.archive_email("msg1")
        call_kwargs = mock_service.users().messages().modify.call_args.kwargs
        assert "INBOX" in call_kwargs["body"]["removeLabelIds"]

    def test_trash_email_calls_trash(self, client, mock_service):
        mock_service.users().messages().trash().execute.return_value = {}
        client.trash_email("msg1")
        mock_service.users().messages().trash.assert_called()
