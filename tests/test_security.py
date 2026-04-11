"""Tests for the security / content-filtering module."""

from __future__ import annotations

import pytest

from gmail_mcp.security import (
    SensitivityLevel,
    filter_attachment,
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


# ---------------------------------------------------------------------------
# filter_attachment – attachment content filtering
# ---------------------------------------------------------------------------

def _make_attachment(**kwargs) -> dict:
    defaults = {
        "filename": "document.txt",
        "mime_type": "text/plain",
        "size": 100,
        "content": "",
    }
    defaults.update(kwargs)
    return defaults


class TestFilterAttachment:
    def test_clean_attachment_passes_through(self):
        att = _make_attachment(content="Just a plain document with no secrets.")
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.NONE
        assert fa.data["content"] == "Just a plain document with no secrets."
        assert not fa.data.get("security_filtered")

    def test_empty_content_passes_through(self):
        att = _make_attachment(content="")
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.NONE

    def test_no_content_key_passes_through(self):
        att = {"filename": "image.png", "mime_type": "image/png", "size": 2048}
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.NONE

    # Credential patterns → BLOCKED

    def test_private_key_in_attachment_is_blocked(self):
        att = _make_attachment(
            filename="key.pem",
            content="-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.BLOCKED
        assert fa.data.get("security_filtered") is True
        assert "[ATTACHMENT BLOCKED" in fa.data["content"]
        assert isinstance(fa.data.get("security_reasons"), list)
        assert len(fa.data["security_reasons"]) > 0

    def test_password_reset_text_in_attachment_is_blocked(self):
        att = _make_attachment(
            filename="email_body.txt",
            content="Please click here to reset your password.",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.BLOCKED
        assert fa.data.get("security_filtered") is True

    def test_plaintext_password_in_attachment_is_blocked(self):
        att = _make_attachment(
            filename="creds.txt",
            content="Your temporary password is: S3cr3tP@ss!",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.BLOCKED

    # PII patterns → REDACTED

    def test_ssn_in_attachment_is_redacted(self):
        att = _make_attachment(
            filename="tax_form.txt",
            content="Taxpayer SSN: 321-54-9876 – please verify.",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.REDACTED
        assert "321-54-9876" not in fa.data["content"]
        assert "[SSN REDACTED]" in fa.data["content"]
        assert fa.data.get("security_filtered") is True

    def test_credit_card_in_attachment_is_redacted(self):
        att = _make_attachment(
            filename="invoice.txt",
            content="Charge to card 4111 1111 1111 1111 for $99.",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.REDACTED
        assert "[CARD NUMBER REDACTED]" in fa.data["content"]

    def test_bearer_token_in_attachment_is_redacted(self):
        att = _make_attachment(
            filename="config.txt",
            content="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.REDACTED
        assert "[TOKEN REDACTED]" in fa.data["content"]

    def test_aws_key_in_attachment_is_redacted(self):
        att = _make_attachment(
            filename="aws_config.txt",
            content="Access key: AKIAIOSFODNN7EXAMPLE",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.REDACTED
        assert "AKIAIOSFODNN7EXAMPLE" not in fa.data["content"]
        assert "[AWS KEY REDACTED]" in fa.data["content"]

    def test_routing_number_in_attachment_is_redacted(self):
        att = _make_attachment(
            filename="bank_info.txt",
            content="ABA routing: 021000021",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.REDACTED
        assert "[ROUTING NUMBER REDACTED]" in fa.data["content"]

    def test_block_takes_priority_over_redact_in_attachment(self):
        att = _make_attachment(
            content="Reset your password. SSN: 123-45-6789.",
        )
        fa = filter_attachment(att)
        assert fa.scan.level == SensitivityLevel.BLOCKED

    def test_original_content_unchanged_on_clean(self):
        original = "Meeting agenda: discuss Q3 targets."
        att = _make_attachment(content=original)
        fa = filter_attachment(att)
        assert fa.data["content"] == original
        assert fa.data.get("security_reasons") is None

    def test_security_reasons_present_on_redact(self):
        att = _make_attachment(content="SSN is 234-56-7890 here.")
        fa = filter_attachment(att)
        assert isinstance(fa.data.get("security_reasons"), list)
        assert len(fa.data["security_reasons"]) > 0

    def test_security_reasons_present_on_block(self):
        att = _make_attachment(content="Your one-time password is 482910.")
        fa = filter_attachment(att)
        assert isinstance(fa.data.get("security_reasons"), list)
        assert len(fa.data["security_reasons"]) > 0

    def test_filename_and_mime_preserved_after_block(self):
        att = _make_attachment(
            filename="secret.txt",
            mime_type="text/plain",
            content="-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkq...",
        )
        fa = filter_attachment(att)
        assert fa.data["filename"] == "secret.txt"
        assert fa.data["mime_type"] == "text/plain"

    def test_filename_and_mime_preserved_after_redact(self):
        att = _make_attachment(
            filename="data.csv",
            mime_type="text/plain",
            content="Row1, SSN 111-22-3333",
        )
        fa = filter_attachment(att)
        assert fa.data["filename"] == "data.csv"
        assert fa.data["mime_type"] == "text/plain"


# ---------------------------------------------------------------------------
# filter_email with attachments
# ---------------------------------------------------------------------------

class TestFilterEmailWithAttachments:
    def test_email_with_clean_attachment_passes(self):
        email = _make_email(
            subject="Report",
            body="Please see the attached report.",
            attachments=[_make_attachment(content="Q3 results look good.")],
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.NONE
        assert len(fe.data["attachments"]) == 1
        assert fe.data["attachments"][0]["content"] == "Q3 results look good."

    def test_email_with_ssn_in_attachment_is_redacted(self):
        email = _make_email(
            subject="Tax document",
            body="See attached.",
            attachments=[
                _make_attachment(
                    filename="tax.txt",
                    content="Taxpayer SSN: 123-45-6789",
                )
            ],
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.REDACTED
        att = fe.data["attachments"][0]
        assert "123-45-6789" not in att["content"]
        assert "[SSN REDACTED]" in att["content"]

    def test_email_with_credential_in_attachment_raises_level(self):
        email = _make_email(
            subject="Keys",
            body="Here are your keys.",
            attachments=[
                _make_attachment(
                    filename="key.pem",
                    content="-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
                )
            ],
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED
        att = fe.data["attachments"][0]
        assert att.get("security_filtered") is True

    def test_email_body_blocked_ignores_attachment_level(self):
        # When the email body itself is blocked, the whole email is blocked
        # regardless of what attachments contain.
        email = _make_email(
            subject="Reset your password",
            body="Click here to reset.",
            attachments=[_make_attachment(content="Normal content.")],
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.BLOCKED

    def test_email_with_no_attachments_key(self):
        email = _make_email(subject="Hello", body="Hi there!")
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.NONE
        # No attachments key in result when there are none
        assert "attachments" not in fe.data or fe.data.get("attachments") == []

    def test_email_with_multiple_attachments_all_filtered(self):
        email = _make_email(
            subject="Documents",
            body="See attached files.",
            attachments=[
                _make_attachment(filename="safe.txt", content="Nothing sensitive."),
                _make_attachment(filename="pii.txt", content="SSN: 234-56-7890"),
                _make_attachment(
                    filename="creds.txt",
                    content="api_key = abcdefghijklmnopqrstuvwxyz12345678",
                ),
            ],
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.REDACTED
        atts = fe.data["attachments"]
        assert atts[0]["content"] == "Nothing sensitive."
        assert "[SSN REDACTED]" in atts[1]["content"]
        assert "[TOKEN REDACTED]" in atts[2]["content"]

    def test_attachment_scan_reasons_propagated_to_email_scan(self):
        email = _make_email(
            subject="Data",
            body="See attached.",
            attachments=[
                _make_attachment(
                    filename="data.txt",
                    content="Card: 4111 1111 1111 1111",
                )
            ],
        )
        fe = filter_email(email)
        assert fe.scan.level == SensitivityLevel.REDACTED
        assert any("data.txt" in r for r in fe.scan.reasons)
