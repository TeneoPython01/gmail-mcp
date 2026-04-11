"""OAuth2 authentication helpers for the Gmail API.

Credentials (credentials.json) and tokens (token.json) are *never* committed
to the repository; they are listed in .gitignore.

The LLM has no visibility into this module – it only ever calls the high-level
MCP tools which return already-filtered email data.
"""

from __future__ import annotations

import os
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Read-only access to Gmail messages + full compose/send scope.
# We do NOT request access to other Google services.
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
]

DEFAULT_CREDENTIALS_FILE = Path(os.environ.get("GMAIL_CREDENTIALS_FILE", "credentials.json"))
DEFAULT_TOKEN_FILE = Path(os.environ.get("GMAIL_TOKEN_FILE", "token.json"))


def get_credentials(
    credentials_file: Path = DEFAULT_CREDENTIALS_FILE,
    token_file: Path = DEFAULT_TOKEN_FILE,
) -> Credentials:
    """Return valid Google OAuth2 credentials, refreshing or re-authorising as needed.

    Args:
        credentials_file: Path to the OAuth2 client-secret JSON downloaded from
            Google Cloud Console.  Defaults to ``credentials.json`` in the
            current working directory (or the ``GMAIL_CREDENTIALS_FILE`` env var).
        token_file: Path where the access/refresh token is persisted between
            runs.  Defaults to ``token.json`` (or the ``GMAIL_TOKEN_FILE`` env
            var).  This file is created on the first successful authorisation
            and re-read on subsequent runs.

    Returns:
        A :class:`google.oauth2.credentials.Credentials` object that is valid
        and ready to use.

    Raises:
        FileNotFoundError: If *credentials_file* does not exist.
        google.auth.exceptions.TransportError: On network failures during token
            refresh.
    """
    creds: Credentials | None = None

    if token_file.exists():
        creds = Credentials.from_authorized_user_file(str(token_file), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not credentials_file.exists():
                raise FileNotFoundError(
                    f"OAuth2 credentials file not found: {credentials_file}\n"
                    "Download it from Google Cloud Console and save it as "
                    "'credentials.json' in the project root (it is gitignored)."
                )
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
            creds = flow.run_local_server(port=0)

        token_file.write_text(creds.to_json())

    return creds
