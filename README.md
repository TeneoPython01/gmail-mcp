# Gmail MCP Server

An MCP (Model Context Protocol) server that lets agentic AI assistants read, manage, and send emails through your Gmail account — with built-in security filtering to prevent exposure of sensitive personal information or passwords.

## Features

- **Read & Search Emails** – List inbox messages, search by query, or fetch a specific email by ID.
- **Manage Emails** – Archive, trash, mark as read/unread.
- **Send & Reply** – Compose new emails or reply in your own voice.
- **Security Filtering** – Automatically redacts or blocks emails containing:
  - Passwords or password-reset instructions
  - Social Security Numbers (SSN)
  - Credit card / bank account numbers
  - API keys, private keys, or bearer tokens
  - Other Sensitive Personal Information (SPI)

## Setup

### 1. Enable Gmail API and create credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project (or select an existing one).
3. Enable the **Gmail API** for the project.
4. Go to **APIs & Services → Credentials** and create an **OAuth 2.0 Client ID** (Application type: *Desktop app*).
5. Download the credential file and save it as `credentials.json` in the root of this project.

> **Important:** `credentials.json` and `token.json` are listed in `.gitignore` and must **never** be committed to the repository.

### 2. Install dependencies

```bash
pip install -e ".[dev]"
```

### 3. Authenticate (first run)

On the first run, the server opens a browser window for Google OAuth consent. Once you authorise access, a `token.json` file is written locally and reused for subsequent runs.

```bash
gmail-mcp --auth
```

### 4. Configure your MCP client

Add the server to your MCP client configuration (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "gmail": {
      "command": "gmail-mcp",
      "args": []
    }
  }
}
```

Or run it directly:

```bash
gmail-mcp
```

## Security Notes

- **No passwords are ever stored** – authentication uses OAuth 2.0 via the Google API.
- **The LLM never sees credentials** – only the MCP server authenticates to Gmail; the LLM only sees email content (after security filtering).
- **Sensitive content is filtered** – emails that match sensitive-pattern heuristics are either redacted or blocked before the content is returned to the LLM.

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_emails` | List emails from a label (default: INBOX) with optional search query |
| `get_email` | Retrieve the full content of an email by its ID |
| `search_emails` | Search emails using Gmail query syntax |
| `send_email` | Send a new email |
| `reply_to_email` | Reply to an existing email |
| `mark_as_read` | Mark an email as read |
| `mark_as_unread` | Mark an email as unread |
| `archive_email` | Archive an email (remove from INBOX) |
| `trash_email` | Move an email to Trash |

## Example Use Cases

- *"Write the code to accomplish what Susan emailed and asked me for."*
- *"Find my action items from emails in my inbox from the last 10 days."*
- *"Read the latest email from Ted, and reply in my own voice."*

## Running Tests

```bash
pytest
```
