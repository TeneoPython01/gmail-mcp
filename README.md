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
- **Prompt-Injection Detection** – Incoming email bodies are scanned for instruction-override attempts before they reach the LLM.
- **Outbound Content Scanning** *(Feature 8)* – The body of every outgoing email is scanned for sensitive content before it is sent, preventing the LLM from forwarding credentials it reconstructed from context.
- **Audit Logging** *(Feature 10)* – Every tool call is recorded in an append-only, hash-chain-tamper-evident JSONL log file with sensitive parameter values masked.
- **Body Truncation** *(Feature 13)* – Email bodies longer than a configurable limit are truncated before being returned to the LLM, reducing bulk data exposure.
- **Custom Pattern Hot-Reload** *(Feature 14)* – Define your own block/redact regex patterns in a YAML file that is reloaded automatically whenever it changes, with no server restart required.
- **Metadata-Only Mode** *(Feature 15)* – `list_emails` and `search_emails` accept a `metadata_only` flag that returns only sender, subject, date, and thread ID — never the body or snippet.
- **Label-Based Access Control** *(Feature 3)* – Configure which Gmail labels (e.g. `finance`, `medical`) the LLM is permitted to access.
- **Per-Tool Permission Scopes** *(Feature 4)* – Individually enable or disable destructive tools (`send_email`, `trash_email`, `reply_to_email`) via environment variables.
- **Confirmation-Required Mode** *(Feature 5)* – Any write operation can return a pending-action object instead of executing immediately; a separate `confirm_action` call is required to proceed.

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

## Configuration

All options are set via environment variables. None are required; everything has a safe default.

| Environment Variable | Default | Description |
|---|---|---|
| `GMAIL_BLOCKED_LABELS` | *(empty)* | Comma-separated label names the LLM cannot access (Feature 3). |
| `GMAIL_DISABLED_TOOLS` | *(empty)* | Comma-separated tool names that are disabled (Feature 4). |
| `GMAIL_REQUIRE_CONFIRMATION` | `false` | Set to `true` / `1` / `yes` to require `confirm_action` before write operations execute (Feature 5). |
| `GMAIL_AUDIT_LOG` | *(empty)* | Path to the append-only audit log file. Audit logging is disabled when unset (Feature 10). |
| `GMAIL_MAX_BODY_CHARS` | `0` | Maximum characters returned from any single email body. `0` means no limit (Feature 13). |
| `GMAIL_PATTERNS_FILE` | *(empty)* | Path to a YAML file with custom block/redact patterns, hot-reloaded on change (Feature 14). |

### Custom Pattern File Format (Feature 14)

Create a YAML file and set `GMAIL_PATTERNS_FILE` to its path:

```yaml
block_patterns:
  - name: "employee ID"
    pattern: 'EMP-\d{6}'

redact_patterns:
  - name: "internal account number"
    pattern: 'ACC-\d{8}'
    placeholder: "[ACCOUNT REDACTED]"
```

The file is re-read automatically whenever its modification time changes — no restart needed.

## Security Notes

- **No passwords are ever stored** – authentication uses OAuth 2.0 via the Google API.
- **The LLM never sees credentials** – only the MCP server authenticates to Gmail; the LLM only sees email content (after security filtering).
- **Sensitive content is filtered** – emails that match sensitive-pattern heuristics are either redacted or blocked before the content is returned to the LLM.
- **Outbound scanning** – the body of every outgoing email is scanned for sensitive content before sending; the send is blocked if sensitive data is detected (Feature 8).
- **Audit logging** – when enabled, every tool call is written to an append-only log with a SHA-256 hash chain, making undetected tampering of earlier entries computationally infeasible (Feature 10).

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_emails` | List emails from a label (default: INBOX) with optional search query and `metadata_only` flag |
| `get_email` | Retrieve the full content of an email by its ID |
| `search_emails` | Search emails using Gmail query syntax, with optional `metadata_only` flag |
| `send_email` | Send a new email (outbound body is security-scanned before sending) |
| `reply_to_email` | Reply to an existing email (outbound body is security-scanned before sending) |
| `mark_as_read` | Mark an email as read |
| `mark_as_unread` | Mark an email as unread |
| `archive_email` | Archive an email (remove from INBOX) |
| `trash_email` | Move an email to Trash |
| `confirm_action` | Execute a pending write action (used with confirmation-required mode) |

### Metadata-Only Mode (Feature 15)

Pass `metadata_only=true` to `list_emails` or `search_emails` to receive only sender, subject, date, and thread ID — never the body or snippet. This lets the LLM browse at scale and then fetch only the specific emails it needs in full, minimising data exposure.

## Example Use Cases

- *"Write the code to accomplish what Susan emailed and asked me for."*
- *"Find my action items from emails in my inbox from the last 10 days."*
- *"Read the latest email from Ted, and reply in my own voice."*
- *"List the subjects of all emails from the last week without reading their content."* (`metadata_only=true`)

## Running Tests

```bash
pytest
```
