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

Follow these steps in order to get the server running from scratch.

---

### Step 1 – Prerequisites

Make sure the following are installed before you begin:

| Requirement | Minimum version | Check |
|---|---|---|
| Python | 3.10 | `python --version` |
| pip | bundled with Python | `pip --version` |
| git | any recent version | `git --version` |

You also need a **Google account** whose Gmail inbox you want to connect.

---

### Step 2 – Clone the repository

```bash
git clone https://github.com/TeneoPython01/gmail-mcp.git
cd gmail-mcp
```

---

### Step 3 – Install dependencies

```bash
pip install -e ".[dev]"
```

This installs the `gmail-mcp` CLI entry-point and all runtime + development dependencies.

---

### Step 4 – Create a Google Cloud project and enable the Gmail API

1. Open [Google Cloud Console](https://console.cloud.google.com/) and sign in.
2. Click the project selector at the top of the page, then click **New Project**.
   - Enter a project name (e.g. `gmail-mcp`) and click **Create**.
3. Make sure your new project is selected in the project selector.
4. In the left navigation menu go to **APIs & Services → Library**.
5. Search for **Gmail API** and click on it, then click **Enable**.

---

### Step 5 – Configure the OAuth consent screen

> This step is required before you can create OAuth credentials.

1. Go to **APIs & Services → OAuth consent screen**.
2. Select **External** as the user type (or **Internal** if you are on Google Workspace and only want organisational accounts to use it), then click **Create**.
3. Fill in the required fields:
   - **App name** – e.g. `Gmail MCP`
   - **User support email** – your Google account email
   - **Developer contact email** – your Google account email
4. Click **Save and Continue** through the **Scopes** and **Test users** screens (you can leave them at their defaults for now).
5. On the **Summary** screen click **Back to Dashboard**.
6. While the app is in *Testing* status, only accounts you add as test users can authenticate.  Click **+ Add Users** on the **OAuth consent screen** page and add your own Google account email.

---

### Step 6 – Create OAuth 2.0 credentials

1. Go to **APIs & Services → Credentials**.
2. Click **+ Create Credentials → OAuth client ID**.
3. Set **Application type** to **Desktop app**.
4. Give it a name (e.g. `gmail-mcp-desktop`) and click **Create**.
5. A dialog shows your client ID and secret — click **Download JSON**.
6. Rename the downloaded file to `credentials.json` and place it in the **root of this repository** (the same folder as `pyproject.toml`).

> **Important:** `credentials.json` and `token.json` are listed in `.gitignore` and must **never** be committed to the repository.

---

### Step 7 – Authenticate (first run)

Run the auth helper. It opens a browser window for the Google OAuth consent flow. Select your Google account, grant the requested permissions, and the browser will confirm that authentication was successful.

```bash
gmail-mcp --auth
```

A `token.json` file is written to the project root and reused automatically for all subsequent runs. You only need to repeat this step if you delete `token.json` or if the token is revoked.

---

### Step 8 – (Optional) Configure environment variables

All runtime options are controlled through environment variables. You can set them in your shell or in a `.env` file in the project root (the server uses `python-dotenv` to load it automatically).

**Example `.env` file:**

```dotenv
# Restrict which Gmail labels the LLM can access
GMAIL_BLOCKED_LABELS=finance,medical

# Disable destructive tools you don't need
GMAIL_DISABLED_TOOLS=trash_email

# Require explicit confirmation before any write operation executes
GMAIL_REQUIRE_CONFIRMATION=true

# Enable append-only audit logging
GMAIL_AUDIT_LOG=/path/to/audit.jsonl

# Truncate email bodies longer than this many characters (0 = no limit)
GMAIL_MAX_BODY_CHARS=10000

# Path to a YAML file with custom block/redact patterns (hot-reloaded)
GMAIL_PATTERNS_FILE=/path/to/patterns.yaml
```

See the [Configuration](#configuration) section below for the full list of options.

---

### Step 9 – Connect to your MCP client

#### Claude Desktop

Add the server to your Claude Desktop config file.

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

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

Restart Claude Desktop. You should see a 🔨 (tools) icon in the chat input bar indicating the Gmail tools are available.

#### Other MCP clients

Consult your client's documentation for how to register a stdio MCP server. The command to run is simply:

```bash
gmail-mcp
```

---

### Step 10 – Verify the setup

Start the server manually to confirm everything is working:

```bash
gmail-mcp
```

If authentication is valid and the Gmail API is reachable the server starts silently and waits for MCP requests. You can also run the test suite:

```bash
pytest
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
