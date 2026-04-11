# New Feature Ideas: Security & Privacy Enhancements

Ideas for making the Gmail MCP server more secure and better at preventing exposure of personal information to an LLM or bad actor.

---

## 1. Configurable Sender Allowlist / Blocklist
Let users define a list of trusted senders whose emails are always surfaced, and a blocklist of senders (e.g. banks, healthcare providers) whose emails are always blocked before the LLM sees them—regardless of content scanning results.

## 2. PII Scrubbing for Names, Phone Numbers, and Addresses
Extend the redaction engine to detect and redact additional PII categories: full names (when combined with other identifiers), US/international phone numbers, postal addresses, and passport or driver's license numbers.

## 3. Label-Based Access Control
Allow users to configure which Gmail labels (e.g. `work`, `finance`, `medical`) the LLM is permitted to access. Any email in a restricted label is blocked outright, even if its content passes the current pattern-based filter.

## 4. Per-Tool Permission Scopes
Introduce a permissions config so users can individually enable or disable destructive or sensitive tools—`send_email`, `trash_email`, `reply_to_email`—without having to modify code. This limits the blast radius if an LLM is manipulated via prompt injection.

## 5. Confirmation-Required Mode for Write Operations
Add an optional `require_confirmation` flag. When enabled, any tool that modifies state (send, reply, archive, trash, mark read/unread) returns a pending action object instead of executing immediately, and a separate `confirm_action` tool must be called to proceed.

## 6. Prompt-Injection Detection in Incoming Emails
Scan email bodies for patterns that attempt to hijack the LLM's behaviour—phrases like "Ignore previous instructions", "You are now a…", or system-prompt overrides—and block or flag those emails before they reach the model.

## 7. Attachment Content Filtering
Before surfacing attachment metadata or extracted text to the LLM, scan attachment content (PDFs, DOCX, plain text) with the same sensitive-pattern engine used for email bodies to catch credentials or PII embedded in files.

## 8. Outbound Email Content Scanning
Apply the same security filter to the `body` parameter of `send_email` and `reply_to_email` before the message is sent. This prevents the LLM from accidentally (or maliciously) forwarding redacted or sensitive content that it reconstructed from context.

## 9. Rate Limiting and Quota Enforcement
Enforce per-session and per-day limits on how many emails can be listed, read, or sent. This mitigates abuse if the MCP server is exposed over a network transport and also limits data exfiltration volume in a compromised session.

## 10. Audit Logging
Write an append-only, tamper-evident local log of every tool call: timestamp, tool name, parameters (with sensitive values masked), and the security filter result. This provides forensic visibility into what the LLM accessed or sent.

## 11. Encrypted Token Storage
Instead of storing `token.json` as a plain JSON file, encrypt it at rest using a key derived from a user-supplied passphrase or the OS keychain (e.g. `keyring` on macOS/Linux/Windows). This protects OAuth credentials if the filesystem is compromised.

## 12. Minimal OAuth Scopes by Default
Split the OAuth scope into read-only (`gmail.readonly`) and read-write (`gmail.modify`, `gmail.send`) profiles, and request only the scopes needed for the tools the user has enabled. Starting in read-only mode significantly reduces risk.

## 13. Email Body Truncation Limit
Cap the maximum number of characters returned from any single email body. Long emails (newsletters, log dumps) are more likely to contain incidentally sensitive data; truncating them reduces exposure surface and LLM context pollution.

## 14. Regex Pattern Hot-Reload from Config File
Allow users to define custom block and redact patterns in a local YAML/TOML config file without modifying source code. This makes it easy to add domain-specific patterns (e.g. internal employee IDs, account numbers) and update them without redeployment.

## 15. Metadata-Only Mode
Add a `metadata_only` flag to `list_emails` and `search_emails` that returns only sender, subject, date, and thread ID—never the body or snippet. The LLM can then decide which specific emails to fetch in full, reducing bulk data exposure.

## 16. Session Isolation and Time-Bounded Tokens
Generate a short-lived session token when the MCP server starts. Any tool call that arrives without a valid session token (or after the session expires) is rejected. This prevents replayed or delayed tool invocations from a stale agent context.

## 17. Redaction of Email Addresses in CC/BCC/To Fields
Optionally anonymise or redact email addresses in `to`, `cc`, and `bcc` headers before returning them to the LLM. This prevents third-party contact lists from leaking to the model when it has no need to know the full addresses.

## 18. Sensitive-Domain Blocklist for Outbound Sends
Maintain a configurable list of sensitive domains (e.g. `irs.gov`, `healthcare.gov`, internal corporate domains) to which the LLM is never permitted to send email. Any `send_email` or `reply_to_email` call targeting a blocked domain is rejected with an error.

## 19. HTML-to-Text Sanitisation Before Scanning
Strip HTML markup and decode encoded entities (e.g. `&#112;&#97;&#115;&#115;`) before running the security filter. Attackers can use HTML encoding or CSS tricks to smuggle plaintext passwords or tokens past regex-based scanners that operate on raw HTML.

## 20. Security Filter Transparency Report Tool
Expose a `get_security_summary` MCP tool that returns aggregate statistics about the current session—how many emails were scanned, how many were blocked, how many were redacted, and which pattern categories triggered—without revealing the underlying content. This gives the LLM (and the user) visibility into filtering activity.
