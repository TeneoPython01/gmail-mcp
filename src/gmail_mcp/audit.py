"""Append-only, tamper-evident audit log for Gmail MCP tool calls (Feature 10).

Every tool invocation is recorded as a JSON line containing:

* ``seq``        – monotonically increasing sequence number.
* ``timestamp``  – UTC ISO-8601 timestamp.
* ``tool``       – name of the MCP tool that was called.
* ``params``     – tool parameters with sensitive values masked.
* ``result``     – outcome string: ``"ok"``, ``"blocked"``, ``"error"``,
                   or ``"pending"``.
* ``reasons``    – list of security filter reasons (may be empty).
* ``prev_hash``  – SHA-256 hex digest of the *previous* log line, forming a
                   hash chain that makes undetected tampering of earlier
                   entries computationally infeasible.

Audit logging is enabled by setting the ``GMAIL_AUDIT_LOG`` environment
variable to the desired log file path.  When the variable is unset or empty,
no log file is written.

The singleton :func:`get_audit_logger` returns ``None`` when logging is
disabled, so call sites can guard with a simple ``if logger:`` check.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Parameters whose *values* are replaced by a length annotation in the log.
# ---------------------------------------------------------------------------
_BODY_PARAMS: frozenset[str] = frozenset({"body"})

# Maximum characters stored verbatim for any single non-body string parameter.
_MAX_VERBATIM_LEN = 500


class AuditLogger:
    """Thread-safe, append-only audit logger with a SHA-256 hash chain."""

    def __init__(self, log_path: str) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        self._seq: int = 0
        # SHA-256 of an empty byte string as the genesis hash.
        self._prev_hash: str = hashlib.sha256(b"").hexdigest()
        self._load_state()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _load_state(self) -> None:
        """Resume sequence numbering and hash chain from an existing log."""
        if not os.path.exists(self._path):
            return
        last_line: str | None = None
        try:
            with open(self._path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
        except OSError:
            return
        if last_line:
            try:
                entry = json.loads(last_line)
                self._seq = int(entry.get("seq", 0)) + 1
                self._prev_hash = hashlib.sha256(last_line.encode()).hexdigest()
            except (json.JSONDecodeError, ValueError, KeyError):
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_params(params: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of *params* with sensitive values masked."""
        masked: dict[str, Any] = {}
        for key, value in params.items():
            if key in _BODY_PARAMS and isinstance(value, str) and value:
                masked[key] = f"[{len(value)} chars]"
            elif isinstance(value, str) and len(value) > _MAX_VERBATIM_LEN:
                masked[key] = value[:_MAX_VERBATIM_LEN] + "...[truncated]"
            else:
                masked[key] = value
        return masked

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        tool: str,
        params: dict[str, Any],
        result: str,
        reasons: list[str] | None = None,
    ) -> None:
        """Append one audit entry.

        Args:
            tool:    Name of the MCP tool that was invoked.
            params:  Raw tool parameters (sensitive values will be masked).
            result:  Short outcome string (``"ok"``, ``"blocked"``,
                     ``"error"``, ``"pending"``).
            reasons: Optional list of security-filter reason strings.
        """
        with self._lock:
            entry: dict[str, Any] = {
                "seq": self._seq,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": tool,
                "params": self._mask_params(params),
                "result": result,
                "reasons": reasons or [],
                "prev_hash": self._prev_hash,
            }
            line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
            self._prev_hash = hashlib.sha256(line.encode()).hexdigest()
            self._seq += 1
            try:
                parent_dir = os.path.dirname(os.path.abspath(self._path))
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Singleton management
# ---------------------------------------------------------------------------

_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger | None:
    """Return the singleton :class:`AuditLogger`, or ``None`` if disabled.

    The logger is created lazily on the first call using the ``GMAIL_AUDIT_LOG``
    environment variable.  If the variable is unset or empty, returns ``None``.
    """
    global _logger
    if _logger is None:
        log_path = os.environ.get("GMAIL_AUDIT_LOG", "").strip()
        if log_path:
            _logger = AuditLogger(log_path)
    return _logger


def reset_audit_logger() -> None:
    """Reset the singleton logger (used in tests to reinitialise state)."""
    global _logger
    _logger = None
