"""
Agent Gate — Audit Logger

Structured JSONL logging for all tool calls passing through
the MCP proxy. Every tool call gets an audit record regardless
of verdict — this is the audit trail.

Design decisions:
  - JSONL format (one JSON object per line) for easy parsing,
    streaming, and integration with log aggregation systems.
  - File-based by default, but the AuditLogger interface is
    simple enough to swap in a database or API backend.
  - Records include: timestamp, tool name, arguments (sanitized),
    verdict, tier, reason, server name, and session info.
  - Sensitive arguments can be redacted via configuration.

This is the "auditability" complement to the gate's "prevention."
The gate makes the wrong action unreachable. The audit log
records what was attempted and what happened.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Any, TextIO


@dataclass
class AuditRecord:
    """
    A single audit log entry for a tool call.

    Every tool call through the proxy generates one of these,
    regardless of whether it was allowed, denied, or escalated.
    """
    timestamp: str
    tool_name: str
    arguments: dict
    verdict: str       # "allow", "deny", "escalate"
    tier: str          # "read_only", "destructive", "blocked", "network", "unclassified"
    reason: str        # Human-readable explanation
    server_name: Optional[str] = None
    session_id: Optional[str] = None
    msg_id: Optional[Any] = None      # JSON-RPC message id
    vault_path: Optional[str] = None  # Path to vault backup, if any
    duration_ms: Optional[float] = None  # Gate evaluation time

    def to_json(self) -> str:
        """Serialize to a single JSON line (no embedded newlines)."""
        d = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))


class AuditLogger:
    """
    Writes structured audit records to a JSONL file.

    Usage:
        logger = AuditLogger("/path/to/audit.jsonl")
        logger.log(record)
        logger.close()

    Thread safety: Not thread-safe. In the stdio proxy (single-threaded),
    this is fine. For HTTP+SSE, wrap with a lock or use a queue.
    """

    def __init__(
        self,
        path: str,
        server_name: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """
        Args:
            path: Path to the JSONL audit log file
            server_name: Name of the MCP server being proxied
            session_id: Unique session identifier
        """
        self.path = os.path.expanduser(path)
        self.server_name = server_name
        self.session_id = session_id
        self._file: Optional[TextIO] = None
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Create the audit log directory if it doesn't exist."""
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _open(self) -> TextIO:
        """Lazy-open the audit log file."""
        if self._file is None or self._file.closed:
            self._file = open(self.path, "a", encoding="utf-8")
        return self._file

    def log(self, record: AuditRecord) -> None:
        """
        Write an audit record to the log file.

        Records are appended as single JSON lines, flushed immediately.
        """
        # Inject session context if not already set
        if not record.server_name and self.server_name:
            record.server_name = self.server_name
        if not record.session_id and self.session_id:
            record.session_id = self.session_id

        try:
            f = self._open()
            f.write(record.to_json() + "\n")
            f.flush()
        except (IOError, OSError) as e:
            # Audit logging failure should not crash the proxy.
            # Log to stderr and continue.
            print(
                f"[agent-gate] audit log write failed: {e}",
                file=sys.stderr,
            )

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        verdict: str,
        tier: str,
        reason: str,
        msg_id: Optional[Any] = None,
        vault_path: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        """
        Convenience method to log a tool call with common fields.

        This is the primary interface for the proxy — call this
        after Gate.evaluate() returns a decision.
        """
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool_name=tool_name,
            arguments=arguments,
            verdict=verdict,
            tier=tier,
            reason=reason,
            msg_id=msg_id,
            vault_path=vault_path,
            duration_ms=duration_ms,
        )
        self.log(record)

    def log_passthrough(
        self,
        method: str,
        msg_id: Optional[Any] = None,
    ) -> None:
        """
        Log a non-tool-call message that was passed through.

        Lighter weight than a full tool call record — just tracks
        that a message passed through the proxy.
        """
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool_name=f"__passthrough:{method}",
            arguments={},
            verdict="passthrough",
            tier="none",
            reason=f"Non-tool-call message: {method}",
            msg_id=msg_id,
        )
        self.log(record)

    def log_proxy_event(
        self,
        event: str,
        details: Optional[dict] = None,
    ) -> None:
        """
        Log a proxy lifecycle event (startup, shutdown, error).
        """
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool_name="__proxy_event",
            arguments=details or {},
            verdict="event",
            tier="none",
            reason=event,
        )
        self.log(record)

    def close(self) -> None:
        """Close the audit log file."""
        if self._file and not self._file.closed:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
