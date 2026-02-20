"""
Agent Gate â€” Audit Logger

Structured JSONL logging for all tool calls passing through
the MCP proxy. Every tool call gets an audit record regardless
of verdict â€” this is the audit trail.

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

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Any, TextIO

# Genesis hash â€" the prev_hash for the first record in any chain.
# Using a well-known constant makes chain verification deterministic.
GENESIS_HASH = "0" * 64  # 64 hex chars = 256 bits of zeros


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
    prev_hash: Optional[str] = None   # SHA-256 hash of previous record (chain link)
    record_hash: Optional[str] = None  # SHA-256 hash of this record's content

    def _content_for_hashing(self) -> str:
        """
        Produce a deterministic string of this record's content for hashing.

        Includes all fields EXCEPT record_hash (which is derived from this
        content).  prev_hash IS included â€" it's part of what makes this
        record unique in the chain.  Sorted keys + separators without
        spaces ensure the same content always produces the same hash.
        """
        d = {k: v for k, v in asdict(self).items()
             if v is not None and k != "record_hash"}
        return json.dumps(d, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this record's content."""
        return hashlib.sha256(
            self._content_for_hashing().encode("utf-8")
        ).hexdigest()

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
        self._last_hash: str = self._seed_chain()

    def _ensure_directory(self) -> None:
        """Create the audit log directory if it doesn't exist."""
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _seed_chain(self) -> str:
        """
        Read the last record from an existing log to resume the chain.

        If the file doesn't exist or is empty, returns GENESIS_HASH.
        If the last record lacks a record_hash (pre-chain log), returns
        GENESIS_HASH â€" new records will start a chain from that point.
        """
        if not os.path.exists(self.path):
            return GENESIS_HASH
        try:
            last_line = None
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if last_line:
                record = json.loads(last_line)
                return record.get("record_hash", GENESIS_HASH)
        except (IOError, OSError, json.JSONDecodeError):
            pass
        return GENESIS_HASH

    def _chain_record(self, record: AuditRecord) -> None:
        """
        Set the hash chain fields on a record before writing.

        Links this record to the previous one via prev_hash,
        then computes this record's own hash.
        """
        record.prev_hash = self._last_hash
        record.record_hash = record.compute_hash()
        self._last_hash = record.record_hash

    def _open(self) -> TextIO:
        """Lazy-open the audit log file."""
        if self._file is None or self._file.closed:
            self._file = open(self.path, "a", encoding="utf-8")
        return self._file

    def log(self, record: AuditRecord) -> None:
        """
        Write an audit record to the log file.

        Records are chained via SHA-256 hashes, then appended as
        single JSON lines, flushed immediately.
        """
        # Inject session context if not already set
        if not record.server_name and self.server_name:
            record.server_name = self.server_name
        if not record.session_id and self.session_id:
            record.session_id = self.session_id

        # Link into the hash chain
        self._chain_record(record)

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

        This is the primary interface for the proxy â€” call this
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

        Lighter weight than a full tool call record â€” just tracks
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


def verify_chain(path: str) -> tuple[bool, int, Optional[str]]:
    """
    Walk an audit log and verify the hash chain integrity.

    Returns:
        (valid, records_checked, error_message)
        - valid: True if the entire chain is intact
        - records_checked: Number of records successfully verified
        - error_message: None if valid, description of the break if not

    A log with no chain-enabled records (pre-chain legacy log)
    returns (True, 0, None).
    """
    if not os.path.exists(path):
        return (True, 0, None)

    expected_prev = GENESIS_HASH
    checked = 0

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                record_dict = json.loads(stripped)

                # Skip pre-chain records (no hash fields)
                if "record_hash" not in record_dict:
                    continue

                # Verify prev_hash links to the previous record
                actual_prev = record_dict.get("prev_hash", "")
                if actual_prev != expected_prev:
                    return (
                        False, checked,
                        f"Chain broken at line {line_num}: "
                        f"expected prev_hash={expected_prev[:16]}..., "
                        f"got {actual_prev[:16]}..."
                    )

                # Recompute and verify this record's hash
                stored_hash = record_dict["record_hash"]
                # Rebuild the content dict the same way AuditRecord does:
                # all fields except record_hash, sorted keys
                content = {k: v for k, v in record_dict.items()
                           if k != "record_hash" and v is not None}
                content_str = json.dumps(
                    content, sort_keys=True, ensure_ascii=False,
                    separators=(",", ":")
                )
                computed_hash = hashlib.sha256(
                    content_str.encode("utf-8")
                ).hexdigest()

                if computed_hash != stored_hash:
                    return (
                        False, checked,
                        f"Hash mismatch at line {line_num}: "
                        f"stored={stored_hash[:16]}..., "
                        f"computed={computed_hash[:16]}..."
                    )

                expected_prev = stored_hash
                checked += 1

    except (IOError, OSError, json.JSONDecodeError) as e:
        return (False, checked, f"Read error: {e}")

    return (True, checked, None)
