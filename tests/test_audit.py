"""
Tests for Agent Gate audit logger.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.audit import AuditLogger, AuditRecord
from agent_gate.audit import verify_chain, GENESIS_HASH


class TestAuditRecord(unittest.TestCase):
    """Test AuditRecord serialization."""

    def test_to_json_basic(self):
        record = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="read_file",
            arguments={"path": "/etc/hosts"},
            verdict="allow",
            tier="read_only",
            reason="Read-only action, auto-allowed",
        )
        line = record.to_json()
        parsed = json.loads(line)
        self.assertEqual(parsed["tool_name"], "read_file")
        self.assertEqual(parsed["verdict"], "allow")

    def test_to_json_no_embedded_newlines(self):
        record = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="write_file",
            arguments={"content": "line1\nline2\nline3"},
            verdict="allow",
            tier="destructive",
            reason="test",
        )
        line = record.to_json()
        # Newlines in content should be escaped
        self.assertNotIn("\n", line)

    def test_to_json_omits_none_fields(self):
        record = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="ping",
            arguments={},
            verdict="allow",
            tier="read_only",
            reason="test",
            # All optional fields left as None
        )
        line = record.to_json()
        parsed = json.loads(line)
        self.assertNotIn("server_name", parsed)
        self.assertNotIn("vault_path", parsed)
        self.assertNotIn("duration_ms", parsed)

    def test_to_json_includes_optional_fields(self):
        record = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="rm",
            arguments={"path": "/tmp/test"},
            verdict="allow",
            tier="destructive",
            reason="Vault backup created",
            server_name="filesystem",
            session_id="abc123",
            vault_path="/vault/backup.tar",
            duration_ms=12.5,
        )
        line = record.to_json()
        parsed = json.loads(line)
        self.assertEqual(parsed["server_name"], "filesystem")
        self.assertEqual(parsed["vault_path"], "/vault/backup.tar")
        self.assertEqual(parsed["duration_ms"], 12.5)


class TestAuditLogger(unittest.TestCase):
    """Test AuditLogger file I/O."""

    def test_log_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call(
                    tool_name="test",
                    arguments={},
                    verdict="allow",
                    tier="read_only",
                    reason="test",
                )
            self.assertTrue(os.path.exists(path))

    def test_log_appends_jsonl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call("tool1", {}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {}, "deny", "blocked", "r2")

            with open(path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["tool_name"], "tool1")
            self.assertEqual(json.loads(lines[1])["tool_name"], "tool2")

    def test_log_injects_session_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path, server_name="fs", session_id="s1") as logger:
                logger.log_tool_call("test", {}, "allow", "read_only", "r")

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertEqual(record["server_name"], "fs")
            self.assertEqual(record["session_id"], "s1")

    def test_log_passthrough(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_passthrough("initialize", msg_id=1)

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertIn("passthrough", record["tool_name"])
            self.assertEqual(record["verdict"], "passthrough")

    def test_log_proxy_event(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_proxy_event("proxy_started", {"config": "test"})

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertEqual(record["reason"], "proxy_started")
            self.assertEqual(record["arguments"]["config"], "test")

    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "deep", "nested", "audit.jsonl")
            with AuditLogger(nested) as logger:
                logger.log_tool_call("test", {}, "allow", "read_only", "r")
            self.assertTrue(os.path.exists(nested))

    def test_context_manager_closes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            logger = AuditLogger(path)
            logger.log_tool_call("test", {}, "allow", "read_only", "r")
            self.assertFalse(logger._file.closed)
            logger.close()
            self.assertTrue(logger._file is None or logger._file.closed)


class TestHashChain(unittest.TestCase):
    """Test cryptographic hash chaining for audit log tamper evidence."""

    def test_records_have_hash_fields(self):
        """Every logged record should have prev_hash and record_hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call("test", {}, "allow", "read_only", "r")

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertIn("prev_hash", record)
            self.assertIn("record_hash", record)
            self.assertEqual(len(record["record_hash"]), 64)  # SHA-256 hex

    def test_first_record_links_to_genesis(self):
        """The first record in a new log should have prev_hash = GENESIS_HASH."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call("test", {}, "allow", "read_only", "r")

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertEqual(record["prev_hash"], GENESIS_HASH)

    def test_chain_links_correctly(self):
        """Each record's prev_hash should match the previous record's record_hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call("tool1", {"a": 1}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {"b": 2}, "deny", "blocked", "r2")
                logger.log_tool_call("tool3", {"c": 3}, "allow", "read_only", "r3")

            with open(path) as f:
                records = [json.loads(line) for line in f]

            self.assertEqual(len(records), 3)
            # First links to genesis
            self.assertEqual(records[0]["prev_hash"], GENESIS_HASH)
            # Second links to first
            self.assertEqual(records[1]["prev_hash"], records[0]["record_hash"])
            # Third links to second
            self.assertEqual(records[2]["prev_hash"], records[1]["record_hash"])

    def test_verify_chain_valid(self):
        """verify_chain should return True for an intact chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                for i in range(5):
                    logger.log_tool_call(f"tool{i}", {}, "allow", "read_only", "r")

            valid, checked, error = verify_chain(path)
            self.assertTrue(valid)
            self.assertEqual(checked, 5)
            self.assertIsNone(error)

    def test_verify_chain_detects_tampered_record(self):
        """verify_chain should detect when a record's content is modified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call("tool1", {}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {}, "deny", "blocked", "r2")
                logger.log_tool_call("tool3", {}, "allow", "read_only", "r3")

            # Tamper with the middle record
            with open(path, "r") as f:
                lines = f.readlines()
            record = json.loads(lines[1])
            record["verdict"] = "allow"  # Change deny -> allow
            lines[1] = json.dumps(record) + "\n"
            with open(path, "w") as f:
                f.writelines(lines)

            valid, checked, error = verify_chain(path)
            self.assertFalse(valid)
            self.assertEqual(checked, 1)  # First record OK, second fails
            self.assertIn("Hash mismatch", error)

    def test_verify_chain_detects_deleted_record(self):
        """verify_chain should detect when a record is removed from the chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call("tool1", {}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {}, "deny", "blocked", "r2")
                logger.log_tool_call("tool3", {}, "allow", "read_only", "r3")

            # Delete the middle record
            with open(path, "r") as f:
                lines = f.readlines()
            with open(path, "w") as f:
                f.write(lines[0])
                f.write(lines[2])  # Skip middle

            valid, checked, error = verify_chain(path)
            self.assertFalse(valid)
            self.assertEqual(checked, 1)  # First OK, third breaks chain
            self.assertIn("Chain broken", error)

    def test_chain_resumes_after_restart(self):
        """A new AuditLogger should resume the chain from the last record."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")

            # First session
            with AuditLogger(path) as logger:
                logger.log_tool_call("tool1", {}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {}, "deny", "blocked", "r2")

            # Second session (new logger instance)
            with AuditLogger(path) as logger:
                logger.log_tool_call("tool3", {}, "allow", "read_only", "r3")

            # The chain should be continuous across sessions
            valid, checked, error = verify_chain(path)
            self.assertTrue(valid, f"Chain should be valid but got: {error}")
            self.assertEqual(checked, 3)

    def test_verify_chain_empty_file(self):
        """verify_chain should handle an empty/missing file gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "nonexistent.jsonl")
            valid, checked, error = verify_chain(path)
            self.assertTrue(valid)
            self.assertEqual(checked, 0)

    def test_record_hash_is_deterministic(self):
        """Same content should always produce the same hash."""
        r1 = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="test", arguments={"x": 1},
            verdict="allow", tier="read_only", reason="r",
            prev_hash=GENESIS_HASH,
        )
        r2 = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="test", arguments={"x": 1},
            verdict="allow", tier="read_only", reason="r",
            prev_hash=GENESIS_HASH,
        )
        self.assertEqual(r1.compute_hash(), r2.compute_hash())

    def test_different_content_different_hash(self):
        """Different content should produce different hashes."""
        r1 = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="test", arguments={"x": 1},
            verdict="allow", tier="read_only", reason="r",
            prev_hash=GENESIS_HASH,
        )
        r2 = AuditRecord(
            timestamp="2026-02-19T12:00:00Z",
            tool_name="test", arguments={"x": 2},  # Different
            verdict="allow", tier="read_only", reason="r",
            prev_hash=GENESIS_HASH,
        )
        self.assertNotEqual(r1.compute_hash(), r2.compute_hash())


if __name__ == "__main__":
    unittest.main()
