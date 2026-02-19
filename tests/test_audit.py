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


if __name__ == "__main__":
    unittest.main()
