"""
Tests for Phase 6.4: Identity fields in audit records.

Verifies that:
  - AuditRecord accepts operator, agent_id, service_account, role fields.
  - Identity fields serialize correctly (present when set, absent when None).
  - Identity fields are included in the hash chain.
  - log_tool_call accepts identity parameters with backward compatibility.
  - Mixed chains (old records without identity + new records with identity) verify.
  - Tampering with identity fields is detected by hash verification.
  - Special characters in identity fields are handled correctly.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.audit import AuditLogger, AuditRecord, verify_chain, GENESIS_HASH


class TestAuditRecordIdentityBackwardCompat(unittest.TestCase):
    """Identity fields default to None and don't affect existing behavior."""

    def test_audit_record_no_identity_fields(self):
        """AuditRecord without identity fields has them as None, omitted from JSON."""
        record = AuditRecord(
            timestamp="2026-02-23T12:00:00Z",
            tool_name="cat",
            arguments={"path": "/etc/hosts"},
            verdict="allow",
            tier="read_only",
            reason="Read-only action.",
        )
        self.assertIsNone(record.operator)
        self.assertIsNone(record.agent_id)
        self.assertIsNone(record.service_account)
        self.assertIsNone(record.role)

        parsed = json.loads(record.to_json())
        self.assertNotIn("operator", parsed)
        self.assertNotIn("agent_id", parsed)
        self.assertNotIn("service_account", parsed)
        self.assertNotIn("role", parsed)

    def test_existing_hash_chain_valid_after_upgrade(self):
        """Records without identity, then records with identity — chain stays valid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                # Old-style records (no identity)
                logger.log_tool_call("tool1", {}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {}, "deny", "blocked", "r2")
                # New-style records (with identity)
                logger.log_tool_call(
                    "tool3", {}, "allow", "read_only", "r3",
                    operator="sean", role="admin",
                )
                logger.log_tool_call(
                    "tool4", {}, "allow", "read_only", "r4",
                    operator="sean", agent_id="claude-001",
                )

            valid, checked, error = verify_chain(path)
            self.assertTrue(valid, f"Chain should be valid but got: {error}")
            self.assertEqual(checked, 4)


class TestAuditRecordIdentitySerialization(unittest.TestCase):
    """Identity fields serialize correctly in JSON output."""

    def test_audit_record_with_operator(self):
        """Only set operator — appears in JSON, others absent."""
        record = AuditRecord(
            timestamp="2026-02-23T12:00:00Z",
            tool_name="cat",
            arguments={},
            verdict="allow",
            tier="read_only",
            reason="test",
            operator="sean",
        )
        parsed = json.loads(record.to_json())
        self.assertEqual(parsed["operator"], "sean")
        self.assertNotIn("agent_id", parsed)
        self.assertNotIn("service_account", parsed)
        self.assertNotIn("role", parsed)

    def test_audit_record_with_all_identity(self):
        """All four identity fields set — all appear in JSON."""
        record = AuditRecord(
            timestamp="2026-02-23T12:00:00Z",
            tool_name="rm",
            arguments={"path": "/tmp/test"},
            verdict="allow",
            tier="destructive",
            reason="test",
            operator="sean",
            agent_id="claude-001",
            service_account="ci",
            role="admin",
        )
        parsed = json.loads(record.to_json())
        self.assertEqual(parsed["operator"], "sean")
        self.assertEqual(parsed["agent_id"], "claude-001")
        self.assertEqual(parsed["service_account"], "ci")
        self.assertEqual(parsed["role"], "admin")

    def test_audit_record_identity_in_hash(self):
        """Identity fields affect the computed hash."""
        base_args = dict(
            timestamp="2026-02-23T12:00:00Z",
            tool_name="cat",
            arguments={},
            verdict="allow",
            tier="read_only",
            reason="test",
            prev_hash=GENESIS_HASH,
        )
        r1 = AuditRecord(**base_args, operator="sean")
        r2 = AuditRecord(**base_args)  # no operator
        self.assertNotEqual(r1.compute_hash(), r2.compute_hash())


class TestLogToolCallIdentity(unittest.TestCase):
    """log_tool_call accepts identity parameters."""

    def test_log_tool_call_with_identity(self):
        """Identity fields appear in log file when passed to log_tool_call."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call(
                    tool_name="rm",
                    arguments={"path": "/tmp/x"},
                    verdict="allow",
                    tier="destructive",
                    reason="test",
                    operator="sean",
                    role="admin",
                )

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertEqual(record["operator"], "sean")
            self.assertEqual(record["role"], "admin")

    def test_log_tool_call_without_identity_backward_compat(self):
        """log_tool_call without identity params produces no identity fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call(
                    tool_name="cat",
                    arguments={},
                    verdict="allow",
                    tier="read_only",
                    reason="test",
                )

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertNotIn("operator", record)
            self.assertNotIn("agent_id", record)
            self.assertNotIn("service_account", record)
            self.assertNotIn("role", record)


class TestHashChainWithIdentity(unittest.TestCase):
    """Hash chain integrity with mixed identity/no-identity records."""

    def test_chain_mixed_identity_and_no_identity(self):
        """3 records without identity + 3 with identity — chain valid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                for i in range(3):
                    logger.log_tool_call(f"tool{i}", {}, "allow", "read_only", "r")
                for i in range(3, 6):
                    logger.log_tool_call(
                        f"tool{i}", {}, "allow", "read_only", "r",
                        operator="sean", agent_id=f"agent-{i}",
                    )

            valid, checked, error = verify_chain(path)
            self.assertTrue(valid, f"Chain should be valid but got: {error}")
            self.assertEqual(checked, 6)

    def test_chain_integrity_identity_fields_tampered(self):
        """Tampering with an identity field is detected by hash verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call(
                    "tool1", {}, "allow", "read_only", "r",
                    operator="sean",
                )
                logger.log_tool_call("tool2", {}, "allow", "read_only", "r")

            # Tamper: change operator
            with open(path, "r") as f:
                lines = f.readlines()
            record = json.loads(lines[0])
            record["operator"] = "attacker"
            lines[0] = json.dumps(record) + "\n"
            with open(path, "w") as f:
                f.writelines(lines)

            valid, checked, error = verify_chain(path)
            self.assertFalse(valid)
            self.assertIn("Hash mismatch", error)


class TestIdentityEdgeCases(unittest.TestCase):
    """Edge cases for identity fields."""

    def test_identity_fields_with_special_characters(self):
        """Special characters in identity fields serialize and hash correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call(
                    tool_name="test",
                    arguments={},
                    verdict="allow",
                    tier="read_only",
                    reason="test",
                    operator="sean o'connor",
                    role="admin & manager",
                )

            with open(path) as f:
                record = json.loads(f.readline())
            self.assertEqual(record["operator"], "sean o'connor")
            self.assertEqual(record["role"], "admin & manager")

            # Chain should be intact
            valid, checked, error = verify_chain(path)
            self.assertTrue(valid, f"Chain should be valid but got: {error}")
            self.assertEqual(checked, 1)


if __name__ == "__main__":
    unittest.main()
