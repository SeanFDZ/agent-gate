"""
Tests for Phase 4: policy_hash and rate_context in audit records.

Verifies that:
  - policy_hash appears in AuditRecord and audit log entries.
  - policy_hash is consistent across evaluations with the same policy.
  - Different policy content produces a different hash.
  - rate_context appears on rate-limited decisions.
  - rate_context is absent on normal (non-rate-limited) decisions.
  - AuditRecord backward compatibility (new fields default to None).
  - log_tool_call backward compatibility (new params are optional).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.audit import AuditLogger, AuditRecord
from agent_gate.gate import Gate, Verdict
from agent_gate.classifier_base import ActionTier


class AuditHashTestEnv:
    """
    Temporary workspace, vault, and policy for audit hash tests.
    Provides helpers to write policies with or without rate_limits.
    """

    def __init__(self, rate_limits_yaml=""):
        self.base = os.path.realpath(
            tempfile.mkdtemp(prefix="agent_gate_audit_hash_test_")
        )
        self.workdir = os.path.join(self.base, "workspace")
        self.vault = os.path.join(self.base, "vault")
        self.logs = os.path.join(self.base, "logs")
        os.makedirs(self.workdir)
        os.makedirs(self.vault)
        os.makedirs(self.logs)
        self.policy_path = os.path.join(self.base, "test_policy.yaml")
        self._write_policy(rate_limits_yaml)

    def _write_policy(self, rate_limits_yaml):
        """Write a test policy with optional rate_limits section."""
        policy = f"""
schema_version: "0.1.0"

gate:
  name: "audit-hash-test"
  description: "Test policy for audit hash integration"

envelope:
  allowed_paths:
    - "{self.workdir}/**"
  denied_paths:
    - "{self.vault}/**"
    - "/etc/**"
    - "/tmp/.agent-gate-vault/**"

vault:
  path: "{self.vault}"
  retention:
    max_snapshots_per_file: 5
    max_age_days: 7
  on_failure: "deny"

actions:
  destructive:
    description: "Trigger vault backup"
    patterns:
      - command: "rm"
        description: "File deletion"
      - command: "write_file"
        condition: "target_exists"
        description: "Overwrite existing file"

  read_only:
    description: "Auto-allow"
    patterns:
      - command: "cat"
      - command: "ls"
      - command: "read_file"

  blocked:
    description: "Hard deny"
    patterns:
      - command: "rm"
        args_contain: ["-rf /", "-rf ~"]
        description: "Recursive force delete at root"

  network:
    description: "Network-capable commands"
    patterns:
      - command: "curl"
        description: "HTTP client"

gate_behavior:
  on_destructive:
    - "extract_target_paths"
    - "verify_paths_in_envelope"
    - "snapshot_targets_to_vault"
    - "log_action"
    - "allow_execution"
  on_read_only:
    - "verify_paths_in_envelope"
    - "allow_execution"
  on_blocked:
    - "deny_execution"
    - "log_attempt"
    - "return_denial_reason"
  on_network:
    default: "escalate"
    message: "Network access requires approval."
  on_unclassified:
    default: "deny"
    message: "Unclassified action."

logging:
  path: "{self.logs}"
  format: "jsonl"
  log_allowed: true
  log_denied: true
  log_vault_operations: true
{rate_limits_yaml}
"""
        with open(self.policy_path, "w") as f:
            f.write(policy)

    def cleanup(self):
        shutil.rmtree(self.base, ignore_errors=True)


class TestPolicyHashInAuditLog(unittest.TestCase):
    """Policy hash appears in the gate's JSONL audit log entries."""

    def setUp(self):
        self.env = AuditHashTestEnv()
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    def test_policy_hash_appears_in_log_entry(self):
        """A gate evaluation should produce a log entry with policy_hash."""
        tool_call = {"tool": "bash", "input": {"command": "cat README.md"}}
        decision = self.gate.evaluate(tool_call)

        # Read the gate log.
        log_file = os.path.join(self.env.logs, "gate.jsonl")
        self.assertTrue(os.path.exists(log_file))

        with open(log_file) as f:
            lines = f.readlines()

        # Find the decision log entry (skip the init event).
        decision_entries = []
        for line in lines:
            entry = json.loads(line)
            if "verdict" in entry and "policy_hash" in entry:
                decision_entries.append(entry)

        self.assertTrue(
            len(decision_entries) >= 1,
            "Expected at least one decision log entry with policy_hash"
        )
        entry = decision_entries[0]
        self.assertIsInstance(entry["policy_hash"], str)
        self.assertEqual(len(entry["policy_hash"]), 16)  # Truncated SHA-256

    def test_policy_hash_is_consistent(self):
        """Two evaluations with the same gate produce the same hash."""
        call_1 = {"tool": "bash", "input": {"command": "cat file1.txt"}}
        call_2 = {"tool": "bash", "input": {"command": "ls ."}}
        self.gate.evaluate(call_1)
        self.gate.evaluate(call_2)

        log_file = os.path.join(self.env.logs, "gate.jsonl")
        with open(log_file) as f:
            lines = f.readlines()

        hashes = []
        for line in lines:
            entry = json.loads(line)
            if "policy_hash" in entry:
                hashes.append(entry["policy_hash"])

        self.assertTrue(len(hashes) >= 2)
        self.assertEqual(hashes[0], hashes[1])

    def test_policy_hash_changes_with_policy(self):
        """Different policy content produces a different hash."""
        hash1 = self.gate.policy.policy_hash

        # Create a second environment with different policy content.
        env2 = AuditHashTestEnv()
        # Rewrite the policy with a different name to change content.
        with open(env2.policy_path, "r") as f:
            content = f.read()
        content = content.replace(
            'name: "audit-hash-test"',
            'name: "audit-hash-test-MODIFIED"',
        )
        with open(env2.policy_path, "w") as f:
            f.write(content)

        gate2 = Gate(
            policy_path=env2.policy_path,
            workdir=env2.workdir,
        )
        hash2 = gate2.policy.policy_hash

        self.assertNotEqual(hash1, hash2)
        env2.cleanup()


class TestRateContextInAuditLog(unittest.TestCase):
    """Rate context appears on rate-limited decisions in the gate log."""

    RATE_LIMITS = """
rate_limits:
  tools:
    rm:
      max_calls: 2
      window_seconds: 60
      on_exceed: "deny"
  global:
    max_calls: 200
    window_seconds: 60
"""

    def setUp(self):
        self.env = AuditHashTestEnv(rate_limits_yaml=self.RATE_LIMITS)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    def test_rate_context_on_rate_limited_decision(self):
        """Trigger a rate limit and verify rate_context in the log."""
        # Exhaust the rm rate limit (2 calls).
        for _ in range(3):
            tool_call = {"tool": "bash", "input": {"command": "rm temp.txt"}}
            self.gate.evaluate(tool_call)

        log_file = os.path.join(self.env.logs, "gate.jsonl")
        with open(log_file) as f:
            lines = f.readlines()

        # Find the rate-limited entry.
        rate_limited_entries = []
        for line in lines:
            entry = json.loads(line)
            if entry.get("tier") == "rate_limited":
                rate_limited_entries.append(entry)

        self.assertTrue(
            len(rate_limited_entries) >= 1,
            "Expected at least one rate_limited log entry"
        )
        entry = rate_limited_entries[0]
        self.assertIn("rate_context", entry)
        ctx = entry["rate_context"]
        self.assertIn("tool_counts", ctx)
        self.assertIn("circuit_breaker", ctx)

    def test_rate_context_absent_on_normal_decision(self):
        """Non-rate-limited decisions should NOT have rate_context."""
        tool_call = {"tool": "bash", "input": {"command": "cat README.md"}}
        self.gate.evaluate(tool_call)

        log_file = os.path.join(self.env.logs, "gate.jsonl")
        with open(log_file) as f:
            lines = f.readlines()

        for line in lines:
            entry = json.loads(line)
            if entry.get("tier") in ("read_only", "destructive", "blocked"):
                self.assertNotIn(
                    "rate_context", entry,
                    "rate_context should not appear on non-rate-limited entries"
                )


class TestAuditRecordBackwardCompatibility(unittest.TestCase):
    """AuditRecord and log_tool_call remain backward compatible."""

    def test_audit_record_without_new_fields(self):
        """AuditRecord without policy_hash/rate_context serializes correctly."""
        record = AuditRecord(
            timestamp="2026-02-23T12:00:00Z",
            tool_name="cat",
            arguments={"path": "/etc/hosts"},
            verdict="allow",
            tier="read_only",
            reason="Read-only action.",
        )
        line = record.to_json()
        parsed = json.loads(line)

        # New fields should be absent (None is omitted).
        self.assertNotIn("policy_hash", parsed)
        self.assertNotIn("rate_context", parsed)
        # Core fields present.
        self.assertEqual(parsed["tool_name"], "cat")
        self.assertEqual(parsed["verdict"], "allow")

    def test_audit_record_with_new_fields(self):
        """AuditRecord with policy_hash and rate_context serializes them."""
        record = AuditRecord(
            timestamp="2026-02-23T12:00:00Z",
            tool_name="rm",
            arguments={"command": "rm temp.txt"},
            verdict="deny",
            tier="rate_limited",
            reason="Rate limit exceeded.",
            policy_hash="a3f7b2c9e1d045f8",
            rate_context={
                "tool_counts": {"rm": {"count": 11, "limit": 10}},
                "circuit_breaker": {"state": "closed"},
            },
        )
        line = record.to_json()
        parsed = json.loads(line)

        self.assertEqual(parsed["policy_hash"], "a3f7b2c9e1d045f8")
        self.assertIn("tool_counts", parsed["rate_context"])

    def test_log_tool_call_without_new_params(self):
        """Calling log_tool_call without new params still works."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                # Old-style call without policy_hash or rate_context.
                logger.log_tool_call(
                    tool_name="cat",
                    arguments={"path": "/etc/hosts"},
                    verdict="allow",
                    tier="read_only",
                    reason="Read-only.",
                )

            with open(path) as f:
                record = json.loads(f.readline())

            self.assertEqual(record["tool_name"], "cat")
            self.assertNotIn("policy_hash", record)
            self.assertNotIn("rate_context", record)

    def test_log_tool_call_with_new_params(self):
        """Calling log_tool_call with new params records them."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "audit.jsonl")
            with AuditLogger(path) as logger:
                logger.log_tool_call(
                    tool_name="rm",
                    arguments={"command": "rm temp.txt"},
                    verdict="deny",
                    tier="rate_limited",
                    reason="Rate limit exceeded.",
                    policy_hash="abc123def456",
                    rate_context={"tool_counts": {}, "circuit_breaker": {"state": "closed"}},
                )

            with open(path) as f:
                record = json.loads(f.readline())

            self.assertEqual(record["policy_hash"], "abc123def456")
            self.assertIn("circuit_breaker", record["rate_context"])


if __name__ == "__main__":
    unittest.main()
