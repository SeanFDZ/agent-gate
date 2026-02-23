"""
Tests for Phase 5: Agent Feedback Enrichment.

Verifies that rate-limited and circuit-breaker-tripped decisions
include actionable rate_status data in GateDecision, and that
to_agent_message() and to_dict() surface this data correctly.
"""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.gate import Gate, GateDecision, Verdict
from agent_gate.classifier_base import ActionTier, ClassificationResult
from agent_gate.rate_tracker import BreakerState


class FeedbackTestEnv:
    """
    Temporary workspace, vault, and policy for feedback tests.
    Mirrors GateRateTestEnv from test_gate_rates.py.
    """

    def __init__(self, rate_limits_yaml=""):
        self.base = os.path.realpath(
            tempfile.mkdtemp(prefix="agent_gate_feedback_test_")
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
  name: "feedback-test"
  description: "Test policy for agent feedback enrichment"

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
      - command: "echo"

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

    def create_file(self, name, content="test content"):
        """Create a file in the workspace."""
        path = os.path.join(self.workdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def cleanup(self):
        shutil.rmtree(self.base, ignore_errors=True)


RATE_LIMITS_YAML = """
rate_limits:
  algorithm: "sliding_window"
  tools:
    rm:
      max_calls: 5
      window_seconds: 60
      on_exceed: "deny"
      message: "rm rate limit exceeded.  Max 5 calls per 60s."
  tier_defaults:
    read_only:
      max_calls: 200
      window_seconds: 60
  global:
    max_calls: 300
    window_seconds: 60
    on_exceed: "read_only"
    message: "Global rate limit exceeded."
  circuit_breaker:
    enabled: true
    sliding_window_size: 10
    minimum_calls: 5
    failure_rate_threshold: 0.50
    wait_duration_open_seconds: 30
    permitted_calls_half_open: 3
    on_trip: "deny_all"
    message: "Circuit breaker tripped."
"""


class TestRateLimitDenialMessageFormat(unittest.TestCase):
    """1. Rate limit denial message includes RATE STATUS line."""

    def setUp(self):
        self.env = FeedbackTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_rate_limit_message_has_rate_status_line(self, mock_time):
        """Trigger tool rate limit, verify RATE STATUS in message."""
        mock_time.monotonic.return_value = 0.0

        # Exhaust rm limit (5 calls).
        for i in range(5):
            f = self.env.create_file(f"rl_file_{i}.txt", "data")
            self.gate.evaluate(
                {"tool": "bash", "input": {"command": f"rm {f}"}}
            )

        # 6th call triggers rate limit.
        f = self.env.create_file("rl_file_5.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {f}"}}
        )

        msg = decision.to_agent_message()
        self.assertIn("ACTION DENIED:", msg)
        self.assertIn("RATE STATUS:", msg)
        self.assertIn("tool_remaining=", msg)
        self.assertIn("breaker=", msg)
        self.assertIn("TO PROCEED:", msg)


class TestCircuitBreakerDenialMessageFormat(unittest.TestCase):
    """2. Circuit breaker denial message includes BREAKER STATUS line."""

    def setUp(self):
        self.env = FeedbackTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_circuit_breaker_message_has_breaker_status_line(self, mock_time):
        """Trip breaker, verify BREAKER STATUS in message."""
        mock_time.monotonic.return_value = 0.0

        # Record enough failures to trip the breaker.
        for _ in range(5):
            self.gate.rate_tracker.record_outcome("rm", False, 0)

        self.assertEqual(
            self.gate.rate_tracker.breaker_state, BreakerState.OPEN
        )

        # Evaluate any command — should be denied by breaker.
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {
                "command": f"cat {self.env.workdir}/file.txt"
            }}
        )

        msg = decision.to_agent_message()
        self.assertIn("ACTION DENIED:", msg)
        self.assertIn("BREAKER STATUS:", msg)
        self.assertIn("state=open", msg)
        self.assertIn("recovery_in=", msg)
        self.assertIn("TO PROCEED:", msg)


class TestRateStatusInToDict(unittest.TestCase):
    """3. rate_status appears in to_dict() for rate-limited decisions."""

    def setUp(self):
        self.env = FeedbackTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_to_dict_includes_rate_status(self, mock_time):
        """Verify rate_status dict appears in serialized decision."""
        mock_time.monotonic.return_value = 0.0

        # Exhaust rm limit.
        for i in range(5):
            f = self.env.create_file(f"dict_file_{i}.txt", "data")
            self.gate.evaluate(
                {"tool": "bash", "input": {"command": f"rm {f}"}}
            )

        # Trigger rate limit.
        f = self.env.create_file("dict_file_5.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {f}"}}
        )

        d = decision.to_dict()
        self.assertIn("rate_status", d)
        rs = d["rate_status"]
        self.assertEqual(rs["source"], "tool")
        self.assertIn("limit", rs)
        self.assertIn("current", rs)
        self.assertIn("remaining", rs)
        self.assertIn("window_seconds", rs)
        self.assertIn("reset_seconds", rs)
        self.assertIn("breaker_state", rs)
        self.assertIn("backoff_seconds", rs)
        self.assertEqual(rs["limit"], 5)
        self.assertEqual(rs["window_seconds"], 60)


class TestRateStatusAbsentOnNormalDenial(unittest.TestCase):
    """4. Non-rate-limited denials have no rate_status."""

    def setUp(self):
        self.env = FeedbackTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    def test_blocked_denial_has_no_rate_status(self):
        """A blocked-pattern denial should not include rate_status."""
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": "rm -rf /"}}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)
        self.assertIsNone(decision.rate_status)
        d = decision.to_dict()
        self.assertNotIn("rate_status", d)


class TestRateStatusAbsentOnAllow(unittest.TestCase):
    """5. Allowed decisions have no rate_status."""

    def setUp(self):
        self.env = FeedbackTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    def test_allow_has_no_rate_status(self):
        """Allowed decisions should not include rate_status."""
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {
                "command": f"cat {self.env.workdir}/file.txt"
            }}
        )
        self.assertEqual(decision.verdict, Verdict.ALLOW)
        self.assertIsNone(decision.rate_status)
        d = decision.to_dict()
        self.assertNotIn("rate_status", d)


class TestEscalationHintIncludesWaitTime(unittest.TestCase):
    """6. Escalation hint for rate limit denials includes reset_seconds."""

    def setUp(self):
        self.env = FeedbackTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_escalation_hint_has_wait_time(self, mock_time):
        """Verify reset_seconds appears in escalation hint."""
        mock_time.monotonic.return_value = 0.0

        # Exhaust rm limit.
        for i in range(5):
            f = self.env.create_file(f"esc_file_{i}.txt", "data")
            self.gate.evaluate(
                {"tool": "bash", "input": {"command": f"rm {f}"}}
            )

        # Trigger rate limit.
        f = self.env.create_file("esc_file_5.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {f}"}}
        )

        # The escalation hint should reference the wait time.
        self.assertIn("Wait", decision.escalation_hint)
        self.assertIn("s", decision.escalation_hint)

        # rate_status reset_seconds should be a positive number.
        self.assertIsNotNone(decision.rate_status)
        self.assertGreaterEqual(
            decision.rate_status["reset_seconds"], 0
        )


class TestToAgentMessageUnchangedForNonRateDenials(unittest.TestCase):
    """7. Existing non-rate denial messages are unaffected."""

    def setUp(self):
        self.env = FeedbackTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    def test_blocked_denial_message_unchanged(self):
        """Blocked pattern denial has no RATE STATUS or BREAKER STATUS."""
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": "rm -rf /"}}
        )
        msg = decision.to_agent_message()
        self.assertIn("ACTION DENIED:", msg)
        self.assertNotIn("RATE STATUS:", msg)
        self.assertNotIn("BREAKER STATUS:", msg)

    def test_unclassified_denial_message_unchanged(self):
        """Unclassified tool denial has no RATE STATUS or BREAKER STATUS."""
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": "some_unknown_tool"}}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)
        msg = decision.to_agent_message()
        self.assertIn("ACTION DENIED:", msg)
        self.assertNotIn("RATE STATUS:", msg)
        self.assertNotIn("BREAKER STATUS:", msg)


if __name__ == "__main__":
    unittest.main()
