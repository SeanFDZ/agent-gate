"""
Tests for Agent Gate rate limiting integration.

Verifies that the Gate correctly wires the RateTracker for
tool-specific, tier-default, global rate limits, and circuit
breaker enforcement.  All tests use in-memory temp policies
to avoid touching real state.
"""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.gate import Gate, Verdict
from agent_gate.classifier_base import ActionTier
from agent_gate.rate_tracker import BreakerState


class GateRateTestEnv:
    """
    Temporary workspace, vault, and policy for gate rate tests.
    Provides helpers to write policies with or without rate_limits.
    """

    def __init__(self, rate_limits_yaml=""):
        self.base = os.path.realpath(
            tempfile.mkdtemp(prefix="agent_gate_rate_test_")
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
  name: "rate-test"
  description: "Test policy for rate limiting integration"

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
      - command: "mv"
        description: "Move/rename"
      - command: "write_file"
        condition: "target_exists"
        description: "Overwrite existing file"

  read_only:
    description: "Auto-allow"
    patterns:
      - command: "cat"
      - command: "ls"
      - command: "grep"
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


class TestGateNoRateLimits(unittest.TestCase):
    """Gate works identically to before when rate_limits is absent."""

    def setUp(self):
        self.env = GateRateTestEnv(rate_limits_yaml="")
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    def test_read_only_still_allowed(self):
        """Read-only commands are still allowed without rate_limits."""
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {
                "command": f"cat {self.env.workdir}/readme.txt"
            }}
        )
        self.assertEqual(decision.verdict, Verdict.ALLOW)

    def test_destructive_still_works(self):
        """Destructive commands are still processed normally."""
        test_file = self.env.create_file("to_delete.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {test_file}"}}
        )
        self.assertEqual(decision.verdict, Verdict.ALLOW)
        self.assertIsNotNone(decision.vault_result)

    def test_blocked_still_denied(self):
        """Blocked commands are still denied."""
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": "rm -rf /"}}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)

    def test_rate_tracker_is_disabled(self):
        """RateTracker is initialized but disabled (no-op)."""
        self.assertFalse(self.gate.rate_tracker._enabled)


RATE_LIMITS_YAML = """
rate_limits:
  algorithm: "sliding_window"
  tools:
    rm:
      max_calls: 10
      window_seconds: 60
      on_exceed: "deny"
      message: "rm rate limit exceeded.  Max 10 calls per 60s."
    cat:
      max_calls: 120
      window_seconds: 60
    ls:
      max_calls: 120
      window_seconds: 60
  tier_defaults:
    read_only:
      max_calls: 120
      window_seconds: 60
      on_exceed: "deny"
    destructive:
      max_calls: 30
      window_seconds: 60
      on_exceed: "escalate"
  global:
    max_calls: 200
    window_seconds: 60
    on_exceed: "read_only"
    message: "Global rate limit exceeded.  Agent restricted to read-only."
  circuit_breaker:
    enabled: true
    sliding_window_size: 20
    minimum_calls: 10
    failure_rate_threshold: 0.50
    wait_duration_open_seconds: 30
    permitted_calls_half_open: 3
    on_trip: "read_only"
    message: "Circuit breaker tripped.  Agent restricted to read-only."
"""


class TestGateToolRateLimit(unittest.TestCase):
    """Tool-specific rate limit triggers denial on the 11th rm call."""

    def setUp(self):
        self.env = GateRateTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_tool_rate_limit_denies_at_max(self, mock_time):
        """Fire rm 11 times with max_calls=10, verify 11th is denied."""
        mock_time.monotonic.return_value = 0.0

        # First 10 rm calls should succeed (destructive + vault backup).
        for i in range(10):
            f = self.env.create_file(f"file_{i}.txt", "data")
            decision = self.gate.evaluate(
                {"tool": "bash", "input": {"command": f"rm {f}"}}
            )
            self.assertEqual(
                decision.verdict, Verdict.ALLOW,
                f"Call {i+1} should be allowed"
            )

        # 11th call should be denied by rate limit.
        f = self.env.create_file("file_10.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {f}"}}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)
        self.assertEqual(
            decision.classification.tier, ActionTier.RATE_LIMITED
        )


class TestGateGlobalRateLimit(unittest.TestCase):
    """Global rate limit triggers when total calls exceed threshold."""

    def setUp(self):
        # Use a low global limit for fast testing.
        rate_yaml = """
rate_limits:
  algorithm: "sliding_window"
  tools:
    cat:
      max_calls: 500
      window_seconds: 60
  global:
    max_calls: 15
    window_seconds: 60
    on_exceed: "read_only"
    message: "Global rate limit exceeded."
  circuit_breaker:
    enabled: false
"""
        self.env = GateRateTestEnv(rate_limits_yaml=rate_yaml)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_global_limit_denies_at_max(self, mock_time):
        """Fire 16 read calls with global max=15, verify 16th is denied."""
        mock_time.monotonic.return_value = 0.0

        # First 15 calls should succeed.
        for i in range(15):
            decision = self.gate.evaluate(
                {"tool": "bash", "input": {
                    "command": f"cat {self.env.workdir}/file.txt"
                }}
            )
            self.assertEqual(
                decision.verdict, Verdict.ALLOW,
                f"Call {i+1} should be allowed"
            )

        # 16th call should be denied by global rate limit.
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {
                "command": f"cat {self.env.workdir}/file.txt"
            }}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)
        self.assertEqual(
            decision.classification.tier, ActionTier.RATE_LIMITED
        )


class TestGateRateLimitDenialMessage(unittest.TestCase):
    """Denial feedback includes remaining count and reset time."""

    def setUp(self):
        self.env = GateRateTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_denial_feedback_has_remaining_and_reset(self, mock_time):
        """Verify denial feedback includes remaining and reset_seconds."""
        mock_time.monotonic.return_value = 0.0

        # Exhaust rm limit.
        for i in range(10):
            f = self.env.create_file(f"msg_file_{i}.txt", "data")
            self.gate.evaluate(
                {"tool": "bash", "input": {"command": f"rm {f}"}}
            )

        # Trigger denial.
        f = self.env.create_file("msg_file_10.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {f}"}}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)
        self.assertIn("Remaining:", decision.denial_feedback)
        self.assertIn("resets in", decision.denial_feedback)


class TestGateRateLimitEscalate(unittest.TestCase):
    """on_exceed='escalate' returns ESCALATE verdict."""

    def setUp(self):
        rate_yaml = """
rate_limits:
  algorithm: "sliding_window"
  tools:
    rm:
      max_calls: 3
      window_seconds: 60
      on_exceed: "escalate"
      message: "rm limit exceeded, escalating."
  circuit_breaker:
    enabled: false
"""
        self.env = GateRateTestEnv(rate_limits_yaml=rate_yaml)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_escalate_verdict_on_exceed(self, mock_time):
        """on_exceed='escalate' returns ESCALATE, not DENY."""
        mock_time.monotonic.return_value = 0.0

        # Exhaust rm limit (3 calls).
        for i in range(3):
            f = self.env.create_file(f"esc_file_{i}.txt", "data")
            self.gate.evaluate(
                {"tool": "bash", "input": {"command": f"rm {f}"}}
            )

        # 4th call should ESCALATE.
        f = self.env.create_file("esc_file_3.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {f}"}}
        )
        self.assertEqual(decision.verdict, Verdict.ESCALATE)
        self.assertEqual(
            decision.classification.tier, ActionTier.RATE_LIMITED
        )


class TestGateCircuitBreakerTrip(unittest.TestCase):
    """Circuit breaker trips after sufficient failures and denies calls."""

    def setUp(self):
        rate_yaml = """
rate_limits:
  algorithm: "sliding_window"
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
        self.env = GateRateTestEnv(rate_limits_yaml=rate_yaml)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_circuit_breaker_trips_on_failures(self, mock_time):
        """Feed failures to trip the breaker, then verify denial."""
        mock_time.monotonic.return_value = 0.0

        # Record enough failures to trip the breaker.
        # The breaker needs minimum_calls=5 with 50% failure rate.
        # We'll record 5 failures directly on the rate tracker.
        for _ in range(5):
            self.gate.rate_tracker.record_outcome("rm", False, 0)

        self.assertEqual(
            self.gate.rate_tracker.breaker_state, BreakerState.OPEN
        )

        # Now any evaluate call should be denied by the circuit breaker.
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {
                "command": f"cat {self.env.workdir}/file.txt"
            }}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)
        self.assertIn("Circuit breaker", decision.denial_feedback)


class TestGateCircuitBreakerRecovery(unittest.TestCase):
    """Circuit breaker recovers via HALF_OPEN probing."""

    def setUp(self):
        rate_yaml = """
rate_limits:
  algorithm: "sliding_window"
  circuit_breaker:
    enabled: true
    sliding_window_size: 10
    minimum_calls: 5
    failure_rate_threshold: 0.50
    wait_duration_open_seconds: 10
    permitted_calls_half_open: 3
    on_trip: "deny_all"
    message: "Circuit breaker tripped."
"""
        self.env = GateRateTestEnv(rate_limits_yaml=rate_yaml)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_breaker_recovery_after_wait(self, mock_time):
        """After wait, HALF_OPEN allows probes, successes close breaker."""
        mock_time.monotonic.return_value = 0.0

        # Trip the breaker.
        for _ in range(5):
            self.gate.rate_tracker.record_outcome("rm", False, 0)

        self.assertEqual(
            self.gate.rate_tracker.breaker_state, BreakerState.OPEN
        )

        # Wait for half-open transition.
        mock_time.monotonic.return_value = 10.0
        self.assertEqual(
            self.gate.rate_tracker.breaker_state, BreakerState.HALF_OPEN
        )

        # In HALF_OPEN, calls should be allowed (probing).
        # Read-only calls succeed and record success on the breaker.
        for _ in range(3):
            decision = self.gate.evaluate(
                {"tool": "bash", "input": {
                    "command": f"cat {self.env.workdir}/file.txt"
                }}
            )
            self.assertEqual(decision.verdict, Verdict.ALLOW)

        # After 3 successful probes, breaker should close.
        self.assertEqual(
            self.gate.rate_tracker.breaker_state, BreakerState.CLOSED
        )


class TestGateRateLimitedTier(unittest.TestCase):
    """Verify decision.classification.tier == ActionTier.RATE_LIMITED."""

    def setUp(self):
        self.env = GateRateTestEnv(rate_limits_yaml=RATE_LIMITS_YAML)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_rate_limited_tier_value(self, mock_time):
        """Rate-limited decisions have tier == ActionTier.RATE_LIMITED."""
        mock_time.monotonic.return_value = 0.0

        # Exhaust rm limit.
        for i in range(10):
            f = self.env.create_file(f"tier_file_{i}.txt", "data")
            self.gate.evaluate(
                {"tool": "bash", "input": {"command": f"rm {f}"}}
            )

        # Trigger rate limit.
        f = self.env.create_file("tier_file_10.txt", "data")
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {"command": f"rm {f}"}}
        )
        self.assertEqual(
            decision.classification.tier, ActionTier.RATE_LIMITED
        )
        self.assertEqual(
            decision.classification.tier.value, "rate_limited"
        )


class TestGateRateLimitReadOnlyMode(unittest.TestCase):
    """
    When global on_exceed='read_only', read commands still succeed
    because the global limit only fires via _check_tool_rate_limit
    which runs before classification.  Read-only commands that are
    under the tool-specific limit are counted and allowed; only
    when the global counter itself is hit does denial occur.
    """

    def setUp(self):
        rate_yaml = """
rate_limits:
  algorithm: "sliding_window"
  tools:
    cat:
      max_calls: 500
      window_seconds: 60
  global:
    max_calls: 5
    window_seconds: 60
    on_exceed: "read_only"
    message: "Global limit hit.  Read-only only."
  circuit_breaker:
    enabled: false
"""
        self.env = GateRateTestEnv(rate_limits_yaml=rate_yaml)
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    @patch("agent_gate.rate_tracker.time")
    def test_read_only_mode_denies_after_global_limit(self, mock_time):
        """
        After exceeding the global limit, the gate denies with a
        message indicating only read-only operations are allowed.
        """
        mock_time.monotonic.return_value = 0.0

        # Use up the global limit with 5 read-only calls.
        for i in range(5):
            decision = self.gate.evaluate(
                {"tool": "bash", "input": {
                    "command": f"cat {self.env.workdir}/file.txt"
                }}
            )
            self.assertEqual(decision.verdict, Verdict.ALLOW)

        # 6th call should be denied with read_only message.
        decision = self.gate.evaluate(
            {"tool": "bash", "input": {
                "command": f"cat {self.env.workdir}/file.txt"
            }}
        )
        self.assertEqual(decision.verdict, Verdict.DENY)
        self.assertIn("read-only", decision.reason.lower())


class TestGateRateLimitExtractToolName(unittest.TestCase):
    """Verify _extract_tool_name works for bash and structured tools."""

    def setUp(self):
        self.env = GateRateTestEnv(rate_limits_yaml="")
        self.gate = Gate(
            policy_path=self.env.policy_path,
            workdir=self.env.workdir,
        )

    def tearDown(self):
        self.env.cleanup()

    def test_bash_tool_extraction(self):
        """Extract command name from bash tool call."""
        name = self.gate._extract_tool_name(
            {"tool": "bash", "input": {"command": "rm -f /tmp/file.txt"}}
        )
        self.assertEqual(name, "rm")

    def test_structured_tool_extraction(self):
        """Extract tool name from structured (non-bash) tool call."""
        name = self.gate._extract_tool_name(
            {"tool": "write_file", "input": {
                "path": "/tmp/file.txt", "content": "data"
            }}
        )
        self.assertEqual(name, "write_file")

    def test_empty_command(self):
        """Empty bash command returns 'unknown'."""
        name = self.gate._extract_tool_name(
            {"tool": "bash", "input": {"command": ""}}
        )
        self.assertEqual(name, "unknown")

    def test_missing_tool_key(self):
        """Missing tool key returns 'unknown'."""
        name = self.gate._extract_tool_name({"input": {"command": "ls"}})
        self.assertEqual(name, "unknown")


if __name__ == "__main__":
    unittest.main()
