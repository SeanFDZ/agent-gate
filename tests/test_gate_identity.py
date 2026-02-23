"""
Agent Gate — Gate Identity Integration Tests

Tests for Phase 6.3: identity propagation, role-based rate limit
overrides, role-based gate behavior overrides, and backward
compatibility.
"""

import json
import logging
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.gate import Gate, GateDecision, Verdict
from agent_gate.identity import IdentityContext


class IdentityTestEnvironment:
    """
    Creates a temporary workspace with a policy that includes
    identity roles (admin, restricted) for gate identity tests.
    """

    def __init__(self):
        self.base = os.path.realpath(
            tempfile.mkdtemp(prefix="agent_gate_id_test_")
        )
        self.workdir = os.path.join(self.base, "workspace")
        self.vault = os.path.join(self.base, "vault")
        self.logs = os.path.join(self.base, "logs")
        os.makedirs(self.workdir)
        os.makedirs(self.vault)
        os.makedirs(self.logs)
        self.policy_path = os.path.join(self.base, "identity_policy.yaml")
        self._write_policy()

    def _write_policy(self):
        policy = f"""
gate:
  name: "identity-gate-test"
  description: "Test policy with identity and role overrides"

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
        args_contain: ["-rf /"]
        description: "Recursive force delete at root"

  network:
    description: "Network-capable commands"
    patterns:
      - command: "curl"
        description: "HTTP client"
      - command: "wget"
        description: "HTTP download"

gate_behavior:
  on_destructive:
    - "extract_target_paths"
    - "snapshot_targets_to_vault"
    - "allow_execution"
  on_read_only:
    - "allow_execution"
  on_blocked:
    - "deny_execution"
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

rate_limits:
  global:
    max_calls: 200
    window_seconds: 60
    on_exceed: "deny"

identity:
  source: "environment"
  fields:
    operator: "${{AGENT_GATE_OPERATOR}}"
    role: "${{AGENT_GATE_ROLE}}"

  roles:
    admin:
      rate_limits:
        global:
          max_calls: 500
          window_seconds: 60
      actions:
        network:
          behavior: "allow"

    restricted:
      rate_limits:
        global:
          max_calls: 50
          window_seconds: 60
"""
        with open(self.policy_path, "w") as f:
            f.write(policy)

    def create_file(self, name, content="test content"):
        path = os.path.join(self.workdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def cleanup(self):
        shutil.rmtree(self.base, ignore_errors=True)


def run_tests():
    env = IdentityTestEnvironment()
    passed = 0
    failed = 0
    total = 0

    def test(name, fn):
        nonlocal passed, failed, total
        total += 1
        try:
            fn()
            print(f"  PASS: {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name}")
            print(f"        {e}")
            failed += 1

    print("\n" + "=" * 60)
    print("  AGENT GATE — IDENTITY INTEGRATION TESTS")
    print("=" * 60 + "\n")

    # ---------------------------------------------------------------
    # Backward Compatibility
    # ---------------------------------------------------------------
    print("  Backward Compatibility")
    print("  " + "-" * 40)

    def test_gate_no_identity_works():
        gate = Gate(policy_path=env.policy_path, workdir=env.workdir)
        assert gate.identity is None, "identity should be None"
        decision = gate.evaluate(
            {"tool": "bash", "input": {"command": f"cat {env.workdir}/readme.txt"}}
        )
        assert decision.verdict == Verdict.ALLOW, (
            f"Expected ALLOW, got {decision.verdict}"
        )

    def test_gate_none_identity_explicit():
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=None,
        )
        assert gate.identity is None, "identity should be None"
        decision = gate.evaluate(
            {"tool": "bash", "input": {"command": f"ls {env.workdir}"}}
        )
        assert decision.verdict == Verdict.ALLOW

    test("gate with no identity param works", test_gate_no_identity_works)
    test("gate with identity=None works", test_gate_none_identity_explicit)

    print()

    # ---------------------------------------------------------------
    # Identity Propagation
    # ---------------------------------------------------------------
    print("  Identity Propagation")
    print("  " + "-" * 40)

    def test_decision_includes_identity():
        identity = IdentityContext(operator="sean", role="admin")
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=identity,
        )
        decision = gate.evaluate(
            {"tool": "bash", "input": {"command": f"cat {env.workdir}/readme.txt"}}
        )
        assert decision.identity is not None, "identity should not be None"
        assert decision.identity["operator"] == "sean"
        assert decision.identity["role"] == "admin"

    def test_decision_identity_none_when_no_identity():
        gate = Gate(policy_path=env.policy_path, workdir=env.workdir)
        decision = gate.evaluate(
            {"tool": "bash", "input": {"command": f"cat {env.workdir}/readme.txt"}}
        )
        assert decision.identity is None, (
            f"Expected None, got {decision.identity}"
        )

    def test_decision_to_dict_includes_identity():
        identity = IdentityContext(operator="sean")
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=identity,
        )
        decision = gate.evaluate(
            {"tool": "bash", "input": {"command": f"cat {env.workdir}/readme.txt"}}
        )
        d = decision.to_dict()
        assert "identity" in d, "to_dict() should include identity"
        assert d["identity"]["operator"] == "sean"

    test("decision includes identity dict", test_decision_includes_identity)
    test(
        "decision identity is None when no identity",
        test_decision_identity_none_when_no_identity,
    )
    test(
        "decision.to_dict() includes identity",
        test_decision_to_dict_includes_identity,
    )

    print()

    # ---------------------------------------------------------------
    # Role-Based Rate Limit Overrides
    # ---------------------------------------------------------------
    print("  Role-Based Rate Limit Overrides")
    print("  " + "-" * 40)

    def test_admin_role_gets_higher_rate_limit():
        identity = IdentityContext(role="admin")
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=identity,
        )
        rl = gate._effective_rate_limits
        assert rl["global"]["max_calls"] == 500, (
            f"Expected 500, got {rl['global']['max_calls']}"
        )

    def test_restricted_role_gets_lower_rate_limit():
        identity = IdentityContext(role="restricted")
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=identity,
        )
        rl = gate._effective_rate_limits
        assert rl["global"]["max_calls"] == 50, (
            f"Expected 50, got {rl['global']['max_calls']}"
        )

    def test_unknown_role_gets_base_rate_limits():
        identity = IdentityContext(role="unknown")
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=identity,
        )
        gate_no_id = Gate(
            policy_path=env.policy_path, workdir=env.workdir
        )
        assert gate._effective_rate_limits == gate_no_id._effective_rate_limits

    def test_no_role_gets_base_rate_limits():
        identity = IdentityContext(operator="sean")  # no role
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=identity,
        )
        gate_no_id = Gate(
            policy_path=env.policy_path, workdir=env.workdir
        )
        assert gate._effective_rate_limits == gate_no_id._effective_rate_limits

    test("admin role gets higher rate limit", test_admin_role_gets_higher_rate_limit)
    test(
        "restricted role gets lower rate limit",
        test_restricted_role_gets_lower_rate_limit,
    )
    test(
        "unknown role gets base rate limits",
        test_unknown_role_gets_base_rate_limits,
    )
    test("no role gets base rate limits", test_no_role_gets_base_rate_limits)

    print()

    # ---------------------------------------------------------------
    # Role-Based Gate Behavior Overrides
    # ---------------------------------------------------------------
    print("  Role-Based Gate Behavior Overrides")
    print("  " + "-" * 40)

    def test_admin_network_allowed():
        identity = IdentityContext(role="admin")
        gate = Gate(
            policy_path=env.policy_path,
            workdir=env.workdir,
            identity=identity,
        )
        decision = gate.evaluate(
            {"tool": "bash", "input": {"command": "curl https://example.com"}}
        )
        assert decision.verdict == Verdict.ALLOW, (
            f"Expected ALLOW, got {decision.verdict.value}: {decision.reason}"
        )

    def test_default_network_escalated():
        gate = Gate(policy_path=env.policy_path, workdir=env.workdir)
        decision = gate.evaluate(
            {"tool": "bash", "input": {"command": "curl https://example.com"}}
        )
        assert decision.verdict == Verdict.ESCALATE, (
            f"Expected ESCALATE, got {decision.verdict.value}: {decision.reason}"
        )

    test("admin network action allowed", test_admin_network_allowed)
    test("default network action escalated", test_default_network_escalated)

    print()

    # ---------------------------------------------------------------
    # Deep Merge
    # ---------------------------------------------------------------
    print("  Deep Merge Utility")
    print("  " + "-" * 40)

    def test_deep_merge_basic():
        result = Gate._deep_merge({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}, f"Got {result}"

    def test_deep_merge_override():
        result = Gate._deep_merge({"a": 1}, {"a": 2})
        assert result == {"a": 2}, f"Got {result}"

    def test_deep_merge_nested():
        result = Gate._deep_merge(
            {"a": {"x": 1, "y": 2}},
            {"a": {"y": 3, "z": 4}},
        )
        assert result == {"a": {"x": 1, "y": 3, "z": 4}}, f"Got {result}"

    test("deep merge basic", test_deep_merge_basic)
    test("deep merge override", test_deep_merge_override)
    test("deep merge nested", test_deep_merge_nested)

    print()

    # ---------------------------------------------------------------
    # Init Logging
    # ---------------------------------------------------------------
    print("  Init Logging")
    print("  " + "-" * 40)

    def test_init_log_includes_identity():
        # Clear existing handlers to avoid log pollution
        logger = logging.getLogger("agent_gate")
        for h in logger.handlers[:]:
            logger.removeHandler(h)

        log_dir = os.path.join(env.base, "init_log_test")
        os.makedirs(log_dir, exist_ok=True)

        # Write a policy with custom log dir
        policy_path = os.path.join(env.base, "init_log_policy.yaml")
        with open(policy_path, "w") as f:
            f.write(f"""
gate:
  name: "init-log-test"
  description: "Test init logging"

envelope:
  allowed_paths:
    - "{env.workdir}/**"
  denied_paths:
    - "{env.vault}/**"
    - "/tmp/.agent-gate-vault/**"

vault:
  path: "{env.vault}"
  retention:
    max_snapshots_per_file: 5
    max_age_days: 7
  on_failure: "deny"

actions:
  destructive:
    patterns:
      - command: "rm"
  read_only:
    patterns:
      - command: "cat"
  blocked:
    patterns:
      - command: "rm"
        args_contain: ["-rf /"]

gate_behavior:
  on_network:
    default: "escalate"
  on_unclassified:
    default: "deny"

logging:
  path: "{log_dir}"
  format: "jsonl"
  log_allowed: true
  log_denied: true
""")
        identity = IdentityContext(operator="sean", role="admin")
        Gate(
            policy_path=policy_path,
            workdir=env.workdir,
            identity=identity,
        )

        log_file = os.path.join(log_dir, "gate.jsonl")
        assert os.path.exists(log_file), "Log file should exist"
        with open(log_file, "r") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        assert len(lines) >= 1, "Should have at least one log entry"

        init_entry = json.loads(lines[0])
        assert init_entry["event"] == "gate_initialized"
        assert init_entry["identity"] is not None, (
            "Init log should include identity"
        )
        assert init_entry["identity"]["operator"] == "sean"
        assert init_entry["identity"]["role"] == "admin"

    test("init log includes identity", test_init_log_includes_identity)

    print()

    # --- SUMMARY ---
    print("=" * 60)
    print(f"  RESULTS: {passed} passed, {failed} failed, {total} total")
    print("=" * 60)

    env.cleanup()
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
