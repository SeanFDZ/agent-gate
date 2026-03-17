"""
Agent Gate — Security Fix Tests
Tests for Bug 1 (redirect bypass) and Bug 2 (policy self-modification).
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Ensure imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.gate import Gate, Verdict


class TestEnvironment:
    """
    Creates a temporary workspace and vault for testing.
    Cleans up after itself.
    """

    def __init__(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="agent_gate_secfix_"))
        self.workdir = os.path.join(self.base, "workspace")
        self.vault = os.path.join(self.base, "vault")
        self.logs = os.path.join(self.base, "logs")
        os.makedirs(self.workdir)
        os.makedirs(self.vault)
        os.makedirs(self.logs)
        self.policy_path = os.path.join(self.base, "test_policy.yaml")
        self._write_policy()

    def _write_policy(self):
        policy = f"""
schema_version: "0.1.0"

gate:
  name: "test-secfix"
  description: "Test policy for security fix verification"

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
      - command: "test"

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


def run_tests():
    env = TestEnvironment()
    gate = Gate(policy_path=env.policy_path, workdir=env.workdir)
    passed = 0
    failed = 0
    total = 0

    def test(name, tool_call, expected_verdict, check_fn=None):
        nonlocal passed, failed, total
        total += 1
        try:
            decision = gate.evaluate(tool_call)
            if decision.verdict != expected_verdict:
                print(f"  FAIL: {name}")
                print(f"        Expected {expected_verdict.value}, "
                      f"got {decision.verdict.value}")
                print(f"        Reason: {decision.reason}")
                failed += 1
                return
            if check_fn and not check_fn(decision):
                print(f"  FAIL: {name}")
                print(f"        Custom check failed")
                print(f"        Reason: {decision.reason}")
                failed += 1
                return
            print(f"  PASS: {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name}")
            print(f"        Exception: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print("  AGENT GATE — SECURITY FIX TESTS")
    print("=" * 60 + "\n")

    # =================================================================
    # BUG 1: Redirect Bypass Detection
    # =================================================================
    print("  Bug 1: Shell Redirect Detection")
    print("  " + "-" * 40)

    # --- Commands with redirects should be DENIED ---

    test(
        "echo with > redirect in envelope → DENY",
        {"tool": "bash", "input": {
            "command": f"echo content > {env.workdir}/target.txt"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    test(
        "echo with >> append redirect → DENY",
        {"tool": "bash", "input": {
            "command": f"echo content >> {env.workdir}/target.txt"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    test(
        "ls with 2>/dev/null stderr redirect → DENY",
        {"tool": "bash", "input": {
            "command": "ls 2>/dev/null"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    test(
        "cmd with &> combined redirect → DENY",
        {"tool": "bash", "input": {
            "command": f"cmd &>{env.workdir}/output.log"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    test(
        "grep with > to results file → DENY",
        {"tool": "bash", "input": {
            "command": f"grep -r pattern {env.workdir} > results.txt"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    test(
        "echo with no-space redirect >/etc/passwd → DENY",
        {"tool": "bash", "input": {
            "command": "echo payload >/etc/passwd"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    test(
        "cat with 1> fd redirect → DENY",
        {"tool": "bash", "input": {
            "command": f"cat file 1>{env.workdir}/output.txt"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    print()

    # --- Legitimate commands without redirects should still work ---

    test(
        "echo without redirect → ALLOW",
        {"tool": "bash", "input": {
            "command": "echo hello world"
        }},
        Verdict.ALLOW,
    )

    test(
        'echo literal ">" in double quotes → ALLOW',
        {"tool": "bash", "input": {
            "command": 'echo ">" is a literal string'
        }},
        Verdict.ALLOW,
    )

    test(
        "echo literal '>' in single quotes → ALLOW",
        {"tool": "bash", "input": {
            "command": "echo '>' is a literal string"
        }},
        Verdict.ALLOW,
    )

    test(
        "cat file in workspace (no redirect) → ALLOW",
        {"tool": "bash", "input": {
            "command": f"cat {env.workdir}/readme.txt"
        }},
        Verdict.ALLOW,
    )

    test(
        "ls workspace (no redirect) → ALLOW",
        {"tool": "bash", "input": {
            "command": f"ls {env.workdir}"
        }},
        Verdict.ALLOW,
    )

    test(
        "write_file is structured, not affected by redirect check → ALLOW",
        {"tool": "write_file", "input": {
            "path": os.path.join(env.workdir, "new_file.txt"),
            "content": "structured write"
        }},
        Verdict.ALLOW,
    )

    print()

    # =================================================================
    # BUG 2: Policy Self-Modification Protection
    # =================================================================
    print("  Bug 2: Policy Self-Modification Protection")
    print("  " + "-" * 40)

    # --- Protected files should be DENIED ---

    test(
        "write_file targeting .agent-gate.yaml in WORKDIR → DENY",
        {"tool": "write_file", "input": {
            "path": os.path.join(env.workdir, ".agent-gate.yaml"),
            "content": "permissive: true"
        }},
        Verdict.DENY,
        check_fn=lambda d: "protected file" in d.reason.lower(),
    )

    test(
        "write_file targeting .agent-gate.yml in WORKDIR → DENY",
        {"tool": "write_file", "input": {
            "path": os.path.join(env.workdir, ".agent-gate.yml"),
            "content": "permissive: true"
        }},
        Verdict.DENY,
        check_fn=lambda d: "protected file" in d.reason.lower(),
    )

    test(
        "write_file targeting loaded policy YAML path → DENY",
        {"tool": "write_file", "input": {
            "path": env.policy_path,
            "content": "overwritten policy"
        }},
        Verdict.DENY,
        check_fn=lambda d: "protected file" in d.reason.lower(),
    )

    test(
        "write_file targeting .agent-gate.yaml in subdirectory → DENY",
        {"tool": "write_file", "input": {
            "path": os.path.join(env.workdir, "subdir", ".agent-gate.yaml"),
            "content": "permissive: true"
        }},
        Verdict.DENY,
        check_fn=lambda d: "protected file" in d.reason.lower(),
    )

    # --- Normal files should still be allowed ---

    test(
        "write_file targeting normal file in WORKDIR → ALLOW",
        {"tool": "write_file", "input": {
            "path": os.path.join(env.workdir, "normal_file.txt"),
            "content": "normal content"
        }},
        Verdict.ALLOW,
    )

    test(
        "write_file targeting a .yaml file that is not gate config → ALLOW",
        {"tool": "write_file", "input": {
            "path": os.path.join(env.workdir, "config.yaml"),
            "content": "app_setting: true"
        }},
        Verdict.ALLOW,
    )

    print()

    # --- Compound: redirect + policy file (Bug 1 catches first) ---
    print("  Combined: Redirect to Policy File")
    print("  " + "-" * 40)

    test(
        "bash echo > .agent-gate.yaml → DENY (redirect caught first)",
        {"tool": "bash", "input": {
            "command": f"echo permissive > {env.workdir}/.agent-gate.yaml"
        }},
        Verdict.DENY,
        check_fn=lambda d: "redirect" in d.reason.lower(),
    )

    print()

    # --- SUMMARY ---
    print("=" * 60)
    print(f"  RESULTS: {passed} passed, {failed} failed, {total} total")
    print("=" * 60)

    # Cleanup
    env.cleanup()

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
