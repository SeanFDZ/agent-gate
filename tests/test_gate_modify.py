"""
Agent Gate -- Phase 7.4 Tests
Verdict.MODIFY, _handle_modify(), vault skip, reinvocation suppression.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.gate import Gate, Verdict, GateDecision
from agent_gate.classifier_base import ActionTier, ClassificationResult


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

class ModifyTestEnvironment:
    """
    Creates a temp workspace with a policy that includes modify rules.
    """

    def __init__(self, extra_destructive_patterns=""):
        self.base = os.path.realpath(
            tempfile.mkdtemp(prefix="agent_gate_modify_")
        )
        self.workdir = os.path.join(self.base, "workspace")
        self.vault = os.path.join(self.base, "vault")
        self.logs = os.path.join(self.base, "logs")
        os.makedirs(self.workdir)
        os.makedirs(self.vault)
        os.makedirs(self.logs)
        self.policy_path = os.path.join(self.base, "test_policy.yaml")
        self._write_policy(extra_destructive_patterns)

    def _write_policy(self, extra_destructive_patterns):
        policy = f"""
schema_version: "0.1.0"

gate:
  name: "modify-test"
  description: "Test policy for MODIFY verdict"

envelope:
  allowed_paths:
    - "{self.workdir}/**"
  denied_paths:
    - "{self.vault}/**"
    - "/etc/**"

vault:
  path: "{self.vault}"
  retention:
    max_snapshots_per_file: 5
    max_age_days: 7
  on_failure: "deny"

actions:
  destructive:
    description: "Destructive actions"
    patterns:
      - command: "chmod"
        description: "Permission change, clamp to policy maximum"
        vault: skip
        modify:
          clamp_permission: "755"
      - command: "rm"
        args_contain: ["-f"]
        description: "Force delete, strip -f flag"
        modify:
          strip_flags: ["-f"]
      - command: "rm"
        description: "File deletion"
      - command: "mv"
        description: "Move/rename"
      - command: "write_file"
        condition: "target_exists"
        description: "Overwrite existing file"
{extra_destructive_patterns}

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


@pytest.fixture
def env():
    e = ModifyTestEnvironment()
    yield e
    e.cleanup()


@pytest.fixture
def gate(env):
    return Gate(policy_path=env.policy_path, workdir=env.workdir)


# -------------------------------------------------------------------
# Verdict enum
# -------------------------------------------------------------------

def test_verdict_modify_in_enum():
    """Verdict.MODIFY exists and has value 'modify'."""
    assert Verdict.MODIFY.value == "modify"


# -------------------------------------------------------------------
# GateDecision fields
# -------------------------------------------------------------------

def test_gate_decision_has_modify_fields():
    """GateDecision accepts modified_tool_call and modification_feedback."""
    classification = ClassificationResult(
        tier=ActionTier.DESTRUCTIVE,
        command="chmod",
        args=["755", "file.txt"],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.MODIFY,
        tool_call={"tool": "bash", "input": {"command": "chmod 777 file.txt"}},
        classification=classification,
        reason="Test",
        modified_tool_call={"tool": "bash", "input": {"command": "chmod 755 file.txt"}},
        modification_feedback={"reason": "Clamped"},
    )
    assert decision.modified_tool_call is not None
    assert decision.modification_feedback is not None


# -------------------------------------------------------------------
# to_dict
# -------------------------------------------------------------------

def test_to_dict_includes_modify_data():
    """to_dict() includes modification fields when present."""
    classification = ClassificationResult(
        tier=ActionTier.DESTRUCTIVE,
        command="chmod",
        args=["755", "file.txt"],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.MODIFY,
        tool_call={"tool": "bash", "input": {"command": "chmod 777 file.txt"}},
        classification=classification,
        reason="Clamped",
        modified_tool_call={"tool": "bash", "input": {"command": "chmod 755 file.txt"}},
        modification_feedback={"reason": "Clamped"},
    )
    d = decision.to_dict()
    assert "modified_tool_call" in d
    assert "modification_feedback" in d


def test_to_dict_omits_modify_when_none():
    """to_dict() omits modification fields when None."""
    classification = ClassificationResult(
        tier=ActionTier.READ_ONLY,
        command="cat",
        args=["file.txt"],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.ALLOW,
        tool_call={"tool": "bash", "input": {"command": "cat file.txt"}},
        classification=classification,
        reason="Read-only",
    )
    d = decision.to_dict()
    assert "modified_tool_call" not in d
    assert "modification_feedback" not in d


# -------------------------------------------------------------------
# to_agent_message
# -------------------------------------------------------------------

def test_to_agent_message_modify():
    """MODIFY verdict produces structured feedback message."""
    classification = ClassificationResult(
        tier=ActionTier.DESTRUCTIVE,
        command="chmod",
        args=["755", "file.txt"],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.MODIFY,
        tool_call={"tool": "bash", "input": {"command": "chmod 777 file.txt"}},
        classification=classification,
        reason="Clamped",
        modification_feedback={
            "reason": "Clamped to 755",
            "policy_rule": "chmod-modify",
            "original_call": {"tool": "bash", "args": "chmod 777 file.txt"},
            "modified_call": {"tool": "bash", "args": "chmod 755 file.txt"},
        },
    )
    msg = decision.to_agent_message()
    assert "ACTION MODIFIED:" in msg
    assert "REASON: Clamped to 755" in msg
    assert "POLICY RULE: chmod-modify" in msg


def test_to_agent_message_modify_without_feedback():
    """MODIFY with no feedback still returns a message."""
    classification = ClassificationResult(
        tier=ActionTier.DESTRUCTIVE,
        command="chmod",
        args=["755", "file.txt"],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.MODIFY,
        tool_call={"tool": "bash", "input": {"command": "chmod 777 file.txt"}},
        classification=classification,
        reason="Permission clamped",
    )
    msg = decision.to_agent_message()
    assert "ACTION MODIFIED:" in msg
    assert "REASON: Permission clamped" in msg


def test_to_agent_message_allow_unchanged():
    """ALLOW still returns empty string (backward compat)."""
    classification = ClassificationResult(
        tier=ActionTier.READ_ONLY,
        command="cat",
        args=[],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.ALLOW,
        tool_call={"tool": "bash", "input": {"command": "cat file.txt"}},
        classification=classification,
        reason="Read-only",
    )
    assert decision.to_agent_message() == ""


# -------------------------------------------------------------------
# Gate.evaluate() with MODIFY -- end-to-end
# -------------------------------------------------------------------

def test_handle_modify_returns_modify_verdict(env, gate):
    """chmod 777 with clamp_permission policy returns MODIFY."""
    env.create_file("deploy.sh", "#!/bin/bash")
    tc = {"tool": "bash", "input": {"command": f"chmod 777 {env.workdir}/deploy.sh"}}
    decision = gate.evaluate(tc)
    assert decision.verdict == Verdict.MODIFY


def test_handle_modify_returns_modified_tool_call(env, gate):
    """Modified tool call has clamped permission."""
    env.create_file("deploy.sh", "#!/bin/bash")
    tc = {"tool": "bash", "input": {"command": f"chmod 777 {env.workdir}/deploy.sh"}}
    decision = gate.evaluate(tc)
    assert decision.modified_tool_call is not None
    modified_cmd = decision.modified_tool_call["input"]["command"]
    assert "755" in modified_cmd
    assert "777" not in modified_cmd


def test_handle_modify_returns_feedback(env, gate):
    """MODIFY decision includes structured feedback."""
    env.create_file("deploy.sh", "#!/bin/bash")
    tc = {"tool": "bash", "input": {"command": f"chmod 777 {env.workdir}/deploy.sh"}}
    decision = gate.evaluate(tc)
    assert decision.modification_feedback is not None
    assert "operations_applied" in decision.modification_feedback
    assert decision.modification_feedback["verdict"] == "MODIFY"


def test_handle_modify_preserves_original_tool_call(env, gate):
    """decision.tool_call is the original, unmodified call."""
    env.create_file("deploy.sh", "#!/bin/bash")
    tc = {"tool": "bash", "input": {"command": f"chmod 777 {env.workdir}/deploy.sh"}}
    decision = gate.evaluate(tc)
    assert decision.tool_call is tc


def test_handle_modify_fail_closed(env):
    """When modifier raises an error, gate returns DENY (fail closed)."""
    # Create a policy with an invalid clamp_permission value
    extra = """      - command: "chown"
        description: "Ownership change with bad modify"
        modify:
          clamp_permission: "999"
"""
    e = ModifyTestEnvironment(extra_destructive_patterns=extra)
    try:
        g = Gate(policy_path=e.policy_path, workdir=e.workdir)
        e.create_file("file.txt", "content")
        tc = {"tool": "bash", "input": {"command": f"chown root {e.workdir}/file.txt"}}
        # chown matches the bad pattern, but the modify block has invalid value
        # clamp_permission: "999" is invalid octal (9 not in 0-7)
        decision = g.evaluate(tc)
        assert decision.verdict == Verdict.DENY
        assert "Modification failed" in decision.reason
    finally:
        e.cleanup()


def test_handle_modify_with_strip_flags(env, gate):
    """rm -f with strip_flags policy returns MODIFY with -f stripped."""
    env.create_file("file.txt", "content")
    tc = {"tool": "bash", "input": {"command": f"rm -f {env.workdir}/file.txt"}}
    decision = gate.evaluate(tc)
    assert decision.verdict == Verdict.MODIFY
    modified_cmd = decision.modified_tool_call["input"]["command"]
    assert "-f" not in modified_cmd
    assert "rm" in modified_cmd


# -------------------------------------------------------------------
# Vault skip
# -------------------------------------------------------------------

def test_vault_skip_allows_without_backup(env):
    """Pattern with vault: skip but no modify -> ALLOW, no vault_result."""
    # The chmod pattern has both vault: skip and modify.
    # We need a pattern with just vault: skip.  Let's create one.
    extra = """      - command: "chgrp"
        description: "Group change, audit only"
        vault: skip
"""
    e = ModifyTestEnvironment(extra_destructive_patterns=extra)
    try:
        g = Gate(policy_path=e.policy_path, workdir=e.workdir)
        e.create_file("file.txt", "content")
        tc = {"tool": "bash", "input": {"command": f"chgrp staff {e.workdir}/file.txt"}}
        decision = g.evaluate(tc)
        assert decision.verdict == Verdict.ALLOW
        assert decision.vault_result is None
        assert "vault: skip" in decision.reason
    finally:
        e.cleanup()


def test_vault_skip_with_modify():
    """Pattern with both vault: skip and modify -> MODIFY takes precedence."""
    # The default chmod pattern has both vault: skip and modify.
    e = ModifyTestEnvironment()
    try:
        g = Gate(policy_path=e.policy_path, workdir=e.workdir)
        e.create_file("file.txt", "content")
        tc = {"tool": "bash", "input": {"command": f"chmod 777 {e.workdir}/file.txt"}}
        decision = g.evaluate(tc)
        # modify takes precedence (checked before vault: skip)
        assert decision.verdict == Verdict.MODIFY
    finally:
        e.cleanup()


# -------------------------------------------------------------------
# Reinvocation suppression
# -------------------------------------------------------------------

def test_reinvocation_suppresses_log(env, gate):
    """evaluate() with reinvocation=True does not call _log_decision."""
    env.create_file("file.txt", "content")
    tc = {"tool": "bash", "input": {"command": f"cat {env.workdir}/file.txt"}}
    with patch.object(gate, "_log_decision") as mock_log:
        gate.evaluate(tc, reinvocation=True)
        mock_log.assert_not_called()


def test_reinvocation_false_default(env, gate):
    """evaluate() without reinvocation param calls _log_decision."""
    env.create_file("file.txt", "content")
    tc = {"tool": "bash", "input": {"command": f"cat {env.workdir}/file.txt"}}
    with patch.object(gate, "_log_decision") as mock_log:
        gate.evaluate(tc)
        mock_log.assert_called_once()


# -------------------------------------------------------------------
# Circuit breaker counts MODIFY as success
# -------------------------------------------------------------------

def test_modify_success_counted_as_success(env, gate):
    """MODIFY verdict is counted as success for circuit breaker."""
    env.create_file("deploy.sh", "#!/bin/bash")
    tc = {"tool": "bash", "input": {"command": f"chmod 777 {env.workdir}/deploy.sh"}}
    with patch.object(gate.rate_tracker, "record_outcome") as mock_outcome:
        decision = gate.evaluate(tc)
        assert decision.verdict == Verdict.MODIFY
        # record_outcome should have been called with success=True
        mock_outcome.assert_called_once()
        call_args = mock_outcome.call_args
        assert call_args[0][1] is True  # success=True


# -------------------------------------------------------------------
# Backward compatibility
# -------------------------------------------------------------------

def test_destructive_without_modify_unchanged(env, gate):
    """Standard rm (no modify block) still triggers vault backup."""
    path = env.create_file("plain.txt", "content")
    tc = {"tool": "bash", "input": {"command": f"rm {env.workdir}/plain.txt"}}
    decision = gate.evaluate(tc)
    # rm without -f matches the plain "rm" pattern, no modify block
    assert decision.verdict == Verdict.ALLOW
    assert decision.vault_result is not None


def test_condition_not_met_bypasses_modify(env, gate):
    """write_file with condition target_exists: file doesn't exist -> ALLOW."""
    tc = {
        "tool": "write_file",
        "input": {
            "path": os.path.join(env.workdir, "new_file.txt"),
            "content": "hello",
        },
    }
    decision = gate.evaluate(tc)
    # write_file has condition: target_exists.  File doesn't exist, so
    # condition is not met -> ALLOW without vault or modify.
    assert decision.verdict == Verdict.ALLOW
    assert decision.modified_tool_call is None


# -------------------------------------------------------------------
# allowed property
# -------------------------------------------------------------------

def test_allowed_property_false_for_modify():
    """decision.allowed is False for Verdict.MODIFY."""
    classification = ClassificationResult(
        tier=ActionTier.DESTRUCTIVE,
        command="chmod",
        args=["755", "file.txt"],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.MODIFY,
        tool_call={"tool": "bash", "input": {"command": "chmod 777 file.txt"}},
        classification=classification,
        reason="Modified",
    )
    assert decision.allowed is False


def test_allowed_property_true_for_allow():
    """decision.allowed is True for Verdict.ALLOW (backward compat)."""
    classification = ClassificationResult(
        tier=ActionTier.READ_ONLY,
        command="cat",
        args=[],
        target_paths=[],
    )
    decision = GateDecision(
        verdict=Verdict.ALLOW,
        tool_call={"tool": "bash", "input": {"command": "cat file.txt"}},
        classification=classification,
        reason="Read-only",
    )
    assert decision.allowed is True
