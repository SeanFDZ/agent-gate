"""
Agent Gate — Classifier Modify Tests (Phase 7.3)

Tests for args_match regex support,  modification_rules propagation,
and backward compatibility with existing classification behavior.
"""

import os
import sys
import tempfile
import shutil
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.classifier import PythonClassifier
from agent_gate.classifier_base import (
    ActionTier,
    ClassificationResult,
)
from agent_gate.policy_loader import Policy


class _TestEnv:
    """
    Creates a temporary workspace with a custom policy for testing
    classifier behavior with modify and args_match patterns.

    Extra patterns are inserted BEFORE base patterns so they
    take priority via first-match-wins.
    """

    def __init__(self, extra_destructive=None, extra_network=None):
        self.base = os.path.realpath(
            tempfile.mkdtemp(prefix="agent_gate_cls_test_")
        )
        self.workdir = os.path.join(self.base, "workspace")
        self.vault = os.path.join(self.base, "vault")
        self.logs = os.path.join(self.base, "logs")
        os.makedirs(self.workdir)
        os.makedirs(self.vault)
        os.makedirs(self.logs)
        self.policy_path = os.path.join(self.base, "test_policy.yaml")
        self._write_policy(extra_destructive or [], extra_network or [])

    def _write_policy(self, extra_destr, extra_net):
        """Build policy dict in Python,  then dump to YAML file."""
        destr_patterns = list(extra_destr) + [
            {"command": "rm", "description": "File deletion"},
            {"command": "mv", "description": "File move/rename"},
            {"command": "chmod", "description": "Permission change"},
        ]
        net_patterns = list(extra_net) + [
            {"command": "wget", "description": "HTTP download"},
        ]
        policy = {
            "schema_version": "0.1.0",
            "gate": {
                "name": "classifier-modify-test",
                "description": "Test policy for classifier modify behavior",
            },
            "envelope": {
                "allowed_paths": [self.workdir + "/**"],
                "denied_paths": [
                    self.vault + "/**",
                    "/etc/**",
                    "/tmp/.agent-gate-vault/**",
                ],
            },
            "vault": {
                "path": self.vault,
                "retention": {
                    "max_snapshots_per_file": 5,
                    "max_age_days": 7,
                },
                "on_failure": "deny",
            },
            "actions": {
                "destructive": {"patterns": destr_patterns},
                "blocked": {
                    "patterns": [
                        {"command": "shutdown", "description": "System shutdown"},
                    ]
                },
                "read_only": {
                    "patterns": [
                        {"command": "cat", "description": "File read"},
                        {"command": "ls", "description": "Directory listing"},
                    ]
                },
                "network": {"patterns": net_patterns},
            },
            "gate_behavior": {
                "on_unclassified": {
                    "default": "deny",
                    "message": "Unclassified action.",
                },
                "on_network": {
                    "default": "escalate",
                    "message": "Network access requires approval.",
                },
            },
            "logging": {"path": self.logs},
        }
        with open(self.policy_path, "w") as f:
            yaml.dump(policy, f, default_flow_style=False)

    def load(self):
        """Load and return (Policy, PythonClassifier) tuple."""
        with open(self.policy_path, "r") as f:
            raw = yaml.safe_load(f)
        policy = Policy(raw, self.workdir)
        return policy, PythonClassifier(policy)

    def cleanup(self):
        shutil.rmtree(self.base, ignore_errors=True)


def _bash(cmd_str):
    """Helper to build a bash tool call dict."""
    return {"tool": "bash", "input": {"command": cmd_str}}


# ------------------------------------------------------------------
# Test: args_match simple regex
# ------------------------------------------------------------------

def test_args_match_simple_regex():
    """Pattern with args_match regex matches when regex matches."""
    env = _TestEnv(extra_destructive=[
        {
            "command": "database_query",
            "args_match": "^database_query SELECT",
            "description": "Unbounded SELECT",
            "modify": {"append_arg": "LIMIT 100"},
        },
    ])
    try:
        _, classifier = env.load()
        # Use SELECT id (not SELECT *) to avoid shell expansion block
        result = classifier.classify(
            _bash("database_query SELECT id FROM users")
        )
        assert result.tier == ActionTier.DESTRUCTIVE
        assert result.reason == "Unbounded SELECT"
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: args_match negative lookahead
# ------------------------------------------------------------------

def test_args_match_negative_lookahead():
    """Negative lookahead matches when flag is absent."""
    env = _TestEnv(extra_network=[
        {
            "command": "curl",
            "args_match": "^(?!.*--max-time).*",
            "description": "HTTP call without timeout",
            "modify": {"require_flags": ["--max-time 30"]},
        },
    ])
    try:
        _, classifier = env.load()
        result = classifier.classify(
            _bash("curl http://example.com")
        )
        assert result.tier == ActionTier.NETWORK
        assert result.reason == "HTTP call without timeout"
    finally:
        env.cleanup()


def test_args_match_negative_lookahead_no_match():
    """Negative lookahead does NOT match when flag is present."""
    env = _TestEnv(extra_network=[
        {
            "command": "curl",
            "args_match": "^(?!.*--max-time).*",
            "description": "HTTP call without timeout",
            "modify": {"require_flags": ["--max-time 30"]},
        },
    ])
    try:
        _, classifier = env.load()
        result = classifier.classify(
            _bash("curl --max-time 30 http://example.com")
        )
        # The curl args_match pattern should not fire
        assert result.reason != "HTTP call without timeout"
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: args_match AND args_contain both required
# ------------------------------------------------------------------

def test_args_match_and_args_contain_both_required():
    """Both args_contain and args_match must match for pattern to fire."""
    env = _TestEnv(extra_destructive=[
        {
            "command": "rm",
            "args_contain": ["-f"],
            "args_match": r".*\.txt$",
            "description": "Force delete txt files",
            "modify": {"strip_flags": ["-f"]},
        },
    ])
    try:
        _, classifier = env.load()
        # Both conditions met
        result = classifier.classify(_bash("rm -f file.txt"))
        assert result.reason == "Force delete txt files"
        assert result.modification_rules == {"strip_flags": ["-f"]}
    finally:
        env.cleanup()


def test_args_match_and_args_contain_partial_fail():
    """If args_match fails but args_contain passes,  pattern should not match."""
    env = _TestEnv(extra_destructive=[
        {
            "command": "rm",
            "args_contain": ["-f"],
            "args_match": r".*\.txt$",
            "description": "Force delete txt files",
            "modify": {"strip_flags": ["-f"]},
        },
    ])
    try:
        _, classifier = env.load()
        # args_contain passes (-f present) but args_match fails (.py not .txt)
        result = classifier.classify(_bash("rm -f file.py"))
        # Should fall through to the base "rm" pattern (no modify)
        assert result.reason != "Force delete txt files"
        assert result.tier == ActionTier.DESTRUCTIVE
        assert result.modification_rules is None
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: modify block passed to ClassificationResult
# ------------------------------------------------------------------

def test_modify_block_passed_to_classification_result():
    """When pattern has modify block,  it appears in modification_rules."""
    env = _TestEnv(extra_destructive=[
        {
            "command": "chmod",
            "description": "Permission change with clamp",
            "modify": {"clamp_permission": "755"},
        },
    ])
    try:
        _, classifier = env.load()
        result = classifier.classify(_bash("chmod 777 deploy.sh"))
        # Extra pattern comes first,  so it matches
        assert result.modification_rules == {"clamp_permission": "755"}
    finally:
        env.cleanup()


def test_no_modify_block_classification_result_none():
    """When pattern has no modify key,  modification_rules is None."""
    env = _TestEnv()
    try:
        _, classifier = env.load()
        result = classifier.classify(_bash("rm file.txt"))
        assert result.tier == ActionTier.DESTRUCTIVE
        assert result.modification_rules is None
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: modify block with multiple operations
# ------------------------------------------------------------------

def test_modify_block_with_multiple_ops():
    """Modify block with multiple operations is passed through intact."""
    env = _TestEnv(extra_destructive=[
        {
            "command": "rm",
            "args_contain": ["-f"],
            "description": "Force delete with safety",
            "modify": {
                "strip_flags": ["-f"],
                "require_flags": ["--interactive"],
            },
        },
    ])
    try:
        _, classifier = env.load()
        result = classifier.classify(_bash("rm -f file.txt"))
        assert result.modification_rules == {
            "strip_flags": ["-f"],
            "require_flags": ["--interactive"],
        }
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: args_match invalid regex skipped
# ------------------------------------------------------------------

def test_args_match_invalid_regex_skipped():
    """Invalid regex in args_match is skipped gracefully."""
    env = _TestEnv()
    try:
        _, classifier = env.load()
        # Inject a pattern with invalid regex directly into the index
        # (bypass loader validation)
        classifier._destructive_commands["testcmd"] = [
            {
                "command": "testcmd",
                "args_match": "[invalid",
                "description": "Invalid regex pattern",
            }
        ]
        result = classifier.classify(_bash("testcmd foo"))
        # Should not match the invalid regex pattern
        assert result.reason != "Invalid regex pattern"
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: first match wins with modify
# ------------------------------------------------------------------

def test_first_match_wins_with_modify():
    """First matching pattern wins; its modify block is used."""
    env = _TestEnv()
    try:
        _, classifier = env.load()
        # Override index with two chmod patterns directly
        classifier._destructive_commands["chmod"] = [
            {
                "command": "chmod",
                "description": "Chmod with clamp (first)",
                "modify": {"clamp_permission": "755"},
            },
            {
                "command": "chmod",
                "description": "Chmod without modify (second)",
            },
        ]
        result = classifier._match_tier(
            "chmod", ["777", "file.txt"],
            classifier._destructive_commands,
            ActionTier.DESTRUCTIVE,
        )
        assert result.reason == "Chmod with clamp (first)"
        assert result.modification_rules == {"clamp_permission": "755"}
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: args_match on network tier
# ------------------------------------------------------------------

def test_args_match_on_network_tier():
    """args_match works on network tier patterns too."""
    env = _TestEnv(extra_network=[
        {
            "command": "curl",
            "args_match": ".*",
            "description": "Any curl call",
        },
    ])
    try:
        _, classifier = env.load()
        result = classifier.classify(_bash("curl http://example.com"))
        assert result.tier == ActionTier.NETWORK
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: backward compat — existing patterns without modify/args_match
# ------------------------------------------------------------------

def test_backward_compat_existing_patterns():
    """Existing rm,  mv,  chmod patterns without modify/args_match work identically."""
    env = _TestEnv()
    try:
        _, classifier = env.load()

        # rm
        result = classifier.classify(_bash("rm file.txt"))
        assert result.tier == ActionTier.DESTRUCTIVE
        assert result.modification_rules is None

        # mv
        result = classifier.classify(_bash("mv a.txt b.txt"))
        assert result.tier == ActionTier.DESTRUCTIVE
        assert result.modification_rules is None

        # chmod
        result = classifier.classify(_bash("chmod 644 file.txt"))
        assert result.tier == ActionTier.DESTRUCTIVE
        assert result.modification_rules is None
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: ClassificationResult has modification_rules field
# ------------------------------------------------------------------

def test_classification_result_has_modification_rules_field():
    """ClassificationResult defaults modification_rules to None."""
    result = ClassificationResult(
        tier=ActionTier.DESTRUCTIVE,
        command="test",
        args=[],
        target_paths=[],
    )
    assert result.modification_rules is None


# ------------------------------------------------------------------
# Test: modification_rules preserved through full evaluate path
# ------------------------------------------------------------------

def test_modification_rules_preserved_through_evaluate():
    """Full classify() call propagates modification_rules from pattern."""
    env = _TestEnv(extra_destructive=[
        {
            "command": "database_query",
            "args_match": "^database_query SELECT",
            "description": "Unbounded SELECT",
            "modify": {"append_arg": "LIMIT 100"},
        },
    ])
    try:
        _, classifier = env.load()
        # Use SELECT id (not SELECT *) to avoid shell expansion block
        result = classifier.classify(
            _bash("database_query SELECT id FROM users")
        )
        assert result.modification_rules is not None
        assert result.modification_rules == {"append_arg": "LIMIT 100"}
    finally:
        env.cleanup()


# ------------------------------------------------------------------
# Test: args_match with empty args
# ------------------------------------------------------------------

def test_args_match_empty_args():
    """args_match works when the tool call has no arguments."""
    env = _TestEnv()
    try:
        _, classifier = env.load()
        # Inject a pattern that matches the command with optional trailing space
        classifier._destructive_commands["cmd"] = [
            {
                "command": "cmd",
                "args_match": r"^cmd\s*$",
                "description": "Bare command match",
            }
        ]
        result = classifier._match_tier(
            "cmd", [],
            classifier._destructive_commands,
            ActionTier.DESTRUCTIVE,
        )
        assert result is not None
        assert result.reason == "Bare command match"
    finally:
        env.cleanup()
