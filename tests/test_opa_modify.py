"""
Tests for Phase 7.6 — OPA Classifier & yaml_to_rego Modifications Support.

Tests cover:
  - _format_pattern_entry() with modify, vault, args_match fields
  - generate_modifications_rules() with and without modify blocks
  - generate_rego() includes modifications section
  - generate_tier_result_rules() with args_match support
  - OPA _map_result() with modifications, without modifications, legacy format
  - generate_pattern_key() with args_match
  - Backward compatibility with existing policies
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.policy_loader import Policy
from agent_gate.opa_classifier import OPAClassifier
from agent_gate.classifier_base import ActionTier
from agent_gate.yaml_to_rego import (
    _format_pattern_entry,
    generate_modifications_rules,
    generate_rego,
    generate_tier_result_rules,
    generate_pattern_key,
    generate_tier_patterns,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_policy_dict(workdir="/tmp/test-workspace", vault="/tmp/test-vault"):
    """Minimal valid policy dict for constructing a Policy."""
    return {
        "schema_version": "0.1.0",
        "gate": {
            "name": "test",
            "description": "Test policy",
        },
        "envelope": {
            "allowed_paths": ["{}/**".format(workdir)],
            "denied_paths": ["{}/**".format(vault), "/etc/**"],
        },
        "vault": {
            "path": vault,
            "retention": {"max_snapshots_per_file": 5, "max_age_days": 7},
            "on_failure": "deny",
        },
        "actions": {
            "destructive": {
                "patterns": [{"command": "rm", "description": "File deletion"}],
            },
            "read_only": {
                "patterns": [{"command": "cat"}],
            },
            "blocked": {
                "patterns": [
                    {
                        "command": "rm",
                        "args_contain": ["-rf /"],
                        "description": "Recursive force delete",
                    }
                ],
            },
            "network": {
                "patterns": [
                    {"command": "curl", "description": "HTTP client"},
                ],
            },
        },
        "gate_behavior": {
            "on_network": {"default": "escalate"},
            "on_unclassified": {"default": "deny"},
        },
    }


def _policy_with_modify():
    """Policy dict that includes modify blocks on patterns."""
    p = _minimal_policy_dict()
    p["actions"]["destructive"]["patterns"] = [
        {
            "command": "chmod",
            "description": "Permission change, clamp to policy maximum",
            "vault": "skip",
            "modify": {
                "clamp_permission": "755",
            },
        },
        {
            "command": "rm",
            "args_contain": ["-f"],
            "description": "Force delete, strip -f flag",
            "modify": {
                "strip_flags": ["-f"],
            },
        },
    ]
    return p


def _policy_with_args_match():
    """Policy dict that includes args_match patterns."""
    p = _minimal_policy_dict()
    p["actions"]["destructive"]["patterns"] = [
        {
            "command": "database_query",
            "args_match": "^SELECT",
            "description": "Unbounded SELECT, enforce row limit",
            "modify": {
                "append_arg": "LIMIT 100",
            },
        },
        {
            "command": "rm",
            "description": "File deletion",
        },
    ]
    return p


def _make_opa_classifier(policy):
    """Create an OPAClassifier with mocked OPA binary check."""
    with patch.object(OPAClassifier, '_verify_opa_binary'):
        return OPAClassifier(
            policy, opa_config={"mode": "subprocess"}
        )


# ---------------------------------------------------------------------------
# _format_pattern_entry tests
# ---------------------------------------------------------------------------


class TestFormatPatternEntry:
    """Tests for _format_pattern_entry with new fields."""

    def test_with_modify(self):
        """Pattern with modify: {strip_flags: ['-f']} includes modify in output."""
        pattern = {
            "command": "rm",
            "args_contain": ["-f"],
            "description": "Force delete",
            "modify": {"strip_flags": ["-f"]},
        }
        entry = _format_pattern_entry("rm_f", pattern)
        assert '"modify"' in entry
        assert '"strip_flags"' in entry
        assert '"-f"' in entry

    def test_with_vault(self):
        """Pattern with vault: 'skip' includes vault in output."""
        pattern = {
            "command": "chmod",
            "description": "Permission change",
            "vault": "skip",
        }
        entry = _format_pattern_entry("chmod", pattern)
        assert '"vault": "skip"' in entry

    def test_with_args_match(self):
        """Pattern with args_match includes args_match in output."""
        pattern = {
            "command": "database_query",
            "args_match": "^SELECT",
            "description": "Unbounded SELECT",
        }
        entry = _format_pattern_entry("query", pattern)
        assert '"args_match"' in entry
        assert "^SELECT" in entry

    def test_modify_clamp_permission(self):
        """Modify with clamp_permission string value."""
        pattern = {
            "command": "chmod",
            "description": "Clamp",
            "modify": {"clamp_permission": "755"},
        }
        entry = _format_pattern_entry("chmod", pattern)
        assert '"clamp_permission": "755"' in entry

    def test_modify_max_depth_integer(self):
        """Modify with max_depth integer value."""
        pattern = {
            "command": "find",
            "description": "Limit depth",
            "modify": {"max_depth": 2},
        }
        entry = _format_pattern_entry("find", pattern)
        assert '"max_depth": 2' in entry

    def test_multiline_for_complex_patterns(self):
        """Patterns with >3 fields use multi-line format."""
        pattern = {
            "command": "chmod",
            "description": "Permission change",
            "vault": "skip",
            "modify": {"clamp_permission": "755"},
        }
        entry = _format_pattern_entry("chmod", pattern)
        # Multi-line format has indented fields
        assert "\n" in entry


# ---------------------------------------------------------------------------
# generate_modifications_rules tests
# ---------------------------------------------------------------------------


class TestGenerateModificationsRules:
    """Tests for generate_modifications_rules()."""

    def test_with_modify(self):
        """Policy with chmod pattern having modify generates modifications rules."""
        policy = _policy_with_modify()
        rego = generate_modifications_rules(policy)
        assert "modifications[patch]" in rego
        assert "clamp_permission" in rego

    def test_no_modify(self):
        """Policy with no modify blocks generates empty set."""
        policy = _minimal_policy_dict()
        rego = generate_modifications_rules(policy)
        assert "modifications := set()" in rego

    def test_includes_vault(self):
        """Modify pattern with vault: skip includes vault in patch object."""
        policy = _policy_with_modify()
        rego = generate_modifications_rules(policy)
        assert '"vault": "skip"' in rego

    def test_multiple_patterns(self):
        """Policy with two modify patterns generates two modifications blocks."""
        policy = _policy_with_modify()
        rego = generate_modifications_rules(policy)
        # Count occurrences of modifications[patch]
        count = rego.count("modifications[patch]")
        assert count == 2

    def test_with_args_match(self):
        """Pattern with args_match generates regex.match condition."""
        policy = _policy_with_args_match()
        rego = generate_modifications_rules(policy)
        assert "modifications[patch]" in rego
        assert "regex.match" in rego

    def test_strip_flags_list(self):
        """Modify with strip_flags list generates correct Rego list."""
        policy = _policy_with_modify()
        rego = generate_modifications_rules(policy)
        assert '"strip_flags"' in rego
        assert '"-f"' in rego


# ---------------------------------------------------------------------------
# generate_rego integration tests
# ---------------------------------------------------------------------------


class TestGenerateRegoModifications:
    """Tests for generate_rego() with modifications section."""

    def test_includes_modifications_section(self):
        """generate_rego includes MODIFICATIONS section header."""
        policy = _policy_with_modify()
        rego = generate_rego(policy)
        assert "MODIFICATIONS" in rego

    def test_backward_compat(self):
        """generate_rego with existing policy still generates valid Rego."""
        policy = _minimal_policy_dict()
        rego = generate_rego(policy)
        assert "package agent_gate" in rego
        assert "MODIFICATIONS" in rego
        # Should have empty set since no modify blocks
        assert "modifications := set()" in rego

    def test_full_roundtrip(self):
        """Policy with modify, vault, args_match generates complete Rego."""
        policy = _policy_with_args_match()
        rego = generate_rego(policy)
        assert rego  # Non-empty
        assert "package agent_gate" in rego
        assert "MODIFICATIONS" in rego
        assert "modifications[patch]" in rego


# ---------------------------------------------------------------------------
# generate_tier_result_rules tests
# ---------------------------------------------------------------------------


class TestTierResultRulesArgsMatch:
    """Tests for generate_tier_result_rules with args_match support."""

    def test_with_args_match(self):
        """Tier result rules with args_match include regex.match."""
        rules = generate_tier_result_rules("destructive", False, True)
        assert "regex.match" in rules
        assert "not pattern.args_contain" in rules

    def test_with_both(self):
        """Tier result rules with both args_contain and args_match."""
        rules = generate_tier_result_rules("destructive", True, True)
        assert "regex.match" in rules
        assert "args_contain_match" in rules
        # Should have 4 rule variants
        assert rules.count("_result[name]") == 4

    def test_without_args_match(self):
        """Tier result rules without args_match remain unchanged."""
        rules = generate_tier_result_rules("destructive", False, False)
        assert "regex.match" not in rules
        assert "args_match" not in rules

    def test_args_contain_only(self):
        """Tier result rules with args_contain only (backward compat)."""
        rules = generate_tier_result_rules("destructive", True, False)
        assert "args_contain_match" in rules
        assert rules.count("_result[name]") == 2


# ---------------------------------------------------------------------------
# OPA _map_result tests
# ---------------------------------------------------------------------------


class TestMapResultModifications:
    """Tests for OPAClassifier._map_result with modifications."""

    def _make_classifier(self):
        raw = _minimal_policy_dict()
        policy = Policy(raw, "/tmp/test-workspace")
        return _make_opa_classifier(policy)

    def test_with_modifications(self):
        """OPA result with modifications extracts modification_rules."""
        classifier = self._make_classifier()
        opa_result = {
            "decision": {
                "tier": "destructive",
                "reason": "Permission change",
                "paths_in_envelope": True,
                "paths_outside_envelope": [],
                "matched_pattern": {"command": "chmod"},
            },
            "modifications": [
                {
                    "command": "chmod",
                    "description": "Clamp permission",
                    "modify": {"clamp_permission": "755"},
                }
            ],
        }
        result = classifier._map_result(
            opa_result, "chmod", ["777", "f.sh"], ["/tmp/test-workspace/f.sh"]
        )
        assert result.modification_rules == {"clamp_permission": "755"}
        assert result.tier == ActionTier.DESTRUCTIVE

    def test_without_modifications(self):
        """OPA result with empty modifications has None modification_rules."""
        classifier = self._make_classifier()
        opa_result = {
            "decision": {
                "tier": "destructive",
                "reason": "File deletion",
                "paths_in_envelope": True,
                "paths_outside_envelope": [],
                "matched_pattern": {"command": "rm"},
            },
            "modifications": [],
        }
        result = classifier._map_result(
            opa_result, "rm", ["-f"], ["/tmp/test-workspace/f"]
        )
        assert result.modification_rules is None

    def test_legacy_format(self):
        """Legacy OPA result format (no decision/modifications keys) works."""
        classifier = self._make_classifier()
        opa_result = {
            "tier": "destructive",
            "reason": "File deletion",
            "paths_in_envelope": True,
            "paths_outside_envelope": [],
            "matched_pattern": None,
        }
        result = classifier._map_result(
            opa_result, "rm", [], ["/tmp/test-workspace/f"]
        )
        assert result.tier == ActionTier.DESTRUCTIVE
        assert result.modification_rules is None


# ---------------------------------------------------------------------------
# generate_pattern_key tests
# ---------------------------------------------------------------------------


class TestGeneratePatternKeyArgsMatch:
    """Tests for generate_pattern_key with args_match."""

    def test_args_match_dedup(self):
        """Pattern with args_match and existing key gets _match suffix."""
        pattern = {
            "command": "curl",
            "args_match": "^(?!.*--max-time).*",
            "description": "No timeout",
        }
        existing = {"curl"}
        key = generate_pattern_key("curl", pattern, existing)
        assert "curl" in key
        assert key != "curl"  # Should be deduped

    def test_args_match_no_collision(self):
        """Pattern with args_match and no existing key uses command name."""
        pattern = {
            "command": "curl",
            "args_match": "^(?!.*--max-time).*",
            "description": "No timeout",
        }
        existing = set()
        key = generate_pattern_key("curl", pattern, existing)
        assert key == "curl"
