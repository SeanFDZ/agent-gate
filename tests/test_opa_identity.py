"""
Tests for Phase 6.5 — OPA Classifier & yaml_to_rego Identity Support.

Tests cover:
  - OPA input document identity inclusion/exclusion
  - yaml_to_rego identity data generation
  - yaml_to_rego identity rule generation
  - yaml_to_rego test scaffold identity tests
  - Full generate_rego round-trip with identity
"""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.identity import IdentityContext
from agent_gate.policy_loader import Policy
from agent_gate.opa_classifier import OPAClassifier
from agent_gate.yaml_to_rego import (
    generate_identity_data,
    generate_identity_rules,
    generate_rego,
    generate_test_scaffold,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "test_fixtures")


def _minimal_policy_dict(workdir="/tmp/test-workspace", vault="/tmp/test-vault"):
    """Minimal valid policy dict for constructing a Policy."""
    return {
        "schema_version": "0.1.0",
        "gate": {
            "name": "test",
            "description": "Test policy",
        },
        "envelope": {
            "allowed_paths": [f"{workdir}/**"],
            "denied_paths": [f"{vault}/**", "/etc/**"],
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


def _make_policy(raw, workdir="/tmp/test-workspace"):
    return Policy(raw, workdir)


def _make_opa_classifier(policy, identity=None):
    """Create an OPAClassifier with mocked OPA binary check."""
    with patch.object(OPAClassifier, '_verify_opa_binary'):
        return OPAClassifier(policy, opa_config={"mode": "subprocess"}, identity=identity)


def _sample_tool_call():
    return {
        "tool": "bash",
        "input": {"command": "curl https://example.com"},
    }


# =========================================================================
# OPA INPUT DOCUMENT TESTS
# =========================================================================


class TestOPAInputNoIdentity:
    """OPAClassifier with identity=None omits identity from input doc."""

    def test_opa_input_no_identity(self):
        raw = _minimal_policy_dict()
        policy = _make_policy(raw)
        classifier = _make_opa_classifier(policy, identity=None)

        input_doc = classifier._build_input(
            "curl", ["https://example.com"], ["/tmp/test-workspace/f.txt"],
            _sample_tool_call(),
        )
        assert "identity" not in input_doc


class TestOPAInputWithIdentity:
    """OPAClassifier with identity includes identity in input doc."""

    def test_opa_input_with_identity(self):
        raw = _minimal_policy_dict()
        policy = _make_policy(raw)
        identity = IdentityContext(operator="sean", role="admin")
        classifier = _make_opa_classifier(policy, identity=identity)

        input_doc = classifier._build_input(
            "curl", ["https://example.com"], ["/tmp/test-workspace/f.txt"],
            _sample_tool_call(),
        )
        assert "identity" in input_doc
        assert input_doc["identity"]["operator"] == "sean"
        assert input_doc["identity"]["role"] == "admin"

    def test_opa_input_identity_all_fields(self):
        raw = _minimal_policy_dict()
        policy = _make_policy(raw)
        identity = IdentityContext(
            operator="sean", agent_id="a1", service_account="ci",
            session_id="s1", role="admin",
        )
        classifier = _make_opa_classifier(policy, identity=identity)

        input_doc = classifier._build_input(
            "cat", [], ["/tmp/test-workspace/f.txt"], _sample_tool_call(),
        )
        assert input_doc["identity"]["operator"] == "sean"
        assert input_doc["identity"]["agent_id"] == "a1"
        assert input_doc["identity"]["service_account"] == "ci"
        assert input_doc["identity"]["session_id"] == "s1"
        assert input_doc["identity"]["role"] == "admin"


class TestOPAInputIdentitySessionOnly:
    """IdentityContext with only session_id (has_identity() == False) excluded."""

    def test_opa_input_identity_session_only_excluded(self):
        raw = _minimal_policy_dict()
        policy = _make_policy(raw)
        identity = IdentityContext(session_id="abc")
        classifier = _make_opa_classifier(policy, identity=identity)

        input_doc = classifier._build_input(
            "cat", [], ["/tmp/test-workspace/f.txt"], _sample_tool_call(),
        )
        assert "identity" not in input_doc


class TestOPAInputPreservesExistingFields:
    """Identity addition doesn't affect other input doc fields."""

    def test_existing_fields_preserved(self):
        raw = _minimal_policy_dict()
        policy = _make_policy(raw)
        identity = IdentityContext(operator="sean", role="admin")
        classifier = _make_opa_classifier(policy, identity=identity)

        input_doc = classifier._build_input(
            "curl", ["https://example.com"], ["/tmp/test-workspace/f.txt"],
            _sample_tool_call(),
        )
        assert input_doc["command"] == "curl"
        assert input_doc["args"] == ["https://example.com"]
        assert input_doc["tool"] == "bash"
        assert "envelope" in input_doc


# =========================================================================
# yaml_to_rego IDENTITY DATA GENERATION TESTS
# =========================================================================


class TestGenerateIdentityDataNoRoles:
    """Policy without identity roles → empty identity_roles."""

    def test_generate_identity_data_no_roles(self):
        policy = _minimal_policy_dict()
        output = generate_identity_data(policy)
        assert "identity_roles := {}" in output

    def test_generate_identity_data_empty_identity(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {}
        output = generate_identity_data(policy)
        assert "identity_roles := {}" in output

    def test_generate_identity_data_empty_roles(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {"roles": {}}
        output = generate_identity_data(policy)
        assert "identity_roles := {}" in output


class TestGenerateIdentityDataWithRoles:
    """Policy with identity roles → proper Rego data."""

    def test_generate_identity_data_with_roles(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "admin": {
                    "actions": {
                        "network": {"behavior": "allow"},
                    },
                    "rate_limits": {
                        "global": {"max_calls": 500, "window_seconds": 60},
                    },
                },
                "restricted": {
                    "rate_limits": {
                        "global": {"max_calls": 50, "window_seconds": 60},
                    },
                },
            }
        }
        output = generate_identity_data(policy)
        assert '"admin"' in output
        assert '"restricted"' in output
        assert '"behavior": "allow"' in output
        assert '"max_calls": 500' in output
        assert '"max_calls": 50' in output

    def test_generate_identity_data_actions_only(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "admin": {
                    "actions": {
                        "network": {"behavior": "allow"},
                        "destructive": {"behavior": "deny"},
                    },
                },
            }
        }
        output = generate_identity_data(policy)
        assert '"network"' in output
        assert '"destructive"' in output
        assert '"behavior": "allow"' in output
        assert '"behavior": "deny"' in output

    def test_generate_identity_data_rate_limits_only(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "viewer": {
                    "rate_limits": {
                        "global": {"max_calls": 10, "window_seconds": 30},
                    },
                },
            }
        }
        output = generate_identity_data(policy)
        assert '"viewer"' in output
        assert '"max_calls": 10' in output
        assert '"window_seconds": 30' in output


# =========================================================================
# yaml_to_rego IDENTITY RULES GENERATION TESTS
# =========================================================================


class TestGenerateIdentityRules:
    """Test that identity rules contain the expected Rego constructs."""

    def test_contains_role_has_override(self):
        output = generate_identity_rules()
        assert "role_has_override" in output

    def test_contains_role_behavior(self):
        output = generate_identity_rules()
        assert "role_behavior" in output

    def test_contains_role_rate_limit(self):
        output = generate_identity_rules()
        assert "role_rate_limit" in output

    def test_checks_input_identity(self):
        output = generate_identity_rules()
        assert "input.identity" in output
        assert "input.identity.role" in output

    def test_references_identity_roles_data(self):
        output = generate_identity_rules()
        assert "identity_roles[input.identity.role]" in output


# =========================================================================
# FULL generate_rego TESTS
# =========================================================================


class TestGenerateRegoIncludesIdentity:
    """Full generate_rego() with identity roles."""

    def test_generate_rego_includes_identity_section(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "admin": {
                    "actions": {
                        "network": {"behavior": "allow"},
                    },
                },
            }
        }
        output = generate_rego(policy)
        assert "identity_roles" in output
        assert "role_has_override" in output
        assert "role_behavior" in output
        assert "role_rate_limit" in output

    def test_generate_rego_identity_network_override_rule(self):
        """Generated Rego includes identity-based network allow rule."""
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "admin": {
                    "actions": {
                        "network": {"behavior": "allow"},
                    },
                },
            }
        }
        output = generate_rego(policy)
        assert "Identity override" in output
        assert "role-based network allow" in output
        assert "not role_has_override" in output  # Guard on regular network rule

    def test_generate_rego_identity_with_rate_limits(self):
        """Identity + rate limits produce combined decision rules."""
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "admin": {
                    "actions": {"network": {"behavior": "allow"}},
                },
            }
        }
        policy["rate_limits"] = {
            "tools": {
                "curl": {
                    "max_calls": 10, "window_seconds": 60,
                    "on_exceed": "deny",
                },
            },
            "global": {
                "max_calls": 200, "window_seconds": 60,
                "on_exceed": "deny",
            },
        }
        output = generate_rego(policy)
        assert "any_rate_limit_active" in output
        assert "role_has_override" in output
        assert "Identity override" in output


class TestGenerateRegoNoIdentity:
    """Full generate_rego() without identity section still works."""

    def test_generate_rego_no_identity_still_works(self):
        policy = _minimal_policy_dict()
        output = generate_rego(policy)
        # Should have empty identity_roles
        assert "identity_roles := {}" in output
        # Should still have identity rules (they're inert without input.identity)
        assert "role_has_override" in output
        # Should NOT have identity override decision rule
        assert "Identity override" not in output
        # Regular network rule should NOT have identity guard
        assert "not role_has_override" not in output

    def test_generate_rego_no_identity_has_standard_decision_rules(self):
        policy = _minimal_policy_dict()
        output = generate_rego(policy)
        assert "Priority 2: Blocked" in output
        assert "Priority 4: Network" in output
        assert "Priority 6: Unclassified" in output


# =========================================================================
# TEST SCAFFOLD GENERATION TESTS
# =========================================================================


class TestScaffoldIncludesIdentityTests:
    """generate_test_scaffold() with identity roles includes RBAC tests."""

    def test_scaffold_includes_identity_helper(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "admin": {
                    "actions": {"network": {"behavior": "allow"}},
                },
            }
        }
        output = generate_test_scaffold(policy)
        assert "make_identity_input" in output

    def test_scaffold_includes_role_test(self):
        policy = _minimal_policy_dict()
        policy["identity"] = {
            "roles": {
                "admin": {
                    "actions": {"network": {"behavior": "allow"}},
                },
            }
        }
        output = generate_test_scaffold(policy)
        assert "admin_network_allow" in output
        assert "no_identity_network_escalate" in output

    def test_scaffold_no_identity_no_rbac_tests(self):
        policy = _minimal_policy_dict()
        output = generate_test_scaffold(policy)
        assert "make_identity_input" not in output


# =========================================================================
# ROUND-TRIP TESTS (YAML fixture → generate_rego)
# =========================================================================


class TestYamlToRegoIdentityRoundTrip:
    """Generate Rego from the identity fixture YAML."""

    def test_fixture_generates_valid_rego(self):
        import yaml
        fixture_path = os.path.join(FIXTURE_DIR, "policy_with_identity.yaml")
        with open(fixture_path) as f:
            policy = yaml.safe_load(f)

        output = generate_rego(policy, source_file="policy_with_identity.yaml")
        # Contains identity data
        assert '"admin"' in output
        assert '"restricted"' in output
        assert '"behavior": "allow"' in output
        # Contains identity rules
        assert "role_has_override" in output
        assert "role_behavior" in output
        # Contains identity override decision rule
        assert "Identity override" in output
        # Contains standard structure
        assert "package agent_gate" in output
        assert "decision :=" in output

    def test_fixture_generates_test_scaffold(self):
        import yaml
        fixture_path = os.path.join(FIXTURE_DIR, "policy_with_identity.yaml")
        with open(fixture_path) as f:
            policy = yaml.safe_load(f)

        output = generate_test_scaffold(policy)
        assert "make_identity_input" in output
        assert "admin_network_allow" in output

    def test_fixture_rego_has_all_tiers(self):
        """Generated Rego from fixture has blocked, destructive, network, read_only."""
        import yaml
        fixture_path = os.path.join(FIXTURE_DIR, "policy_with_identity.yaml")
        with open(fixture_path) as f:
            policy = yaml.safe_load(f)

        output = generate_rego(policy, source_file="policy_with_identity.yaml")
        assert "blocked_patterns" in output
        assert "destructive_patterns" in output
        assert "network_patterns" in output
        assert "read_only_patterns" in output


# =========================================================================
# OPAClassifier INIT TESTS
# =========================================================================


class TestOPAClassifierInit:
    """Test that OPAClassifier stores identity parameter."""

    def test_identity_stored(self):
        raw = _minimal_policy_dict()
        policy = _make_policy(raw)
        identity = IdentityContext(operator="sean")
        classifier = _make_opa_classifier(policy, identity=identity)
        assert classifier.identity is identity

    def test_identity_none_default(self):
        raw = _minimal_policy_dict()
        policy = _make_policy(raw)
        classifier = _make_opa_classifier(policy)
        assert classifier.identity is None
