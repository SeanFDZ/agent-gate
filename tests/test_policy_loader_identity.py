"""
Agent Gate — Identity Section Policy Loader Tests
Validates that policy_loader.py correctly parses, validates, and rejects
identity configurations.  The identity section is entirely optional;
existing policies without identity must work identically.
"""

import copy
import os
import sys
import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.policy_loader import Policy, PolicyValidationError, load_policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "test_fixtures")
IDENTITY_FIXTURE = os.path.join(FIXTURE_DIR, "policy_with_identity.yaml")


def _base_policy(workdir="/tmp/test-workspace", vault="/tmp/test-vault"):
    """Return a minimal valid policy dict with no identity section."""
    return {
        "schema_version": "0.1.0",
        "gate": {
            "name": "test-workspace",
            "description": "Test policy for identity tests",
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
                "description": "Destructive actions",
                "patterns": [{"command": "rm", "description": "File deletion"}],
            },
            "read_only": {
                "description": "Read-only actions",
                "patterns": [{"command": "cat"}],
            },
            "blocked": {
                "description": "Blocked actions",
                "patterns": [
                    {
                        "command": "rm",
                        "args_contain": ["-rf /"],
                        "description": "Recursive force delete",
                    }
                ],
            },
        },
        "gate_behavior": {
            "on_destructive": ["extract_target_paths", "allow_execution"],
            "on_read_only": ["allow_execution"],
            "on_blocked": ["deny_execution"],
            "on_network": {"default": "escalate", "message": "Network access."},
            "on_unclassified": {"default": "deny", "message": "Unclassified."},
        },
    }


def _make_policy(raw, workdir="/tmp/test-workspace"):
    """Construct a Policy from a raw dict."""
    return Policy(raw, workdir)


# ---------------------------------------------------------------------------
# Backward Compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    def test_no_identity_section_loads_normally(self):
        """Policy without identity section loads successfully."""
        raw = _base_policy()
        policy = _make_policy(raw)
        assert policy.identity_config == {}
        assert policy.identity_roles == {}
        assert policy.identity_fields == {}
        assert policy.identity_source == "environment"

    def test_no_identity_section_policy_hash_unchanged(self):
        """Hash is deterministic for policies without identity."""
        raw = _base_policy()
        policy1 = _make_policy(copy.deepcopy(raw))
        policy2 = _make_policy(copy.deepcopy(raw))
        assert policy1.policy_hash == policy2.policy_hash

    def test_existing_fields_unaffected(self):
        """All existing fields still populated when identity absent."""
        raw = _base_policy()
        policy = _make_policy(raw)
        assert policy.name == "test-workspace"
        assert len(policy.allowed_paths) > 0
        assert len(policy.denied_paths) > 0


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

class TestIdentityParsing:
    def test_identity_section_parsed(self):
        """Identity section from fixture is parsed correctly."""
        policy = load_policy(IDENTITY_FIXTURE, "/tmp/test-workspace")
        assert policy.identity_source == "environment"
        assert "operator" in policy.identity_fields
        assert "agent_id" in policy.identity_fields
        assert "admin" in policy.identity_roles
        assert "restricted" in policy.identity_roles

    def test_identity_fields_env_vars_resolved(self, monkeypatch):
        """Environment variable references in fields are resolved."""
        monkeypatch.setenv("AGENT_GATE_OPERATOR", "sean")
        monkeypatch.setenv("AGENT_GATE_AGENT_ID", "agent-42")
        monkeypatch.setenv("AGENT_GATE_SERVICE", "ci-runner")
        monkeypatch.setenv("AGENT_GATE_ROLE", "admin")
        policy = load_policy(IDENTITY_FIXTURE, "/tmp/test-workspace")
        assert policy.identity_fields["operator"] == "sean"
        assert policy.identity_fields["agent_id"] == "agent-42"
        assert policy.identity_fields["service_account"] == "ci-runner"
        assert policy.identity_fields["role"] == "admin"

    def test_identity_roles_parsed(self):
        """Role configurations are parsed correctly."""
        policy = load_policy(IDENTITY_FIXTURE, "/tmp/test-workspace")
        assert policy.identity_roles["admin"]["actions"]["network"]["behavior"] == "allow"
        assert policy.identity_roles["restricted"]["rate_limits"]["global"]["max_calls"] == 50

    def test_get_role_overrides_found(self):
        """get_role_overrides returns config for known role."""
        policy = load_policy(IDENTITY_FIXTURE, "/tmp/test-workspace")
        overrides = policy.get_role_overrides("admin")
        assert overrides is not None
        assert overrides["actions"]["network"]["behavior"] == "allow"

    def test_get_role_overrides_not_found(self):
        """get_role_overrides returns None for unknown role."""
        policy = load_policy(IDENTITY_FIXTURE, "/tmp/test-workspace")
        assert policy.get_role_overrides("unknown_role") is None


# ---------------------------------------------------------------------------
# Validation — Invalid Source
# ---------------------------------------------------------------------------

class TestValidationSource:
    def test_invalid_source_raises(self):
        """Invalid identity.source raises PolicyValidationError."""
        raw = _base_policy()
        raw["identity"] = {"source": "invalid"}
        with pytest.raises(PolicyValidationError, match="identity.source"):
            _make_policy(raw)

    def test_valid_sources_accepted(self):
        """All valid source values are accepted."""
        for source in ("environment", "config", "mcp_metadata", "header"):
            raw = _base_policy()
            raw["identity"] = {"source": source}
            policy = _make_policy(raw)
            assert policy.identity_source == source


# ---------------------------------------------------------------------------
# Validation — Fields
# ---------------------------------------------------------------------------

class TestValidationFields:
    def test_invalid_fields_not_mapping_raises(self):
        """Non-dict identity.fields raises PolicyValidationError."""
        raw = _base_policy()
        raw["identity"] = {"fields": "not_a_dict"}
        with pytest.raises(PolicyValidationError, match="identity.fields must be a mapping"):
            _make_policy(raw)

    def test_unknown_field_name_raises(self):
        """Unknown field name raises PolicyValidationError."""
        raw = _base_policy()
        raw["identity"] = {"fields": {"unknown_field": "value"}}
        with pytest.raises(PolicyValidationError, match="unknown_field"):
            _make_policy(raw)

    def test_fields_empty_dict_valid(self):
        """Empty fields dict is valid."""
        raw = _base_policy()
        raw["identity"] = {"fields": {}}
        policy = _make_policy(raw)
        assert policy.identity_fields == {}


# ---------------------------------------------------------------------------
# Validation — Roles
# ---------------------------------------------------------------------------

class TestValidationRoles:
    def test_invalid_role_not_mapping_raises(self):
        """Non-dict role config raises PolicyValidationError."""
        raw = _base_policy()
        raw["identity"] = {"roles": {"admin": "not_a_dict"}}
        with pytest.raises(PolicyValidationError, match="identity.roles.admin must be a mapping"):
            _make_policy(raw)

    def test_invalid_role_override_key_raises(self):
        """Unknown override key in role raises PolicyValidationError."""
        raw = _base_policy()
        raw["identity"] = {"roles": {"admin": {"unknown_key": {}}}}
        with pytest.raises(PolicyValidationError, match="unknown_key"):
            _make_policy(raw)

    def test_roles_empty_dict_valid(self):
        """Empty roles dict is valid."""
        raw = _base_policy()
        raw["identity"] = {"roles": {}}
        policy = _make_policy(raw)
        assert policy.identity_roles == {}

    def test_invalid_roles_not_mapping_raises(self):
        """Non-dict identity.roles raises PolicyValidationError."""
        raw = _base_policy()
        raw["identity"] = {"roles": "not_a_dict"}
        with pytest.raises(PolicyValidationError, match="identity.roles must be a mapping"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Validation — Rate Limit Overrides
# ---------------------------------------------------------------------------

class TestValidationRateLimitOverrides:
    def test_invalid_role_rate_limit_max_calls_raises(self):
        """Negative max_calls in role rate_limits raises error."""
        raw = _base_policy()
        raw["identity"] = {
            "roles": {
                "admin": {
                    "rate_limits": {
                        "global": {"max_calls": -1}
                    }
                }
            }
        }
        with pytest.raises(PolicyValidationError, match="max_calls"):
            _make_policy(raw)

    def test_invalid_role_rate_limits_not_mapping_raises(self):
        """Non-dict rate_limits in role raises error."""
        raw = _base_policy()
        raw["identity"] = {
            "roles": {
                "admin": {"rate_limits": "not_a_dict"}
            }
        }
        with pytest.raises(PolicyValidationError, match="rate_limits"):
            _make_policy(raw)

    def test_role_rate_limit_global_override_parsed(self):
        """Rate limit global override in role is parsed."""
        policy = load_policy(IDENTITY_FIXTURE, "/tmp/test-workspace")
        admin = policy.identity_roles["admin"]
        assert admin["rate_limits"]["global"]["max_calls"] == 500


# ---------------------------------------------------------------------------
# Validation — Action Behavior Overrides
# ---------------------------------------------------------------------------

class TestValidationActionOverrides:
    def test_invalid_role_behavior_raises(self):
        """Invalid behavior value in role actions raises error."""
        raw = _base_policy()
        raw["identity"] = {
            "roles": {
                "admin": {
                    "actions": {
                        "network": {"behavior": "invalid"}
                    }
                }
            }
        }
        with pytest.raises(PolicyValidationError, match="behavior"):
            _make_policy(raw)

    def test_invalid_role_actions_not_mapping_raises(self):
        """Non-dict actions in role raises error."""
        raw = _base_policy()
        raw["identity"] = {
            "roles": {
                "admin": {"actions": "not_a_dict"}
            }
        }
        with pytest.raises(PolicyValidationError, match="actions"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Validation — Envelope Overrides
# ---------------------------------------------------------------------------

class TestValidationEnvelopeOverrides:
    def test_role_envelope_denied_paths_append_parsed(self):
        """Envelope denied_paths_append is parsed from role."""
        policy = load_policy(IDENTITY_FIXTURE, "/tmp/test-workspace")
        restricted = policy.identity_roles["restricted"]
        assert "denied_paths_append" in restricted["envelope"]
        assert any(
            "config" in p
            for p in restricted["envelope"]["denied_paths_append"]
        )

    def test_invalid_role_envelope_not_mapping_raises(self):
        """Non-dict envelope in role raises error."""
        raw = _base_policy()
        raw["identity"] = {
            "roles": {
                "admin": {"envelope": "not_a_dict"}
            }
        }
        with pytest.raises(PolicyValidationError, match="envelope"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_identity_section_empty_dict_valid(self):
        """Empty identity dict is valid, defaults apply."""
        raw = _base_policy()
        raw["identity"] = {}
        policy = _make_policy(raw)
        assert policy.identity_source == "environment"
        assert policy.identity_fields == {}
        assert policy.identity_roles == {}

    def test_identity_source_defaults_to_environment(self):
        """Missing source defaults to 'environment'."""
        raw = _base_policy()
        raw["identity"] = {"fields": {"operator": "sean"}}
        policy = _make_policy(raw)
        assert policy.identity_source == "environment"

    def test_identity_not_mapping_raises(self):
        """Non-dict identity section raises PolicyValidationError."""
        raw = _base_policy()
        raw["identity"] = "not_a_dict"
        with pytest.raises(PolicyValidationError, match="identity must be a mapping"):
            _make_policy(raw)

    def test_identity_with_all_valid_fields(self):
        """All recognized field names are accepted together."""
        raw = _base_policy()
        raw["identity"] = {
            "fields": {
                "operator": "sean",
                "agent_id": "agent-1",
                "service_account": "ci",
                "session_id": "sess-123",
                "role": "admin",
            }
        }
        policy = _make_policy(raw)
        assert len(policy.identity_fields) == 5
