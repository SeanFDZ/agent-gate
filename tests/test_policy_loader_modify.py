"""
Agent Gate — Policy Loader Modify Schema Validation Tests
Validates that policy_loader.py correctly parses, validates, and rejects
the modify, args_match, and vault fields on pattern entries.  The modify
key on patterns is optional; existing policies without modify rules must
work identically to v0.3.0.
"""

import copy
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.policy_loader import Policy, PolicyValidationError, load_policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

POLICY_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")
DEFAULT_YAML = os.path.join(POLICY_DIR, "default.yaml")


def _base_policy(workdir="/tmp/test-workspace", vault="/tmp/test-vault"):
    """Return a minimal valid policy dict with no modify fields."""
    return {
        "schema_version": "0.1.0",
        "gate": {
            "name": "test-workspace",
            "description": "Test policy for modify validation tests",
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
# Valid Modify Fields
# ---------------------------------------------------------------------------

class TestValidModifyFields:
    def test_valid_modify_block_accepted(self):
        """Policy with pattern containing modify: {clamp_permission: "755"} loads."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "clamp_permission": "755",
        }
        policy = _make_policy(raw)
        assert policy.actions["destructive"]["patterns"][0]["modify"]["clamp_permission"] == "755"

    def test_valid_args_match_accepted(self):
        """Policy with pattern containing args_match: "^SELECT" loads."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["args_match"] = "^SELECT"
        policy = _make_policy(raw)
        assert policy.actions["destructive"]["patterns"][0]["args_match"] == "^SELECT"

    def test_valid_vault_skip_accepted(self):
        """Policy with pattern containing vault: skip loads."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["vault"] = "skip"
        policy = _make_policy(raw)
        assert policy.actions["destructive"]["patterns"][0]["vault"] == "skip"

    def test_multiple_ops_in_modify_block(self):
        """Policy with multiple operations in modify block loads."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "strip_flags": ["-f"],
            "require_flags": ["--interactive"],
        }
        policy = _make_policy(raw)
        modify = policy.actions["destructive"]["patterns"][0]["modify"]
        assert modify["strip_flags"] == ["-f"]
        assert modify["require_flags"] == ["--interactive"]


# ---------------------------------------------------------------------------
# Invalid args_match
# ---------------------------------------------------------------------------

class TestInvalidArgsMatch:
    def test_invalid_args_match_bad_regex(self):
        """args_match with invalid regex raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["args_match"] = "[invalid"
        with pytest.raises(PolicyValidationError, match="not a valid regex"):
            _make_policy(raw)

    def test_invalid_args_match_not_string(self):
        """args_match that is not a string raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["args_match"] = 123
        with pytest.raises(PolicyValidationError, match="args_match must be a string"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Invalid vault
# ---------------------------------------------------------------------------

class TestInvalidVault:
    def test_invalid_vault_unknown_value(self):
        """vault: "archive" raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["vault"] = "archive"
        with pytest.raises(PolicyValidationError, match="vault must be one of"):
            _make_policy(raw)

    def test_invalid_vault_boolean(self):
        """vault: true raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["vault"] = True
        with pytest.raises(PolicyValidationError, match="vault must be one of"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Invalid modify
# ---------------------------------------------------------------------------

class TestInvalidModify:
    def test_invalid_modify_not_dict(self):
        """modify: "clamp" raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = "clamp"
        with pytest.raises(PolicyValidationError, match="must be a mapping"):
            _make_policy(raw)

    def test_invalid_modify_empty(self):
        """modify: {} raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {}
        with pytest.raises(PolicyValidationError, match="must not be empty"):
            _make_policy(raw)

    def test_invalid_modify_unknown_operation(self):
        """Unknown operation key raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "unknown_op": "value",
        }
        with pytest.raises(PolicyValidationError, match="known operation"):
            _make_policy(raw)

    def test_invalid_clamp_permission_not_string(self):
        """clamp_permission: 755 (int) raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "clamp_permission": 755,
        }
        with pytest.raises(PolicyValidationError, match="clamp_permission must be a string"):
            _make_policy(raw)

    def test_invalid_strip_flags_not_list(self):
        """strip_flags: "-f" (string) raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "strip_flags": "-f",
        }
        with pytest.raises(PolicyValidationError, match="strip_flags must be a list"):
            _make_policy(raw)

    def test_invalid_require_flags_not_list(self):
        """require_flags: "--interactive" (string) raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "require_flags": "--interactive",
        }
        with pytest.raises(PolicyValidationError, match="require_flags must be a list"):
            _make_policy(raw)

    def test_invalid_append_arg_not_string(self):
        """append_arg: 100 (int) raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "append_arg": 100,
        }
        with pytest.raises(PolicyValidationError, match="append_arg must be a string"):
            _make_policy(raw)

    def test_invalid_max_depth_not_int(self):
        """max_depth: "2" (string) raises PolicyValidationError."""
        raw = _base_policy()
        raw["actions"]["destructive"]["patterns"][0]["modify"] = {
            "max_depth": "2",
        }
        with pytest.raises(PolicyValidationError, match="max_depth must be an integer"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Role Override — modify_rules accepted
# ---------------------------------------------------------------------------

class TestRoleModifyRules:
    def test_modify_rules_accepted_in_role(self):
        """modify_rules key in a role is accepted (schema reservation)."""
        raw = _base_policy()
        raw["identity"] = {
            "roles": {
                "dev": {
                    "modify_rules": [
                        {
                            "command": "database_query",
                            "modify": {"append_arg": "LIMIT 1000"},
                        }
                    ],
                }
            }
        }
        policy = _make_policy(raw)
        assert "modify_rules" in policy.identity_roles["dev"]


# ---------------------------------------------------------------------------
# Backward Compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompat:
    def test_backward_compat_no_modify_fields(self):
        """Existing default.yaml (no modify/args_match/vault keys) loads."""
        policy = load_policy(DEFAULT_YAML, "/tmp/test-workspace")
        assert policy.name == "default-workspace"
        # All action tiers loaded
        assert "destructive" in policy.actions
        assert "read_only" in policy.actions
        assert "blocked" in policy.actions

    def test_existing_base_policy_no_modify(self):
        """Base policy without any modify fields loads without error."""
        raw = _base_policy()
        policy = _make_policy(raw)
        assert policy.name == "test-workspace"


# ---------------------------------------------------------------------------
# Network Tier Patterns Validated
# ---------------------------------------------------------------------------

class TestOptionalTierPatterns:
    def test_network_tier_patterns_validated(self):
        """Modify fields on network tier patterns are validated."""
        raw = _base_policy()
        raw["actions"]["network"] = {
            "description": "Network commands",
            "patterns": [
                {
                    "command": "curl",
                    "description": "HTTP client",
                    "modify": {"require_flags": ["--max-time 30"]},
                }
            ],
        }
        policy = _make_policy(raw)
        assert policy.actions["network"]["patterns"][0]["modify"]["require_flags"] == ["--max-time 30"]

    def test_network_tier_invalid_modify_rejected(self):
        """Invalid modify on network tier pattern raises error."""
        raw = _base_policy()
        raw["actions"]["network"] = {
            "description": "Network commands",
            "patterns": [
                {
                    "command": "curl",
                    "description": "HTTP client",
                    "modify": "bad",
                }
            ],
        }
        with pytest.raises(PolicyValidationError, match="must be a mapping"):
            _make_policy(raw)
