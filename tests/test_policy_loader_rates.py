"""
Agent Gate — Rate Limits Policy Loader Tests
Validates that policy_loader.py correctly parses, validates, and rejects
rate_limits configurations.  All rate_limits functionality is optional;
existing policies without rate_limits must work identically.
"""

import copy
import os
import sys
import tempfile
import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.policy_loader import Policy, PolicyValidationError, load_policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_policy(workdir="/tmp/test-workspace", vault="/tmp/test-vault"):
    """Return a minimal valid policy dict with no rate_limits section."""
    return {
        "schema_version": "0.1.0",
        "gate": {
            "name": "test-workspace",
            "description": "Test policy for rate limit tests",
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


def _full_rate_limits():
    """Return a complete, valid rate_limits section."""
    return {
        "algorithm": "sliding_window",
        "tools": {
            "cat": {"max_calls": 120, "window_seconds": 60},
            "rm": {
                "max_calls": 10,
                "window_seconds": 60,
                "on_exceed": "deny",
                "message": "rm rate limit exceeded.",
            },
        },
        "tier_defaults": {
            "read_only": {
                "max_calls": 120,
                "window_seconds": 60,
                "on_exceed": "deny",
            },
            "destructive": {
                "max_calls": 30,
                "window_seconds": 60,
                "on_exceed": "escalate",
            },
        },
        "global": {
            "max_calls": 200,
            "window_seconds": 60,
            "on_exceed": "read_only",
            "message": "Global rate limit exceeded.",
        },
        "circuit_breaker": {
            "enabled": True,
            "sliding_window_size": 20,
            "minimum_calls": 10,
            "failure_rate_threshold": 0.50,
            "slow_call_rate_threshold": 0.50,
            "slow_call_duration_seconds": 5.0,
            "wait_duration_open_seconds": 30,
            "permitted_calls_half_open": 3,
            "on_trip": "read_only",
            "message": "Circuit breaker tripped.",
        },
        "backoff": {
            "enabled": True,
            "initial_wait_seconds": 5,
            "multiplier": 2.0,
            "max_wait_seconds": 300,
        },
    }


def _make_policy(raw, workdir="/tmp/test-workspace"):
    """Construct a Policy from a raw dict."""
    return Policy(raw, workdir)


def _write_yaml_file(raw):
    """Write a raw dict to a temp YAML file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        yaml.dump(raw, f)
    return path


# ---------------------------------------------------------------------------
# Test 1: No rate_limits section — loads without error, empty dict
# ---------------------------------------------------------------------------

class TestNoRateLimits:
    def test_policy_loads_without_rate_limits(self):
        """Policy without rate_limits loads successfully."""
        raw = _base_policy()
        policy = _make_policy(raw)
        assert policy.rate_limits == {}

    def test_existing_fields_unaffected(self):
        """All existing fields still populated when rate_limits absent."""
        raw = _base_policy()
        policy = _make_policy(raw)
        assert policy.name == "test-workspace"
        assert len(policy.allowed_paths) > 0
        assert len(policy.denied_paths) > 0


# ---------------------------------------------------------------------------
# Test 2: Valid rate_limits — full section loads, all values accessible
# ---------------------------------------------------------------------------

class TestValidRateLimits:
    def test_full_rate_limits_loads(self):
        """Full rate_limits section loads and is accessible."""
        raw = _base_policy()
        raw["rate_limits"] = _full_rate_limits()
        policy = _make_policy(raw)
        assert policy.rate_limits["algorithm"] == "sliding_window"
        assert "cat" in policy.rate_limits["tools"]
        assert policy.rate_limits["tools"]["cat"]["max_calls"] == 120
        assert policy.rate_limits["global"]["max_calls"] == 200

    def test_circuit_breaker_accessible(self):
        """Circuit breaker config is accessible after load."""
        raw = _base_policy()
        raw["rate_limits"] = _full_rate_limits()
        policy = _make_policy(raw)
        cb = policy.rate_limits["circuit_breaker"]
        assert cb["enabled"] is True
        assert cb["sliding_window_size"] == 20
        assert cb["failure_rate_threshold"] == 0.50

    def test_token_bucket_algorithm_valid(self):
        """token_bucket is an accepted algorithm value."""
        raw = _base_policy()
        raw["rate_limits"] = {"algorithm": "token_bucket"}
        policy = _make_policy(raw)
        assert policy.rate_limits["algorithm"] == "token_bucket"


# ---------------------------------------------------------------------------
# Test 3: Invalid algorithm — raises PolicyValidationError
# ---------------------------------------------------------------------------

class TestInvalidAlgorithm:
    def test_invalid_algorithm_rejected(self):
        """Unknown algorithm value raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {"algorithm": "leaky_bucket"}
        with pytest.raises(PolicyValidationError, match="algorithm"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Test 4: Missing max_calls in tool — raises PolicyValidationError
# ---------------------------------------------------------------------------

class TestMissingMaxCalls:
    def test_tool_missing_max_calls(self):
        """Tool entry without max_calls raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "tools": {
                "cat": {"window_seconds": 60}  # missing max_calls
            }
        }
        with pytest.raises(PolicyValidationError, match="max_calls"):
            _make_policy(raw)

    def test_tier_default_missing_max_calls(self):
        """Tier default without max_calls raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "tier_defaults": {
                "read_only": {"window_seconds": 60}  # missing max_calls
            }
        }
        with pytest.raises(PolicyValidationError, match="max_calls"):
            _make_policy(raw)

    def test_global_missing_max_calls(self):
        """Global section without max_calls raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "global": {"window_seconds": 60}  # missing max_calls
        }
        with pytest.raises(PolicyValidationError, match="max_calls"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Test 5: Negative window_seconds — raises PolicyValidationError
# ---------------------------------------------------------------------------

class TestNegativeWindowSeconds:
    def test_tool_negative_window_seconds(self):
        """Negative window_seconds on a tool raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "tools": {
                "cat": {"max_calls": 100, "window_seconds": -1}
            }
        }
        with pytest.raises(PolicyValidationError, match="window_seconds"):
            _make_policy(raw)

    def test_tool_zero_window_seconds(self):
        """Zero window_seconds on a tool raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "tools": {
                "cat": {"max_calls": 100, "window_seconds": 0}
            }
        }
        with pytest.raises(PolicyValidationError, match="window_seconds"):
            _make_policy(raw)

    def test_global_negative_window_seconds(self):
        """Negative window_seconds on global raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "global": {"max_calls": 200, "window_seconds": -5}
        }
        with pytest.raises(PolicyValidationError, match="window_seconds"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Test 6: Invalid on_exceed value — raises PolicyValidationError
# ---------------------------------------------------------------------------

class TestInvalidOnExceed:
    def test_tool_invalid_on_exceed(self):
        """Invalid on_exceed on a tool raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "tools": {
                "rm": {
                    "max_calls": 10,
                    "window_seconds": 60,
                    "on_exceed": "panic",
                }
            }
        }
        with pytest.raises(PolicyValidationError, match="on_exceed"):
            _make_policy(raw)

    def test_global_invalid_on_exceed(self):
        """Invalid on_exceed on global raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "global": {
                "max_calls": 200,
                "window_seconds": 60,
                "on_exceed": "shutdown",
            }
        }
        with pytest.raises(PolicyValidationError, match="on_exceed"):
            _make_policy(raw)


# ---------------------------------------------------------------------------
# Test 7: Circuit breaker threshold out of range
# ---------------------------------------------------------------------------

class TestCircuitBreakerThresholds:
    def test_failure_rate_above_one(self):
        """failure_rate_threshold > 1.0 raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "circuit_breaker": {
                "enabled": True,
                "failure_rate_threshold": 1.5,
            }
        }
        with pytest.raises(PolicyValidationError, match="failure_rate_threshold"):
            _make_policy(raw)

    def test_failure_rate_negative(self):
        """Negative failure_rate_threshold raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "circuit_breaker": {
                "enabled": True,
                "failure_rate_threshold": -0.1,
            }
        }
        with pytest.raises(PolicyValidationError, match="failure_rate_threshold"):
            _make_policy(raw)

    def test_slow_call_rate_above_one(self):
        """slow_call_rate_threshold > 1.0 raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "circuit_breaker": {
                "enabled": True,
                "slow_call_rate_threshold": 2.0,
            }
        }
        with pytest.raises(PolicyValidationError, match="slow_call_rate_threshold"):
            _make_policy(raw)

    def test_disabled_breaker_skips_validation(self):
        """Disabled circuit breaker skips threshold validation."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "circuit_breaker": {
                "enabled": False,
                "failure_rate_threshold": 99.0,  # invalid, but not checked
            }
        }
        # Should NOT raise — breaker is disabled
        policy = _make_policy(raw)
        assert policy.rate_limits["circuit_breaker"]["enabled"] is False


# ---------------------------------------------------------------------------
# Test 8: Circuit breaker minimum_calls > sliding_window_size
# ---------------------------------------------------------------------------

class TestCircuitBreakerMinCalls:
    def test_minimum_calls_exceeds_window_size(self):
        """minimum_calls > sliding_window_size raises PolicyValidationError."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "circuit_breaker": {
                "enabled": True,
                "sliding_window_size": 10,
                "minimum_calls": 20,
            }
        }
        with pytest.raises(PolicyValidationError, match="minimum_calls"):
            _make_policy(raw)

    def test_minimum_calls_equal_window_size(self):
        """minimum_calls == sliding_window_size is valid."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "circuit_breaker": {
                "enabled": True,
                "sliding_window_size": 10,
                "minimum_calls": 10,
            }
        }
        policy = _make_policy(raw)
        cb = policy.rate_limits["circuit_breaker"]
        assert cb["minimum_calls"] == cb["sliding_window_size"]


# ---------------------------------------------------------------------------
# Test 9: Partial rate_limits — only global, no tools or tier_defaults
# ---------------------------------------------------------------------------

class TestPartialRateLimits:
    def test_global_only(self):
        """rate_limits with only global section is valid."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "global": {
                "max_calls": 200,
                "window_seconds": 60,
            }
        }
        policy = _make_policy(raw)
        assert policy.rate_limits["global"]["max_calls"] == 200
        assert "tools" not in policy.rate_limits
        assert "tier_defaults" not in policy.rate_limits

    def test_tools_only(self):
        """rate_limits with only tools section is valid."""
        raw = _base_policy()
        raw["rate_limits"] = {
            "tools": {
                "cat": {"max_calls": 100, "window_seconds": 60},
            }
        }
        policy = _make_policy(raw)
        assert "cat" in policy.rate_limits["tools"]

    def test_empty_rate_limits(self):
        """Empty rate_limits mapping is valid (no sub-sections)."""
        raw = _base_policy()
        raw["rate_limits"] = {}
        policy = _make_policy(raw)
        assert policy.rate_limits == {}


# ---------------------------------------------------------------------------
# Test 10: Policy hash determinism — same policy produces same hash
# ---------------------------------------------------------------------------

class TestPolicyHashDeterminism:
    def test_same_policy_same_hash(self):
        """Loading the same policy twice produces identical hashes."""
        raw = _base_policy()
        policy1 = _make_policy(copy.deepcopy(raw))
        policy2 = _make_policy(copy.deepcopy(raw))
        assert policy1.policy_hash == policy2.policy_hash

    def test_hash_is_hex_string(self):
        """Policy hash is a 16-character hex string."""
        raw = _base_policy()
        policy = _make_policy(raw)
        h = policy.policy_hash
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_with_rate_limits(self):
        """Hash is deterministic even with rate_limits present."""
        raw = _base_policy()
        raw["rate_limits"] = _full_rate_limits()
        policy1 = _make_policy(copy.deepcopy(raw))
        policy2 = _make_policy(copy.deepcopy(raw))
        assert policy1.policy_hash == policy2.policy_hash


# ---------------------------------------------------------------------------
# Test 11: Policy hash changes — modified policy produces different hash
# ---------------------------------------------------------------------------

class TestPolicyHashChanges:
    def test_different_name_different_hash(self):
        """Changing the gate name produces a different hash."""
        raw1 = _base_policy()
        raw2 = _base_policy()
        raw2["gate"]["name"] = "modified-workspace"
        policy1 = _make_policy(raw1)
        policy2 = _make_policy(raw2)
        assert policy1.policy_hash != policy2.policy_hash

    def test_adding_rate_limits_changes_hash(self):
        """Adding rate_limits to a policy changes its hash."""
        raw_without = _base_policy()
        raw_with = _base_policy()
        raw_with["rate_limits"] = _full_rate_limits()
        policy1 = _make_policy(raw_without)
        policy2 = _make_policy(raw_with)
        assert policy1.policy_hash != policy2.policy_hash

    def test_modifying_rate_limit_value_changes_hash(self):
        """Changing a rate limit value produces a different hash."""
        raw1 = _base_policy()
        raw1["rate_limits"] = _full_rate_limits()
        raw2 = _base_policy()
        raw2["rate_limits"] = _full_rate_limits()
        raw2["rate_limits"]["global"]["max_calls"] = 999
        policy1 = _make_policy(raw1)
        policy2 = _make_policy(raw2)
        assert policy1.policy_hash != policy2.policy_hash


# ---------------------------------------------------------------------------
# Integration: load_policy from file with rate_limits
# ---------------------------------------------------------------------------

class TestLoadPolicyFromFile:
    def test_load_policy_with_rate_limits(self, tmp_path):
        """load_policy correctly loads a YAML file with rate_limits."""
        raw = _base_policy(
            workdir=str(tmp_path / "workspace"),
            vault=str(tmp_path / "vault"),
        )
        raw["rate_limits"] = _full_rate_limits()
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(raw))

        policy = load_policy(str(policy_file), str(tmp_path / "workspace"))
        assert policy.rate_limits["algorithm"] == "sliding_window"
        assert policy.rate_limits["global"]["max_calls"] == 200

    def test_load_policy_without_rate_limits(self, tmp_path):
        """load_policy correctly loads a YAML file without rate_limits."""
        raw = _base_policy(
            workdir=str(tmp_path / "workspace"),
            vault=str(tmp_path / "vault"),
        )
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(raw))

        policy = load_policy(str(policy_file), str(tmp_path / "workspace"))
        assert policy.rate_limits == {}
