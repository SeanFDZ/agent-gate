"""
Agent Gate — Policy Loader
Loads, validates, and resolves policy definitions from YAML.
"""

import hashlib
import json
import os
import re
import yaml
from pathlib import Path
from typing import Any


class PolicyValidationError(Exception):
    """Raised when a policy file is invalid or incomplete."""
    pass


class Policy:
    """
    Represents a loaded, resolved, and validated Agent Gate policy.
    
    All path variables are resolved at load time. The policy object
    is immutable after loading — classification at runtime is a lookup,
    not an evaluation.
    """

    REQUIRED_SECTIONS = ["gate", "envelope", "vault", "actions", "gate_behavior"]
    REQUIRED_ACTION_TIERS = ["destructive", "read_only", "blocked"]

    def __init__(self, raw: dict, workdir: str):
        self._raw = raw
        self._workdir = workdir
        self._resolve_variables()
        self._validate()

        # Parsed and ready for runtime lookup
        self.name = self._raw["gate"]["name"]
        self.description = self._raw["gate"]["description"]
        self.allowed_paths = self._raw["envelope"]["allowed_paths"]
        self.denied_paths = self._raw["envelope"]["denied_paths"]
        self.vault_config = self._raw["vault"]
        self.actions = self._raw["actions"]
        self.gate_behavior = self._raw["gate_behavior"]
        self.logging_config = self._raw.get("logging", {})
        self.rate_limits = self._raw.get("rate_limits", {})

    @property
    def policy_hash(self) -> str:
        """SHA-256 hash of the policy content for audit traceability."""
        content = json.dumps(self._raw, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _resolve_variables(self):
        """
        Recursively resolve ${HOME}, ${WORKDIR}, and any other
        environment variables in all string values.
        """
        env_map = {
            "HOME": str(Path.home()),
            "WORKDIR": self._workdir,
        }
        self._raw = self._resolve_recursive(self._raw, env_map)

    def _resolve_recursive(self, obj: Any, env_map: dict) -> Any:
        """Walk the parsed YAML and substitute variables in strings."""
        if isinstance(obj, str):
            def replacer(match):
                var_name = match.group(1)
                if var_name in env_map:
                    return env_map[var_name]
                # Fall back to actual environment variables
                env_val = os.environ.get(var_name)
                if env_val is not None:
                    return env_val
                return match.group(0)  # Leave unresolved if not found
            return re.sub(r"\$\{(\w+)\}", replacer, obj)
        elif isinstance(obj, dict):
            return {k: self._resolve_recursive(v, env_map) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_recursive(item, env_map) for item in obj]
        return obj

    def _validate(self):
        """Validate that the policy has all required sections and structure."""
        # Check required top-level sections
        for section in self.REQUIRED_SECTIONS:
            if section not in self._raw:
                raise PolicyValidationError(
                    f"Missing required section: '{section}'"
                )

        # Check envelope has paths
        envelope = self._raw["envelope"]
        if not envelope.get("allowed_paths"):
            raise PolicyValidationError(
                "envelope.allowed_paths must contain at least one path"
            )
        if not envelope.get("denied_paths"):
            raise PolicyValidationError(
                "envelope.denied_paths must contain at least one path"
            )

        # Check vault config
        vault = self._raw["vault"]
        if not vault.get("path"):
            raise PolicyValidationError("vault.path is required")
        if vault.get("on_failure") not in ("deny", "allow", "escalate"):
            raise PolicyValidationError(
                "vault.on_failure must be 'deny', 'allow', or 'escalate'"
            )

        # Check action tiers exist and have patterns
        actions = self._raw["actions"]
        for tier in self.REQUIRED_ACTION_TIERS:
            if tier not in actions:
                raise PolicyValidationError(
                    f"Missing required action tier: '{tier}'"
                )
            if not actions[tier].get("patterns"):
                raise PolicyValidationError(
                    f"actions.{tier}.patterns must contain at least one pattern"
                )

        # Verify vault path is in denied_paths (critical safety invariant)
        vault_path = vault["path"]
        vault_protected = False
        for denied in envelope["denied_paths"]:
            # Strip glob suffix for comparison
            denied_base = denied.rstrip("*").rstrip("/")
            if vault_path.startswith(denied_base) or denied_base.startswith(vault_path):
                vault_protected = True
                break
        if not vault_protected:
            raise PolicyValidationError(
                f"CRITICAL: Vault path '{vault_path}' is not listed in "
                f"envelope.denied_paths. The agent could access the vault."
            )

        # Validate rate_limits if present
        if "rate_limits" in self._raw:
            self._validate_rate_limits()

    def _validate_rate_limits(self):
        """Validate the optional rate_limits section.  Only called when present."""
        rl = self._raw["rate_limits"]
        if not isinstance(rl, dict):
            raise PolicyValidationError(
                "rate_limits must be a mapping"
            )

        valid_on_exceed = {"deny", "escalate", "read_only", "deny_all"}
        valid_algorithms = {"sliding_window", "token_bucket"}

        # Validate algorithm
        if "algorithm" in rl:
            if rl["algorithm"] not in valid_algorithms:
                raise PolicyValidationError(
                    f"rate_limits.algorithm must be one of {valid_algorithms}, "
                    f"got '{rl['algorithm']}'"
                )

        # Validate per-tool limits
        if "tools" in rl:
            if not isinstance(rl["tools"], dict):
                raise PolicyValidationError(
                    "rate_limits.tools must be a mapping"
                )
            for tool_name, cfg in rl["tools"].items():
                if not isinstance(cfg, dict):
                    raise PolicyValidationError(
                        f"rate_limits.tools.{tool_name} must be a mapping"
                    )
                if "max_calls" not in cfg:
                    raise PolicyValidationError(
                        f"rate_limits.tools.{tool_name} missing required "
                        f"field 'max_calls'"
                    )
                if not isinstance(cfg["max_calls"], int) or cfg["max_calls"] < 0:
                    raise PolicyValidationError(
                        f"rate_limits.tools.{tool_name}.max_calls must be "
                        f"a non-negative integer"
                    )
                if "window_seconds" not in cfg:
                    raise PolicyValidationError(
                        f"rate_limits.tools.{tool_name} missing required "
                        f"field 'window_seconds'"
                    )
                if (not isinstance(cfg["window_seconds"], int)
                        or cfg["window_seconds"] <= 0):
                    raise PolicyValidationError(
                        f"rate_limits.tools.{tool_name}.window_seconds "
                        f"must be a positive integer"
                    )
                if "on_exceed" in cfg and cfg["on_exceed"] not in valid_on_exceed:
                    raise PolicyValidationError(
                        f"rate_limits.tools.{tool_name}.on_exceed must be "
                        f"one of {valid_on_exceed}, got '{cfg['on_exceed']}'"
                    )

        # Validate tier_defaults
        if "tier_defaults" in rl:
            if not isinstance(rl["tier_defaults"], dict):
                raise PolicyValidationError(
                    "rate_limits.tier_defaults must be a mapping"
                )
            for tier_name, cfg in rl["tier_defaults"].items():
                if not isinstance(cfg, dict):
                    raise PolicyValidationError(
                        f"rate_limits.tier_defaults.{tier_name} must be "
                        f"a mapping"
                    )
                if "max_calls" not in cfg:
                    raise PolicyValidationError(
                        f"rate_limits.tier_defaults.{tier_name} missing "
                        f"required field 'max_calls'"
                    )
                if (not isinstance(cfg["max_calls"], int)
                        or cfg["max_calls"] < 0):
                    raise PolicyValidationError(
                        f"rate_limits.tier_defaults.{tier_name}.max_calls "
                        f"must be a non-negative integer"
                    )
                if "window_seconds" not in cfg:
                    raise PolicyValidationError(
                        f"rate_limits.tier_defaults.{tier_name} missing "
                        f"required field 'window_seconds'"
                    )
                if (not isinstance(cfg["window_seconds"], int)
                        or cfg["window_seconds"] <= 0):
                    raise PolicyValidationError(
                        f"rate_limits.tier_defaults.{tier_name}."
                        f"window_seconds must be a positive integer"
                    )

        # Validate global
        if "global" in rl:
            g = rl["global"]
            if not isinstance(g, dict):
                raise PolicyValidationError(
                    "rate_limits.global must be a mapping"
                )
            if "max_calls" not in g:
                raise PolicyValidationError(
                    "rate_limits.global missing required field 'max_calls'"
                )
            if not isinstance(g["max_calls"], int) or g["max_calls"] <= 0:
                raise PolicyValidationError(
                    "rate_limits.global.max_calls must be a positive integer"
                )
            if "window_seconds" not in g:
                raise PolicyValidationError(
                    "rate_limits.global missing required field "
                    "'window_seconds'"
                )
            if (not isinstance(g["window_seconds"], int)
                    or g["window_seconds"] <= 0):
                raise PolicyValidationError(
                    "rate_limits.global.window_seconds must be a "
                    "positive integer"
                )
            if "on_exceed" in g and g["on_exceed"] not in valid_on_exceed:
                raise PolicyValidationError(
                    f"rate_limits.global.on_exceed must be one of "
                    f"{valid_on_exceed}, got '{g['on_exceed']}'"
                )

        # Validate circuit_breaker
        if "circuit_breaker" in rl:
            cb = rl["circuit_breaker"]
            if not isinstance(cb, dict):
                raise PolicyValidationError(
                    "rate_limits.circuit_breaker must be a mapping"
                )
            if cb.get("enabled", False):
                if "sliding_window_size" in cb:
                    if (not isinstance(cb["sliding_window_size"], int)
                            or cb["sliding_window_size"] <= 0):
                        raise PolicyValidationError(
                            "rate_limits.circuit_breaker."
                            "sliding_window_size must be a positive integer"
                        )
                if "minimum_calls" in cb:
                    if (not isinstance(cb["minimum_calls"], int)
                            or cb["minimum_calls"] <= 0):
                        raise PolicyValidationError(
                            "rate_limits.circuit_breaker.minimum_calls "
                            "must be a positive integer"
                        )
                    sws = cb.get("sliding_window_size", cb["minimum_calls"])
                    if cb["minimum_calls"] > sws:
                        raise PolicyValidationError(
                            "rate_limits.circuit_breaker.minimum_calls "
                            "must be <= sliding_window_size"
                        )

                # Validate threshold fields are between 0.0 and 1.0
                threshold_fields = [
                    "failure_rate_threshold",
                    "slow_call_rate_threshold",
                ]
                for field in threshold_fields:
                    if field in cb:
                        val = cb[field]
                        if (not isinstance(val, (int, float))
                                or val < 0.0 or val > 1.0):
                            raise PolicyValidationError(
                                f"rate_limits.circuit_breaker.{field} "
                                f"must be between 0.0 and 1.0"
                            )

                if "wait_duration_open_seconds" in cb:
                    val = cb["wait_duration_open_seconds"]
                    if (not isinstance(val, (int, float))
                            or val <= 0):
                        raise PolicyValidationError(
                            "rate_limits.circuit_breaker."
                            "wait_duration_open_seconds must be positive"
                        )

                if "permitted_calls_half_open" in cb:
                    val = cb["permitted_calls_half_open"]
                    if not isinstance(val, int) or val <= 0:
                        raise PolicyValidationError(
                            "rate_limits.circuit_breaker."
                            "permitted_calls_half_open must be a "
                            "positive integer"
                        )

                if "on_trip" in cb:
                    if cb["on_trip"] not in valid_on_exceed:
                        raise PolicyValidationError(
                            f"rate_limits.circuit_breaker.on_trip must "
                            f"be one of {valid_on_exceed}, "
                            f"got '{cb['on_trip']}'"
                        )

    def __repr__(self):
        return f"Policy(name='{self.name}', allowed={len(self.allowed_paths)} paths)"


def load_policy(policy_path: str, workdir: str) -> Policy:
    """
    Load a policy from a YAML file.

    Args:
        policy_path: Path to the policy YAML file.
        workdir: The agent's working directory (resolves ${WORKDIR}).

    Returns:
        A validated, resolved Policy object ready for runtime use.

    Raises:
        FileNotFoundError: If the policy file doesn't exist.
        PolicyValidationError: If the policy is invalid.
    """
    policy_path = Path(policy_path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    with open(policy_path, "r") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise PolicyValidationError("Policy file must contain a YAML mapping")

    return Policy(raw, workdir)
