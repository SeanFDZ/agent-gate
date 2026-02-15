"""
Agent Gate — Policy Loader
Loads, validates, and resolves policy definitions from YAML.
"""

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
