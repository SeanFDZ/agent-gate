"""
Agent Gate — Proxy Configuration Loader

Loads proxy settings from three sources (in priority order):
  1. Environment variables (highest priority)
  2. Config file (~/.config/agent-gate/proxy.yaml or local .agent-gate.yaml)
  3. Sensible defaults (lowest priority)

Environment variables override config file values. Config file
values override defaults. This tiered approach means:
  - Simple setups: just set AGENT_GATE_POLICY and AGENT_GATE_WORKDIR
  - Complex setups: use a config file for OPA, audit, multi-server
  - Enterprise: config file with env var overrides for secrets

Security principle: Agent Gate config NEVER stores MCP server
credentials. Those stay in the user's environment and pass through
to the server subprocess naturally.
"""

import os
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


# Default locations to search for config
CONFIG_SEARCH_PATHS = [
    ".agent-gate.yaml",                          # Project-local
    ".agent-gate.yml",                           # Alt extension
    os.path.expanduser("~/.config/agent-gate/proxy.yaml"),  # User config
    os.path.expanduser("~/.config/agent-gate/proxy.yml"),
]

# Environment variable prefix
ENV_PREFIX = "AGENT_GATE_"

# Environment variable mappings
ENV_MAP = {
    "AGENT_GATE_POLICY": "policy",
    "AGENT_GATE_WORKDIR": "workdir",
    "AGENT_GATE_BACKEND": "classifier_backend",
    "AGENT_GATE_AUDIT_LOG": "audit_log",
    "AGENT_GATE_VAULT_PATH": "vault_path",
    "AGENT_GATE_LOG_LEVEL": "log_level",
    # OPA-specific
    "AGENT_GATE_OPA_MODE": "opa.mode",
    "AGENT_GATE_OPA_ENDPOINT": "opa.endpoint",
    "AGENT_GATE_OPA_POLICY_PATH": "opa.policy_path",
    "AGENT_GATE_OPA_PACKAGE": "opa.package",
    "AGENT_GATE_OPA_TOKEN": "opa.token",
    "AGENT_GATE_OPA_FILTER_TOOLS": "opa.filter_tools_list",
}

# Default configuration values
DEFAULTS = {
    "policy": None,  # Required — no sensible default
    "workdir": os.getcwd(),
    "classifier_backend": "python",
    "audit_log": os.path.expanduser("~/.config/agent-gate/audit.jsonl"),
    "vault_path": os.path.expanduser("~/.config/agent-gate/vault/"),
    "log_level": "INFO",
    "opa": {
        "mode": "subprocess",
        "endpoint": None,
        "policy_path": None,
        "package": "agent_gate",
        "token": None,
        "filter_tools_list": False,
    },
}

# Variable pattern for ${VAR} resolution
VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


@dataclass
class OPAConfig:
    """OPA backend configuration."""
    mode: str = "subprocess"          # "subprocess" or "http"
    endpoint: Optional[str] = None    # HTTP endpoint URL
    policy_path: Optional[str] = None  # Local Rego policy path
    package: str = "agent_gate"
    token: Optional[str] = None       # Auth token (from env only)
    filter_tools_list: bool = False    # Filter tools/list by policy

    def to_dict(self) -> dict:
        """Convert to dict for Gate constructor."""
        result = {
            "mode": self.mode,
            "package": self.package,
            "filter_tools_list": self.filter_tools_list,
        }
        if self.endpoint:
            result["endpoint"] = self.endpoint
        if self.policy_path:
            result["policy_path"] = self.policy_path
        if self.token:
            result["token"] = self.token
        return result


@dataclass
class ProxyConfig:
    """
    Complete proxy configuration.

    This is the resolved, validated config that the proxy uses
    at runtime. All variables resolved, all defaults applied.
    """
    policy: Optional[str] = None
    workdir: str = field(default_factory=os.getcwd)
    classifier_backend: str = "python"
    audit_log: str = field(
        default_factory=lambda: os.path.expanduser(
            "~/.config/agent-gate/audit.jsonl"
        )
    )
    vault_path: str = field(
        default_factory=lambda: os.path.expanduser(
            "~/.config/agent-gate/vault/"
        )
    )
    log_level: str = "INFO"
    opa: OPAConfig = field(default_factory=OPAConfig)
    config_source: str = "defaults"  # Track where config came from

    def validate(self) -> List[str]:
        """
        Validate the configuration.

        Returns a list of error messages (empty if valid).
        """
        errors = []

        if not self.policy:
            # Try to find default.yaml in common locations
            search = [
                os.path.join(self.workdir, "policies", "default.yaml"),
                os.path.join(self.workdir, "default.yaml"),
                os.path.expanduser("~/.config/agent-gate/default.yaml"),
            ]
            for path in search:
                if os.path.exists(path):
                    self.policy = path
                    break

            if not self.policy:
                errors.append(
                    "No policy path specified. Set AGENT_GATE_POLICY or "
                    "add 'policy:' to config file."
                )

        if self.policy and not os.path.exists(self.policy):
            errors.append(f"Policy file not found: {self.policy}")

        if self.classifier_backend not in ("python", "opa"):
            errors.append(
                f"Unknown classifier backend: '{self.classifier_backend}'. "
                f"Supported: 'python', 'opa'"
            )

        if self.classifier_backend == "opa":
            if self.opa.mode == "http" and not self.opa.endpoint:
                errors.append(
                    "OPA HTTP mode requires endpoint. Set AGENT_GATE_OPA_ENDPOINT."
                )
            if self.opa.mode == "subprocess" and not self.opa.policy_path:
                errors.append(
                    "OPA subprocess mode requires policy_path. "
                    "Set AGENT_GATE_OPA_POLICY_PATH."
                )

        return errors

    def to_gate_kwargs(self) -> dict:
        """
        Build kwargs for Gate() constructor.

        Returns dict suitable for: Gate(**config.to_gate_kwargs())
        """
        kwargs = {
            "policy_path": self.policy,
            "workdir": self.workdir,
            "classifier_backend": self.classifier_backend,
        }
        if self.classifier_backend == "opa":
            kwargs["opa_config"] = self.opa.to_dict()
        return kwargs


def resolve_variables(value: str) -> str:
    """
    Resolve ${VAR} placeholders from environment.

    Supports:
      - ${HOME} → os.environ["HOME"]
      - ${WORKDIR} → os.environ.get("WORKDIR", "")
      - Nested: ${AGENT_GATE_OPA_URL} for secrets

    Unresolved variables are left as-is (not an error).
    """
    def replacer(match):
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    return VAR_PATTERN.sub(replacer, value)


def resolve_dict_variables(d: dict) -> dict:
    """Recursively resolve ${VAR} placeholders in a dict."""
    result = {}
    for key, value in d.items():
        if isinstance(value, str):
            result[key] = resolve_variables(value)
        elif isinstance(value, dict):
            result[key] = resolve_dict_variables(value)
        else:
            result[key] = value
    return result


def _set_nested(d: dict, dotted_key: str, value: Any) -> None:
    """Set a value in a nested dict using dotted key notation."""
    keys = dotted_key.split(".")
    current = d
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def _get_nested(d: dict, dotted_key: str, default: Any = None) -> Any:
    """Get a value from a nested dict using dotted key notation."""
    keys = dotted_key.split(".")
    current = d
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def load_config_file(path: str) -> dict:
    """
    Load a YAML config file.

    Returns empty dict if file doesn't exist or is empty.
    Raises ValueError on parse errors.
    """
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in config file {path}: {e}")

    if not isinstance(data, dict):
        raise ValueError(f"Config file must be a YAML mapping, got {type(data)}")

    return data


def find_config_file() -> Optional[str]:
    """
    Search for a config file in standard locations.

    Returns the path to the first config file found, or None.
    """
    for path in CONFIG_SEARCH_PATHS:
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            return expanded
    return None


def load_env_overrides() -> dict:
    """
    Load configuration overrides from environment variables.

    Returns a flat dict with dotted keys for nested values.
    """
    overrides = {}
    for env_var, config_key in ENV_MAP.items():
        value = os.environ.get(env_var)
        if value is not None:
            # Type coercion for known boolean fields
            if config_key.endswith("filter_tools_list"):
                value = value.lower() in ("true", "1", "yes")
            overrides[config_key] = value
    return overrides


def merge_configs(defaults: dict, file_config: dict, env_overrides: dict) -> dict:
    """
    Merge configuration from all three sources.

    Priority: env_overrides > file_config > defaults
    """
    import copy
    merged = copy.deepcopy(defaults)

    # Apply file config (shallow merge for top-level, deep for nested)
    for key, value in file_config.items():
        if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
            merged[key].update(value)
        else:
            merged[key] = value

    # Apply env overrides (supports dotted keys for nested values)
    for key, value in env_overrides.items():
        _set_nested(merged, key, value)

    return merged


def build_config(
    config_path: Optional[str] = None,
    env: bool = True,
) -> ProxyConfig:
    """
    Build a complete ProxyConfig from all sources.

    Args:
        config_path: Explicit config file path (skips auto-discovery)
        env: Whether to read environment variables (default True)

    Returns:
        A fully resolved ProxyConfig ready for the proxy to use.
    """
    import copy

    # Step 1: Start with defaults
    defaults = copy.deepcopy(DEFAULTS)
    source = "defaults"

    # Step 2: Load config file
    file_config = {}
    if config_path:
        file_config = load_config_file(config_path)
        if file_config:
            source = f"file:{config_path}"
    else:
        found = find_config_file()
        if found:
            file_config = load_config_file(found)
            if file_config:
                source = f"file:{found}"

    # Step 3: Resolve ${VAR} in file config
    if file_config:
        file_config = resolve_dict_variables(file_config)

    # Step 4: Load env overrides
    env_overrides = load_env_overrides() if env else {}
    if env_overrides and source == "defaults":
        source = "env"
    elif env_overrides:
        source += "+env"

    # Step 5: Merge
    merged = merge_configs(defaults, file_config, env_overrides)

    # Step 6: Build typed config
    opa_raw = merged.get("opa", {})
    opa_config = OPAConfig(
        mode=opa_raw.get("mode", "subprocess"),
        endpoint=opa_raw.get("endpoint"),
        policy_path=opa_raw.get("policy_path"),
        package=opa_raw.get("package", "agent_gate"),
        token=opa_raw.get("token"),
        filter_tools_list=bool(opa_raw.get("filter_tools_list", False)),
    )

    config = ProxyConfig(
        policy=merged.get("policy"),
        workdir=merged.get("workdir", os.getcwd()),
        classifier_backend=merged.get("classifier_backend", "python"),
        audit_log=merged.get("audit_log", DEFAULTS["audit_log"]),
        vault_path=merged.get("vault_path", DEFAULTS["vault_path"]),
        log_level=merged.get("log_level", "INFO"),
        opa=opa_config,
        config_source=source,
    )

    return config
