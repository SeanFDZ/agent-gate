"""
Agent Gate — Identity Resolver

Resolves identity context from configuration, environment variables,
and defaults.  Produces an immutable IdentityContext that flows
through the gate pipeline.

The identity resolver does NOT authenticate.  It collects identity
claims from trusted sources (environment, config).  Authentication
is the operator's responsibility.
"""

import os
import re
import uuid
from dataclasses import dataclass
from typing import Optional


# Environment variable names for each identity field.
_ENV_MAP = {
    "operator": "AGENT_GATE_OPERATOR",
    "agent_id": "AGENT_GATE_AGENT_ID",
    "service_account": "AGENT_GATE_SERVICE",
    "session_id": "AGENT_GATE_SESSION",
    "role": "AGENT_GATE_ROLE",
}


@dataclass(frozen=True)
class IdentityContext:
    """
    Immutable identity context for a gate session.

    Maps to the five AARM R6 identity levels:
      - operator:        Human who launched/authorized the agent
      - agent_id:        Unique identifier for this agent instance
      - service_account: Service-level identity (CI pipeline, deployment system)
      - session_id:      Unique session identifier (auto-generated if not provided)
      - role:            Role for RBAC policy differentiation

    All fields are Optional[str].  An absent field means that
    identity level is not bound for this session.
    """
    operator: Optional[str] = None
    agent_id: Optional[str] = None
    service_account: Optional[str] = None
    session_id: Optional[str] = None
    role: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dict, omitting None values."""
        return {k: v for k, v in {
            "operator": self.operator,
            "agent_id": self.agent_id,
            "service_account": self.service_account,
            "session_id": self.session_id,
            "role": self.role,
        }.items() if v is not None}

    def has_identity(self) -> bool:
        """Return True if any identity field is set (besides session_id)."""
        return any([
            self.operator,
            self.agent_id,
            self.service_account,
            self.role,
        ])

    @property
    def display_name(self) -> str:
        """Human-readable identity summary for logging."""
        parts = []
        if self.operator:
            parts.append(self.operator)
        elif self.agent_id:
            parts.append(f"agent:{self.agent_id}")
        elif self.service_account:
            parts.append(f"service:{self.service_account}")

        if not parts:
            return "anonymous"

        name = parts[0]
        extras = []
        if self.role:
            extras.append(f"role={self.role}")
        if extras:
            name += f" ({', '.join(extras)})"
        return name


def _resolve_env_ref(value: str) -> Optional[str]:
    """
    If value is a ${VAR} reference, resolve it against os.environ.
    Returns None if the variable is not set.
    Returns the literal value if it's not a ${VAR} reference.
    """
    match = re.fullmatch(r'\$\{(\w+)\}', value)
    if match:
        return os.environ.get(match.group(1))
    return value


def _resolve_field(
    field_name: str,
    config_value: Optional[str],
    env_var: str,
) -> Optional[str]:
    """
    Resolve a single identity field.

    Priority:
      1. config_value (if not None and not empty after env resolution)
      2. os.environ.get(env_var)
      3. None
    """
    if config_value is not None:
        resolved = _resolve_env_ref(config_value)
        if resolved is not None and resolved != "":
            return resolved

    env_val = os.environ.get(env_var)
    if env_val is not None and env_val != "":
        return env_val

    return None


def resolve_identity(
    identity_config: Optional[dict] = None,
    session_id: Optional[str] = None,
) -> IdentityContext:
    """
    Resolve identity from configuration and environment.

    Resolution order per field:
      1. Explicit identity_config dict (from parsed YAML identity.fields)
      2. Environment variables (AGENT_GATE_OPERATOR, etc.)
      3. Defaults (session_id auto-generated if not provided)

    The identity_config values may contain ${ENV_VAR} references
    which are resolved against the environment.
    """
    config = identity_config or {}

    fields = {}
    for field_name, env_var in _ENV_MAP.items():
        if field_name == "session_id":
            continue  # Handle session_id separately
        fields[field_name] = _resolve_field(
            field_name,
            config.get(field_name),
            env_var,
        )

    # Session ID resolution: param > config > env > auto-generate
    if session_id is not None:
        fields["session_id"] = session_id
    else:
        resolved_session = _resolve_field(
            "session_id",
            config.get("session_id"),
            _ENV_MAP["session_id"],
        )
        fields["session_id"] = resolved_session or str(uuid.uuid4())

    return IdentityContext(**fields)
