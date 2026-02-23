"""
Tests for agent_gate.identity — Identity Resolver Module.

Tests the IdentityContext frozen dataclass and resolve_identity()
function that resolves identity from config, environment variables,
and defaults.
"""

import os
import re
import dataclasses
import pytest

from agent_gate.identity import IdentityContext, resolve_identity


class TestResolveIdentityDefaults:
    """Test resolve_identity with no config and no env vars."""

    def test_empty_identity_all_none(self, monkeypatch):
        """resolve_identity() with no config, no env vars → all None except session_id."""
        for var in [
            "AGENT_GATE_OPERATOR",
            "AGENT_GATE_AGENT_ID",
            "AGENT_GATE_SERVICE",
            "AGENT_GATE_SESSION",
            "AGENT_GATE_ROLE",
        ]:
            monkeypatch.delenv(var, raising=False)

        ctx = resolve_identity()
        assert ctx.operator is None
        assert ctx.agent_id is None
        assert ctx.service_account is None
        assert ctx.role is None
        # session_id auto-generated
        assert ctx.session_id is not None
        assert len(ctx.session_id) > 0


class TestEnvVarResolution:
    """Test that environment variables are picked up."""

    def test_env_var_resolution(self, monkeypatch):
        """Set AGENT_GATE_OPERATOR and AGENT_GATE_ROLE → resolved."""
        monkeypatch.setenv("AGENT_GATE_OPERATOR", "sean")
        monkeypatch.setenv("AGENT_GATE_ROLE", "admin")
        monkeypatch.delenv("AGENT_GATE_AGENT_ID", raising=False)
        monkeypatch.delenv("AGENT_GATE_SERVICE", raising=False)
        monkeypatch.delenv("AGENT_GATE_SESSION", raising=False)

        ctx = resolve_identity()
        assert ctx.operator == "sean"
        assert ctx.role == "admin"


class TestConfigLiteralValues:
    """Test identity_config with literal string values."""

    def test_config_literal_values(self, monkeypatch):
        """resolve_identity({"operator": "sean", "role": "admin"}) → literal values."""
        # Clear env vars to ensure config is source
        for var in [
            "AGENT_GATE_OPERATOR",
            "AGENT_GATE_AGENT_ID",
            "AGENT_GATE_SERVICE",
            "AGENT_GATE_SESSION",
            "AGENT_GATE_ROLE",
        ]:
            monkeypatch.delenv(var, raising=False)

        ctx = resolve_identity({"operator": "sean", "role": "admin"})
        assert ctx.operator == "sean"
        assert ctx.role == "admin"


class TestConfigEnvVarReferences:
    """Test ${VAR} references in config values."""

    def test_config_env_var_references(self, monkeypatch):
        """Config value ${AGENT_GATE_OPERATOR} resolves against env."""
        monkeypatch.setenv("AGENT_GATE_OPERATOR", "sean")
        ctx = resolve_identity({"operator": "${AGENT_GATE_OPERATOR}"})
        assert ctx.operator == "sean"


class TestConfigOverridesEnv:
    """Test that config takes precedence over env vars."""

    def test_config_overrides_env(self, monkeypatch):
        """Config literal value beats env var."""
        monkeypatch.setenv("AGENT_GATE_OPERATOR", "env_user")
        ctx = resolve_identity({"operator": "config_user"})
        assert ctx.operator == "config_user"


class TestUnresolvedEnvVar:
    """Test that unresolvable ${VAR} references become None."""

    def test_unresolved_env_var_becomes_none(self, monkeypatch):
        """${NONEXISTENT_VAR} → None (not the literal string)."""
        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        ctx = resolve_identity({"operator": "${NONEXISTENT_VAR}"})
        assert ctx.operator is None


class TestSessionId:
    """Test session_id resolution and auto-generation."""

    def test_session_id_preserved(self, monkeypatch):
        """Explicit session_id param is preserved."""
        for var in [
            "AGENT_GATE_OPERATOR",
            "AGENT_GATE_AGENT_ID",
            "AGENT_GATE_SERVICE",
            "AGENT_GATE_SESSION",
            "AGENT_GATE_ROLE",
        ]:
            monkeypatch.delenv(var, raising=False)

        ctx = resolve_identity(session_id="abc123")
        assert ctx.session_id == "abc123"

    def test_session_id_auto_generated(self, monkeypatch):
        """No session_id provided → auto-generated UUID format."""
        for var in [
            "AGENT_GATE_OPERATOR",
            "AGENT_GATE_AGENT_ID",
            "AGENT_GATE_SERVICE",
            "AGENT_GATE_SESSION",
            "AGENT_GATE_ROLE",
        ]:
            monkeypatch.delenv(var, raising=False)

        ctx = resolve_identity()
        assert ctx.session_id is not None
        assert len(ctx.session_id) > 0
        # Should look like a UUID (8-4-4-4-12 or truncated UUID)
        assert re.match(r'^[0-9a-f-]+$', ctx.session_id)

    def test_session_id_param_overrides_config(self, monkeypatch):
        """session_id param takes precedence over config."""
        for var in [
            "AGENT_GATE_OPERATOR",
            "AGENT_GATE_AGENT_ID",
            "AGENT_GATE_SERVICE",
            "AGENT_GATE_SESSION",
            "AGENT_GATE_ROLE",
        ]:
            monkeypatch.delenv(var, raising=False)

        ctx = resolve_identity({"session_id": "from_config"}, session_id="from_param")
        assert ctx.session_id == "from_param"


class TestFrozenDataclass:
    """Test that IdentityContext is immutable."""

    def test_frozen_dataclass(self):
        """Attempt to mutate a field → raises FrozenInstanceError."""
        ctx = resolve_identity({"operator": "sean"})
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.operator = "other"


class TestToDict:
    """Test IdentityContext.to_dict() serialization."""

    def test_to_dict_omits_none(self):
        """to_dict() omits None fields."""
        ctx = IdentityContext(operator="sean", role="admin")
        d = ctx.to_dict()
        assert d == {"operator": "sean", "role": "admin"}
        assert "agent_id" not in d
        assert "service_account" not in d
        assert "session_id" not in d

    def test_to_dict_includes_session(self):
        """to_dict() includes session_id when set."""
        ctx = IdentityContext(session_id="abc")
        d = ctx.to_dict()
        assert d == {"session_id": "abc"}


class TestHasIdentity:
    """Test IdentityContext.has_identity() method."""

    def test_has_identity_true(self):
        """Any identity field set (besides session_id) → True."""
        ctx = IdentityContext(operator="sean")
        assert ctx.has_identity() is True

    def test_has_identity_false_session_only(self):
        """session_id alone doesn't count as identity."""
        ctx = IdentityContext(session_id="abc")
        assert ctx.has_identity() is False


class TestDisplayName:
    """Test IdentityContext.display_name property."""

    def test_display_name_with_operator(self):
        """Operator + role → 'sean (role=admin)'."""
        ctx = IdentityContext(operator="sean", role="admin")
        assert ctx.display_name == "sean (role=admin)"

    def test_display_name_anonymous(self):
        """No identity fields → 'anonymous'."""
        ctx = IdentityContext()
        assert ctx.display_name == "anonymous"
