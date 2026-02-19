"""
Tests for Agent Gate proxy configuration loader.

Tests cover:
  - Default configuration
  - Environment variable overrides
  - Config file loading
  - Variable resolution (${VAR})
  - Merge priority (env > file > defaults)
  - Validation (missing policy, bad backend, OPA requirements)
  - to_gate_kwargs() output
  - Nested key handling (dotted notation)
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.proxy_config import (
    OPAConfig,
    ProxyConfig,
    build_config,
    find_config_file,
    load_config_file,
    load_env_overrides,
    merge_configs,
    resolve_variables,
    resolve_dict_variables,
    DEFAULTS,
    ENV_MAP,
)


class TestDefaults(unittest.TestCase):
    """Test default configuration values."""

    def test_build_config_returns_defaults(self):
        """With no file or env, returns defaults."""
        # Clear all AGENT_GATE_ env vars
        saved = {}
        for key in ENV_MAP:
            if key in os.environ:
                saved[key] = os.environ.pop(key)
        try:
            config = build_config(config_path="/nonexistent/path.yaml", env=False)
            self.assertEqual(config.classifier_backend, "python")
            self.assertEqual(config.log_level, "INFO")
            self.assertEqual(config.config_source, "defaults")
        finally:
            os.environ.update(saved)

    def test_default_opa_config(self):
        config = build_config(config_path="/nonexistent/path.yaml", env=False)
        self.assertEqual(config.opa.mode, "subprocess")
        self.assertEqual(config.opa.package, "agent_gate")
        self.assertFalse(config.opa.filter_tools_list)


class TestEnvOverrides(unittest.TestCase):
    """Test environment variable configuration."""

    def setUp(self):
        """Save and clear AGENT_GATE_ env vars."""
        self.saved = {}
        for key in ENV_MAP:
            if key in os.environ:
                self.saved[key] = os.environ.pop(key)

    def tearDown(self):
        """Restore env vars."""
        for key in ENV_MAP:
            os.environ.pop(key, None)
        os.environ.update(self.saved)

    def test_policy_from_env(self):
        os.environ["AGENT_GATE_POLICY"] = "/tmp/test-policy.yaml"
        config = build_config(config_path="/nonexistent", env=True)
        self.assertEqual(config.policy, "/tmp/test-policy.yaml")

    def test_backend_from_env(self):
        os.environ["AGENT_GATE_BACKEND"] = "opa"
        config = build_config(config_path="/nonexistent", env=True)
        self.assertEqual(config.classifier_backend, "opa")

    def test_opa_filter_tools_from_env(self):
        os.environ["AGENT_GATE_OPA_FILTER_TOOLS"] = "true"
        config = build_config(config_path="/nonexistent", env=True)
        self.assertTrue(config.opa.filter_tools_list)

    def test_opa_filter_tools_false_from_env(self):
        os.environ["AGENT_GATE_OPA_FILTER_TOOLS"] = "false"
        config = build_config(config_path="/nonexistent", env=True)
        self.assertFalse(config.opa.filter_tools_list)

    def test_env_overrides_source_tracking(self):
        os.environ["AGENT_GATE_POLICY"] = "/tmp/test.yaml"
        config = build_config(config_path="/nonexistent", env=True)
        self.assertIn("env", config.config_source)

    def test_workdir_from_env(self):
        os.environ["AGENT_GATE_WORKDIR"] = "/custom/workdir"
        config = build_config(config_path="/nonexistent", env=True)
        self.assertEqual(config.workdir, "/custom/workdir")


class TestConfigFile(unittest.TestCase):
    """Test YAML config file loading."""

    def setUp(self):
        self.saved = {}
        for key in ENV_MAP:
            if key in os.environ:
                self.saved[key] = os.environ.pop(key)

    def tearDown(self):
        for key in ENV_MAP:
            os.environ.pop(key, None)
        os.environ.update(self.saved)

    def test_load_yaml_config(self):
        """Load a valid YAML config file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("policy: /tmp/my-policy.yaml\n")
            f.write("classifier_backend: python\n")
            f.write("log_level: DEBUG\n")
            f.name
        try:
            config = build_config(config_path=f.name, env=False)
            self.assertEqual(config.policy, "/tmp/my-policy.yaml")
            self.assertEqual(config.log_level, "DEBUG")
            self.assertIn("file:", config.config_source)
        finally:
            os.unlink(f.name)

    def test_load_opa_config_from_file(self):
        """Load OPA settings from config file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("classifier_backend: opa\n")
            f.write("opa:\n")
            f.write("  mode: http\n")
            f.write("  endpoint: http://localhost:8181\n")
            f.write("  package: my_policy\n")
            f.write("  filter_tools_list: true\n")
        try:
            config = build_config(config_path=f.name, env=False)
            self.assertEqual(config.classifier_backend, "opa")
            self.assertEqual(config.opa.mode, "http")
            self.assertEqual(config.opa.endpoint, "http://localhost:8181")
            self.assertEqual(config.opa.package, "my_policy")
            self.assertTrue(config.opa.filter_tools_list)
        finally:
            os.unlink(f.name)

    def test_empty_config_file(self):
        """Empty config file returns defaults."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("")
        try:
            config = build_config(config_path=f.name, env=False)
            self.assertEqual(config.classifier_backend, "python")
        finally:
            os.unlink(f.name)

    def test_invalid_yaml_raises(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(":::invalid yaml{{{\n")
        try:
            with self.assertRaises(ValueError):
                load_config_file(f.name)
        finally:
            os.unlink(f.name)

    def test_nonexistent_file_returns_empty(self):
        result = load_config_file("/nonexistent/config.yaml")
        self.assertEqual(result, {})


class TestVariableResolution(unittest.TestCase):
    """Test ${VAR} placeholder resolution."""

    def test_resolve_home(self):
        result = resolve_variables("${HOME}/.config")
        self.assertEqual(result, os.environ["HOME"] + "/.config")

    def test_resolve_unknown_var_unchanged(self):
        """Unknown variables are left as-is."""
        result = resolve_variables("${NONEXISTENT_VAR_12345}")
        self.assertEqual(result, "${NONEXISTENT_VAR_12345}")

    def test_resolve_multiple_vars(self):
        os.environ["TEST_AG_A"] = "alpha"
        os.environ["TEST_AG_B"] = "beta"
        try:
            result = resolve_variables("${TEST_AG_A}/${TEST_AG_B}")
            self.assertEqual(result, "alpha/beta")
        finally:
            del os.environ["TEST_AG_A"]
            del os.environ["TEST_AG_B"]

    def test_resolve_dict_variables(self):
        os.environ["TEST_AG_URL"] = "http://opa:8181"
        try:
            d = {
                "endpoint": "${TEST_AG_URL}",
                "nested": {"token": "${TEST_AG_URL}/v1"},
                "number": 42,
            }
            result = resolve_dict_variables(d)
            self.assertEqual(result["endpoint"], "http://opa:8181")
            self.assertEqual(result["nested"]["token"], "http://opa:8181/v1")
            self.assertEqual(result["number"], 42)
        finally:
            del os.environ["TEST_AG_URL"]


class TestMergePriority(unittest.TestCase):
    """Test that merge order is env > file > defaults."""

    def test_env_overrides_file(self):
        defaults = {"policy": None, "log_level": "INFO"}
        file_config = {"policy": "/from/file.yaml", "log_level": "DEBUG"}
        env_overrides = {"policy": "/from/env.yaml"}

        merged = merge_configs(defaults, file_config, env_overrides)
        # env wins for policy
        self.assertEqual(merged["policy"], "/from/env.yaml")
        # file wins for log_level (no env override)
        self.assertEqual(merged["log_level"], "DEBUG")

    def test_file_overrides_defaults(self):
        defaults = {"policy": None, "log_level": "INFO"}
        file_config = {"log_level": "WARNING"}
        env_overrides = {}

        merged = merge_configs(defaults, file_config, env_overrides)
        self.assertEqual(merged["log_level"], "WARNING")
        self.assertIsNone(merged["policy"])

    def test_nested_env_overrides(self):
        """Dotted env keys override nested file values."""
        defaults = {"opa": {"mode": "subprocess", "package": "agent_gate"}}
        file_config = {"opa": {"mode": "http", "endpoint": "http://file:8181"}}
        env_overrides = {"opa.endpoint": "http://env:9999"}

        merged = merge_configs(defaults, file_config, env_overrides)
        self.assertEqual(merged["opa"]["mode"], "http")  # from file
        self.assertEqual(merged["opa"]["endpoint"], "http://env:9999")  # from env


class TestValidation(unittest.TestCase):
    """Test configuration validation."""

    def test_missing_policy_error(self):
        config = ProxyConfig(policy=None, workdir="/nonexistent/workdir")
        errors = config.validate()
        self.assertTrue(any("policy" in e.lower() for e in errors))

    def test_nonexistent_policy_file_error(self):
        config = ProxyConfig(policy="/nonexistent/policy.yaml")
        errors = config.validate()
        self.assertTrue(any("not found" in e.lower() for e in errors))

    def test_invalid_backend_error(self):
        config = ProxyConfig(
            policy="/tmp/test.yaml",
            classifier_backend="invalid",
        )
        errors = config.validate()
        self.assertTrue(any("backend" in e.lower() for e in errors))

    def test_opa_http_missing_endpoint_error(self):
        config = ProxyConfig(
            policy="/tmp/test.yaml",
            classifier_backend="opa",
            opa=OPAConfig(mode="http", endpoint=None),
        )
        errors = config.validate()
        self.assertTrue(any("endpoint" in e.lower() for e in errors))

    def test_opa_subprocess_missing_policy_path_error(self):
        config = ProxyConfig(
            policy="/tmp/test.yaml",
            classifier_backend="opa",
            opa=OPAConfig(mode="subprocess", policy_path=None),
        )
        errors = config.validate()
        self.assertTrue(any("policy_path" in e.lower() for e in errors))

    def test_valid_python_config(self):
        """Valid Python backend config has no errors (except maybe policy file)."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write("gate:\n  name: test\n")
        try:
            config = ProxyConfig(
                policy=f.name,
                classifier_backend="python",
            )
            errors = config.validate()
            self.assertEqual(errors, [])
        finally:
            os.unlink(f.name)

    def test_auto_discover_policy(self):
        """Validation auto-discovers default.yaml in workdir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policies_dir = os.path.join(tmpdir, "policies")
            os.makedirs(policies_dir)
            policy_file = os.path.join(policies_dir, "default.yaml")
            with open(policy_file, "w") as f:
                f.write("gate:\n  name: test\n")

            config = ProxyConfig(policy=None, workdir=tmpdir)
            errors = config.validate()
            self.assertEqual(errors, [])
            self.assertEqual(config.policy, policy_file)


class TestGateKwargs(unittest.TestCase):
    """Test to_gate_kwargs() output."""

    def test_python_backend_kwargs(self):
        config = ProxyConfig(
            policy="/tmp/policy.yaml",
            workdir="/home/user/project",
            classifier_backend="python",
        )
        kwargs = config.to_gate_kwargs()
        self.assertEqual(kwargs["policy_path"], "/tmp/policy.yaml")
        self.assertEqual(kwargs["workdir"], "/home/user/project")
        self.assertEqual(kwargs["classifier_backend"], "python")
        self.assertNotIn("opa_config", kwargs)

    def test_opa_backend_kwargs(self):
        config = ProxyConfig(
            policy="/tmp/policy.yaml",
            workdir="/home/user/project",
            classifier_backend="opa",
            opa=OPAConfig(
                mode="http",
                endpoint="http://opa:8181",
                package="custom_policy",
                filter_tools_list=True,
            ),
        )
        kwargs = config.to_gate_kwargs()
        self.assertEqual(kwargs["classifier_backend"], "opa")
        self.assertIn("opa_config", kwargs)
        self.assertEqual(kwargs["opa_config"]["mode"], "http")
        self.assertEqual(kwargs["opa_config"]["endpoint"], "http://opa:8181")
        self.assertTrue(kwargs["opa_config"]["filter_tools_list"])


class TestOPAConfig(unittest.TestCase):
    """Test OPA configuration dataclass."""

    def test_to_dict_minimal(self):
        opa = OPAConfig()
        d = opa.to_dict()
        self.assertEqual(d["mode"], "subprocess")
        self.assertEqual(d["package"], "agent_gate")
        self.assertNotIn("endpoint", d)
        self.assertNotIn("token", d)

    def test_to_dict_full(self):
        opa = OPAConfig(
            mode="http",
            endpoint="http://opa:8181",
            token="secret",
            filter_tools_list=True,
        )
        d = opa.to_dict()
        self.assertEqual(d["endpoint"], "http://opa:8181")
        self.assertEqual(d["token"], "secret")
        self.assertTrue(d["filter_tools_list"])


if __name__ == "__main__":
    unittest.main()
