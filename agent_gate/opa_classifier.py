"""
Agent Gate — OPA Classifier Backend
Delegates policy evaluation to Open Policy Agent (OPA).

OPA evaluates Rego policies against structured input documents.
This backend translates Agent Gate's pre-processed tool call data
into an OPA input document, calls OPA for evaluation, and maps
the response back to a ClassificationResult.

Two evaluation modes:
  - subprocess: Calls `opa eval` directly (development, CI)
  - http: Queries a running OPA server (production, sidecar)

Why OPA?
  - Policy composition: base + team + project + JIT overlays
  - Attribute-based decisions: who, when, where, not just what
  - Formal policy testing: unit tests in Rego
  - Enterprise ecosystem: Kubernetes, API gateways, data filtering

The Python classifier remains the zero-dependency default.
OPA is opt-in for teams that need its capabilities.
"""

import json
import os
import subprocess
import logging
from pathlib import Path
from typing import List, Optional
from fnmatch import fnmatch

from agent_gate.policy_loader import Policy
from agent_gate.classifier_base import (
    ClassifierBase,
    ActionTier,
    ClassificationResult,
)

logger = logging.getLogger("agent_gate.opa")


class OPAError(Exception):
    """Raised when OPA evaluation fails."""
    pass


class OPAClassifier(ClassifierBase):
    """
    OPA-backed classifier.

    Pre-processing (parsing, shell expansion, path extraction) is
    handled by ClassifierBase. This class builds the OPA input
    document from pre-processed data and evaluates it against
    Rego policy.

    Configuration via policy YAML:
        classifier:
          backend: "opa"
          opa:
            mode: "subprocess"          # or "http"
            policy_path: "./rego/"      # directory containing .rego files
            package: "agent_gate"       # Rego package name
            # For HTTP mode:
            url: "http://localhost:8181" # OPA server URL
    """

    # Map OPA tier strings back to ActionTier enum
    TIER_MAP = {
        "blocked": ActionTier.BLOCKED,
        "destructive": ActionTier.DESTRUCTIVE,
        "network": ActionTier.NETWORK,
        "read_only": ActionTier.READ_ONLY,
        "unclassified": ActionTier.UNCLASSIFIED,
    }

    def __init__(self, policy: Policy, opa_config: Optional[dict] = None):
        super().__init__(policy)

        # OPA configuration — from policy or explicit
        self.opa_config = opa_config or self._extract_opa_config(policy)
        self.mode = self.opa_config.get("mode", "subprocess")
        self.rego_path = self.opa_config.get("policy_path", "./rego/")
        self.package = self.opa_config.get("package", "agent_gate")
        self.opa_url = self.opa_config.get("url", "http://localhost:8181")

        # Verify OPA is available
        if self.mode == "subprocess":
            self._verify_opa_binary()

    def _extract_opa_config(self, policy: Policy) -> dict:
        """Extract OPA config from the policy's raw data if present."""
        raw = getattr(policy, '_raw', {})
        classifier_config = raw.get("classifier", {})
        return classifier_config.get("opa", {})

    def _verify_opa_binary(self):
        """Check that the `opa` binary is available on PATH."""
        try:
            result = subprocess.run(
                ["opa", "version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                raise OPAError(
                    f"OPA binary found but returned error: {result.stderr}"
                )
            logger.info(f"OPA available: {result.stdout.strip().splitlines()[0]}")
        except FileNotFoundError:
            raise OPAError(
                "OPA binary not found on PATH. Install from "
                "https://www.openpolicyagent.org/docs/latest/#running-opa "
                "or switch to classifier.backend: 'python' in your policy."
            )
        except subprocess.TimeoutExpired:
            raise OPAError("OPA version check timed out.")

    def _evaluate(
        self,
        command: str,
        args: List[str],
        target_paths: List[str],
        tool_call: dict,
    ) -> ClassificationResult:
        """
        Evaluate via OPA.

        Builds a structured input document from the pre-processed
        tool call data and sends it to OPA for policy evaluation.
        Maps OPA's response back to a ClassificationResult.
        """
        # Build the input document OPA will evaluate
        input_doc = self._build_input(command, args, target_paths, tool_call)

        # Call OPA
        try:
            if self.mode == "subprocess":
                opa_result = self._eval_subprocess(input_doc)
            elif self.mode == "http":
                opa_result = self._eval_http(input_doc)
            else:
                raise OPAError(f"Unknown OPA mode: {self.mode}")
        except OPAError as e:
            # OPA failure — fail closed (deny)
            logger.error(f"OPA evaluation failed: {e}")
            return ClassificationResult(
                tier=ActionTier.BLOCKED,
                command=command,
                args=args,
                target_paths=target_paths,
                reason=f"Policy engine error (OPA): {e}. Failing closed.",
            )

        # Map OPA result to ClassificationResult
        return self._map_result(opa_result, command, args, target_paths)

    def _build_input(
        self,
        command: str,
        args: List[str],
        target_paths: List[str],
        tool_call: dict,
    ) -> dict:
        """
        Build the OPA input document.

        This is the structured data that Rego policies evaluate.
        It contains the pre-processed tool call data plus envelope
        configuration so OPA can do envelope checking in Rego.
        """
        return {
            "command": command,
            "args": args,
            "target_paths": target_paths,
            "tool": tool_call.get("tool", ""),
            "raw_input": tool_call.get("input", {}),
            "envelope": {
                "allowed_paths": self.policy.allowed_paths,
                "denied_paths": self.policy.denied_paths,
            },
        }

    def _eval_subprocess(self, input_doc: dict) -> dict:
        """
        Evaluate via `opa eval` subprocess.

        Good for development and CI — no running server needed.
        Slower than HTTP mode but zero infrastructure.
        """
        input_json = json.dumps({"input": input_doc})
        rego_dir = Path(self.rego_path)

        if not rego_dir.exists():
            raise OPAError(f"Rego policy directory not found: {rego_dir}")

        # Find all .rego files in the policy directory
        rego_files = list(rego_dir.glob("*.rego"))
        if not rego_files:
            raise OPAError(f"No .rego files found in {rego_dir}")

        # Build the opa eval command
        # Query the main decision document
        query = f"data.{self.package}.decision"

        cmd = [
            "opa", "eval",
            "--format", "json",
            "--input", "/dev/stdin",
            "--data", str(rego_dir),
            query,
        ]

        try:
            result = subprocess.run(
                cmd,
                input=input_json,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise OPAError("OPA evaluation timed out (10s limit)")

        if result.returncode != 0:
            raise OPAError(f"OPA eval failed: {result.stderr}")

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise OPAError(f"OPA returned invalid JSON: {result.stdout[:200]}")

        # Extract the result from OPA's response format
        # opa eval returns: {"result": [{"expressions": [{"value": {...}}]}]}
        try:
            expressions = output.get("result", [{}])[0].get("expressions", [])
            if not expressions:
                raise OPAError("OPA returned no expressions")
            return expressions[0].get("value", {})
        except (IndexError, KeyError) as e:
            raise OPAError(f"Unexpected OPA response format: {e}")

    def _eval_http(self, input_doc: dict) -> dict:
        """
        Evaluate via OPA's REST API.

        Production mode — requires a running OPA server (typically
        as a sidecar or centralized service). Faster than subprocess,
        supports bundling, decision logs, and status API.
        """
        import urllib.request
        import urllib.error

        url = f"{self.opa_url}/v1/data/{self.package.replace('.', '/')}/decision"
        payload = json.dumps({"input": input_doc}).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                body = json.loads(response.read().decode("utf-8"))
                return body.get("result", {})
        except urllib.error.URLError as e:
            raise OPAError(f"Failed to reach OPA server at {self.opa_url}: {e}")
        except json.JSONDecodeError:
            raise OPAError("OPA server returned invalid JSON")

    def _map_result(
        self,
        opa_result: dict,
        command: str,
        args: List[str],
        target_paths: List[str],
    ) -> ClassificationResult:
        """
        Map OPA's decision document back to a ClassificationResult.

        Expected OPA result format:
        {
            "tier": "destructive",
            "reason": "File deletion",
            "paths_in_envelope": true,
            "paths_outside_envelope": [],
            "matched_pattern": {"command": "rm", "description": "..."}
        }
        """
        tier_str = opa_result.get("tier", "unclassified")
        tier = self.TIER_MAP.get(tier_str, ActionTier.UNCLASSIFIED)

        paths_in_envelope = opa_result.get("paths_in_envelope", True)
        paths_outside = opa_result.get("paths_outside_envelope", [])
        reason = opa_result.get("reason", f"OPA classified as {tier_str}")
        matched_pattern = opa_result.get("matched_pattern")

        # If OPA reports envelope violation, override tier to BLOCKED
        if not paths_in_envelope:
            tier = ActionTier.BLOCKED
            reason = f"Path(s) outside envelope: {', '.join(paths_outside)}"

        return ClassificationResult(
            tier=tier,
            command=command,
            args=args,
            target_paths=target_paths,
            matched_pattern=matched_pattern,
            reason=reason,
            paths_in_envelope=paths_in_envelope,
            paths_outside_envelope=paths_outside,
        )
