"""
Agent Gate — Gate Core
The execution authority layer.

This module is the gate itself. It receives a structured tool call,
classifies it, enforces the policy, and returns an allow/deny decision.

The gate does not evaluate reasoning. It does not assess intent.
It inspects the structured action, checks it against pre-computed
policy, ensures backups happen before destruction, and returns
a verdict.

Inspired by Permissive Action Links (PALs) in nuclear C2:
verify that the proposed action falls within the authority envelope.
"""

import json
import logging
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List

from agent_gate.policy_loader import Policy, load_policy
from agent_gate.classifier_base import ActionTier, ClassificationResult
from agent_gate.classifier import PythonClassifier, ActionClassifier
from agent_gate.vault import VaultManager, VaultResult
from agent_gate.rate_tracker import RateTracker
from agent_gate.identity import IdentityContext


class Verdict(Enum):
    """The gate's final decision on a tool call."""
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    MODIFY = "modify"


@dataclass
class GateDecision:
    """
    The complete output of the gate for a single tool call.

    This is what the calling framework receives. It contains:
    - The verdict (allow/deny/escalate)
    - Why (human-readable reason)
    - What was backed up (if anything)
    - What would be needed to proceed (if denied)
    """
    verdict: Verdict
    tool_call: dict
    classification: ClassificationResult
    reason: str
    vault_result: Optional[VaultResult] = None
    timestamp: str = ""
    escalation_hint: str = ""
    denial_feedback: str = ""
    rate_status: Optional[dict] = None
    identity: Optional[dict] = None
    modified_tool_call: Optional[dict] = None
    modification_feedback: Optional[dict] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def to_dict(self) -> dict:
        """Serialize for logging and feedback to the agent."""
        d = {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "command": self.classification.command,
            "args": self.classification.args,
            "target_paths": self.classification.target_paths,
            "tier": self.classification.tier.value,
            "escalation_hint": self.escalation_hint,
            "denial_feedback": self.denial_feedback,
            "vault_snapshots": (
                len(self.vault_result.snapshots)
                if self.vault_result
                else 0
            ),
        }
        if self.rate_status:
            d["rate_status"] = self.rate_status
        if self.identity:
            d["identity"] = self.identity
        if self.modified_tool_call:
            d["modified_tool_call"] = self.modified_tool_call
        if self.modification_feedback:
            d["modification_feedback"] = self.modification_feedback
        return d

    def to_agent_message(self) -> str:
        """
        Format the decision as a message to send back to the agent.
        This is part of the design: denial includes why and what
        would unlock the action.
        """
        if self.verdict == Verdict.ALLOW:
            return ""  # No message needed on allow

        if self.verdict == Verdict.MODIFY:
            lines = ["ACTION MODIFIED:"]
            if self.modification_feedback:
                fb = self.modification_feedback
                lines.append(f"REASON: {fb.get('reason', self.reason)}")
                if "original_call" in fb:
                    lines.append(f"ORIGINAL: {fb['original_call']}")
                if "modified_call" in fb:
                    lines.append(f"MODIFIED: {fb['modified_call']}")
                if "policy_rule" in fb:
                    lines.append(f"POLICY RULE: {fb['policy_rule']}")
            else:
                lines.append(f"REASON: {self.reason}")
            return "\n".join(lines)

        lines = [f"ACTION DENIED: {self.reason}"]

        if self.denial_feedback:
            lines.append(f"DETAILS: {self.denial_feedback}")

        # Rate status or breaker status line for rate-limited denials.
        if self.rate_status:
            rs = self.rate_status
            source = rs.get("source", "unknown")
            if source == "circuit_breaker":
                lines.append(
                    f"BREAKER STATUS: state={rs.get('breaker_state', 'unknown')}, "
                    f"recovery_in={rs.get('reset_seconds', '?')}s"
                )
            else:
                remaining = rs.get("remaining", "?")
                lines.append(
                    f"RATE STATUS: {source}_remaining={remaining}, "
                    f"breaker={rs.get('breaker_state', 'closed')}"
                )

        if self.escalation_hint:
            lines.append(f"TO PROCEED: {self.escalation_hint}")

        return "\n".join(lines)


class Gate:
    """
    The Agent Gate.

    Usage:
        # Default (Python classifier, YAML policies):
        gate = Gate(policy_path="policies/default.yaml", workdir="/path/to/project")

        # OPA backend:
        gate = Gate(
            policy_path="policies/default.yaml",
            workdir="/path/to/project",
            classifier_backend="opa",
            opa_config={"mode": "subprocess", "policy_path": "./rego/"}
        )

        decision = gate.evaluate(tool_call)
        if decision.allowed:
            execute_tool(tool_call)
        else:
            send_to_agent(decision.to_agent_message())
    """

    def __init__(
        self,
        policy_path: str,
        workdir: str,
        classifier_backend: str = "python",
        opa_config: Optional[dict] = None,
        identity: Optional[IdentityContext] = None,
    ):
        self.policy = load_policy(policy_path, workdir)
        self.identity = identity

        # Sub-agent hierarchy context (optional, Phase 8A)
        # Set AGENT_GATE_DEPTH and AGENT_GATE_PARENT_SESSION in subagent frontmatter
        # to capture hierarchy in audit records.  See integrations/claude_code/README.md.
        raw_depth = os.environ.get("AGENT_GATE_DEPTH", "0")
        try:
            self.agent_depth = int(raw_depth)
        except ValueError:
            self.agent_depth = 0
        self.parent_session_id = os.environ.get("AGENT_GATE_PARENT_SESSION", None)
        self.inherited_policy = self.agent_depth > 0 or None

        # Apply role-based overrides to rate limits
        self._effective_rate_limits = self._resolve_rate_limits()

        self.classifier = self._create_classifier(
            classifier_backend, opa_config
        )
        self.vault = VaultManager(self.policy.vault_config)
        self.logger = self._setup_logger()

        # Rate tracker uses effective (role-merged) rate limits.
        self.rate_tracker = RateTracker(self._effective_rate_limits)

        # Apply role-based gate behavior overrides
        self._effective_gate_behavior = self._resolve_gate_behavior()

        self.logger.info(json.dumps({
            "event": "gate_initialized",
            "policy": self.policy.name,
            "workdir": workdir,
            "vault": self.policy.vault_config["path"],
            "classifier_backend": classifier_backend,
            "identity": (
                self.identity.to_dict() if self.identity else None
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

    def _resolve_rate_limits(self) -> dict:
        """
        Merge role-based rate limit overrides with base policy.

        If identity has a role and the policy defines overrides
        for that role, merge them.  Role overrides extend/replace
        base values, they don't remove them.
        """
        base = self.policy.rate_limits.copy()
        if not self.identity or not self.identity.role:
            return base

        overrides = self.policy.get_role_overrides(self.identity.role)
        if not overrides or "rate_limits" not in overrides:
            return base

        return self._deep_merge(base, overrides["rate_limits"])

    def _resolve_gate_behavior(self) -> dict:
        """
        Merge role-based gate behavior overrides with base policy.

        If identity role has action behavior overrides (e.g.,
        admin gets network: allow), apply them.
        """
        base = dict(self.policy.gate_behavior)
        if not self.identity or not self.identity.role:
            return base

        overrides = self.policy.get_role_overrides(self.identity.role)
        if not overrides or "actions" not in overrides:
            return base

        for tier_name, tier_cfg in overrides["actions"].items():
            behavior = tier_cfg.get("behavior")
            if behavior:
                behavior_key = f"on_{tier_name}"
                if behavior_key in base:
                    if isinstance(base[behavior_key], dict):
                        base[behavior_key] = dict(base[behavior_key])
                        base[behavior_key]["default"] = behavior
                    else:
                        base[behavior_key] = {"default": behavior}
        return base

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """
        Deep merge override into base.  Override values win.
        Both dicts are treated as immutable (copies are made).
        """
        result = {}
        for key in set(list(base.keys()) + list(override.keys())):
            if key in override and key in base:
                if isinstance(base[key], dict) and isinstance(override[key], dict):
                    result[key] = Gate._deep_merge(base[key], override[key])
                else:
                    result[key] = override[key]
            elif key in override:
                result[key] = override[key]
            else:
                result[key] = base[key]
        return result

    def _create_classifier(
        self,
        backend: str,
        opa_config: Optional[dict] = None,
    ):
        """
        Instantiate the appropriate classifier backend.

        The classifier is a pluggable component — the gate doesn't
        care how classification happens, only that it receives a
        ClassificationResult with tier and metadata.

        Backends:
          - "python" (default): YAML policies, pure Python evaluation
          - "opa": Open Policy Agent, Rego policies
        """
        # Check if policy itself specifies a backend
        raw = getattr(self.policy, '_raw', {})
        policy_backend = raw.get("classifier", {}).get("backend", None)
        effective_backend = policy_backend or backend

        if effective_backend == "python":
            return PythonClassifier(self.policy)

        elif effective_backend == "opa":
            # Lazy import — don't require OPA unless explicitly requested
            from agent_gate.opa_classifier import OPAClassifier
            # Merge config sources: explicit > policy > defaults
            config = opa_config or raw.get("classifier", {}).get("opa", {})
            return OPAClassifier(
                self.policy, opa_config=config, identity=self.identity,
            )

        else:
            raise ValueError(
                f"Unknown classifier backend: '{effective_backend}'. "
                f"Supported: 'python', 'opa'"
            )

    def evaluate(self, tool_call: dict, reinvocation: bool = False) -> GateDecision:
        """
        Evaluate a single tool call against policy.

        This is the main entry point.  Every tool call passes through
        here before execution.

        Flow:
          0. Extract tool name for rate tracking.
          1. Check circuit breaker state.
          2. Check tool-specific and global rate limits (tier unknown).
          3. Classify the action (existing flow).
          4. Check tier-default rate limits (tier now known).
          5. Record the call for rate tracking.
          6. Route based on classification tier (existing flow).
          7. Record outcome for circuit breaker.
          8. Log the decision.

        Args:
            tool_call: Structured tool call dict, e.g.:
                {
                    "tool": "bash",
                    "input": {"command": "rm important.txt"}
                }

        Returns:
            GateDecision with verdict, reason, and vault info.
        """
        # Step 0: Extract tool name for rate tracking.
        tool_name = self._extract_tool_name(tool_call)

        # Step 1: Check circuit breaker state.
        breaker_result = self._check_circuit_breaker(tool_name, tool_call)
        if breaker_result is not None:
            self._log_decision(breaker_result)
            return breaker_result

        # Step 2: Check tool-specific and global rate limits.
        # Tier is unknown before classification, so we pass None.
        rate_result = self._check_tool_rate_limit(tool_name, tool_call)
        if rate_result is not None:
            self.rate_tracker.record_outcome(tool_name, False, 0)
            self._log_decision(rate_result)
            return rate_result

        # Step 3: Classify the action (existing flow).
        classification = self.classifier.classify(tool_call)

        # Step 4: Check tier-default rate limits (tier now known).
        tier_rate_result = self._check_tier_rate_limit(
            tool_name, classification.tier.value, tool_call
        )
        if tier_rate_result is not None:
            self.rate_tracker.record_outcome(tool_name, False, 0)
            self._log_decision(tier_rate_result)
            return tier_rate_result

        # Step 5: Record the call for rate tracking.
        self.rate_tracker.record_call(
            tool_name, classification.tier.value
        )

        # Step 6: Route based on classification tier (existing flow).
        if classification.tier == ActionTier.BLOCKED:
            decision = self._handle_blocked(tool_call, classification)

        elif classification.tier == ActionTier.DESTRUCTIVE:
            decision = self._handle_destructive(tool_call, classification)

        elif classification.tier == ActionTier.NETWORK:
            decision = self._handle_network(tool_call, classification)

        elif classification.tier == ActionTier.READ_ONLY:
            decision = self._handle_read_only(tool_call, classification)

        elif classification.tier == ActionTier.UNCLASSIFIED:
            decision = self._handle_unclassified(tool_call, classification)

        else:
            decision = self._handle_unclassified(tool_call, classification)

        # Step 7: Attach identity to decision for downstream consumers.
        decision.identity = (
            self.identity.to_dict() if self.identity else None
        )

        # Step 8: Record outcome for circuit breaker.
        success = decision.verdict in (Verdict.ALLOW, Verdict.MODIFY)
        self.rate_tracker.record_outcome(tool_name, success, 0)

        # Step 9: Log the decision (suppressed on reinvocation).
        if not reinvocation:
            self._log_decision(decision)

        return decision

    # ------------------------------------------------------------------
    # Rate limiting helpers
    # ------------------------------------------------------------------

    def _extract_tool_name(self, tool_call: dict) -> str:
        """
        Extract the command/tool name from the tool call dict.

        Uses the same logic as the classifier's _parse_tool_call so
        rate limit keys match classification keys.
        """
        tool = tool_call.get("tool", "")
        input_data = tool_call.get("input", {})

        if tool == "bash":
            raw_command = input_data.get("command", "")
            try:
                parts = shlex.split(raw_command)
            except ValueError:
                parts = raw_command.split()
            return parts[0] if parts else "unknown"

        return tool or "unknown"

    def _check_circuit_breaker(
        self, tool_name: str, tool_call: dict
    ) -> Optional[GateDecision]:
        """Check if the circuit breaker blocks this call."""
        state = self.rate_tracker.breaker_state
        if not state or state.value == "closed":
            return None

        # In HALF_OPEN, allow limited probe calls.
        if state.value == "half_open":
            return None

        # OPEN — deny the action.
        breaker = self.rate_tracker.circuit_breaker
        trip_reason = (
            breaker.trip_reason()
            if breaker
            else "Circuit breaker open."
        )

        classification = ClassificationResult(
            tier=ActionTier.RATE_LIMITED,
            command=tool_name,
            args=[],
            target_paths=[],
            reason=trip_reason,
        )

        secs = breaker.seconds_until_half_open() if breaker else 0

        rate_status = {
            "source": "circuit_breaker",
            "limit": 0,
            "current": 0,
            "remaining": 0,
            "window_seconds": 0,
            "reset_seconds": round(secs, 1),
            "breaker_state": state.value,
            "backoff_seconds": 0,
        }

        return GateDecision(
            verdict=Verdict.DENY,
            tool_call=tool_call,
            classification=classification,
            reason=trip_reason,
            denial_feedback=(
                "Circuit breaker is OPEN due to elevated failure rate."
            ),
            escalation_hint=(
                "Wait for the circuit breaker to transition to HALF_OPEN "
                f"(~{secs:.0f}s), "
                "or request human intervention to reset."
            ),
            rate_status=rate_status,
        )

    def _check_tool_rate_limit(
        self, tool_name: str, tool_call: dict
    ) -> Optional[GateDecision]:
        """
        Check tool-specific and global rate limits.

        Called before classification, so tier is None (tier-default
        limits are checked after classification in _check_tier_rate_limit).
        """
        limit_info = self.rate_tracker.check_rate_limit(tool_name, None)
        if limit_info is None:
            return None
        # Skip circuit breaker results (handled in _check_circuit_breaker).
        if limit_info.get("source") == "circuit_breaker":
            return None
        return self._build_rate_limit_decision(
            tool_name, tool_call, limit_info
        )

    def _check_tier_rate_limit(
        self, tool_name: str, tier: str, tool_call: dict
    ) -> Optional[GateDecision]:
        """
        Check tier-default rate limits after classification.

        Called after classification, so tier is known.  Re-checks
        via check_rate_limit which also re-validates tool and global,
        but those were already verified in _check_tool_rate_limit
        and counters have not been incremented in between.
        """
        limit_info = self.rate_tracker.check_rate_limit(tool_name, tier)
        if limit_info is None:
            return None
        # Skip circuit breaker and tool/global (already checked).
        if limit_info.get("source") in ("circuit_breaker", "tool", "global"):
            return None
        return self._build_rate_limit_decision(
            tool_name, tool_call, limit_info
        )

    def _build_rate_limit_decision(
        self, tool_name: str, tool_call: dict, limit_info: dict
    ) -> GateDecision:
        """Build a GateDecision from a rate limit check result."""
        on_exceed = limit_info.get("on_exceed", "deny")
        message = limit_info.get("message", "Rate limit exceeded.")

        # Map on_exceed to verdict.
        if on_exceed == "escalate":
            verdict = Verdict.ESCALATE
        elif on_exceed == "read_only":
            verdict = Verdict.DENY
            message = (
                "Rate limit exceeded.  "
                "Only read-only operations are currently allowed."
            )
        else:
            verdict = Verdict.DENY

        classification = ClassificationResult(
            tier=ActionTier.RATE_LIMITED,
            command=tool_name,
            args=[],
            target_paths=[],
            reason=message,
        )

        remaining = limit_info.get("rate_remaining", 0)
        reset_seconds = limit_info.get("reset_seconds", 0)

        denial_feedback = (
            f"{message}  "
            f"Remaining: {remaining:.0f}, "
            f"resets in {reset_seconds:.0f}s."
        )

        if on_exceed == "escalate":
            escalation_hint = (
                "Rate limit exceeded.  "
                "Human approval required to continue."
            )
        elif on_exceed == "read_only":
            escalation_hint = (
                "Switch to read-only operations until the "
                "rate limit resets."
            )
        else:
            escalation_hint = (
                f"Wait {reset_seconds:.0f}s for the rate limit to reset, "
                f"or request a policy change."
            )

        # Add retry_after if backoff is configured.
        if "retry_after_seconds" in limit_info:
            escalation_hint += (
                f"  Suggested retry after "
                f"{limit_info['retry_after_seconds']:.0f}s."
            )

        # Build rate_status for agent feedback.
        rate_status = {
            "source": limit_info.get("source", "unknown"),
            "limit": limit_info.get("rate_limit", 0),
            "current": int(round(limit_info.get("current_count", 0))),
            "remaining": int(round(remaining)),
            "window_seconds": limit_info.get("window_seconds", 0),
            "reset_seconds": round(reset_seconds, 1),
            "breaker_state": limit_info.get(
                "breaker_state",
                self.rate_tracker.breaker_state.value,
            ),
            "backoff_seconds": limit_info.get(
                "retry_after_seconds", 0
            ),
        }

        return GateDecision(
            verdict=verdict,
            tool_call=tool_call,
            classification=classification,
            reason=message,
            denial_feedback=denial_feedback,
            escalation_hint=escalation_hint,
            rate_status=rate_status,
        )

    # ------------------------------------------------------------------
    # Classification condition evaluation
    # ------------------------------------------------------------------

    def _evaluate_conditions(
        self, classification: ClassificationResult
    ) -> bool:
        """
        Evaluate conditions declared in a matched policy pattern.

        Conditions are filesystem checks that determine whether a
        classification actually applies. For example, write_file is
        only destructive if the target already exists (overwrite).
        Writing a new file has nothing to destroy.

        Returns True if all conditions are met (or no conditions exist).
        Returns False if any condition is not satisfied.
        """
        pattern = classification.matched_pattern
        if not pattern or "condition" not in pattern:
            return True  # No conditions — classification stands

        condition = pattern["condition"]

        if condition == "target_exists":
            if not classification.target_paths:
                return False
            return all(Path(path).exists() for path in classification.target_paths)

        elif condition == "target_is_dir":
            if not classification.target_paths:
                return False
            return all(Path(path).is_dir() for path in classification.target_paths)

        # Unknown condition — fail open with a warning log
        self.logger.warning(json.dumps({
            "event": "unknown_condition",
            "condition": condition,
            "command": classification.command,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        return True

    def _handle_blocked(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """Hard deny. No vault, no escalation."""
        # Path outside envelope
        if not classification.paths_in_envelope:
            return GateDecision(
                verdict=Verdict.DENY,
                tool_call=tool_call,
                classification=classification,
                reason=f"Target path(s) outside authorized envelope.",
                denial_feedback=(
                    f"Paths outside envelope: "
                    f"{', '.join(classification.paths_outside_envelope)}"
                ),
                escalation_hint=(
                    "Modify the policy envelope to include these paths, "
                    "or operate on files within the allowed directory."
                ),
            )

        # Blocked pattern match
        return GateDecision(
            verdict=Verdict.DENY,
            tool_call=tool_call,
            classification=classification,
            reason=f"Action matches blocked pattern: {classification.reason}",
            denial_feedback=classification.reason,
            escalation_hint=(
                "This action is prohibited by policy. "
                "A policy change is required to allow it."
            ),
        )

    def _handle_modify(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """
        Apply modify operations and return Verdict.MODIFY.

        Called from _handle_destructive() when the matched pattern
        has a modify block.  Uses modifier.apply_modifications() to
        rewrite arguments, then builds the modified tool call dict.

        On ModificationError, returns Verdict.DENY (fail closed).
        """
        from agent_gate.modifier import apply_modifications, ModificationError

        modify_block = classification.modification_rules
        try:
            modified_args, ops_applied = apply_modifications(
                classification.command,
                classification.args,
                modify_block,
            )
        except ModificationError as e:
            return GateDecision(
                verdict=Verdict.DENY,
                tool_call=tool_call,
                classification=classification,
                reason=f"Modification failed: {e}.  Action denied.",
                denial_feedback=str(e),
                escalation_hint=(
                    "Fix the modify rule in the policy, or "
                    "submit a corrected command."
                ),
            )

        # Build modified tool call dict
        modified_tool_call = dict(tool_call)
        modified_input = dict(tool_call.get("input", {}))

        if tool_call.get("tool") == "bash":
            # Reconstruct the command string
            modified_cmd = classification.command
            if modified_args:
                modified_cmd += " " + " ".join(modified_args)
            modified_input["command"] = modified_cmd
        modified_tool_call["input"] = modified_input

        # Build structured feedback
        description = classification.matched_pattern.get("description", "")
        rule_id = f"{classification.command}-modify"
        modification_feedback = {
            "verdict": "MODIFY",
            "original_call": {
                "tool": tool_call.get("tool", ""),
                "args": f"{classification.command} {' '.join(classification.args)}",
            },
            "modified_call": {
                "tool": modified_tool_call.get("tool", ""),
                "args": modified_input.get("command", ""),
            },
            "reason": f"{description}" if description else "Policy modification applied.",
            "policy_rule": rule_id,
            "operations_applied": ops_applied,
        }

        return GateDecision(
            verdict=Verdict.MODIFY,
            tool_call=tool_call,
            classification=classification,
            reason=f"Action modified: {description}",
            modified_tool_call=modified_tool_call,
            modification_feedback=modification_feedback,
        )

    def _handle_destructive(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """
        Destructive action — check for modify rules first, then
        vault skip, then existing vault backup logic.
        """
        # Check conditions before anything else
        if not self._evaluate_conditions(classification):
            condition = classification.matched_pattern.get("condition", "")
            return GateDecision(
                verdict=Verdict.ALLOW,
                tool_call=tool_call,
                classification=classification,
                reason=(
                    f"Condition '{condition}' not met. "
                    f"Action allowed without vault backup."
                ),
            )

        # Check for modify rules -- delegate to _handle_modify()
        if classification.modification_rules:
            return self._handle_modify(tool_call, classification)

        # Check for vault: skip
        pattern = classification.matched_pattern or {}
        vault_override = pattern.get("vault")

        if vault_override == "skip":
            # Audit the action but skip vault backup
            return GateDecision(
                verdict=Verdict.ALLOW,
                tool_call=tool_call,
                classification=classification,
                reason=(
                    f"Destructive action allowed (vault: skip).  "
                    f"Audit record written, no vault backup."
                ),
            )

        action_desc = (
            f"{classification.command} {' '.join(classification.args)}"
        )

        vault_result = self.vault.snapshot(
            classification.target_paths, action_desc
        )

        if vault_result.all_backed_up:
            snapshot_count = len(vault_result.snapshots)
            return GateDecision(
                verdict=Verdict.ALLOW,
                tool_call=tool_call,
                classification=classification,
                reason=(
                    f"Destructive action allowed. "
                    f"{snapshot_count} file(s) backed up to vault."
                ),
                vault_result=vault_result,
            )

        # Backup failed
        if self.vault.on_failure == "deny":
            return GateDecision(
                verdict=Verdict.DENY,
                tool_call=tool_call,
                classification=classification,
                reason="Vault backup failed. Action denied per policy.",
                vault_result=vault_result,
                denial_feedback=(
                    f"Backup errors: {'; '.join(vault_result.errors)}"
                ),
                escalation_hint=(
                    "Resolve the vault backup issue (disk space, permissions) "
                    "and retry, or change vault.on_failure policy."
                ),
            )
        elif self.vault.on_failure == "escalate":
            return GateDecision(
                verdict=Verdict.ESCALATE,
                tool_call=tool_call,
                classification=classification,
                reason="Vault backup failed. Escalating for human review.",
                vault_result=vault_result,
                escalation_hint="Human approval required to proceed without backup.",
            )
        else:
            return GateDecision(
                verdict=Verdict.ALLOW,
                tool_call=tool_call,
                classification=classification,
                reason=(
                    "WARNING: Vault backup failed but policy allows "
                    "proceeding without backup."
                ),
                vault_result=vault_result,
            )

    def _handle_network(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """
        Network-capable action. Default: escalate for human approval.
        """
        network_config = self._effective_gate_behavior.get("on_network", {})
        default_action = network_config.get("default", "escalate")
        message = network_config.get(
            "message",
            "Network access requires approval. "
            "This command can reach external systems.",
        )

        if default_action == "allow":
            return GateDecision(
                verdict=Verdict.ALLOW,
                tool_call=tool_call,
                classification=classification,
                reason=f"Network action allowed by policy: {classification.reason}",
            )
        elif default_action == "deny":
            return GateDecision(
                verdict=Verdict.DENY,
                tool_call=tool_call,
                classification=classification,
                reason=message,
                denial_feedback=classification.reason,
                escalation_hint=(
                    "Change gate_behavior.on_network.default to 'allow' "
                    "or 'escalate' in the policy to permit network access."
                ),
            )
        else:  # escalate
            return GateDecision(
                verdict=Verdict.ESCALATE,
                tool_call=tool_call,
                classification=classification,
                reason=message,
                escalation_hint=(
                    "Human approval required for network access. "
                    "To auto-allow, set gate_behavior.on_network.default "
                    "to 'allow' in the policy."
                ),
            )

    def _handle_read_only(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """Read-only action within envelope. Fast path — allow immediately."""
        return GateDecision(
            verdict=Verdict.ALLOW,
            tool_call=tool_call,
            classification=classification,
            reason="Read-only action within envelope.",
        )

    def _handle_unclassified(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """Unknown action. Default deny with explanation."""
        default = self._effective_gate_behavior.get("on_unclassified", {})
        default_action = default.get("default", "deny")
        message = default.get(
            "message",
            "Unclassified action. Requires policy update or human review.",
        )

        if default_action == "deny":
            return GateDecision(
                verdict=Verdict.DENY,
                tool_call=tool_call,
                classification=classification,
                reason=message,
                denial_feedback=(
                    f"Command '{classification.command}' is not recognized "
                    f"in any policy tier."
                ),
                escalation_hint=(
                    "Add this command to the appropriate tier in the policy "
                    "file, or request human approval for this action."
                ),
            )
        else:
            return GateDecision(
                verdict=Verdict.ESCALATE,
                tool_call=tool_call,
                classification=classification,
                reason=message,
                escalation_hint="Human review required for unclassified actions.",
            )

    def _setup_logger(self) -> logging.Logger:
        """Configure logging for gate decisions."""
        logger = logging.getLogger("agent_gate")
        logger.setLevel(logging.INFO)

        log_config = self.policy.logging_config
        if log_config.get("path"):
            log_dir = Path(log_config["path"])
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / "gate.jsonl"
            handler = logging.FileHandler(str(log_file))
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)

        return logger

    def _log_decision(self, decision: GateDecision):
        """Write decision to the audit log as JSONL."""
        log_config = self.policy.logging_config
        if not log_config:
            return

        if decision.verdict == Verdict.ALLOW and not log_config.get("log_allowed", True):
            return
        if decision.verdict == Verdict.DENY and not log_config.get("log_denied", True):
            return

        log_entry = decision.to_dict()
        log_entry["policy_hash"] = self.policy.policy_hash

        if self.agent_depth > 0:
            log_entry["agent_depth"] = self.agent_depth
            log_entry["parent_agent_id"] = self.parent_session_id
            log_entry["inherited_policy"] = True

        if decision.classification.tier == ActionTier.RATE_LIMITED:
            log_entry["rate_context"] = self.rate_tracker.get_rate_context()

        self.logger.info(json.dumps(log_entry))
