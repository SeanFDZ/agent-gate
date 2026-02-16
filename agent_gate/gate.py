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
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List

from agent_gate.policy_loader import Policy, load_policy
from agent_gate.classifier import ActionClassifier, ActionTier, ClassificationResult
from agent_gate.vault import VaultManager, VaultResult


class Verdict(Enum):
    """The gate's final decision on a tool call."""
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


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

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def to_dict(self) -> dict:
        """Serialize for logging and feedback to the agent."""
        return {
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

    def to_agent_message(self) -> str:
        """
        Format the decision as a message to send back to the agent.
        This is part of the design: denial includes why and what
        would unlock the action.
        """
        if self.verdict == Verdict.ALLOW:
            return ""  # No message needed on allow

        lines = [f"ACTION DENIED: {self.reason}"]

        if self.denial_feedback:
            lines.append(f"DETAILS: {self.denial_feedback}")

        if self.escalation_hint:
            lines.append(f"TO PROCEED: {self.escalation_hint}")

        return "\n".join(lines)


class Gate:
    """
    The Agent Gate.

    Usage:
        gate = Gate(policy_path="policies/default.yaml", workdir="/path/to/project")
        decision = gate.evaluate(tool_call)
        if decision.allowed:
            execute_tool(tool_call)
        else:
            send_to_agent(decision.to_agent_message())
    """

    def __init__(self, policy_path: str, workdir: str):
        self.policy = load_policy(policy_path, workdir)
        self.classifier = ActionClassifier(self.policy)
        self.vault = VaultManager(self.policy.vault_config)
        self.logger = self._setup_logger()

        self.logger.info(json.dumps({
            "event": "gate_initialized",
            "policy": self.policy.name,
            "workdir": workdir,
            "vault": self.policy.vault_config["path"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

    def evaluate(self, tool_call: dict) -> GateDecision:
        """
        Evaluate a single tool call against policy.

        This is the main entry point. Every tool call passes through
        here before execution.

        Args:
            tool_call: Structured tool call dict, e.g.:
                {
                    "tool": "bash",
                    "input": {"command": "rm important.txt"}
                }

        Returns:
            GateDecision with verdict, reason, and vault info.
        """
        # Step 1: Classify the action
        classification = self.classifier.classify(tool_call)

        # Step 2: Route based on classification tier
        if classification.tier == ActionTier.BLOCKED:
            decision = self._handle_blocked(tool_call, classification)

        elif classification.tier == ActionTier.DESTRUCTIVE:
            decision = self._handle_destructive(tool_call, classification)

        elif classification.tier == ActionTier.READ_ONLY:
            decision = self._handle_read_only(tool_call, classification)

        elif classification.tier == ActionTier.UNCLASSIFIED:
            decision = self._handle_unclassified(tool_call, classification)

        else:
            decision = self._handle_unclassified(tool_call, classification)

        # Step 3: Log the decision
        self._log_decision(decision)

        return decision

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
            # All target paths must exist for this to be destructive.
            # For cp src dest, this ensures the destination exists
            # (i.e., this is an overwrite, not a new copy).
            if not classification.target_paths:
                return False
            return all(Path(path).exists() for path in classification.target_paths)

        elif condition == "target_is_dir":
            # All target paths must be directories
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
        return True  # Don't block on unknown conditions

    def _handle_blocked(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """
        Hard deny. No vault, no escalation for most cases.
        Just stop.
        """
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

    def _handle_destructive(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """
        Destructive action — back up targets to vault first,
        then allow if backup succeeds.

        If the matched pattern has a condition (e.g., target_exists)
        and the condition is not met, the action is reclassified as
        non-destructive and allowed without vault backup.
        """
        # Check conditions before committing to vault backup
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

        action_desc = (
            f"{classification.command} {' '.join(classification.args)}"
        )

        # Perform vault backup
        vault_result = self.vault.snapshot(
            classification.target_paths, action_desc
        )

        # Check if backup succeeded
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

        # Backup failed — check policy for what to do
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
            # on_failure: allow (use with extreme caution)
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

    def _handle_read_only(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """
        Read-only action within envelope. Fast path — allow immediately.
        """
        return GateDecision(
            verdict=Verdict.ALLOW,
            tool_call=tool_call,
            classification=classification,
            reason="Read-only action within envelope.",
        )

    def _handle_unclassified(
        self, tool_call: dict, classification: ClassificationResult
    ) -> GateDecision:
        """
        Unknown action. Default deny with explanation.
        """
        default = self.policy.gate_behavior.get("on_unclassified", {})
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

        # Check if we should log this type
        if decision.verdict == Verdict.ALLOW and not log_config.get("log_allowed", True):
            return
        if decision.verdict == Verdict.DENY and not log_config.get("log_denied", True):
            return

        self.logger.info(json.dumps(decision.to_dict()))