"""
Agent Gate — Python Classifier (default backend)
Classifies tool calls against YAML policy-defined action tiers.

This is the zero-dependency backend. Policies are defined in YAML,
loaded at startup, and evaluated as pure Python pattern matching.
No external services required.

For enterprise deployments that need policy composition, RBAC,
or integration with existing governance toolchains, see
OPAClassifier (opa_classifier.py).
"""

import re
from fnmatch import fnmatch
from typing import List, Optional
import os

from agent_gate.policy_loader import Policy
from agent_gate.classifier_base import (
    ClassifierBase,
    ActionTier,
    ClassificationResult,
)

# Re-export so existing code can import from agent_gate.classifier
__all__ = [
    "ActionTier",
    "ClassificationResult",
    "PythonClassifier",
    "ActionClassifier",
    "ClassifierBase",
]


class PythonClassifier(ClassifierBase):
    """
    Pure Python classifier backend.

    Evaluates envelope boundaries and tier matching against YAML
    policy definitions loaded at startup. All rules are pre-indexed
    by command name for O(1) lookup at classification time.

    This is the default backend — works everywhere Python runs,
    no external dependencies beyond PyYAML for policy loading.
    """

    def __init__(self, policy: Policy):
        super().__init__(policy)
        # Pre-index command names per tier for fast lookup
        self._blocked_commands = self._index_patterns(
            policy.actions["blocked"]
        )
        self._destructive_commands = self._index_patterns(
            policy.actions["destructive"]
        )
        self._read_only_commands = self._index_patterns(
            policy.actions["read_only"]
        )
        # Network tier is optional
        self._network_commands = self._index_patterns(
            policy.actions.get("network", {})
        )

    def _index_patterns(self, tier_config: dict) -> dict:
        """
        Build a lookup dict of command_name -> [pattern_definitions]
        for fast matching at classification time.
        """
        index = {}
        for pattern in tier_config.get("patterns", []):
            cmd = pattern["command"]
            if cmd not in index:
                index[cmd] = []
            index[cmd].append(pattern)
        return index

    def _evaluate(
        self,
        command: str,
        args: List[str],
        target_paths: List[str],
        tool_call: dict,
    ) -> ClassificationResult:
        """
        Python-native policy evaluation.

        1. Check envelope — are all paths within allowed bounds?
        2. Match tiers in severity order: blocked → destructive → network → read_only
        3. Fall through to unclassified if nothing matched.
        """
        # Check envelope first — any path outside envelope is auto-denied
        outside = self._check_envelope(target_paths)
        if outside:
            return ClassificationResult(
                tier=ActionTier.BLOCKED,
                command=command,
                args=args,
                target_paths=target_paths,
                reason=f"Path(s) outside envelope: {', '.join(outside)}",
                paths_in_envelope=False,
                paths_outside_envelope=outside,
            )

        # Check tiers in severity order
        for tier_index, tier in [
            (self._blocked_commands, ActionTier.BLOCKED),
            (self._destructive_commands, ActionTier.DESTRUCTIVE),
            (self._network_commands, ActionTier.NETWORK),
            (self._read_only_commands, ActionTier.READ_ONLY),
        ]:
            result = self._match_tier(command, args, tier_index, tier)
            if result:
                result.target_paths = target_paths
                return result

        # Nothing matched — unclassified
        return ClassificationResult(
            tier=ActionTier.UNCLASSIFIED,
            command=command,
            args=args,
            target_paths=target_paths,
            reason="No matching pattern in policy. Requires human review.",
        )

    def _check_envelope(self, paths: List[str]) -> List[str]:
        """
        Check if all target paths fall within the allowed envelope.
        Returns list of paths that are outside the envelope.

        Resolves symlinks via realpath() before checking — a symlink
        inside the workspace pointing to /etc/ is caught here even
        if the string path looks safe.
        """
        outside = []
        for path in paths:
            resolved = os.path.realpath(path)
            if self._path_is_denied(resolved):
                outside.append(resolved)
            elif not self._path_is_allowed(resolved):
                outside.append(resolved)
        return outside

    def _path_is_allowed(self, path: str) -> bool:
        """Check if a path matches any allowed_paths pattern."""
        for pattern in self.policy.allowed_paths:
            if fnmatch(path, pattern) or path.startswith(
                pattern.rstrip("/*").rstrip("*")
            ):
                return True
        return False

    def _path_is_denied(self, path: str) -> bool:
        """
        Check if a path matches any denied_paths pattern.
        Denied takes precedence over allowed.
        """
        for pattern in self.policy.denied_paths:
            if fnmatch(path, pattern) or path.startswith(
                pattern.rstrip("/*").rstrip("*")
            ):
                return True
        return False

    def _match_tier(
        self,
        command: str,
        args: List[str],
        tier_index: dict,
        tier: ActionTier,
    ) -> Optional[ClassificationResult]:
        """
        Check if a command matches any pattern in a given tier.
        Returns ClassificationResult if matched, None if not.
        """
        if command not in tier_index:
            return None

        for pattern in tier_index[command]:
            if "args_contain" in pattern:
                args_str = " ".join(args)
                full_str = f"{command} {args_str}"
                matched = any(
                    re.search(re.escape(trigger) + r'(\s|$)', full_str)
                    for trigger in pattern["args_contain"]
                )
                if not matched:
                    continue

            reason = pattern.get(
                "description", f"Matched {tier.value} pattern"
            )

            return ClassificationResult(
                tier=tier,
                command=command,
                args=args,
                target_paths=[],  # filled by caller
                matched_pattern=pattern,
                reason=reason,
            )

        return None


# Backward compatibility alias.
# All existing code imports ActionClassifier — this keeps it working.
ActionClassifier = PythonClassifier
