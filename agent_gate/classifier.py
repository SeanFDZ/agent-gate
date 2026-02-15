"""
Agent Gate — Action Classifier
Classifies tool calls against policy-defined action tiers.

This is a lookup, not an evaluation. All classification rules
are pre-computed at policy load time. Runtime is pattern matching
against structured data.
"""

import shlex
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from fnmatch import fnmatch
from typing import List, Optional

from agent_gate.policy_loader import Policy


class ActionTier(Enum):
    """
    The four possible classifications for any action.
    Ordered by severity — check blocked first, then destructive,
    then read_only, then fall through to unclassified.
    """
    BLOCKED = "blocked"
    DESTRUCTIVE = "destructive"
    READ_ONLY = "read_only"
    UNCLASSIFIED = "unclassified"


@dataclass
class ClassificationResult:
    """
    The output of classifying a tool call.
    Contains everything the gate needs to decide what to do.
    """
    tier: ActionTier
    command: str
    args: List[str]
    target_paths: List[str]
    matched_pattern: Optional[dict] = None
    reason: str = ""
    paths_in_envelope: bool = True
    paths_outside_envelope: List[str] = field(default_factory=list)


class ActionClassifier:
    """
    Classifies a parsed tool call against a loaded policy.

    The classifier does not decide what to do — it only determines
    what tier the action falls into and extracts the relevant
    metadata. The gate core uses this classification to route
    to the correct behavior.
    """

    def __init__(self, policy: Policy):
        self.policy = policy
        # Pre-index command names per tier for fast lookup
        self._blocked_commands = self._index_patterns(policy.actions["blocked"])
        self._destructive_commands = self._index_patterns(policy.actions["destructive"])
        self._read_only_commands = self._index_patterns(policy.actions["read_only"])

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

    def classify(self, tool_call: dict) -> ClassificationResult:
        """
        Classify a structured tool call.

        Args:
            tool_call: A dict representing the tool call, expected format:
                {
                    "tool": "bash" | "write_file" | "read_file" | ...,
                    "input": {
                        "command": "rm -rf ./tmp/old_cache",  # for bash
                        "path": "/some/file.txt",             # for file ops
                        "content": "..."                      # for writes
                    }
                }

        Returns:
            ClassificationResult with tier, extracted paths, and metadata.
        """
        command, args = self._parse_tool_call(tool_call)
        target_paths = self._extract_target_paths(command, args, tool_call)

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

        # Check tiers in severity order: blocked → destructive → read_only
        # Blocked check
        result = self._match_tier(
            command, args, self._blocked_commands, ActionTier.BLOCKED
        )
        if result:
            result.target_paths = target_paths
            return result

        # Destructive check
        result = self._match_tier(
            command, args, self._destructive_commands, ActionTier.DESTRUCTIVE
        )
        if result:
            result.target_paths = target_paths
            return result

        # Read-only check
        result = self._match_tier(
            command, args, self._read_only_commands, ActionTier.READ_ONLY
        )
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

    def _parse_tool_call(self, tool_call: dict) -> tuple:
        """
        Extract the command name and arguments from a tool call.
        Handles both bash commands and structured file operations.
        """
        tool = tool_call.get("tool", "")
        input_data = tool_call.get("input", {})

        if tool == "bash":
            raw_command = input_data.get("command", "")
            try:
                parts = shlex.split(raw_command)
            except ValueError:
                # Malformed command string — treat as unclassified
                parts = raw_command.split()
            command = parts[0] if parts else ""
            args = parts[1:] if len(parts) > 1 else []
            return command, args

        # Structured file operations (write_file, read_file, etc.)
        return tool, []

    def _extract_target_paths(
        self, command: str, args: List[str], tool_call: dict
    ) -> List[str]:
        """
        Extract file/directory paths that the action targets.
        This is the critical data the gate needs for envelope checking
        and vault backup.
        """
        paths = []
        input_data = tool_call.get("input", {})

        # Structured file ops have explicit paths
        if "path" in input_data:
            paths.append(input_data["path"])

        # For bash commands, extract paths from arguments
        # Skip flags (args starting with -)
        for arg in args:
            if not arg.startswith("-"):
                # Resolve relative paths against workdir
                p = Path(arg)
                if not p.is_absolute():
                    # We'll resolve relative to the policy's first allowed path
                    # In practice, this is the workdir
                    base = self.policy.allowed_paths[0].rstrip("/*")
                    p = Path(base) / arg
                paths.append(str(p))

        return paths

    def _check_envelope(self, paths: List[str]) -> List[str]:
        """
        Check if all target paths fall within the allowed envelope.
        Returns list of paths that are outside the envelope.
        """
        outside = []
        for path in paths:
            if self._path_is_denied(path):
                outside.append(path)
            elif not self._path_is_allowed(path):
                outside.append(path)
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
            # If pattern has args_contain, check those
            if "args_contain" in pattern:
                args_str = " ".join(args)
                full_str = f"{command} {args_str}"
                import re
                matched = any(
                    re.search(re.escape(trigger) + r'(\s|$)', full_str)
                    for trigger in pattern["args_contain"]
                )
                if not matched:
                    continue

            # If pattern has a condition, note it for the gate to evaluate
            # (e.g., "target_exists" requires filesystem check at gate level)
            reason = pattern.get("description", f"Matched {tier.value} pattern")

            return ClassificationResult(
                tier=tier,
                command=command,
                args=args,
                target_paths=[],  # filled by caller
                matched_pattern=pattern,
                reason=reason,
            )

        return None
