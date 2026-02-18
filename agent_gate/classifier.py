"""
Agent Gate — Action Classifier
Classifies tool calls against policy-defined action tiers.

This is a lookup, not an evaluation. All classification rules
are pre-computed at policy load time. Runtime is pattern matching
against structured data.
"""

import shlex
import os
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from fnmatch import fnmatch
from typing import List, Optional

from agent_gate.policy_loader import Policy


class ActionTier(Enum):
    """
    The five possible classifications for any action.
    Ordered by severity — check blocked first, then destructive,
    then network, then read_only, then fall through to unclassified.
    """
    BLOCKED = "blocked"
    DESTRUCTIVE = "destructive"
    NETWORK = "network"
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
        # Network tier is optional — graceful handling if not in policy
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

        # For bash commands, verify the command is fully literal.
        # If shell expansion syntax is detected, we can't trust extracted
        # paths — deny and tell the agent to rewrite with literal values.
        if tool_call.get("tool") == "bash":
            raw_command = tool_call.get("input", {}).get("command", "")
            expansion = self._detect_shell_expansion(command, raw_command)
            if expansion:
                return ClassificationResult(
                    tier=ActionTier.BLOCKED,
                    command=command,
                    args=args,
                    target_paths=[],
                    reason=(
                        f"Non-literal command: {expansion}. "
                        f"Rewrite using literal paths and values."
                    ),
                )

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

        # Check tiers in severity order: blocked → destructive → network → read_only
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

        # Network check
        result = self._match_tier(
            command, args, self._network_commands, ActionTier.NETWORK
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

    def _detect_shell_expansion(
        self, command: str, raw_command: str
    ) -> Optional[str]:
        """
        Detect shell expansion syntax in a bash command string.

        Agent Gate operates on an allowlist model: known commands with
        literal arguments. If the shell would transform the command
        before execution, the gate can't trust the extracted paths
        or arguments — the literal string doesn't match what runs.

        Instead of trying to enumerate every shell trick, we define
        what "literal" looks like and reject anything else:
        - Paths: /absolute/path, ./relative, ~/home-relative
        - Flags: -f, --force, -rf
        - Simple values: numbers, plain strings
        - Single-quoted strings: 'no expansion inside'

        Anything containing shell expansion syntax gets rejected with
        a message telling the agent to rewrite using literal values.

        Returns None if the command is fully literal.
        Returns a description of what was detected if expansion found.
        """
        import re

        # --- PATTERNS THAT INDICATE NON-LITERAL COMMANDS ---

        # Variable expansion: $VAR, ${VAR}, ${VAR:-default}
        # But NOT inside single quotes (which suppress expansion)
        # We check the raw command after stripping single-quoted segments
        stripped = re.sub(r"'[^']*'", "", raw_command)

        if re.search(r'\$\w', stripped) or re.search(r'\$\{', stripped):
            return "contains variable expansion ($VAR or ${VAR})"

        # Command substitution: $(command) or `command`
        if re.search(r'\$\(', stripped) or '`' in stripped:
            return "contains command substitution ($() or backticks)"

        # Process substitution: <(command) or >(command)
        if re.search(r'[<>]\(', stripped):
            return "contains process substitution (<() or >())"

        # Brace expansion: {a,b} or {1..10}
        # Match braces containing comma or .. (but not ${} which is variable)
        if re.search(r'(?<!\$)\{[^}]*(,|\.\.)[^}]*\}', stripped):
            return "contains brace expansion ({a,b} or {1..10})"

        # Unquoted glob in argument position: *, ?, [abc]
        # We check arguments only (skip the command name itself)
        # Allow * inside quoted strings (already stripped single quotes above)
        parts = stripped.split(None, 1)
        args_portion = parts[1] if len(parts) > 1 else ""
        # Remove double-quoted segments for glob check
        args_no_dquotes = re.sub(r'"[^"]*"', '', args_portion)
        if re.search(r'(?<!\\)[*?]', args_no_dquotes):
            return "contains unquoted glob pattern (* or ?)"
        if re.search(r'(?<!\\)\[[^\]]+\]', args_no_dquotes):
            return "contains glob character class ([...])"

        # eval, exec, source — commands that execute computed strings
        if command in ('eval', 'exec', 'source', '.'):
            return f"'{command}' executes computed commands"

        # Interpreter with inline code: python3 -c, perl -e, ruby -e, node -e
        interpreter_inline = {
            'python3': ['-c'], 'python': ['-c'],
            'perl': ['-e', '-E'], 'ruby': ['-e'],
            'node': ['-e'], 'bash': ['-c'], 'sh': ['-c'], 'zsh': ['-c'],
        }
        if command in interpreter_inline:
            for flag in interpreter_inline[command]:
                if flag in raw_command.split():
                    return (
                        f"'{command} {flag}' executes inline code "
                        f"that the gate cannot inspect"
                    )

        # xargs — takes input and builds commands dynamically
        if command == 'xargs' or ' xargs ' in f' {raw_command} ':
            return "'xargs' builds commands dynamically from input"

        # Here-string / here-doc redirection used with interpreters
        # e.g., python3 <<< "os.remove(...)" or python3 << EOF
        if '<<<' in stripped or '<<' in stripped:
            # Only flag if combined with an interpreter
            for interp in interpreter_inline:
                if interp in raw_command:
                    return (
                        f"here-document/here-string with '{interp}' — "
                        f"gate cannot inspect the piped code"
                    )

        return None  # Command is literal — safe to proceed

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
            raw = os.path.expanduser(input_data["path"])
            resolved = os.path.realpath(raw)
            paths.append(resolved)

        # For bash commands, extract paths from arguments
        # Skip flags (args starting with -)
        for arg in args:
            if not arg.startswith("-"):
                # Expand ~ and resolve to absolute path
                expanded = os.path.expanduser(arg)
                p = Path(expanded)
                if not p.is_absolute():
                    # Resolve relative paths against workdir
                    base = self.policy.allowed_paths[0].rstrip("/*")
                    p = Path(base) / expanded
                paths.append(str(p.resolve()))

        return paths

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
            # Resolve symlinks to get the true filesystem target.
            # This is the core defense against symlink-based envelope bypass.
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
