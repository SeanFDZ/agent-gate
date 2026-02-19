"""
Agent Gate — Classifier Base
Abstract base class for all classifier backends.

The classifier's job is to take a structured tool call and return
a ClassificationResult with the action's risk tier, extracted paths,
and metadata the gate needs for routing.

Pre-processing (parsing, shell expansion detection, path extraction)
is shared across all backends. Only the policy evaluation step —
envelope checking and tier matching — varies by backend.

Backends:
  - PythonClassifier: YAML policies evaluated in pure Python (zero dependencies)
  - OPAClassifier: Policies evaluated via Open Policy Agent (enterprise scale)
"""

import shlex
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from agent_gate.policy_loader import Policy


# ---------------------------------------------------------------------------
# Data classes and enums live here so both backends import from one place.
# This avoids circular imports and keeps the contract in a single module.
# ---------------------------------------------------------------------------

from enum import Enum
from dataclasses import dataclass, field


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


class ClassifierBase(ABC):
    """
    Abstract base for all classifier backends.

    Implements the template method pattern:
    - classify() handles shared pre-processing (parsing, shell expansion,
      path extraction) that is structural and backend-independent
    - _evaluate() is the abstract method that each backend implements
      for policy-specific evaluation (envelope checking, tier matching)

    Why this split matters:
    Shell expansion detection is a structural safety check — it protects
    the gate from evaluating commands whose arguments the shell would
    transform. Path extraction resolves symlinks and normalizes paths.
    These are pre-conditions for any policy evaluation, not policy
    decisions themselves.

    Envelope checking and tier matching ARE policy decisions — and this
    is exactly what OPA replaces. The Python backend does both in Python.
    The OPA backend sends pre-processed data to OPA for evaluation.
    """

    def __init__(self, policy: Policy):
        self.policy = policy

    def classify(self, tool_call: dict) -> ClassificationResult:
        """
        Classify a structured tool call.

        Template method — pre-processes the tool call, then delegates
        to the backend-specific _evaluate() for policy evaluation.

        Args:
            tool_call: A dict representing the tool call:
                {
                    "tool": "bash" | "write_file" | "read_file" | ...,
                    "input": {
                        "command": "rm -rf ./tmp/old_cache",
                        "path": "/some/file.txt",
                        "content": "..."
                    }
                }

        Returns:
            ClassificationResult with tier, paths, and metadata.
        """
        command, args = self._parse_tool_call(tool_call)

        # For bash commands, verify the command is fully literal.
        # This is a structural safety check — if shell expansion syntax
        # is present, we can't trust extracted paths. Block before any
        # policy evaluation.
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

        # Delegate to backend for envelope check + tier matching
        return self._evaluate(command, args, target_paths, tool_call)

    @abstractmethod
    def _evaluate(
        self,
        command: str,
        args: List[str],
        target_paths: List[str],
        tool_call: dict,
    ) -> ClassificationResult:
        """
        Backend-specific policy evaluation.

        Receives pre-processed data (parsed command, literal-verified
        arguments, symlink-resolved paths) and evaluates against policy.

        Must handle:
        1. Envelope checking — are all target_paths within allowed bounds?
        2. Tier matching — which policy tier does this action fall into?

        Args:
            command: The parsed command name (e.g., "rm", "write_file")
            args: Parsed arguments (e.g., ["-f", "/workspace/file.txt"])
            target_paths: Symlink-resolved absolute paths
            tool_call: The original tool call dict (for context)

        Returns:
            ClassificationResult with tier and metadata.
        """
        ...

    # ------------------------------------------------------------------
    # Shared pre-processing methods
    # These are identical regardless of policy backend.
    # ------------------------------------------------------------------

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
        or arguments.

        Returns None if the command is fully literal.
        Returns a description of what was detected if expansion found.
        """
        # Variable expansion: $VAR, ${VAR}, ${VAR:-default}
        # But NOT inside single quotes (which suppress expansion)
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
        if re.search(r'(?<!\$)\{[^}]*(,|\.\.)[^}]*\}', stripped):
            return "contains brace expansion ({a,b} or {1..10})"

        # Unquoted glob in argument position
        parts = stripped.split(None, 1)
        args_portion = parts[1] if len(parts) > 1 else ""
        args_no_dquotes = re.sub(r'"[^"]*"', '', args_portion)
        if re.search(r'(?<!\\)[*?]', args_no_dquotes):
            return "contains unquoted glob pattern (* or ?)"
        if re.search(r'(?<!\\)\[[^\]]+\]', args_no_dquotes):
            return "contains glob character class ([...])"

        # eval, exec, source — commands that execute computed strings
        if command in ('eval', 'exec', 'source', '.'):
            return f"'{command}' executes computed commands"

        # Interpreter with inline code
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

        # xargs — dynamic command building
        if command == 'xargs' or ' xargs ' in f' {raw_command} ':
            return "'xargs' builds commands dynamically from input"

        # Here-string / here-doc with interpreters
        if '<<<' in stripped or '<<' in stripped:
            for interp in interpreter_inline:
                if interp in raw_command:
                    return (
                        f"here-document/here-string with '{interp}' — "
                        f"gate cannot inspect the piped code"
                    )

        return None  # Command is literal

    def _extract_target_paths(
        self, command: str, args: List[str], tool_call: dict
    ) -> List[str]:
        """
        Extract file/directory paths that the action targets.
        Resolves ~ expansion and symlinks to absolute real paths.
        """
        paths = []
        input_data = tool_call.get("input", {})

        # Structured file ops have explicit paths
        if "path" in input_data:
            raw = os.path.expanduser(input_data["path"])
            resolved = os.path.realpath(raw)
            paths.append(resolved)

        # For bash commands, extract paths from arguments
        for arg in args:
            if not arg.startswith("-"):
                expanded = os.path.expanduser(arg)
                p = Path(expanded)
                if not p.is_absolute():
                    base = self.policy.allowed_paths[0].rstrip("/*")
                    p = Path(base) / expanded
                paths.append(str(p.resolve()))

        return paths
