# Phase 7.1: Modifier Operations Module

**File:** `modifier.py` (NEW)
**Depends on:** Nothing (standalone new module)
**Parallel:** This is the first phase.  Nothing else starts until this passes.

---

## Before You Start

Read these files to understand the patterns and conventions:

- `agent_gate/gate.py` — Understand how GateDecision is built and returned
- `agent_gate/classifier_base.py` — Understand ClassificationResult dataclass pattern
- `agent_gate/policy_loader.py` — Understand how YAML patterns are structured
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Authoritative reference for all operation names and semantics

---

## Context

The modifier module implements five pure-function operations that rewrite tool call arguments into policy-compliant form.  Each operation takes arguments (as a list of strings) and operation parameters, and returns modified arguments.

All operations MUST be idempotent: applying any operation to already-modified parameters must be a no-op.  This is enforced in code, not just documentation.

On error (malformed argument, type mismatch, unparseable value), operations raise `ModificationError`.  The gate catches this and denies the action (fail closed).

Operations apply in YAML declaration order within a single `modify` block.  Only one pattern's `modify` block fires per tool call (first match wins).

---

## Deliverables

### `agent_gate/modifier.py`

```python
# Module: agent_gate/modifier.py

"""
Agent Gate — Modifier Operations

Pure-function operations that rewrite tool call arguments
into policy-compliant form.  Each operation is idempotent
and raises ModificationError on failure.

Operations:
  - clamp_permission: Reduce octal permission to a maximum value
  - strip_flags: Remove specified flags from argument list
  - require_flags: Inject flags if not already present
  - append_arg: Append a literal string if not already present
  - max_depth: Clamp recursive depth to a maximum value

All operations are applied in YAML declaration order via
apply_modifications(), which iterates the modify dict.
"""

import re
from typing import List, Tuple, Optional


class ModificationError(Exception):
    """Raised when a modify operation cannot be applied cleanly."""
    pass


# Registry of known operation names -> handler functions.
# Used by apply_modifications() to dispatch in YAML order.
OPERATION_HANDLERS = {}


def _register(name: str):
    """Decorator to register an operation handler."""
    def decorator(fn):
        OPERATION_HANDLERS[name] = fn
        return fn
    return decorator


def apply_modifications(
    command: str,
    args: List[str],
    modify_block: dict,
) -> Tuple[List[str], List[dict]]:
    """
    Apply all operations from a modify block in YAML declaration order.

    Args:
        command: The command name (e.g., "chmod", "rm").
        args: The current argument list.
        modify_block: The modify dict from the matched pattern.

    Returns:
        Tuple of (modified_args, operations_applied).
        operations_applied is a list of dicts, each with:
          {"operation": name, "params": value, "changed": bool}

    Raises:
        ModificationError: If any operation cannot be applied cleanly.
    """
    modified = list(args)  # Copy to avoid mutating input
    operations_applied = []

    for op_name, op_params in modify_block.items():
        handler = OPERATION_HANDLERS.get(op_name)
        if handler is None:
            raise ModificationError(
                f"Unknown modify operation: '{op_name}'.  "
                f"Known operations: {list(OPERATION_HANDLERS.keys())}"
            )
        before = list(modified)
        modified = handler(command, modified, op_params)
        changed = modified != before
        operations_applied.append({
            "operation": op_name,
            "params": op_params,
            "changed": changed,
        })

    return modified, operations_applied


@_register("clamp_permission")
def clamp_permission(
    command: str,
    args: List[str],
    max_perm: str,
) -> List[str]:
    """
    Clamp octal permission to a maximum value.

    Scans args for an octal permission value (3-4 digit string
    where all digits are 0-7).  If found and higher than max_perm,
    replaces it with max_perm.  If already at or below, no-op.

    Args:
        command: The command name (e.g., "chmod").
        args: Current argument list.
        max_perm: Maximum octal permission string (e.g., "755").

    Returns:
        Modified argument list.

    Raises:
        ModificationError: If max_perm is not a valid octal string.
    """
    if not re.match(r'^[0-7]{3,4}$', max_perm):
        raise ModificationError(
            f"clamp_permission: invalid max_perm '{max_perm}'.  "
            f"Must be 3-4 octal digits."
        )

    max_val = int(max_perm, 8)
    result = []
    for arg in args:
        if re.match(r'^[0-7]{3,4}$', arg):
            current_val = int(arg, 8)
            if current_val > max_val:
                # Preserve original digit count (3 or 4)
                fmt = f"{{:0{len(max_perm)}o}}"
                result.append(fmt.format(max_val))
            else:
                result.append(arg)
        else:
            result.append(arg)
    return result


@_register("strip_flags")
def strip_flags(
    command: str,
    args: List[str],
    flags: List[str],
) -> List[str]:
    """
    Remove specified flags from the argument list.

    Handles both standalone flags ("-f") and combined short
    flags ("-rf" strips "-f" -> "-r").  Idempotent: stripping
    a flag not present is a no-op.

    Args:
        command: The command name.
        args: Current argument list.
        flags: List of flags to remove (e.g., ["-f"]).

    Returns:
        Modified argument list.
    """
    if not isinstance(flags, list):
        raise ModificationError(
            f"strip_flags: flags must be a list, got {type(flags).__name__}"
        )

    flags_set = set(flags)
    result = []

    for arg in args:
        if arg in flags_set:
            # Exact match, remove entirely
            continue
        # Handle combined short flags: "-rf" with strip "-f" -> "-r"
        if (arg.startswith("-")
                and not arg.startswith("--")
                and len(arg) > 2):
            stripped = arg[0]  # Keep the "-"
            for ch in arg[1:]:
                if f"-{ch}" not in flags_set:
                    stripped += ch
            if len(stripped) > 1:  # Still has flags left
                result.append(stripped)
            # If only "-" remains, drop it entirely
        else:
            result.append(arg)
    return result


@_register("require_flags")
def require_flags(
    command: str,
    args: List[str],
    flags: List[str],
) -> List[str]:
    """
    Inject flags if not already present.  Idempotent.

    Flags can be multi-word (e.g., "--max-time 30") and are
    checked/injected as a unit.  Injected at the beginning
    of the argument list (before positional args).

    Args:
        command: The command name.
        args: Current argument list.
        flags: List of flags to require (e.g., ["--max-time 30"]).

    Returns:
        Modified argument list.
    """
    if not isinstance(flags, list):
        raise ModificationError(
            f"require_flags: flags must be a list, got {type(flags).__name__}"
        )

    result = list(args)
    full_str = " ".join(args)

    for flag in flags:
        # Check if the flag (or its parts) already exists
        if flag in full_str:
            continue  # Already present, idempotent
        # Split multi-word flags into individual tokens
        flag_parts = flag.split()
        result = flag_parts + result

    return result


@_register("append_arg")
def append_arg(
    command: str,
    args: List[str],
    arg: str,
) -> List[str]:
    """
    Append a literal string to arguments if not already present.
    Idempotent: if the string is already in the joined args, no-op.

    Args:
        command: The command name.
        args: Current argument list.
        arg: String to append (e.g., "LIMIT 100").

    Returns:
        Modified argument list.
    """
    if not isinstance(arg, str):
        raise ModificationError(
            f"append_arg: arg must be a string, got {type(arg).__name__}"
        )

    full_str = " ".join(args)
    if arg in full_str:
        return list(args)  # Already present, idempotent

    # Append as individual tokens
    return list(args) + arg.split()


@_register("max_depth")
def max_depth(
    command: str,
    args: List[str],
    depth: int,
) -> List[str]:
    """
    Limit recursive depth for commands that accept a depth argument.

    Looks for existing depth flags (-maxdepth, --max-depth, -depth)
    and clamps to the specified maximum.  If no depth flag exists,
    injects one.

    Args:
        command: The command name.
        args: Current argument list.
        depth: Maximum depth value (e.g., 2).

    Returns:
        Modified argument list.
    """
    if not isinstance(depth, int) or depth < 0:
        raise ModificationError(
            f"max_depth: depth must be a non-negative integer, got {depth!r}"
        )

    # Known depth flag patterns
    depth_flags = ["-maxdepth", "--max-depth", "-depth"]
    result = list(args)

    for i, arg in enumerate(result):
        if arg in depth_flags and i + 1 < len(result):
            try:
                current = int(result[i + 1])
                if current > depth:
                    result[i + 1] = str(depth)
                return result  # Found and handled
            except ValueError:
                raise ModificationError(
                    f"max_depth: existing depth value "
                    f"'{result[i + 1]}' is not an integer"
                )

    # No existing depth flag found, inject one
    # Use -maxdepth for find, --max-depth for others
    if command == "find":
        result = result[:1] + ["-maxdepth", str(depth)] + result[1:]
    else:
        result = [f"--max-depth={depth}"] + result

    return result
```

---

## Test Cases

### File: `tests/test_modifier.py` (NEW)

```
test_clamp_permission_reduces_777_to_755
    clamp_permission("chmod", ["777", "deploy.sh"], "755")
    -> ["755", "deploy.sh"]

test_clamp_permission_no_op_when_below
    clamp_permission("chmod", ["644", "file.txt"], "755")
    -> ["644", "file.txt"]

test_clamp_permission_no_op_when_equal
    clamp_permission("chmod", ["755", "file.txt"], "755")
    -> ["755", "file.txt"]

test_clamp_permission_four_digit_octal
    clamp_permission("chmod", ["0777", "file.txt"], "0755")
    -> ["0755", "file.txt"]

test_clamp_permission_invalid_max_perm
    clamp_permission("chmod", ["777", "file.txt"], "999")
    -> raises ModificationError

test_clamp_permission_non_octal_arg_untouched
    clamp_permission("chmod", ["+x", "file.txt"], "755")
    -> ["+x", "file.txt"]

test_strip_flags_removes_exact_match
    strip_flags("rm", ["-f", "file.txt"], ["-f"])
    -> ["file.txt"]

test_strip_flags_combined_short_flags
    strip_flags("rm", ["-rf", "dir/"], ["-f"])
    -> ["-r", "dir/"]

test_strip_flags_no_op_when_absent
    strip_flags("rm", ["-r", "dir/"], ["-f"])
    -> ["-r", "dir/"]

test_strip_flags_multiple_flags
    strip_flags("rm", ["-rf", "--force", "dir/"], ["-f", "--force"])
    -> ["-r", "dir/"]

test_strip_flags_idempotent
    result = strip_flags("rm", ["-r", "dir/"], ["-f"])
    strip_flags("rm", result, ["-f"])
    -> ["-r", "dir/"]

test_require_flags_injects_missing
    require_flags("curl", ["http://example.com"], ["--max-time 30"])
    -> ["--max-time", "30", "http://example.com"]

test_require_flags_no_op_when_present
    require_flags("curl", ["--max-time", "30", "http://example.com"], ["--max-time 30"])
    -> ["--max-time", "30", "http://example.com"]

test_require_flags_idempotent
    result = require_flags("curl", ["http://example.com"], ["--max-time 30"])
    require_flags("curl", result, ["--max-time 30"])
    -> same as result

test_append_arg_adds_when_absent
    append_arg("database_query", ["SELECT", "*", "FROM", "users"], "LIMIT 100")
    -> ["SELECT", "*", "FROM", "users", "LIMIT", "100"]

test_append_arg_no_op_when_present
    append_arg("database_query", ["SELECT", "*", "FROM", "users", "LIMIT", "100"], "LIMIT 100")
    -> ["SELECT", "*", "FROM", "users", "LIMIT", "100"]

test_max_depth_clamps_existing
    max_depth("find", [".", "-maxdepth", "10", "-name", "*.py"], 2)
    -> [".", "-maxdepth", "2", "-name", "*.py"]

test_max_depth_no_op_when_below
    max_depth("find", [".", "-maxdepth", "1", "-name", "*.py"], 2)
    -> [".", "-maxdepth", "1", "-name", "*.py"]

test_max_depth_injects_when_absent
    max_depth("find", [".", "-name", "*.py"], 2)
    -> [".", "-maxdepth", "2", "-name", "*.py"]

test_max_depth_invalid_depth
    max_depth("find", [".", "-name", "*.py"], -1)
    -> raises ModificationError

test_apply_modifications_single_op
    apply_modifications("chmod", ["777", "deploy.sh"], {"clamp_permission": "755"})
    -> (["755", "deploy.sh"], [{"operation": "clamp_permission", "params": "755", "changed": True}])

test_apply_modifications_multiple_ops_yaml_order
    apply_modifications("rm", ["-rf", "dir/"], {"strip_flags": ["-f"], "require_flags": ["--interactive"]})
    -> first strips -f, then injects --interactive

test_apply_modifications_unknown_op
    apply_modifications("rm", ["-f"], {"unknown_op": "value"})
    -> raises ModificationError

test_apply_modifications_empty_block
    apply_modifications("rm", ["-f", "file.txt"], {})
    -> (["-f", "file.txt"], [])
```

---

## Verification

```bash
# Run just the new tests
python -m pytest tests/test_modifier.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Expected: all 313 existing tests pass, ~20 new tests pass
```

---

## Commit

```
Phase 7.1: Modifier operations module

New module: agent_gate/modifier.py
- Five modify operations: clamp_permission, strip_flags,
  require_flags, append_arg, max_depth
- apply_modifications() dispatches in YAML declaration order
- All operations idempotent, fail closed via ModificationError
- Operation registry for extensibility
- ~20 new tests in tests/test_modifier.py
```
