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
