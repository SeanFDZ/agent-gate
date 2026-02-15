"""
Agent Gate — Rollback CLI
Human-facing interface for vault management.

This is how you recover from anything the agent did.
The agent can't reach the vault. You can.

Usage:
    agent-gate list [--file PATH]
    agent-gate restore <vault_path> [--to PATH]
    agent-gate diff <vault_path> [--against PATH]
    agent-gate history <file_path>
    agent-gate purge [--dry-run]
"""

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from agent_gate.vault import VaultManager


def get_vault_manager(vault_path: Optional[str] = None) -> VaultManager:
    """
    Create a VaultManager from the default or specified vault location.
    """
    if vault_path is None:
        vault_path = str(Path.home() / ".config" / "agent-gate" / "vault")

    config = {
        "path": vault_path,
        "retention": {
            "max_snapshots_per_file": 20,
            "max_age_days": 30,
        },
        "on_failure": "deny",
    }
    return VaultManager(config)


def cmd_list(args):
    """List all snapshots in the vault."""
    vault = get_vault_manager(args.vault_path)

    file_filter = args.file if hasattr(args, "file") and args.file else None
    snapshots = vault.list_snapshots(original_path=file_filter)

    if not snapshots:
        if file_filter:
            print(f"No snapshots found for: {file_filter}")
        else:
            print("Vault is empty. No snapshots recorded.")
        return

    # Group by original path
    by_file = {}
    for snap in snapshots:
        orig = snap["original_path"]
        if orig not in by_file:
            by_file[orig] = []
        by_file[orig].append(snap)

    print(f"\n{'='*70}")
    print(f"  AGENT GATE VAULT — {len(snapshots)} snapshot(s)")
    print(f"{'='*70}\n")

    for orig_path, file_snapshots in sorted(by_file.items()):
        print(f"  {orig_path}")
        print(f"  {'─'*60}")
        for snap in sorted(file_snapshots, key=lambda s: s["timestamp"]):
            ts = snap["timestamp"]
            size = _format_size(snap.get("file_size", 0))
            action = snap.get("action_that_triggered", "unknown")
            vault_loc = snap["vault_path"]
            success = "✓" if snap.get("success") else "✗"

            # Format timestamp for readability
            display_ts = _format_timestamp(ts)

            print(f"    {success} {display_ts}  {size:>8}  {action}")
            print(f"      vault: {vault_loc}")
        print()

    print(f"{'='*70}")
    print(f"  Restore:  agent-gate restore <vault_path>")
    print(f"  Diff:     agent-gate diff <vault_path>")
    print(f"{'='*70}\n")


def cmd_history(args):
    """Show snapshot history for a specific file."""
    vault = get_vault_manager(args.vault_path)
    snapshots = vault.list_snapshots(original_path=args.file_path)

    if not snapshots:
        print(f"No snapshots found for: {args.file_path}")
        return

    print(f"\n  History for: {args.file_path}")
    print(f"  {'─'*60}")

    for i, snap in enumerate(
        sorted(snapshots, key=lambda s: s["timestamp"], reverse=True)
    ):
        ts = _format_timestamp(snap["timestamp"])
        size = _format_size(snap.get("file_size", 0))
        action = snap.get("action_that_triggered", "unknown")
        sha = snap.get("sha256", "")[:12]

        marker = "  [latest]" if i == 0 else ""
        print(f"    {ts}  {size:>8}  sha:{sha}  {action}{marker}")
        print(f"      vault: {snap['vault_path']}")
    print()


def cmd_restore(args):
    """Restore a file from the vault."""
    vault = get_vault_manager(args.vault_path)

    restore_to = args.to if hasattr(args, "to") and args.to else None

    # Show what we're about to do
    snapshots = vault.list_snapshots()
    source_snap = None
    for snap in snapshots:
        if snap["vault_path"] == args.snapshot_path:
            source_snap = snap
            break

    if source_snap is None:
        # Try treating it as a path directly
        if not Path(args.snapshot_path).exists():
            print(f"Snapshot not found: {args.snapshot_path}")
            return

    destination = restore_to or (
        source_snap["original_path"] if source_snap else "original location"
    )

    print(f"\n  Restoring from vault:")
    print(f"    Source:  {args.snapshot_path}")
    print(f"    Dest:    {destination}")

    if not args.yes:
        confirm = input("\n  Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("  Cancelled.")
            return

    try:
        vault.restore(args.snapshot_path, restore_to=restore_to)
        print(f"  ✓ Restored successfully.")
    except Exception as e:
        print(f"  ✗ Restore failed: {e}")


def cmd_diff(args):
    """Show diff between vault snapshot and current file."""
    vault = get_vault_manager(args.vault_path)

    # Determine the current file path
    current = args.against if hasattr(args, "against") and args.against else None

    if current is None:
        # Look up original path from manifest
        snapshots = vault.list_snapshots()
        for snap in snapshots:
            if snap["vault_path"] == args.snapshot_path:
                current = snap["original_path"]
                break

    if current is None:
        print("Could not determine current file path. Use --against PATH.")
        return

    result = vault.diff(args.snapshot_path, current)

    if result is None:
        print(f"Files are identical.")
    else:
        print(result)


def cmd_purge(args):
    """Clean up vault per retention policy."""
    vault = get_vault_manager(args.vault_path)

    snapshots = vault.list_snapshots()
    if not snapshots:
        print("Vault is empty. Nothing to purge.")
        return

    now = datetime.now(timezone.utc)
    to_purge = []

    for snap in snapshots:
        # Parse timestamp — format is YYYYMMDD_HHMMSS_ffffff
        try:
            ts = datetime.strptime(snap["timestamp"], "%Y%m%d_%H%M%S_%f")
            ts = ts.replace(tzinfo=timezone.utc)
            age_days = (now - ts).days
            if age_days > vault.max_age_days:
                to_purge.append(snap)
        except (ValueError, KeyError):
            continue

    if not to_purge:
        print(f"No snapshots older than {vault.max_age_days} days.")
        return

    print(f"\n  Found {len(to_purge)} snapshot(s) older than {vault.max_age_days} days.")

    if args.dry_run:
        print("  Dry run — no files will be deleted.\n")
        for snap in to_purge:
            print(f"    Would purge: {snap['vault_path']}")
        return

    if not args.yes:
        confirm = input("\n  Purge these snapshots? [y/N] ").strip().lower()
        if confirm != "y":
            print("  Cancelled.")
            return

    purged = 0
    for snap in to_purge:
        try:
            p = Path(snap["vault_path"])
            if p.exists():
                p.unlink()
                purged += 1
        except Exception as e:
            print(f"  ✗ Failed to purge {snap['vault_path']}: {e}")

    print(f"  ✓ Purged {purged} snapshot(s).")


# --- HELPERS ---

def _format_size(size_bytes: int) -> str:
    """Format file size for display."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f}MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f}GB"


def _format_timestamp(ts: str) -> str:
    """Format vault timestamp for display."""
    try:
        dt = datetime.strptime(ts, "%Y%m%d_%H%M%S_%f")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


# --- MAIN ---

def main():
    parser = argparse.ArgumentParser(
        prog="agent-gate",
        description="Agent Gate — Execution authority and rollback for AI agents",
    )
    parser.add_argument(
        "--vault-path",
        help="Path to vault directory (default: ~/.config/agent-gate/vault)",
        default=None,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list
    list_parser = subparsers.add_parser("list", help="List vault snapshots")
    list_parser.add_argument(
        "--file", help="Filter by original file path", default=None
    )

    # history
    history_parser = subparsers.add_parser(
        "history", help="Show snapshot history for a file"
    )
    history_parser.add_argument("file_path", help="Original file path")

    # restore
    restore_parser = subparsers.add_parser(
        "restore", help="Restore a file from vault"
    )
    restore_parser.add_argument("snapshot_path", help="Path to vault snapshot")
    restore_parser.add_argument(
        "--to", help="Restore to this path (default: original location)"
    )
    restore_parser.add_argument(
        "-y", "--yes", action="store_true", help="Skip confirmation"
    )

    # diff
    diff_parser = subparsers.add_parser(
        "diff", help="Diff vault snapshot against current file"
    )
    diff_parser.add_argument("snapshot_path", help="Path to vault snapshot")
    diff_parser.add_argument(
        "--against", help="Compare against this path (default: original location)"
    )

    # purge
    purge_parser = subparsers.add_parser(
        "purge", help="Clean up old snapshots per retention policy"
    )
    purge_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be purged"
    )
    purge_parser.add_argument(
        "-y", "--yes", action="store_true", help="Skip confirmation"
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    commands = {
        "list": cmd_list,
        "history": cmd_history,
        "restore": cmd_restore,
        "diff": cmd_diff,
        "purge": cmd_purge,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
