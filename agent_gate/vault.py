"""
Agent Gate — Vault Manager
Manages the agent-unreachable backup store.

The vault is the safety net that makes full agent autonomy possible.
Every destructive action gets a snapshot here before execution.
The agent cannot reach this directory — enforced by the same gate
that routes actions through the vault in the first place.
"""

import hashlib
import json
import shutil
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, asdict


@dataclass
class VaultSnapshot:
    """Record of a single file backed up to the vault."""
    original_path: str
    vault_path: str
    timestamp: str
    file_size: int
    sha256: str
    action_that_triggered: str
    success: bool
    error: Optional[str] = None


@dataclass
class VaultResult:
    """
    Result of a vault backup operation.
    The gate checks this before allowing a destructive action.
    If success is False and policy says on_failure: deny,
    the destructive action is blocked.
    """
    success: bool
    snapshots: List[VaultSnapshot]
    errors: List[str]

    @property
    def all_backed_up(self) -> bool:
        return self.success and all(s.success for s in self.snapshots)


class VaultManager:
    """
    Manages backup snapshots in the agent-unreachable vault.

    Responsibilities:
    - Copy files to vault before destructive actions
    - Maintain snapshot metadata for rollback
    - Enforce retention policy (max snapshots, max age)
    - Provide rollback/restore capabilities
    """

    METADATA_FILENAME = "manifest.jsonl"

    def __init__(self, vault_config: dict):
        self.vault_path = Path(vault_config["path"])
        self.retention = vault_config.get("retention", {})
        self.max_snapshots = self.retention.get("max_snapshots_per_file", 20)
        self.max_age_days = self.retention.get("max_age_days", 30)
        self.on_failure = vault_config.get("on_failure", "deny")

        # Ensure vault directory exists
        self.vault_path.mkdir(parents=True, exist_ok=True)

        # Ensure metadata file exists
        self.metadata_path = self.vault_path / self.METADATA_FILENAME
        if not self.metadata_path.exists():
            self.metadata_path.touch()

    def snapshot(
        self, target_paths: List[str], action_description: str
    ) -> VaultResult:
        """
        Back up all target paths to the vault.

        This is called by the gate BEFORE a destructive action executes.
        If any backup fails and policy is on_failure: deny, the gate
        will block the action.

        Args:
            target_paths: List of absolute paths to back up.
            action_description: What action triggered this (for audit log).

        Returns:
            VaultResult indicating success/failure of all backups.
        """
        snapshots = []
        errors = []

        for target in target_paths:
            target_path = Path(target)

            # Skip if target doesn't exist (nothing to back up)
            # This is not an error — e.g., rm on a nonexistent file
            if not target_path.exists():
                continue

            # Skip directories for now — back up contents individually
            # Future: support recursive directory snapshots
            if target_path.is_dir():
                dir_snapshots, dir_errors = self._snapshot_directory(
                    target_path, action_description
                )
                snapshots.extend(dir_snapshots)
                errors.extend(dir_errors)
                continue

            snapshot = self._snapshot_file(target_path, action_description)
            snapshots.append(snapshot)
            if not snapshot.success:
                errors.append(snapshot.error)

        success = len(errors) == 0
        result = VaultResult(success=success, snapshots=snapshots, errors=errors)

        return result

    def _snapshot_file(
        self, source: Path, action_description: str
    ) -> VaultSnapshot:
        """Back up a single file to the vault."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

        try:
            # Create a stable subdirectory based on original path
            path_hash = self._path_hash(str(source))
            dest_dir = self.vault_path / path_hash
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Destination filename: timestamp_originalname
            dest_filename = f"{timestamp}_{source.name}"
            dest_path = dest_dir / dest_filename

            # Copy the file preserving metadata
            shutil.copy2(str(source), str(dest_path))

            # Calculate hash for integrity verification
            file_hash = self._file_sha256(dest_path)
            file_size = dest_path.stat().st_size

            snapshot = VaultSnapshot(
                original_path=str(source),
                vault_path=str(dest_path),
                timestamp=timestamp,
                file_size=file_size,
                sha256=file_hash,
                action_that_triggered=action_description,
                success=True,
            )

            # Write to manifest
            self._append_manifest(snapshot)

            # Enforce retention for this file's snapshots
            self._enforce_retention(dest_dir)

            return snapshot

        except Exception as e:
            return VaultSnapshot(
                original_path=str(source),
                vault_path="",
                timestamp=timestamp,
                file_size=0,
                sha256="",
                action_that_triggered=action_description,
                success=False,
                error=str(e),
            )

    def _snapshot_directory(
        self, source: Path, action_description: str
    ) -> tuple:
        """Back up all files in a directory recursively."""
        snapshots = []
        errors = []

        for item in source.rglob("*"):
            if item.is_file():
                snapshot = self._snapshot_file(item, action_description)
                snapshots.append(snapshot)
                if not snapshot.success:
                    errors.append(snapshot.error)

        return snapshots, errors

    def _path_hash(self, path: str) -> str:
        """
        Create a short, stable hash of a file path.
        Used as the vault subdirectory name so snapshots of the
        same file are grouped together.
        """
        return hashlib.sha256(path.encode()).hexdigest()[:12]

    def _file_sha256(self, path: Path) -> str:
        """Calculate SHA-256 hash of a file for integrity verification."""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _append_manifest(self, snapshot: VaultSnapshot):
        """Append a snapshot record to the vault manifest (JSONL)."""
        with open(self.metadata_path, "a") as f:
            f.write(json.dumps(asdict(snapshot)) + "\n")

    def _enforce_retention(self, snapshot_dir: Path):
        """
        Remove old snapshots beyond the retention limit.
        Keeps the most recent N snapshots per file.
        """
        snapshots = sorted(snapshot_dir.iterdir(), key=lambda p: p.name)
        # Exclude non-file entries
        snapshots = [s for s in snapshots if s.is_file()]

        while len(snapshots) > self.max_snapshots:
            oldest = snapshots.pop(0)
            oldest.unlink()

    # --- ROLLBACK INTERFACE (used by CLI) ---

    def list_snapshots(self, original_path: Optional[str] = None) -> List[dict]:
        """
        List all snapshots, optionally filtered by original path.
        Returns parsed manifest entries.
        """
        snapshots = []
        if not self.metadata_path.exists():
            return snapshots

        with open(self.metadata_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if original_path is None or entry.get("original_path") == original_path:
                        snapshots.append(entry)
                except json.JSONDecodeError:
                    continue

        return snapshots

    def restore(self, vault_path: str, restore_to: Optional[str] = None) -> bool:
        """
        Restore a file from the vault.

        Args:
            vault_path: Path to the snapshot in the vault.
            restore_to: Where to restore. Defaults to original path.

        Returns:
            True if restore succeeded.
        """
        source = Path(vault_path)
        if not source.exists():
            raise FileNotFoundError(f"Vault snapshot not found: {vault_path}")

        # Find original path from manifest
        if restore_to is None:
            snapshots = self.list_snapshots()
            for snap in snapshots:
                if snap["vault_path"] == vault_path:
                    restore_to = snap["original_path"]
                    break

        if restore_to is None:
            raise ValueError(
                "Could not determine restore destination. Specify restore_to."
            )

        dest = Path(restore_to)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(source), str(dest))

        return True

    def diff(self, vault_path: str, current_path: str) -> Optional[str]:
        """
        Show difference between a vault snapshot and the current file.
        Returns a unified diff string, or None if files are identical.
        """
        import difflib

        vault_file = Path(vault_path)
        current_file = Path(current_path)

        if not vault_file.exists():
            return f"Vault snapshot not found: {vault_path}"
        if not current_file.exists():
            return f"Current file not found (deleted): {current_path}"

        with open(vault_file, "r", errors="replace") as f:
            vault_lines = f.readlines()
        with open(current_file, "r", errors="replace") as f:
            current_lines = f.readlines()

        diff = difflib.unified_diff(
            vault_lines,
            current_lines,
            fromfile=f"vault: {vault_path}",
            tofile=f"current: {current_path}",
        )

        result = "".join(diff)
        return result if result else None
