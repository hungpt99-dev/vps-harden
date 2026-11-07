#!/usr/bin/env python3
"""Configuration snapshot engine for vps-harden.

Only files listed in config/managed_paths.yml are ever captured or restored,
which is what makes `rollback` safe on a machine running unrelated services.

Snapshot layout::

    <backup_dir>/snapshots/20261107T061500Z-configure/
        manifest.json
        files/etc/ssh/sshd_config.d/00-vps-harden.conf

The manifest records, per path: whether it existed, its content hash, mode and
ownership. Restoring a path that did not exist before deletes the file we
created; it never deletes a path that is not in the managed list.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("ERROR: PyYAML is required (apt-get install -y python3-yaml)\n")
    sys.exit(2)

SCHEMA_VERSION = 1
MANIFEST = "manifest.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_snapshot_id(reason: str) -> str:
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in reason)[:32].strip("-")
    return f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{slug or 'snapshot'}"


def managed_paths(paths_file: Path) -> list[str]:
    """Return the union of owned and modified paths, order preserved."""
    data = yaml.safe_load(paths_file.read_text(encoding="utf-8")) or {}
    managed = data.get("vh_managed", {})
    result: list[str] = []
    for key in ("owned_files", "modified_files"):
        for item in managed.get(key, []):
            if item not in result:
                result.append(item)
    return result


def safe_path(raw: str) -> Path:
    """Reject anything that is not a simple absolute path (no traversal)."""
    if not raw.startswith("/"):
        raise ValueError(f"refusing non-absolute path: {raw!r}")
    if ".." in Path(raw).parts:
        raise ValueError(f"refusing path with traversal: {raw!r}")
    return Path(raw)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------
def create_snapshot(
    backup_dir: Path,
    paths: list[str],
    reason: str,
    version: str,
    root: str = "",
) -> Path:
    snapshots = backup_dir / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)

    snapshot_id = new_snapshot_id(reason)
    target = snapshots / snapshot_id
    target.mkdir(mode=0o700)

    entries: list[dict[str, Any]] = []
    for raw in paths:
        entry: dict[str, Any] = {"path": raw, "existed": False}
        try:
            path = Path(root + str(safe_path(raw)))
        except ValueError as exc:
            sys.stderr.write(f"WARN: skipping {raw}: {exc}\n")
            continue

        if path.is_symlink():
            entry["existed"] = True
            entry["symlink"] = os.readlink(path)
            entries.append(entry)
            continue

        if path.is_file():
            stored = target / "files" / raw.lstrip("/")
            stored.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, stored)
            stat = path.stat()
            entry.update(
                existed=True,
                stored=str(stored.relative_to(target)),
                mode=f"{stat.st_mode & 0o7777:04o}",
                uid=stat.st_uid,
                gid=stat.st_gid,
                sha256=sha256_file(stored),
                size=stat.st_size,
            )
        entries.append(entry)

    manifest = {
        "schema": SCHEMA_VERSION,
        "id": snapshot_id,
        "created_utc": utc_now(),
        "reason": reason,
        "host": socket.gethostname(),
        "vps_harden_version": version,
        "entries": entries,
    }
    manifest_path = target / MANIFEST
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    return target


def prune(backup_dir: Path, keep: int) -> list[str]:
    snapshots = backup_dir / "snapshots"
    if not snapshots.is_dir() or keep < 0:
        return []
    candidates = sorted(
        (p for p in snapshots.iterdir() if p.is_dir() and (p / MANIFEST).is_file()),
        key=lambda p: p.name,
    )
    removed = []
    for old in candidates[:-keep] if keep else candidates:
        shutil.rmtree(old)
        removed.append(old.name)
    return removed


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------
def load_manifest(snapshot: Path) -> dict[str, Any]:
    manifest_path = snapshot / MANIFEST
    if not manifest_path.is_file():
        raise FileNotFoundError(f"no manifest in {snapshot}")
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA_VERSION:
        raise ValueError(f"unsupported manifest schema: {data.get('schema')}")
    return data


def list_snapshots(backup_dir: Path) -> list[dict[str, Any]]:
    snapshots = backup_dir / "snapshots"
    if not snapshots.is_dir():
        return []
    rows = []
    for path in sorted(snapshots.iterdir(), reverse=True):
        if not path.is_dir() or not (path / MANIFEST).is_file():
            continue
        try:
            manifest = load_manifest(path)
        except (OSError, ValueError):
            continue
        present = sum(1 for e in manifest.get("entries", []) if e.get("existed"))
        total = 0
        files_dir = path / "files"
        if files_dir.is_dir():
            total = sum(f.stat().st_size for f in files_dir.rglob("*") if f.is_file())
        rows.append(
            {
                "id": manifest.get("id", path.name),
                "created_utc": manifest.get("created_utc", ""),
                "reason": manifest.get("reason", ""),
                "entries": len(manifest.get("entries", [])),
                "present": present,
                "bytes": total,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------
def restore_snapshot(
    snapshot: Path,
    managed: list[str],
    root: str = "",
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    manifest = load_manifest(snapshot)
    allowed = set(managed)
    actions: list[dict[str, Any]] = []

    for entry in manifest.get("entries", []):
        raw = entry.get("path", "")
        try:
            safe_path(raw)
        except ValueError as exc:
            actions.append({"path": raw, "action": "refused", "detail": str(exc)})
            continue
        if raw not in allowed:
            actions.append(
                {"path": raw, "action": "refused", "detail": "no longer a managed path"}
            )
            continue

        target = Path(root + raw)
        if entry.get("symlink"):
            if not dry_run:
                if target.is_symlink() or target.exists():
                    target.unlink()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(entry["symlink"])
            actions.append({"path": raw, "action": "symlink"})
            continue

        if entry.get("existed"):
            stored = snapshot / entry["stored"]
            if not stored.is_file():
                actions.append({"path": raw, "action": "missing", "detail": str(stored)})
                continue
            if not dry_run:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(stored, target)
                os.chmod(target, int(entry.get("mode", "0644"), 8))
                try:
                    os.chown(target, int(entry.get("uid", 0)), int(entry.get("gid", 0)))
                except PermissionError:
                    pass
            actions.append(
                {
                    "path": raw,
                    "action": "restored",
                    "mode": entry.get("mode"),
                    "sha256": entry.get("sha256"),
                }
            )
        else:
            if target.exists() or target.is_symlink():
                if not dry_run:
                    target.unlink()
                actions.append({"path": raw, "action": "removed"})
            else:
                actions.append({"path": raw, "action": "absent"})
    return actions


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="vps-harden snapshot engine")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create a snapshot")
    create.add_argument("--backup-dir", required=True, type=Path)
    create.add_argument("--paths-file", required=True, type=Path)
    create.add_argument("--reason", default="manual")
    create.add_argument("--version", default="0.0.0")
    create.add_argument("--root", default="")
    create.add_argument("--keep", type=int, default=10)

    listing = sub.add_parser("list", help="list snapshots")
    listing.add_argument("--backup-dir", required=True, type=Path)
    listing.add_argument("--json", action="store_true")

    restore = sub.add_parser("restore", help="restore a snapshot")
    restore.add_argument("--backup-dir", required=True, type=Path)
    restore.add_argument("--id", default=None)
    restore.add_argument("--paths-file", required=True, type=Path)
    restore.add_argument("--root", default="")
    restore.add_argument("--dry-run", action="store_true")
    restore.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "create":
        paths = managed_paths(args.paths_file)
        target = create_snapshot(
            args.backup_dir, paths, args.reason, args.version, args.root
        )
        removed = prune(args.backup_dir, args.keep)
        for name in removed:
            sys.stderr.write(f"pruned old snapshot {name}\n")
        print(target.name)
        return 0

    if args.command == "list":
        rows = list_snapshots(args.backup_dir)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            if not rows:
                print("No snapshots found.")
            for row in rows:
                print(
                    f"{row['id']:<44} {row['created_utc']:<22} "
                    f"{row['reason']:<12} {row['present']}/{row['entries']} files "
                    f"{row['bytes'] / 1024:.0f} KiB"
                )
        return 0

    snapshots = args.backup_dir / "snapshots"
    if args.id:
        snapshot = snapshots / args.id
    else:
        candidates = sorted(
            (p for p in snapshots.glob("*") if (p / MANIFEST).is_file()),
            key=lambda p: p.name,
        )
        if not candidates:
            sys.stderr.write("ERROR: no snapshot available\n")
            return 1
        snapshot = candidates[-1]

    if not snapshot.is_dir():
        sys.stderr.write(f"ERROR: snapshot not found: {snapshot}\n")
        return 1

    actions = restore_snapshot(
        snapshot, managed_paths(args.paths_file), args.root, args.dry_run
    )
    if args.json:
        print(json.dumps(actions, indent=2))
    else:
        for action in actions:
            print(f"{action['action']:<9} {action['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
