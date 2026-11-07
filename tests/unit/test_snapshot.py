"""Snapshot engine tests: capture, restore, path safety, pruning."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import snapshot  # noqa: E402

PATHS_FILE = ROOT / "config" / "managed_paths.yml"


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    (tmp_path / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (tmp_path / "etc/ssh/sshd_config.d/00-vps-harden.conf").write_text(
        "PasswordAuthentication no\n"
    )
    return tmp_path


def test_create_and_restore(sandbox: Path, tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    paths = snapshot.managed_paths(PATHS_FILE)
    snap = snapshot.create_snapshot(backup_dir, paths, "unit", "1.0.0", str(sandbox))

    target = sandbox / "etc/ssh/sshd_config.d/00-vps-harden.conf"
    target.write_text("BROKEN\n")

    actions = snapshot.restore_snapshot(snap, paths, str(sandbox))
    restored = [a for a in actions if a["action"] == "restored"]
    assert any(a["path"].endswith("00-vps-harden.conf") for a in restored)
    assert target.read_text() == "PasswordAuthentication no\n"


def test_restore_removes_files_that_did_not_exist(sandbox: Path, tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    paths = snapshot.managed_paths(PATHS_FILE)
    snap = snapshot.create_snapshot(backup_dir, paths, "unit", "1.0.0", str(sandbox))

    created = sandbox / "etc/sysctl.d/99-vps-harden.conf"
    created.parent.mkdir(parents=True)
    created.write_text("kernel.kptr_restrict = 0\n")

    snapshot.restore_snapshot(snap, paths, str(sandbox))
    assert not created.exists()


def test_dry_run_changes_nothing(sandbox: Path, tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    paths = snapshot.managed_paths(PATHS_FILE)
    snap = snapshot.create_snapshot(backup_dir, paths, "unit", "1.0.0", str(sandbox))
    target = sandbox / "etc/ssh/sshd_config.d/00-vps-harden.conf"
    target.write_text("MODIFIED\n")

    snapshot.restore_snapshot(snap, paths, str(sandbox), dry_run=True)
    assert target.read_text() == "MODIFIED\n"


def test_restore_refuses_paths_outside_the_inventory(sandbox: Path, tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    paths = snapshot.managed_paths(PATHS_FILE)
    snap = snapshot.create_snapshot(backup_dir, paths, "unit", "1.0.0", str(sandbox))

    actions = snapshot.restore_snapshot(snap, ["/etc/hostname"], str(sandbox))
    assert all(a["action"] == "refused" for a in actions)


def test_safe_path_rejects_traversal() -> None:
    with pytest.raises(ValueError):
        snapshot.safe_path("/etc/../../etc/shadow")
    with pytest.raises(ValueError):
        snapshot.safe_path("etc/passwd")


def test_manifest_records_hash_and_mode(sandbox: Path, tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    paths = snapshot.managed_paths(PATHS_FILE)
    snap = snapshot.create_snapshot(backup_dir, paths, "unit", "1.0.0", str(sandbox))
    manifest = json.loads((snap / "manifest.json").read_text())
    entry = next(
        e for e in manifest["entries"] if e["path"].endswith("00-vps-harden.conf")
    )
    assert entry["existed"] is True
    assert entry["mode"] == "0644"
    assert len(entry["sha256"]) == 64


def test_prune_keeps_newest(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    paths = snapshot.managed_paths(PATHS_FILE)
    ids = [
        snapshot.create_snapshot(backup_dir, paths, f"run{i}", "1.0.0", str(tmp_path)).name
        for i in range(3)
    ]
    snapshot.prune(backup_dir, 2)
    remaining = sorted(p.name for p in (backup_dir / "snapshots").iterdir())
    assert len(remaining) == 2
    assert ids[0] not in remaining


def test_list_snapshots_reports_entries(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    paths = snapshot.managed_paths(PATHS_FILE)
    snapshot.create_snapshot(backup_dir, paths, "listing", "1.0.0", str(tmp_path))
    rows = snapshot.list_snapshots(backup_dir)
    assert len(rows) == 1
    assert rows[0]["reason"] == "listing"
    assert rows[0]["entries"] == len(paths)
