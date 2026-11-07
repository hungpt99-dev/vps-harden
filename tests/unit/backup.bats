#!/usr/bin/env bats
# Snapshot / rollback tests. Everything happens inside VH_ROOT: no /etc write,
# no service reload.

setup() {
    REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
    export VH_ROOT="$BATS_TEST_TMPDIR/root"
    export VH_BACKUP_DIR="$BATS_TEST_TMPDIR/backups"
    export VH_LOG_DISABLE=1
    export NO_COLOR=1
    mkdir -p "$VH_ROOT/etc/ssh/sshd_config.d"
    mkdir -p "$VH_ROOT/etc/fail2ban/jail.d"
    echo "original-dropin" >"$VH_ROOT/etc/ssh/sshd_config.d/00-vps-harden.conf"
    echo "original-jail" >"$VH_ROOT/etc/fail2ban/jail.d/99-vps-harden.local"
}

@test "backup creates a snapshot containing managed files" {
    run "$REPO_ROOT/scripts/backup.sh" --quiet --reason unit-test
    [ "$status" -eq 0 ]
    snapshot_id="$(echo "$output" | tail -1)"
    [[ "$snapshot_id" == *"unit-test"* ]]
    [ -f "$VH_BACKUP_DIR/snapshots/$snapshot_id/manifest.json" ]
    [ -f "$VH_BACKUP_DIR/snapshots/$snapshot_id/files/etc/ssh/sshd_config.d/00-vps-harden.conf" ]
}

@test "manifest records which files existed and which did not" {
    run "$REPO_ROOT/scripts/backup.sh" --quiet
    [ "$status" -eq 0 ]
    snapshot_id="$(echo "$output" | tail -1)"
    python3 - "$VH_BACKUP_DIR/snapshots/$snapshot_id/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
entries = {e["path"]: e for e in m["entries"]}
assert entries["/etc/ssh/sshd_config.d/00-vps-harden.conf"]["existed"] is True
assert entries["/etc/ssh/sshd_config.d/00-vps-harden.conf"]["mode"] == "0644"
assert entries["/etc/sysctl.d/99-vps-harden.conf"]["existed"] is False
PY
}

@test "rollback restores modified content" {
    "$REPO_ROOT/scripts/backup.sh" --quiet >/dev/null
    echo "BROKEN CONFIG" >"$VH_ROOT/etc/ssh/sshd_config.d/00-vps-harden.conf"
    run "$REPO_ROOT/scripts/rollback.sh" --yes
    [ "$status" -eq 0 ]
    [ "$(cat "$VH_ROOT/etc/ssh/sshd_config.d/00-vps-harden.conf")" = "original-dropin" ]
}

@test "rollback removes files that did not exist when snapshotted" {
    rm "$VH_ROOT/etc/fail2ban/jail.d/99-vps-harden.local"
    "$REPO_ROOT/scripts/backup.sh" --quiet >/dev/null
    echo "created later" >"$VH_ROOT/etc/fail2ban/jail.d/99-vps-harden.local"
    run "$REPO_ROOT/scripts/rollback.sh" --yes
    [ "$status" -eq 0 ]
    [ ! -f "$VH_ROOT/etc/fail2ban/jail.d/99-vps-harden.local" ]
}

@test "rollback --dry-run changes nothing" {
    "$REPO_ROOT/scripts/backup.sh" --quiet >/dev/null
    echo "KEEP ME" >"$VH_ROOT/etc/ssh/sshd_config.d/00-vps-harden.conf"
    run "$REPO_ROOT/scripts/rollback.sh" --dry-run
    [ "$status" -eq 0 ]
    [ "$(cat "$VH_ROOT/etc/ssh/sshd_config.d/00-vps-harden.conf")" = "KEEP ME" ]
}

@test "a snapshot id can be selected explicitly" {
    first="$("$REPO_ROOT/scripts/backup.sh" --quiet --reason first | tail -1)"
    echo "second content" >"$VH_ROOT/etc/ssh/sshd_config.d/00-vps-harden.conf"
    "$REPO_ROOT/scripts/backup.sh" --quiet --reason second >/dev/null
    run "$REPO_ROOT/scripts/rollback.sh" --id "$first" --yes
    [ "$status" -eq 0 ]
    [ "$(cat "$VH_ROOT/etc/ssh/sshd_config.d/00-vps-harden.conf")" = "original-dropin" ]
}

@test "snapshot pruning keeps the configured number" {
    for i in 1 2 3 4; do "$REPO_ROOT/scripts/backup.sh" --quiet --keep 2 >/dev/null; sleep 1; done
    count="$(find "$VH_BACKUP_DIR/snapshots" -maxdepth 1 -type d | wc -l)"
    # one line is the snapshots directory itself
    [ "$count" -le 3 ]
}

@test "snapshot.py refuses path traversal" {
    run python3 "$REPO_ROOT/scripts/snapshot.py" create \
        --backup-dir "$VH_BACKUP_DIR" \
        --paths-file /dev/stdin --reason traversal <<'YAML'
vh_managed:
  owned_files:
    - /etc/../../etc/passwd
YAML
    [ "$status" -eq 0 ]
    # the entry is refused with a warning and never captured
    [[ "$output" == *"refusing path with traversal"* ]]
    ! find "$VH_BACKUP_DIR/snapshots" -name passwd -print -quit | grep -q .
}
