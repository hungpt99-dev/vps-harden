#!/usr/bin/env bash
#
# Create a configuration snapshot of every path vps-harden manages.
#
#   backup.sh [--quiet] [--reason REASON] [--list] [--keep N]
#
# Prints the snapshot id on the last line of stdout so playbooks can capture it.
set -Eeuo pipefail
umask 077

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "$HERE/common.sh"

QUIET=0
REASON="manual"
LIST=0
KEEP=10

usage() {
    cat <<'EOF'
Create or list vps-harden configuration snapshots.

Usage: backup.sh [options]

Options:
  --reason REASON   Label stored in the manifest (default: manual)
  --list            List existing snapshots and exit
  --keep N          Number of snapshots to retain (default: 10)
  --quiet           Only print the snapshot id
  -h, --help        Show this help

Snapshots live in <backup_dir>/snapshots and contain only the files listed in
config/managed_paths.yml. Restore with: install.sh rollback --id <id>
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reason)
            REASON="${2:?--reason needs a value}"
            shift 2
            ;;
        --list)
            LIST=1
            shift
            ;;
        --keep)
            KEEP="${2:?--keep needs a value}"
            shift 2
            ;;
        --quiet)
            QUIET=1
            shift
            ;;
        -h | --help)
            usage
            exit "$VH_EXIT_OK"
            ;;
        *)
            vh_err "Unknown argument: $1"
            usage >&2
            exit "$VH_EXIT_USAGE"
            ;;
    esac
done

PY="$(vh_require_python_yaml)" || exit "$VH_EXIT_PREREQ"
BACKUP_DIR="${VH_BACKUP_DIR:-$(vh_path "$(vh_config_value backup_dir /var/backups/vps-harden)")}"
PATHS_FILE="$HERE/../config/managed_paths.yml"

if [[ "$LIST" == "1" ]]; then
    exec "$PY" "$HERE/snapshot.py" list --backup-dir "$BACKUP_DIR"
fi

[[ -r "$PATHS_FILE" ]] || vh_die "$VH_EXIT_CONFIG" "Missing path inventory: $PATHS_FILE"
mkdir -p -- "$BACKUP_DIR"
chmod 0750 -- "$BACKUP_DIR"

[[ "$QUIET" == "1" ]] || vh_info "Snapshotting $(grep -c '^    - /' "$PATHS_FILE") managed paths into $BACKUP_DIR"

snapshot_id="$(
    "$PY" "$HERE/snapshot.py" create \
        --backup-dir "$BACKUP_DIR" \
        --paths-file "$PATHS_FILE" \
        --reason "$REASON" \
        --version "$(vh_version)" \
        --root "${VH_ROOT:-}" \
        --keep "$KEEP"
)"

[[ "$QUIET" == "1" ]] || vh_ok "Snapshot created: $snapshot_id"
printf '%s\n' "$snapshot_id"
