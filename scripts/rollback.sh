#!/usr/bin/env bash
#
# Restore a configuration snapshot created by backup.sh.
#
#   rollback.sh [--list] [--id ID] [--dry-run] [--yes]
#
# Only paths listed in config/managed_paths.yml are restored. Files that did not
# exist before the snapshot are removed. SSH configuration is validated before
# the service is reloaded, so a rollback cannot silently break sshd.
set -Eeuo pipefail
umask 077

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "$HERE/common.sh"

LIST=0
SNAP_ID=""
DRY_RUN=0

usage() {
    cat <<'EOF'
Restore a vps-harden configuration snapshot.

Usage: rollback.sh [options]

Options:
  --list          List available snapshots
  --id ID         Snapshot to restore (default: most recent)
  --dry-run       Print the restore plan without changing anything
  --yes           Skip the confirmation prompt (automation)
  -h, --help      Show this help

Service reloads happen only after the restored configuration validates.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST=1
            shift
            ;;
        --id)
            SNAP_ID="${2:?--id needs a value}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --yes | -y)
            VH_ASSUME_YES=1
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

base_args=(restore --backup-dir "$BACKUP_DIR" --paths-file "$PATHS_FILE" --root "${VH_ROOT:-}" --json)
[[ -n "$SNAP_ID" ]] && base_args+=(--id "$SNAP_ID")

# Always compute the plan without writing, so the confirmation prompt is
# shown BEFORE anything changes.
plan="$("$PY" "$HERE/snapshot.py" "${base_args[@]}" --dry-run)" ||
    vh_die "$VH_EXIT_ERROR" "Rollback failed."

count_restore=$(grep -c '"action": "restored"' <<<"$plan" || true)
count_remove=$(grep -c '"action": "removed"' <<<"$plan" || true)
count_refused=$(grep -c '"action": "refused"' <<<"$plan" || true)

vh_info "Plan: ${count_restore} restored, ${count_remove} removed, ${count_refused} refused"

if [[ "$DRY_RUN" == "1" ]]; then
    "$PY" -c '
import json, sys
for action in json.load(sys.stdin):
    print(f"{action[\"action\"]:<9} {action[\"path\"]}")
' <<<"$plan"
    exit "$VH_EXIT_OK"
fi

if [[ "$count_refused" != "0" ]]; then
    vh_err "Some paths in this snapshot are no longer managed; refusing to continue."
    "$PY" -c '
import json, sys
for action in json.load(sys.stdin):
    if action["action"] == "refused":
        print(f"  refused  {action[\"path\"]}: {action.get(\"detail\", \"\")}")
' <<<"$plan"
    exit "$VH_EXIT_ERROR"
fi

vh_warn "This restores configuration on $(hostname) and reloads affected services."
vh_confirm "Restore this snapshot now?" "no" || vh_die "$VH_EXIT_ERROR" "Rollback cancelled."

if ! "$PY" "$HERE/snapshot.py" "${base_args[@]}" >/dev/null; then
    vh_die "$VH_EXIT_ERROR" "Rollback failed while writing files."
fi
vh_ok "Configuration files restored."

# Sandbox mode (VH_ROOT) exists for tests: never reload the real services.
if [[ -n "${VH_ROOT:-}" ]]; then
    vh_warn "Sandbox mode (VH_ROOT set): skipping service validation and reloads."
    exit "$VH_EXIT_OK"
fi

# ---------------------------------------------------------------- reload logic
# Only reload what we touched, and only after validating the result.
reload_ssh=0
reload_fail2ban=0
reload_crowdsec=0
reload_ufw=0
grep -q '/etc/ssh/' <<<"$plan" && reload_ssh=1
grep -q '/etc/fail2ban/' <<<"$plan" && reload_fail2ban=1
grep -q '/etc/crowdsec/' <<<"$plan" && reload_crowdsec=1
grep -q '/etc/ufw/' <<<"$plan" && reload_ufw=1

if [[ "$reload_ssh" == "1" ]]; then
    if /usr/sbin/sshd -t 2>/dev/null; then
        if systemctl is-active --quiet ssh; then
            systemctl reload ssh && vh_ok "SSH configuration validated and reloaded."
        else
            vh_warn "sshd is not running; configuration validated but not reloaded."
        fi
    else
        vh_err "Restored SSH configuration FAILS validation. SSH was NOT reloaded."
        vh_err "Fix /etc/ssh/sshd_config* now, before closing this session."
        exit "$VH_EXIT_CONFIG"
    fi
fi

if [[ "$reload_fail2ban" == "1" ]] && systemctl is-active --quiet fail2ban; then
    if fail2ban-client -t >/dev/null 2>&1; then
        systemctl restart fail2ban && vh_ok "fail2ban restarted."
    else
        vh_err "fail2ban configuration is invalid after restore; service left running."
    fi
fi

if [[ "$reload_crowdsec" == "1" ]] && systemctl is-active --quiet crowdsec; then
    systemctl restart crowdsec && vh_ok "crowdsec restarted."
fi

if [[ "$reload_ufw" == "1" ]] && command -v ufw >/dev/null 2>&1; then
    ufw reload >/dev/null && vh_ok "Firewall rules reloaded."
fi

vh_ok "Rollback complete. Verify with: sudo ./install.sh verify"
