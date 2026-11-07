#!/usr/bin/env bash
#
# vps-harden — Ubuntu VPS security & homelab hardening toolkit.
#
# This script is deliberately thin: it checks prerequisites, parses arguments,
# selects a playbook and reports results. All configuration is implemented in
# Ansible (playbooks/ + roles/).
#
# Run `./install.sh help` for usage.
set -Eeuo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/common.sh
source "$REPO_ROOT/scripts/common.sh"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
CONFIG_FILE="${VH_CONFIG_FILE:-$REPO_ROOT/config/vps-harden.yml}"
DRY_RUN=0
QUIET=0
JSON_OUT=0
EXTRA_ARGS=()
COMPONENTS=()
DEADMAN=""
NO_BOOTSTRAP=0
PURGE=0

declare -A COMPONENT_TAGS=(
    [common]=common
    [baseline]=common
    [ssh]=ssh
    [ufw]=ufw
    [firewall]=ufw
    [fail2ban]=fail2ban
    [crowdsec]=crowdsec
    [unattended]=unattended
    [upgrades]=unattended
    [unattended-upgrades]=unattended
    [tailscale]=tailscale
    [docker]=docker
    [monitoring]=monitoring
    [logging]=logging
    [hermes]=hermes
    [backup]=backup
)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
vps-harden — security hardening and homelab baseline for Ubuntu VPS

USAGE
  sudo ./install.sh <command> [components] [options]

COMMANDS
  check                 Verify prerequisites, dependencies and configuration.
                        Changes nothing; safe to run as an unprivileged user.
  discover              Read-only infrastructure inventory (writes a report).
  install [comp...]     Install packages and repositories.
  configure [comp...]   Apply configuration to installed components.
  audit                 Read-only security audit with PASS/WARN/FAIL findings.
  verify                Verify that configured controls are actually in effect.
  status                Component and service status summary.
  backup                Snapshot all vps-harden managed configuration.
  rollback              Restore configuration from a snapshot.
  uninstall             Remove vps-harden configuration (keeps packages).
  config show|validate  Show the effective configuration / validate the file.
  firewall status|rules|cancel-deadman
  fail2ban status|bans|unban <ip>
  crowdsec status|decisions|bouncers|alerts
  ssh status|validate
  help [command]        Detailed help for one command.
  version               Print the version.

COMPONENTS
  common      Baseline: packages, timezone, time sync, sysctl, permissions, auditd
  ssh         OpenSSH hardening (keys, root login, password auth, limits)
  ufw         Firewall: default deny, explicit allowlist, Docker awareness
  fail2ban    Intrusion prevention with progressive bans
  crowdsec    Threat detection (firewall enforcement is opt-in)
  unattended  Automatic security updates
  tailscale   Private overlay networking (never auto-authenticated)
  docker      Docker Engine + Compose plugin with hardened daemon defaults
  monitoring  Prometheus + Grafana + node_exporter (localhost-bound)
  logging     journald retention + optional Loki/Promtail stack
  hermes      Hermes Agent integration (read-only MCP server + skill)
  backup      Scheduled restic backups of configuration and data

  With no component, every enabled component is applied. Naming a component
  limits the run to that component (the baseline package cache still runs).

OPTIONS
  --check, --dry-run    Show what would change; make no changes (Ansible check mode)
  --diff                Show configuration diffs (implied by --check)
  -y, --yes             Assume yes for confirmation prompts (automation)
  --non-interactive     Never prompt; requires --yes for changing commands
  --config FILE         Use FILE instead of config/vps-harden.yml
  --deadman MINUTES     Auto-disable UFW after N minutes (lockout escape hatch)
  -e, --extra-vars VARS Pass extra Ansible variables (e.g. tailscale_auth_key=...)
  --vault-password-file FILE   Decrypt Ansible Vault variables with FILE
  --vault-id ID         Vault identity (see ansible-playbook --help)
  --purge               uninstall: also remove packages vps-harden installed
  --json                audit: print the machine-readable report
  -v, --verbose         Verbose output (repeat for more: -vv)
  --no-bootstrap        Do not install Ansible automatically
  --no-color            Disable ANSI colour
  -h, --help            This help
  --version             Print the version

EXAMPLES
  sudo ./install.sh check
  sudo ./install.sh discover
  sudo ./install.sh install ufw
  sudo ./install.sh configure
  sudo ./install.sh audit
  sudo ./install.sh audit --json
  sudo ./install.sh install --check          # dry run
  sudo ./install.sh backup --reason before-upgrade
  sudo ./install.sh rollback --list
  sudo ./install.sh rollback --id 20261107T061500Z-configure --yes

EXIT CODES
  0 success   2 usage   3 prerequisites   4 unsupported system
  5 invalid configuration   6 apply/verify failed   7 audit found FAIL
EOF
}

help_command() {
    local cmd=${1:-}
    case "$cmd" in
        install | configure | site)
            cat <<EOF
$cmd — apply configuration

  sudo ./install.sh $cmd [component...] [--check] [--yes]

Runs playbooks/$([[ "$cmd" == "configure" ]] && echo configure || echo install).yml through Ansible.
Order is fixed: baseline -> SSH -> firewall -> fail2ban -> crowdsec ->
automatic updates -> optional components. A configuration snapshot is taken
before the first change.

Safety: the SSH role refuses to disable password authentication unless it can
see an authorized key for a sudo user; the firewall role refuses to enable UFW
unless an allow rule covers the SSH port.
EOF
            ;;
        audit)
            cat <<'EOF'
audit — read-only security report

  sudo ./install.sh audit [--json] [--fail-on warn|fail|never]

Checks system, firewall, listening ports, SSH, fail2ban, CrowdSec, automatic
updates, file permissions, kernel hardening, Tailscale and Docker. Each finding
is PASS, WARN, FAIL, NOT CONFIGURED or SKIPPED, with a remediation command.
Exit code 7 when a FAIL finding exists (configurable in vps_harden.audit).
EOF
            ;;
        rollback)
            cat <<'EOF'
rollback — restore managed configuration

  sudo ./install.sh rollback --list
  sudo ./install.sh rollback --dry-run
  sudo ./install.sh rollback --id <snapshot> --yes

Only files listed in config/managed_paths.yml are restored. Files created by
vps-harden are removed if they did not exist in the snapshot. sshd is validated
with `sshd -t` before being reloaded; if the restored configuration is invalid,
SSH is left untouched and the command exits non-zero.
EOF
            ;;
        *)
            usage
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
# Commands that define their own argument grammar get everything after the verb
# verbatim, so `rollback --list` and `fail2ban unban 1.2.3.4` work unchanged.
PASSTHRU=()
case "${1:-}" in
    rollback | firewall | fail2ban | crowdsec | ssh | config | discover | status | help | version)
        COMMAND="$1"
        shift
        PASSTHRU=("$@")
        set --
        ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check | --dry-run)
            DRY_RUN=1
            shift
            ;;
        --diff)
            EXTRA_ARGS+=(--diff)
            shift
            ;;
        -y | --yes)
            VH_ASSUME_YES=1
            shift
            ;;
        --non-interactive)
            VH_NON_INTERACTIVE=1
            shift
            ;;
        --config)
            CONFIG_FILE="${2:?--config needs a path}"
            shift 2
            ;;
        --deadman)
            DEADMAN="${2:?--deadman needs minutes}"
            shift 2
            ;;
        --reason)
            BACKUP_REASON="${2:?--reason needs a value}"
            shift 2
            ;;
        -e | --extra-vars)
            EXTRA_ARGS+=(-e "${2:?--extra-vars needs a value}")
            shift 2
            ;;
        --vault-password-file)
            EXTRA_ARGS+=(--vault-password-file "${2:?--vault-password-file needs a path}")
            shift 2
            ;;
        --vault-id)
            EXTRA_ARGS+=(--vault-id "${2:?--vault-id needs a value}")
            shift 2
            ;;
        --purge)
            PURGE=1
            shift
            ;;
        --json)
            JSON_OUT=1
            shift
            ;;
        -v | --verbose)
            VH_VERBOSE=1
            EXTRA_ARGS+=(-v)
            shift
            ;;
        -vv)
            VH_VERBOSE=1
            EXTRA_ARGS+=(-vv)
            shift
            ;;
        --no-bootstrap)
            NO_BOOTSTRAP=1
            shift
            ;;
        --no-color)
            NO_COLOR=1
            shift
            ;;
        -q | --quiet)
            QUIET=1
            shift
            ;;
        -h | --help)
            USAGE_HELP=1
            shift
            ;;
        --version)
            COMMAND=version
            shift
            ;;
        --)
            shift
            EXTRA_ARGS+=("$@")
            break
            ;;
        -*)
            vh_err "Unknown option: $1"
            printf "Run './install.sh help' for usage.\n" >&2
            exit "$VH_EXIT_USAGE"
            ;;
        *)
            if [[ -z "${COMMAND:-}" ]]; then
                COMMAND="$1"
            else
                COMPONENTS+=("$1")
            fi
            shift
            ;;
    esac
done

COMMAND="${COMMAND:-help}"
export VH_CONFIG_FILE="$CONFIG_FILE"
if [[ "${USAGE_HELP:-0}" == "1" && "$COMMAND" == "help" ]]; then
    usage
    exit "$VH_EXIT_OK"
fi

# ---------------------------------------------------------------------------
# Ansible plumbing
# ---------------------------------------------------------------------------
vh_ansible_playbook() {
    if [[ -n "${VH_ANSIBLE:-}" && -x "${VH_ANSIBLE}" ]]; then
        printf '%s\n' "$VH_ANSIBLE"
        return 0
    fi
    local candidate
    for candidate in \
        "$(command -v ansible-playbook || true)" \
        "$HOME/.vps-harden/venv/bin/ansible-playbook" \
        /usr/bin/ansible-playbook; do
        [[ -n "$candidate" && -x "$candidate" ]] && {
            printf '%s\n' "$candidate"
            return 0
        }
    done
    return 1
}

ensure_ansible() {
    if vh_ansible_playbook >/dev/null; then
        return 0
    fi
    if [[ "$NO_BOOTSTRAP" == "1" ]]; then
        vh_die "$VH_EXIT_PREREQ" "Ansible is not installed and --no-bootstrap was given."
    fi
    vh_step "Ansible is required; installing it"
    "$REPO_ROOT/scripts/bootstrap.sh" || vh_die "$VH_EXIT_PREREQ" "Could not install Ansible."
}

resolve_tags() {
    local out=()
    local component tag
    for component in "$@"; do
        tag="${COMPONENT_TAGS[$component]:-}"
        if [[ -z "$tag" ]]; then
            vh_err "Unknown component: $component"
            vh_info "Known components: ${!COMPONENT_TAGS[*]}"
            exit "$VH_EXIT_USAGE"
        fi
        [[ " ${out[*]:-} " == *" $tag "* ]] || out+=("$tag")
    done
    local IFS=,
    printf '%s\n' "${out[*]}"
}

validate_config() {
    local py
    py="$(vh_require_python_yaml)" || return "$VH_EXIT_PREREQ"
    local args=(--defaults "$REPO_ROOT/config/defaults.yml")
    if [[ -f "$CONFIG_FILE" ]]; then
        args+=(--user "$CONFIG_FILE")
    fi
    [[ "${VH_VERBOSE:-0}" == "1" ]] && args+=(--strict)
    if ! "$py" "$REPO_ROOT/scripts/validate_config.py" "${args[@]}"; then
        vh_err "Configuration validation failed: $CONFIG_FILE"
        return "$VH_EXIT_CONFIG"
    fi
}

run_playbook() {
    local playbook=$1
    local tags=${2:-}
    shift 2 || true
    local -a cmd
    cmd=("$(vh_ansible_playbook)" -i "$REPO_ROOT/inventory/localhost.yml" "$REPO_ROOT/playbooks/$playbook")

    [[ -f "$CONFIG_FILE" ]] && cmd+=(-e "vps_harden_config_file=$CONFIG_FILE")
    [[ -n "$tags" ]] && cmd+=(--tags "$tags")
    [[ "$DRY_RUN" == "1" ]] && cmd+=(--check --diff)
    [[ -n "$DEADMAN" ]] && cmd+=(-e "ufw_deadman_minutes=$DEADMAN")
    [[ ${#EXTRA_ARGS[@]} -gt 0 ]] && cmd+=("${EXTRA_ARGS[@]}")
    [[ $# -gt 0 ]] && cmd+=("$@")

    export ANSIBLE_FORCE_COLOR="${ANSIBLE_FORCE_COLOR:-$(vh_is_tty && echo 1 || echo 0)}"
    export ANSIBLE_NOCOLOR="${NO_COLOR:+1}"
    export ANSIBLE_RETRY_FILES_ENABLED=False
    export ANSIBLE_HOST_KEY_CHECKING=False
    export ANSIBLE_CONFIG="$REPO_ROOT/ansible.cfg"
    export ANSIBLE_ROLES_PATH="$REPO_ROOT/roles"
    mkdir -p -- "$(vh_log_dir)"
    ANSIBLE_LOG_PATH="$(vh_log_file)"
    export ANSIBLE_LOG_PATH
    cd "$REPO_ROOT"

    vh_debug "Running: ${cmd[*]}"
    set +e
    "${cmd[@]}"
    local rc=$?
    set -e
    return "$rc"
}

# ---------------------------------------------------------------------------
# Pre-flight summary
# ---------------------------------------------------------------------------
preflight_summary() {
    local mode=$1
    # shellcheck disable=SC1091
    . /etc/os-release
    printf '\n'
    vh_info "Host      : $(hostname) — ${PRETTY_NAME:-unknown} ($(uname -r))"
    vh_info "Mode      : $mode$([[ "$DRY_RUN" == "1" ]] && echo ' (dry run — no changes)')"
    vh_info "Config    : $CONFIG_FILE$([[ -f "$CONFIG_FILE" ]] || echo ' (absent — defaults apply)')"
    vh_info "SSH port  : $(vh_config_value ssh.port 22)"
    vh_info "UFW       : $(vh_config_value ufw.enabled true) · fail2ban: $(vh_config_value fail2ban.enabled true) · crowdsec: $(vh_config_value crowdsec.enabled true)"
    vh_info "Snapshot  : ${VH_BACKUP_DIR:-$(vh_config_value backup_dir /var/backups/vps-harden)}"
    printf '\n'

    vh_warn "Installing or configuring security software changes the running system."
    vh_warn "Keep this SSH session open until you have verified access in a new one."
    printf '\n'
}

confirm_run() {
    local verb=$1
    [[ "$DRY_RUN" == "1" ]] && return 0
    [[ "${VH_ASSUME_YES:-0}" == "1" ]] && return 0
    if [[ "${VH_NON_INTERACTIVE:-0}" == "1" || ! -t 0 ]]; then
        vh_err "Refusing to $verb without confirmation (non-interactive session)."
        vh_info "Re-run with --yes to confirm."
        return 1
    fi
    vh_confirm "$verb on $(hostname) now?" "no"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_check() {
    local failures=0
    local os_unsupported=0

    vh_step "Prerequisites"
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        vh_warn "Not running as root: changing commands will need sudo."
    else
        vh_ok "Running as root"
    fi

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}:${VERSION_ID:-}" in
            ubuntu:22.04 | ubuntu:24.04) vh_ok "Supported OS: ${PRETTY_NAME}" ;;
            ubuntu:*) vh_warn "Untested Ubuntu release: ${PRETTY_NAME} (22.04 and 24.04 are supported)" ;;
            *)
                vh_err "Unsupported OS: ${PRETTY_NAME:-unknown} (Ubuntu 22.04/24.04 required)"
                os_unsupported=1
                ;;
        esac
    else
        vh_err "/etc/os-release is missing; cannot determine the OS"
        os_unsupported=1
    fi

    if [[ -d /run/systemd/system ]]; then
        vh_ok "systemd is running"
    else
        vh_err "systemd is not running (containers without systemd are unsupported)"; failures=$((failures + 1))
    fi

    local cmd
    for cmd in curl tar gpg; do
        if vh_have "$cmd"; then
            vh_debug "$cmd present"
        else
            vh_warn "$cmd is missing; it will be installed by the baseline role"
        fi
    done

    vh_step "Ansible"
    if vh_have ansible-playbook; then
        vh_ok "$(ansible-playbook --version 2>/dev/null | head -1)"
    else
        vh_warn "Ansible is not installed (install.sh will bootstrap it)"
    fi

    vh_step "Configuration"
    if [[ -f "$CONFIG_FILE" ]]; then
        validate_config || failures=$((failures + 1))
    else
        vh_warn "No user configuration at $CONFIG_FILE — built-in defaults apply"
        vh_info "Start with: cp config/example.yml config/vps-harden.yml"
        local py
        py="$(vh_require_python_yaml)" || failures=$((failures + 1))
        if [[ -n "${py:-}" ]]; then
            "$py" "$REPO_ROOT/scripts/validate_config.py" \
                --defaults "$REPO_ROOT/config/defaults.yml" >/dev/null || failures=$((failures + 1))
        fi
    fi

    vh_step "SSH access"
    local keys=0
    local home
    for home in /root /home/*; do
        [[ -f "$home/.ssh/authorized_keys" ]] || continue
        local count
        count="$(grep -c '^\(ssh\|ecdsa\|sk\)-' "$home/.ssh/authorized_keys" 2>/dev/null || true)"
        keys=$((keys + count))
        [[ "$count" -gt 0 ]] && vh_ok "$home has $count authorized key(s)"
    done
    if [[ "$keys" -eq 0 ]]; then
        vh_warn "No authorized SSH keys found. Do NOT disable password authentication yet."
    fi

    vh_step "Current security state"
    printf '  firewall : %s\n' "$(ufw status 2>/dev/null | head -1 || echo 'ufw not installed')"
    printf '  fail2ban : %s\n' "$(systemctl is-active fail2ban 2>/dev/null || echo 'not installed')"
    printf '  crowdsec : %s\n' "$(systemctl is-active crowdsec 2>/dev/null || echo 'not installed')"

    printf '\n'
    if [[ "$os_unsupported" == "1" ]]; then
        vh_err "This system is not supported; vps-harden will not run here."
        return "$VH_EXIT_UNSUPPORTED"
    fi
    if [[ "$failures" -gt 0 ]]; then
        vh_err "Check found $failures blocking problem(s)."
        return "$VH_EXIT_PREREQ"
    fi
    vh_ok "Prerequisites look good. Next: sudo ./install.sh install --check"
}

cmd_apply() {
    local phase=$1
    shift
    local playbook tags=""
    case "$phase" in
        install) playbook=install.yml ;;
        configure) playbook=configure.yml ;;
        site) playbook=site.yml ;;
        *) vh_die "$VH_EXIT_USAGE" "Unknown phase: $phase" ;;
    esac

    vh_require_root "$phase"
    ensure_ansible
    validate_config || exit "$VH_EXIT_CONFIG"

    if [[ ${#COMPONENTS[@]} -gt 0 ]]; then
        tags="$(resolve_tags "${COMPONENTS[@]}")"
    fi

    preflight_summary "$phase${tags:+ · components: ${tags}}"
    confirm_run "Apply $phase" || vh_die "$VH_EXIT_ERROR" "Cancelled."

    vh_step "Running playbooks/$playbook"
    local rc=0
    run_playbook "$playbook" "$tags" || rc=$?

    if [[ "$rc" -ne 0 ]]; then
        vh_err "Playbook failed (exit $rc). Configuration snapshot:"
        vh_info "  sudo ./install.sh rollback --list"
        return "$VH_EXIT_APPLY"
    fi

    vh_ok "Playbook completed."
    if [[ "$DRY_RUN" == "1" ]]; then
        vh_info "Dry run: nothing was changed."
    else
        vh_info "Verify the result with: sudo ./install.sh verify"
        vh_info "Then audit the posture: sudo ./install.sh audit"
    fi
}

cmd_audit() {
    vh_require_root audit
    ensure_ansible
    validate_config || exit "$VH_EXIT_CONFIG"

    local reports_dir
    reports_dir="$(vh_config_value reports_dir /var/lib/vps-harden/reports)"
    local rc=0
    run_playbook audit.yml audit || rc=$?

    if [[ "$JSON_OUT" == "1" ]]; then
        local newest
        newest="$(find "$reports_dir" -maxdepth 1 -name 'audit-*.json' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true)"
        if [[ -n "$newest" ]]; then
            cat "$newest"
        else
            vh_err "No JSON audit report was produced in $reports_dir"
            return "$VH_EXIT_ERROR"
        fi
    else
        local newest
        newest="$(find "$reports_dir" -maxdepth 1 -name 'audit-*.txt' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true)"
        if [[ -n "$newest" ]]; then
            cat "$newest"
        fi
    fi

    [[ "$rc" -eq 0 ]] || return "$VH_EXIT_AUDIT"
    return 0
}

cmd_verify() {
    vh_require_root verify
    ensure_ansible
    validate_config || exit "$VH_EXIT_CONFIG"
    local rc=0
    run_playbook verify.yml verify || rc=$?
    [[ "$rc" -eq 0 ]] || return "$VH_EXIT_APPLY"
    vh_ok "All configured controls verified."
}

cmd_backup() {
    vh_require_root backup
    local -a args=()
    [[ "$QUIET" == "1" ]] && args+=(--quiet)
    args+=(--reason "${BACKUP_REASON:-manual}")
    "$REPO_ROOT/scripts/backup.sh" "${args[@]}"
}

cmd_rollback() {
    vh_require_root rollback
    "$REPO_ROOT/scripts/rollback.sh" "$@"
}

cmd_uninstall() {
    vh_require_root uninstall
    ensure_ansible
    preflight_summary "uninstall"
    vh_warn "This removes vps-harden configuration files. Packages and data stay."
    confirm_run "Uninstall vps-harden configuration" ||
        vh_die "$VH_EXIT_ERROR" "Cancelled."

    local rc=0
    run_playbook uninstall.yml "" \
        -e vh_uninstall_confirm=true \
        -e "vh_uninstall_purge=$([[ "$PURGE" == "1" ]] && echo true || echo false)" || rc=$?
    [[ "$rc" -eq 0 ]] || return "$VH_EXIT_APPLY"
    vh_ok "Uninstalled. Snapshots remain available via: ./install.sh rollback --list"
}

cmd_config() {
    local action=${1:-show}
    local py
    py="$(vh_require_python_yaml)" || exit "$VH_EXIT_PREREQ"
    case "$action" in
        path)
            printf '%s\n' "$CONFIG_FILE"
            ;;
        validate)
            validate_config || exit "$VH_EXIT_CONFIG"
            ;;
        show)
            "$py" - "$REPO_ROOT/config/defaults.yml" "$CONFIG_FILE" <<'PY'
import sys, yaml

def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except OSError:
        return {}

def merge(base, override):
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = value
    return out

cfg = merge(load(sys.argv[1]).get("vps_harden", {}), load(sys.argv[2]).get("vps_harden", {}))
print(yaml.safe_dump({"vps_harden": cfg}, sort_keys=False, default_flow_style=False), end="")
PY
            ;;
        *)
            vh_err "Unknown config action: $action (use show|validate|path)"
            return "$VH_EXIT_USAGE"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Component shortcuts (read-only unless stated)
# ---------------------------------------------------------------------------
need_component() {
    local bin=$1 name=$2
    vh_have "$bin" || vh_die "$VH_EXIT_PREREQ" "$name is not installed. Run: sudo ./install.sh install $3"
}

cmd_firewall() {
    local action=${1:-status}
    case "$action" in
        status)
            need_component ufw "UFW" ufw
            ufw status verbose
            ;;
        rules)
            need_component ufw "UFW" ufw
            vh_step "UFW rules"
            ufw status numbered
            printf '\n'
            vh_step "Docker publishes (bypass UFW INPUT)"
            if vh_have docker; then
                docker ps --format '{{.Names}}\t{{.Ports}}' | grep -v '127.0.0.1' || printf 'none\n'
                printf '\nDOCKER-USER chain:\n'
                iptables -S DOCKER-USER 2>/dev/null || printf '(absent)\n'
            else
                printf 'docker not installed\n'
            fi
            ;;
        cancel-deadman)
            vh_require_root cancel-deadman
            if systemctl list-timers --all --no-legend 2>/dev/null | grep -q 'vh-ufw-deadman'; then
                systemctl stop vh-ufw-deadman.timer 2>/dev/null || true
                vh_ok "Dead-man switch cancelled. Firewall changes are now permanent."
            else
                vh_warn "No pending dead-man switch found."
            fi
            ;;
        *)
            vh_err "Unknown firewall action: $action (status|rules|cancel-deadman)"
            return "$VH_EXIT_USAGE"
            ;;
    esac
}

cmd_fail2ban() {
    local action=${1:-status}
    case "$action" in
        status)
            need_component fail2ban-client "Fail2ban" fail2ban
            fail2ban-client status
            ;;
        bans)
            need_component fail2ban-client "Fail2ban" fail2ban
            fail2ban-client status sshd
            ;;
        unban)
            local ip=${2:-}
            [[ -n "$ip" ]] || vh_die "$VH_EXIT_USAGE" "Usage: install.sh fail2ban unban <ip>"
            vh_require_root unban
            fail2ban-client set sshd unbanip "$ip"
            ;;
        *)
            vh_err "Unknown fail2ban action: $action (status|bans|unban)"
            return "$VH_EXIT_USAGE"
            ;;
    esac
}

cmd_crowdsec() {
    local action=${1:-status}
    need_component cscli "CrowdSec" crowdsec
    case "$action" in
        status)
            systemctl status crowdsec --no-pager -n 5 || true
            cscli lapi status || true
            ;;
        decisions) cscli decisions list ;;
        bouncers) cscli bouncers list ;;
        alerts) cscli alerts list ;;
        *)
            vh_err "Unknown crowdsec action: $action (status|decisions|bouncers|alerts)"
            return "$VH_EXIT_USAGE"
            ;;
    esac
}

cmd_ssh() {
    local action=${1:-status}
    case "$action" in
        status)
            printf '%-32s %s\n' "Effective configuration" ""
            local key
            for key in port permitrootlogin passwordauthentication pubkeyauthentication \
                kbdinteractiveauthentication maxauthtries x11forwarding allowtcpforwarding; do
                printf '  %-30s %s\n' "$key" "$(sshd -T 2>/dev/null | awk -v k="$key" '$1==k{print $2}')"
            done
            printf '\nDrop-in files:\n'
            find /etc/ssh/sshd_config.d -maxdepth 1 -name '*.conf' -printf '  %f\n' 2>/dev/null
            ;;
        validate)
            vh_require_root validate
            if sshd -t; then
                vh_ok "sshd configuration is valid."
            else
                vh_err "sshd configuration is INVALID."
                return "$VH_EXIT_CONFIG"
            fi
            ;;
        *)
            vh_err "Unknown ssh action: $action (status|validate)"
            return "$VH_EXIT_USAGE"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "$COMMAND" in
    help) help_command "${PASSTHRU[0]:-}" ;;
    version)
        printf 'vps-harden %s\n' "$(vh_version)"
        ;;
    check) cmd_check ;;
    discover)
        "$REPO_ROOT/scripts/inventory.sh" ${PASSTHRU[@]+"${PASSTHRU[@]}"}
        ;;
    install | configure | site) cmd_apply "$COMMAND" ;;
    audit) cmd_audit ;;
    verify) cmd_verify ;;
    status) "$REPO_ROOT/scripts/status.sh" ${PASSTHRU[@]+"${PASSTHRU[@]}"} ;;
    backup) cmd_backup ;;
    rollback) cmd_rollback ${PASSTHRU[@]+"${PASSTHRU[@]}"} ;;
    uninstall) cmd_uninstall ;;
    firewall) cmd_firewall ${PASSTHRU[@]+"${PASSTHRU[@]}"} ;;
    fail2ban) cmd_fail2ban ${PASSTHRU[@]+"${PASSTHRU[@]}"} ;;
    crowdsec) cmd_crowdsec ${PASSTHRU[@]+"${PASSTHRU[@]}"} ;;
    ssh) cmd_ssh ${PASSTHRU[@]+"${PASSTHRU[@]}"} ;;
    config) cmd_config ${PASSTHRU[@]+"${PASSTHRU[@]}"} ;;
    *)
        vh_err "Unknown command: $COMMAND"
        printf "Run './install.sh help' for usage.\n" >&2
        exit "$VH_EXIT_USAGE"
        ;;
esac
