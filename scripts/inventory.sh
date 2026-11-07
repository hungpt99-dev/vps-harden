#!/usr/bin/env bash
#
# Read-only infrastructure inventory.
#
#   inventory.sh [--output FILE] [--quiet]
#
# Produces the "what is already running here" report that must exist before an
# adoption project changes anything. Every probe is read-only; the only write is
# the report file itself (reports/ by default).
set -Eeuo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "$HERE/common.sh"

OUTPUT=""
QUIET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) OUTPUT="${2:?--output needs a value}"; shift 2 ;;
        --quiet) QUIET=1; shift ;;
        -h | --help)
            sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
            exit "$VH_EXIT_OK"
            ;;
        *) vh_err "Unknown argument: $1"; exit "$VH_EXIT_USAGE" ;;
    esac
done

stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
if [[ -z "$OUTPUT" ]]; then
    mkdir -p -- "$(vh_path "$(vh_repo_root)/reports")"
    OUTPUT="$(vh_path "$(vh_repo_root)/reports")/inventory-$stamp.md"
fi

section() { printf '\n## %s\n\n' "$1"; }
cmd_block() {
    local title=$1
    shift
    printf '### %s\n\n```\n' "$title"
    if "$@" 2>&1; then :; else printf '(command failed or unavailable)\n'; fi
    printf '```\n\n'
}

main() {
    printf '# Infrastructure inventory — %s\n\n' "$(hostname)"
    printf 'Generated: %s (UTC) by vps-harden %s\n\n' "$stamp" "$(vh_version)"
    printf '> Read-only discovery. No configuration was changed.\n'

    section "Operating system"
    printf '```\n'
    # shellcheck disable=SC1091
    . /etc/os-release
    printf 'Distribution : %s\n' "${PRETTY_NAME:-unknown}"
    printf 'Kernel       : %s\n' "$(uname -r)"
    printf 'Architecture : %s\n' "$(uname -m)"
    printf 'Uptime       : %s\n' "$(uptime -p 2>/dev/null || uptime)"
    printf 'CPUs         : %s\n' "$(nproc 2>/dev/null || echo '?')"
    printf 'Memory       : %s\n' "$(free -h 2>/dev/null | awk '/^Mem:/{print $3 " used / " $2}')"
    printf 'Root disk    : %s\n' "$(df -h / 2>/dev/null | awk 'NR==2{print $3 " used / " $2 " (" $5 ")"}')"
    printf 'Time sync    : %s\n' "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo 'unknown')"
    printf '```\n'

    section "Network exposure"
    printf 'Listening sockets (0.0.0.0 / :: are internet-reachable):\n\n```\n'
    ss -tulpnH 2>/dev/null | awk '{split($7,a,","); print $1, $5, a[1]}' | sort -u ||
        printf '(ss unavailable)\n'
    printf '```\n\n'

    printf '### Firewall\n\n```\n'
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose 2>&1 || true
    else
        printf 'ufw not installed\n'
    fi
    printf '\n--- nftables ruleset (first 40 lines) ---\n'
    nft list ruleset 2>/dev/null | head -40 || printf '(nft unavailable)\n'
    printf '```\n\n'

    if command -v docker >/dev/null 2>&1; then
        section "Docker"
        printf '```\n'
        docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>&1 | sort || true
        printf '\nVolumes: %s   Networks: %s   Images: %s\n' \
            "$(docker volume ls -q 2>/dev/null | wc -l)" \
            "$(docker network ls -q 2>/dev/null | wc -l)" \
            "$(docker images -q 2>/dev/null | wc -l)"
        printf '```\n\n'
        printf 'Publicly published container ports (these bypass UFW):\n\n```\n'
        docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null |
            grep -o '0\.0\.0\.0:[0-9]*->[0-9]*/[a-z]*' || printf '(none)\n'
        printf '```\n'
    fi

    section "Security controls"
    printf '```\n'
    printf 'ufw          : %s\n' "$(ufw status 2>/dev/null | head -1 || echo 'not installed')"
    printf 'fail2ban     : %s\n' "$(systemctl is-active fail2ban 2>/dev/null || echo 'not installed')"
    printf 'crowdsec     : %s\n' "$(systemctl is-active crowdsec 2>/dev/null || echo 'not installed')"
    printf 'unattended   : %s\n' "$(systemctl is-enabled unattended-upgrades 2>/dev/null || echo 'unknown')"
    printf 'auditd       : %s\n' "$(systemctl is-active auditd 2>/dev/null || echo 'not installed')"
    printf 'tailscaled   : %s\n' "$(systemctl is-active tailscaled 2>/dev/null || echo 'not installed')"
    printf 'docker       : %s\n' "$(systemctl is-active docker 2>/dev/null || echo 'not installed')"
    printf '```\n'

    if command -v tailscale >/dev/null 2>&1; then
        section "Tailscale"
        cmd_block "Status" tailscale status
        cmd_block "Addresses" tailscale ip -4
    fi

    section "SSH effective configuration"
    printf '```\n'
    for key in port permitrootlogin passwordauthentication pubkeyauthentication \
        kbdinteractiveauthentication maxauthtries x11forwarding allowtcpforwarding; do
        printf '%-32s %s\n' "$key" "$(sshd -T 2>/dev/null | awk -v k="$key" '$1==k{print $2}')"
    done
    printf '\nDrop-in files:\n'
    ls -l /etc/ssh/sshd_config.d/ 2>/dev/null || true
    printf '\nAuthorized keys:\n'
    for home in /root /home/*; do
        if [[ -f "$home/.ssh/authorized_keys" ]]; then
            printf '%-16s %s key line(s)\n' "$home" "$(grep -c '^ssh-' "$home/.ssh/authorized_keys" || true)"
        fi
    done
    printf '```\n'

    if command -v fail2ban-client >/dev/null 2>&1; then
        section "Fail2ban"
        cmd_block "Jails" fail2ban-client status
        cmd_block "SSH jail" fail2ban-client status sshd
    fi

    if command -v cscli >/dev/null 2>&1; then
        section "CrowdSec"
        cmd_block "LAPI" cscli lapi status
        cmd_block "Collections" cscli collections list
        cmd_block "Bouncers" cscli bouncers list
        cmd_block "Active decisions" cscli decisions list
    fi

    section "Workloads and data"
    printf '```\n'
    printf '/opt entries:\n'
    ls -1 /opt 2>/dev/null || true
    printf '\n/opt/homelab:\n'
    ls -1 /opt/homelab 2>/dev/null || printf '(absent)\n'
    printf '\nEnabled non-vendor services:\n'
    systemctl list-unit-files --state=enabled --type=service --no-legend --no-pager 2>/dev/null |
        grep -Ev '^(systemd-|dbus|cron|ssh|rsyslog|unattended|apparmor|networkd|resolved|timesyncd|getty|snap|polkit|udisks|multipathd|open-vm|walinuxagent|chrony|qemu)' |
        awk '{print $1}' || true
    printf '```\n'

    section "Pending updates"
    printf '```\n'
    if [[ -x /usr/lib/update-notifier/apt-check ]]; then
        /usr/lib/update-notifier/apt-check --human-readable 2>&1 || true
    else
        apt-get -s upgrade 2>/dev/null | awk '/^[0-9]+ upgraded/{print}' || printf '(apt lists not available)\n'
    fi
    printf '```\n'

    section "Files that vps-harden would own"
    printf '```\n'
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        if [[ -e "$path" ]]; then
            printf 'EXISTS   %s\n' "$path"
        else
            printf 'absent   %s\n' "$path"
        fi
    done < <(grep -E '^    - /' "$HERE/../config/managed_paths.yml" | sed 's/^    - //')
    printf '```\n'
}

main >"$OUTPUT"
[[ "$QUIET" == "1" ]] || cat "$OUTPUT"

vh_ok "Inventory written to $OUTPUT"
