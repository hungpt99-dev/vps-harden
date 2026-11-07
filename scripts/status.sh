#!/usr/bin/env bash
#
# Component status summary. Read-only; no configuration is evaluated for
# compliance here (that is `install.sh audit`).
set -Eeuo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "$HERE/common.sh"

QUIET=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet) QUIET=1; shift ;;
        -h | --help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) vh_err "Unknown argument: $1"; exit "$VH_EXIT_USAGE" ;;
    esac
done

unit_state() {
    local unit=$1
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        printf 'n/a'
        return
    fi
    local active enabled
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    printf '%s/%s' "${active:-unknown}" "${enabled:-unknown}"
}

pkg_state() {
    local pkg=$1
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
        printf 'yes'
    else
        printf 'no'
    fi
}

row() {
    printf '%-14s %-10s %-22s %s\n' "$1" "$2" "$3" "$4"
}

main() {
    # shellcheck disable=SC1091
    . /etc/os-release
    printf '\n%s — %s (%s)\n' "$(hostname)" "${PRETTY_NAME:-unknown}" "$(uname -r)"
    printf 'vps-harden %s · %s\n\n' "$(vh_version)" "$(date -u '+%Y-%m-%d %H:%M UTC')"

    row "COMPONENT" "INSTALLED" "SERVICE/BOOT" "DETAIL"

    if command -v ufw >/dev/null 2>&1; then
        local ufw_first
        ufw_first="$(ufw status 2>/dev/null | head -1 || true)"
        row "ufw" "yes" "$(unit_state ufw)" "${ufw_first:-unknown}"
    else
        row "ufw" "no" "n/a" "not installed"
    fi

    if command -v sshd >/dev/null 2>&1; then
        local ssh_port
        ssh_port="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"
        row "openssh" "yes" "$(unit_state ssh)" "listening on port ${ssh_port:-?}"
    else
        row "openssh" "no" "n/a" "not installed"
    fi

    if command -v fail2ban-client >/dev/null 2>&1; then
        local jails
        jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr -d '\t' || true)"
        row "fail2ban" "yes" "$(unit_state fail2ban)" "jails: ${jails:-none}"
    else
        row "fail2ban" "no" "n/a" "not installed"
    fi

    if command -v cscli >/dev/null 2>&1; then
        local dec bouncers
        dec="$(cscli decisions list -o json 2>/dev/null | grep -c '"id"' || true)"
        bouncers="$(cscli bouncers list -o json 2>/dev/null | grep -c '"name"' || true)"
        row "crowdsec" "yes" "$(unit_state crowdsec)" "${dec} decision(s), ${bouncers} bouncer(s)"
    else
        row "crowdsec" "no" "n/a" "not installed"
    fi

    row "unattended" "$(pkg_state unattended-upgrades)" "$(unit_state unattended-upgrades)" \
        "$(grep -h 'Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | tr -d '\n' || echo 'not configured')"

    if command -v tailscale >/dev/null 2>&1; then
        local ts_ip
        ts_ip="$(tailscale ip -4 2>/dev/null | head -1 || true)"
        row "tailscale" "yes" "$(unit_state tailscaled)" "ip: ${ts_ip:-unauthenticated}"
    else
        row "tailscale" "no" "n/a" "not installed"
    fi

    if command -v docker >/dev/null 2>&1; then
        local containers
        containers="$(docker ps -q 2>/dev/null | wc -l)"
        row "docker" "yes" "$(unit_state docker)" "${containers} running container(s)"
    else
        row "docker" "no" "n/a" "not installed"
    fi

    if command -v hermes >/dev/null 2>&1; then
        row "hermes" "yes" "$(unit_state "${VH_HERMES_UNIT:-hermes-gateway.service}")" \
            "$(hermes --version 2>/dev/null | head -1 || echo 'installed')"
    else
        row "hermes" "no" "n/a" "not installed"
    fi

    printf '\nConfiguration: %s\n' "${VH_CONFIG_FILE:-$(vh_repo_root)/config/vps-harden.yml}"
    printf 'Next: sudo %s audit\n' "$0"
}

[[ "$QUIET" == "1" ]] && exec >/dev/null
main
