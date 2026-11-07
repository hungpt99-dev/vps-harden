#!/usr/bin/env bash
#
# Install (or locate) Ansible on this host.
#
#   bootstrap.sh [--check] [--minimal]
#
# Strategy, in order:
#   1. Use an existing ansible-playbook (any recent version).
#   2. Install the distribution package (ansible-core) from Ubuntu.
#   3. Fall back to a dedicated virtualenv with pip, and print its path.
#
# No curl | sh. No third-party repositories.
set -Eeuo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "$HERE/common.sh"

CHECK_ONLY=0
MINIMAL=0
MIN_VERSION="2.15"

usage() {
    cat <<'EOF'
Ensure Ansible is available.

Usage: bootstrap.sh [options]

Options:
  --check     Report what would happen; change nothing
  --minimal   Skip the venv fallback, only use the distribution package
  -h, --help  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        --minimal) MINIMAL=1; shift ;;
        -h | --help) usage; exit "$VH_EXIT_OK" ;;
        *) vh_err "Unknown argument: $1"; usage >&2; exit "$VH_EXIT_USAGE" ;;
    esac
done

version_ok() {
    local bin=$1
    local raw
    raw="$("$bin" --version 2>/dev/null | head -1)" || return 1
    local ver
    ver="$(sed -n 's/.*core \([0-9][0-9.]*\).*/\1/p' <<<"$raw")"
    [[ -n "$ver" ]] || return 1
    printf '%s\n' "$ver" | awk -v min="$MIN_VERSION" '
        function cmp(a, b,   i, n, pa, pb) {
            n = split(a, pa, "."); split(b, pb, ".")
            for (i = 1; i <= 3; i++) {
                if ((pa[i] + 0) > (pb[i] + 0)) return 1
                if ((pa[i] + 0) < (pb[i] + 0)) return -1
            }
            return 0
        }
        { exit (cmp($0, min) >= 0) ? 0 : 1 }
    '
}

report_existing() {
    local bin=$1
    vh_ok "Ansible found: $bin ($("$bin" --version 2>/dev/null | head -1))"
    printf 'ANSIBLE_PLAYBOOK=%s\n' "$bin"
}

if vh_have ansible-playbook && version_ok ansible-playbook; then
    report_existing "$(command -v ansible-playbook)"
    exit "$VH_EXIT_OK"
fi

if [[ "$CHECK_ONLY" == "1" ]]; then
    vh_warn "Ansible >= $MIN_VERSION is not installed; 'install' would install it."
    vh_info "Command that would run: apt-get install -y ansible-core"
    exit "$VH_EXIT_OK"
fi

vh_step "Installing ansible-core"
if vh_have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || vh_warn "apt-get update failed; continuing with cached lists"
    if apt-get install -y -qq ansible-core >/dev/null 2>&1 &&
        vh_have ansible-playbook && version_ok ansible-playbook; then
        report_existing "$(command -v ansible-playbook)"
        exit "$VH_EXIT_OK"
    fi
    vh_warn "Distribution package did not provide Ansible >= $MIN_VERSION"
fi

if [[ "$MINIMAL" == "1" ]]; then
    vh_die "$VH_EXIT_PREREQ" "Ansible >= $MIN_VERSION is required. Install it with: apt-get install -y ansible-core"
fi

vh_step "Falling back to a dedicated virtualenv"
VENV="${VH_VENV:-$HOME/.vps-harden/venv}"
vh_info "Creating $VENV"
if ! python3 -m venv "$VENV" 2>/dev/null; then
    vh_err "python3-venv is missing. Install it with: apt-get install -y python3-venv"
    exit "$VH_EXIT_PREREQ"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
if ! "$VENV/bin/pip" install --quiet "ansible-core>=${MIN_VERSION}"; then
    vh_die "$VH_EXIT_PREREQ" "Could not install ansible-core from PyPI (no network?)."
fi
report_existing "$VENV/bin/ansible-playbook"
