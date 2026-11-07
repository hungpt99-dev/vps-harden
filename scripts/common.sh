#!/usr/bin/env bash
# shellcheck shell=bash
#
# vps-harden shared shell library.
#
# Sourced by install.sh and every script in scripts/. It must stay free of side
# effects: no root check, no writes, no trap installation at source time.
#
# Testability: every filesystem path goes through vh_path(), which prefixes
# $VH_ROOT. Production runs leave VH_ROOT empty; Bats suites point it at a
# sandbox so they can exercise backup/rollback without touching /etc.

# ---------------------------------------------------------------------------
# Constants (consumed by the scripts that source this library)
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034
VH_EXIT_OK=0
VH_EXIT_ERROR=1        # generic failure
VH_EXIT_USAGE=2        # bad CLI arguments
VH_EXIT_PREREQ=3       # missing dependency / not root
VH_EXIT_UNSUPPORTED=4  # unsupported OS, version or architecture
VH_EXIT_CONFIG=5       # invalid configuration
VH_EXIT_APPLY=6        # playbook/apply failure
VH_EXIT_AUDIT=7        # audit found FAIL findings

# shellcheck disable=SC2034
VH_READONLY_MARKER="managed by vps-harden"

# ---------------------------------------------------------------------------
# Paths and environment
# ---------------------------------------------------------------------------
vh_repo_root() {
    local src="${BASH_SOURCE[0]}"
    if [[ -n "${VH_REPO_ROOT:-}" ]]; then
        printf '%s\n' "$VH_REPO_ROOT"
        return 0
    fi
    # Resolve symlinks so `make install` (symlink in /usr/local/bin) works.
    while [[ -L "$src" ]]; do
        local dir
        dir="$(cd -P "$(dirname "$src")" && pwd)"
        src="$(readlink "$src")"
        [[ "$src" != /* ]] && src="$dir/$src"
    done
    cd -P "$(dirname "$src")/.." && pwd
}

# Prefix a system path with $VH_ROOT (tests) or leave it untouched (production).
vh_path() {
    printf '%s%s\n' "${VH_ROOT:-}" "$1"
}

vh_version() {
    local vf
    vf="$(vh_path "$(vh_repo_root)/VERSION")"
    if [[ -r "$vf" ]]; then
        tr -d '[:space:]' <"$vf"
    else
        printf '0.0.0\n'
    fi
}

vh_is_tty() { [[ -t 1 ]]; }

vh_have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
vh_log_dir() { printf '%s\n' "${VH_LOG_DIR:-$(vh_path /var/log/vps-harden)}"; }
vh_log_file() { printf '%s\n' "${VH_LOG_FILE:-$(vh_log_dir)/vps-harden.log}"; }

_vh_color() {
    local code=$1
    shift
    if vh_is_tty && [[ -z "${NO_COLOR:-}" ]]; then
        printf '\033[%sm%s\033[0m' "$code" "$*"
    else
        printf '%s' "$*"
    fi
}

_vh_log_write() {
    local level=$1
    shift
    local file
    file="$(vh_log_file)"
    [[ "${VH_LOG_DISABLE:-0}" == "1" ]] && return 0
    mkdir -p -- "$(dirname -- "$file")" 2>/dev/null || return 0
    printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$level" "$*" \
        >>"$file" 2>/dev/null || true
}

vh_info() {
    _vh_log_write INFO "$*"
    printf '%s %s\n' "$(_vh_color '0;36' '[INFO]')" "$*"
}

vh_ok() {
    _vh_log_write OK "$*"
    printf '%s %s\n' "$(_vh_color '0;32' '[ OK ]')" "$*"
}

vh_warn() {
    _vh_log_write WARN "$*"
    printf '%s %s\n' "$(_vh_color '0;33' '[WARN]')" "$*" >&2
}

vh_err() {
    _vh_log_write ERROR "$*"
    printf '%s %s\n' "$(_vh_color '0;31' '[FAIL]')" "$*" >&2
}

vh_step() {
    _vh_log_write STEP "$*"
    printf '\n%s %s\n' "$(_vh_color '1;34' '==>')" "$*"
}

vh_debug() {
    [[ "${VH_VERBOSE:-0}" == "1" ]] || return 0
    _vh_log_write DEBUG "$*"
    printf '%s %s\n' "$(_vh_color '0;90' '[DBG ]')" "$*" >&2
}

# Print a fatal message and exit with the given code.
vh_die() {
    local code=$1
    shift
    vh_err "$*"
    exit "$code"
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
vh_require_root() {
    if [[ "${VH_ALLOW_NONROOT:-0}" == "1" ]]; then
        vh_debug "Root check skipped (VH_ALLOW_NONROOT=1)"
        return 0
    fi
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        vh_die "$VH_EXIT_PREREQ" "This command changes system state and must run as root. Try: sudo $0 $*"
    fi
}

vh_require_cmd() {
    local missing=()
    local cmd
    for cmd in "$@"; do
        vh_have "$cmd" || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        vh_err "Missing required command(s): ${missing[*]}"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Interactive confirmation
# ---------------------------------------------------------------------------
# Returns 0 when the operation may proceed.
#   VH_ASSUME_YES=1        -> yes (CI / automation)
#   stdin not a terminal   -> no, with an explanation (never guess)
vh_confirm() {
    local prompt=$1
    local default=${2:-no}
    if [[ "${VH_ASSUME_YES:-0}" == "1" ]]; then
        vh_debug "Auto-confirmed: $prompt"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        vh_err "Refusing to continue without confirmation in a non-interactive session: $prompt"
        vh_info "Re-run with --yes to confirm explicitly."
        return 1
    fi
    local reply suffix="[y/N]"
    [[ "$default" == "yes" ]] && suffix="[Y/n]"
    printf '%s %s ' "$prompt" "$suffix" >&2
    read -r reply
    case "${reply:-$default}" in
        y | Y | yes | YES) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Python selection
# ---------------------------------------------------------------------------
# Candidates in priority order; the first one that can import PyYAML wins.
vh_python() {
    local candidate
    for candidate in "${VH_PYTHON:-}" "$(command -v python3 || true)" \
        /usr/bin/python3 "${HOME:-/root}/.venv-vh/bin/python"; do
        [[ -n "$candidate" && -x "$candidate" ]] || continue
        if "$candidate" -c 'import yaml' >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

vh_require_python_yaml() {
    local py
    if ! py="$(vh_python)"; then
        vh_err "No Python interpreter with PyYAML was found."
        vh_info "Install it with: sudo apt-get install -y python3-yaml"
        return 1
    fi
    printf '%s\n' "$py"
}

# Read a value from the effective configuration (defaults <- user file).
#   vh_config_value <dotted.key> [fallback]
# Prints the value; never fails the caller (falls back instead).
vh_config_value() {
    local key=$1
    local fallback=${2:-}
    local py
    if ! py="$(vh_python)"; then
        printf '%s\n' "$fallback"
        return 0
    fi
    "$py" - "$key" "$fallback" \
        "$(vh_repo_root)/config/defaults.yml" \
        "${VH_CONFIG_FILE:-$(vh_repo_root)/config/vps-harden.yml}" <<'PY'
import sys

try:
    import yaml
except ImportError:
    print(sys.argv[2])
    raise SystemExit(0)

key, fallback, defaults_file, user_file = sys.argv[1:5]


def load(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except OSError:
        return {}


def merge(base, override):
    out = dict(base)
    for name, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(name), dict):
            out[name] = merge(out[name], value)
        else:
            out[name] = value
    return out


cfg = merge(load(defaults_file).get("vps_harden", {}), load(user_file).get("vps_harden", {}))
node = cfg
for part in key.split("."):
    if not isinstance(node, dict) or part not in node:
        print(fallback)
        raise SystemExit(0)
    node = node[part]
if isinstance(node, bool):
    print("true" if node else "false")
elif isinstance(node, list):
    print(" ".join(str(item) for item in node))
elif node is None:
    print(fallback)
else:
    print(node)
PY
}

# Secure temporary directory, removed on exit.
vh_mktemp_dir() {
    local dir
    dir="$(mktemp -d "${TMPDIR:-/tmp}/vps-harden.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf -- '$dir'" EXIT
    printf '%s\n' "$dir"
}
