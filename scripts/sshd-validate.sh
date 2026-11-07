#!/usr/bin/env bash
#
# Validate an sshd configuration snippet before it is installed.
#
#   sshd-validate.sh /path/to/candidate.conf
#
# sshd_config.d snippets are not standalone configurations: `sshd -t -f snippet`
# fails with "no hostkeys available". This builds a throw-away wrapper that
# includes the candidate plus a usable host key, so `sshd -t` validates the real
# directive set (including syntax and unsupported values) without touching
# /etc/ssh.
set -Eeuo pipefail

candidate="${1:?usage: sshd-validate.sh <candidate.conf>}"
[[ -r "$candidate" ]] || {
    echo "sshd-validate: cannot read $candidate" >&2
    exit 1
}

SSHD="/usr/sbin/sshd"
[[ -x "$SSHD" ]] || SSHD="$(command -v sshd || true)"
[[ -n "$SSHD" && -x "$SSHD" ]] || {
    echo "sshd-validate: sshd binary not found" >&2
    exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/vh-sshd.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT

# Reuse a real host key when one exists, otherwise generate a temporary one so
# the syntax check does not depend on the host being fully provisioned.
hostkey=""
for key in /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ecdsa_key \
    /etc/ssh/ssh_host_rsa_key; do
    if [[ -r "$key" ]]; then
        hostkey="$key"
        break
    fi
done
if [[ -z "$hostkey" ]]; then
    command -v ssh-keygen >/dev/null 2>&1 || {
        echo "sshd-validate: no host key and no ssh-keygen available" >&2
        exit 1
    }
    ssh-keygen -q -t ed25519 -N '' -f "$tmp/hostkey" >/dev/null
    hostkey="$tmp/hostkey"
fi

cat >"$tmp/sshd_config" <<EOF
Include $candidate
HostKey $hostkey
PidFile $tmp/sshd.pid
EOF

exec_sshd=("$SSHD" -t -f "$tmp/sshd_config")
rc=0
"${exec_sshd[@]}" || rc=$?
exit "$rc"
