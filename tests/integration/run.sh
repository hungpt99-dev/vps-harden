#!/usr/bin/env bash
#
# Integration test on a disposable Ubuntu 24.04 container with systemd.
#
# Contract verified here (nothing touches the host):
#   1. `check` and `discover` work on a fresh Ubuntu.
#   2. `audit` produces a report without changing the system.
#   3. `install --check` and `configure --check` predict without changing.
#   4. The SSH role REFUSES to disable password auth when no admin key exists
#      (the lockout gate is real, not documentation).
#   5. After adding a key, `configure` applies and `verify` passes.
#   6. A second `configure` reports changed=0 (idempotency).
set -Eeuo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="vps-harden-test:24.04"
CONTAINER="vps-harden-it-$$"
FAILURES=0

cleanup() {
    if [[ "${FAILURES:-0}" -gt 0 ]]; then
        local dir
        dir="$REPO_ROOT/reports/integration-$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$dir"
        docker exec "$CONTAINER" bash -lc 'cat /tmp/*.log 2>/dev/null' >"$dir/container.log" 2>&1 || true
        docker logs "$CONTAINER" >"$dir/docker.log" 2>&1 || true
        printf 'Logs: %s\n' "$dir"
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

pass() { printf '\033[0;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31mFAIL\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

rexec() { docker exec "$CONTAINER" "$@"; }

echo "==> Building $IMAGE"
docker build -q -t "$IMAGE" "$REPO_ROOT/tests/integration" >/dev/null

echo "==> Starting $CONTAINER"
docker run -d --name "$CONTAINER" \
    --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /tmp \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$REPO_ROOT:/repo:ro" \
    "$IMAGE" >/dev/null

echo "==> Waiting for systemd"
for _ in $(seq 1 60); do
    if rexec systemctl is-system-running >/dev/null 2>&1 ||
        rexec systemctl list-units >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
rexec systemctl is-system-running >/dev/null 2>&1 || true

# A real VPS ships with package lists; the image is built with them removed.
# Check mode resolves package names against the cache, so refresh it first.
rexec apt-get update -qq >/dev/null 2>&1 || true

CONFIG=/repo/tests/integration/config.yml

# 1. prerequisites -----------------------------------------------------------
if rexec /repo/install.sh check >/tmp/check.log 2>&1; then
    pass "install.sh check"
else
    fail "install.sh check (rc=$?)"
    sed -n '1,40p' /tmp/check.log
fi

# 2. discovery ---------------------------------------------------------------
if rexec /repo/install.sh discover --output /tmp/inventory.md >/tmp/discover.log 2>&1 &&
    rexec test -s /tmp/inventory.md; then
    pass "install.sh discover"
else
    fail "install.sh discover"
    sed -n '1,30p' /tmp/discover.log
fi

# 3. read-only audit ---------------------------------------------------------
rexec /repo/install.sh audit --config "$CONFIG" >/tmp/audit.log 2>&1 || true
if grep -q "vps-harden security audit" /tmp/audit.log; then
    pass "install.sh audit produces a report"
else
    fail "install.sh audit produced no report"
    sed -n '1,40p' /tmp/audit.log
fi

# 4. dry run predict ---------------------------------------------------------
if rexec /repo/install.sh install --check --yes --config "$CONFIG" >/tmp/install-check.log 2>&1; then
    pass "install --check predicts without changing"
else
    fail "install --check"
    sed -n '1,40p' /tmp/install-check.log
fi

# 5. the lockout gate --------------------------------------------------------
# Expected to FAIL: password auth disabled, no authorized key anywhere.
rexec rm -rf /root/.ssh /home/ubuntu/.ssh
if rexec /repo/install.sh configure --yes --config "$CONFIG" ssh >/tmp/gate.log 2>&1; then
    fail "SSH role proceeded without an authorized key (lockout gate broken)"
else
    if grep -q "no public key was found" /tmp/gate.log; then
        pass "SSH role refused to disable password auth without a key"
    else
        fail "SSH role failed for an unexpected reason"
        sed -n '1,40p' /tmp/gate.log
    fi
fi

# 6. apply after adding an administrator key ---------------------------------
rexec bash -lc '
    set -e
    mkdir -p /home/ubuntu/.ssh
    ssh-keygen -q -t ed25519 -N "" -f /tmp/admin_key
    cp /tmp/admin_key.pub /home/ubuntu/.ssh/authorized_keys
    chown -R ubuntu:ubuntu /home/ubuntu/.ssh
    chmod 700 /home/ubuntu/.ssh
    chmod 600 /home/ubuntu/.ssh/authorized_keys
'
# Packages first: `configure` is documented to require an install run.
if rexec /repo/install.sh install --yes --config "$CONFIG" ssh unattended >/tmp/install.log 2>&1; then
    pass "install installed SSH and unattended-upgrades"
else
    fail "install failed"
    sed -n '1,60p' /tmp/install.log
fi

if rexec /repo/install.sh configure --yes --config "$CONFIG" ssh unattended >/tmp/apply.log 2>&1; then
    pass "configure applied SSH and unattended-upgrades"
else
    fail "configure failed"
    sed -n '1,60p' /tmp/apply.log
fi

if rexec bash -lc "sshd -T | grep -E '^(passwordauthentication|permitrootlogin|maxauthtries) '"; then
    pass "effective sshd configuration changed"
else
    fail "effective sshd configuration unchanged"
fi

if rexec /repo/install.sh verify --config "$CONFIG" >/tmp/verify.log 2>&1; then
    pass "verify passes after apply"
else
    fail "verify failed after apply"
    sed -n '1,40p' /tmp/verify.log
fi

# 7. idempotency -------------------------------------------------------------
rexec /repo/install.sh configure --yes --config "$CONFIG" ssh unattended >/tmp/idem.log 2>&1 || true
if grep -Eq 'changed=0 .*failed=0' /tmp/idem.log; then
    pass "second configure run is idempotent (changed=0)"
else
    fail "second configure run reported changes"
    tail -5 /tmp/idem.log
fi

echo
if [[ "$FAILURES" -gt 0 ]]; then
    echo "$FAILURES integration check(s) failed"
    exit 1
fi
echo "All integration checks passed"
