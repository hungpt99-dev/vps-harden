#!/usr/bin/env bats
# Configuration validator tests. Pure Python, no system access.

setup() {
    REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
    VALIDATOR="$REPO_ROOT/scripts/validate_config.py"
    DEFAULTS="$REPO_ROOT/config/defaults.yml"
    PY="$(command -v python3)"
    export NO_COLOR=1
}

validate() {
    "$PY" "$VALIDATOR" --defaults "$DEFAULTS" --user "$1"
}

@test "the shipped example configuration is valid" {
    run validate "$REPO_ROOT/config/example.yml"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Configuration OK"* ]]
}

@test "invalid SSH port is rejected" {
    f="$BATS_TEST_TMPDIR/c.yml"
    printf 'vps_harden:\n  ssh:\n    port: 70000\n' >"$f"
    run validate "$f"
    [ "$status" -eq 1 ]
    [[ "$output" == *"ssh.port"* ]]
}

@test "invalid duration is rejected" {
    f="$BATS_TEST_TMPDIR/c.yml"
    printf 'vps_harden:\n  fail2ban:\n    findtime: ten-minutes\n' >"$f"
    run validate "$f"
    [ "$status" -eq 1 ]
    [[ "$output" == *"findtime"* ]]
}

@test "invalid CIDR in ignoreip is rejected" {
    f="$BATS_TEST_TMPDIR/c.yml"
    printf 'vps_harden:\n  fail2ban:\n    ignoreip: ["10.0.0.0/33"]\n' >"$f"
    run validate "$f"
    [ "$status" -eq 1 ]
    [[ "$output" == *"invalid IP address"* ]]
}

@test "firewall rule with no target is rejected" {
    f="$BATS_TEST_TMPDIR/c.yml"
    cat >"$f" <<'YAML'
vps_harden:
  ufw:
    extra_rules:
      - rule: allow
        comment: "no port, no interface"
YAML
    run validate "$f"
    [ "$status" -eq 1 ]
    [[ "$output" == *"at least one of: port, interface, from"* ]]
}

@test "SSH port missing from firewall rules is an error (lockout guard)" {
    f="$BATS_TEST_TMPDIR/c.yml"
    cat >"$f" <<'YAML'
vps_harden:
  ssh:
    port: 2222
  ufw:
    auto_allow_ssh: false
    extra_rules:
      - rule: allow
        port: "443"
        proto: tcp
YAML
    run validate "$f"
    [ "$status" -eq 1 ]
    [[ "$output" == *"would cut your SSH access"* ]]
}

@test "disabling password auth without allow_no_keys warns" {
    f="$BATS_TEST_TMPDIR/c.yml"
    cat >"$f" <<'YAML'
vps_harden:
  ssh:
    password_authentication: false
    allow_no_keys: true
YAML
    run validate "$f"
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARN"* ]]
}

@test "strict mode turns warnings into a failure" {
    f="$BATS_TEST_TMPDIR/c.yml"
    printf 'vps_harden:\n  ssh:\n    permit_root_login: true\n' >"$f"
    run "$PY" "$VALIDATOR" --defaults "$REPO_ROOT/config/defaults.yml" --user "$f" --strict
    [ "$status" -eq 1 ]
}

@test "unknown top-level key is rejected" {
    f="$BATS_TEST_TMPDIR/c.yml"
    printf 'hardening:\n  ssh: {}\n' >"$f"
    run validate "$f"
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown top-level key"* ]]
}

@test "json output is machine readable" {
    run "$PY" "$VALIDATOR" --defaults "$REPO_ROOT/config/defaults.yml" --json
    [ "$status" -eq 0 ]
    echo "$output" | "$PY" -c 'import json,sys; d=json.load(sys.stdin); assert d["valid"] is True'
}
