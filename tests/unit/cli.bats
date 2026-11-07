#!/usr/bin/env bats
# CLI contract tests: argument parsing, help, version, exit codes.
# These must never touch system configuration.

setup() {
    REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
    export VH_LOG_DISABLE=1
    export NO_COLOR=1
}

@test "help exits 0 and lists the main commands" {
    run "$REPO_ROOT/install.sh" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"audit"* ]]
    [[ "$output" == *"rollback"* ]]
    [[ "$output" == *"EXIT CODES"* ]]
}

@test "help works for a single command" {
    run "$REPO_ROOT/install.sh" help audit
    [ "$status" -eq 0 ]
    [[ "$output" == *"read-only security report"* ]]
}

@test "version prints the version from VERSION" {
    run "$REPO_ROOT/install.sh" version
    [ "$status" -eq 0 ]
    [ "$output" = "vps-harden $(tr -d '[:space:]' <"$REPO_ROOT/VERSION")" ]
}

@test "unknown command exits with usage error (2)" {
    run "$REPO_ROOT/install.sh" frobnicate
    [ "$status" -eq 2 ]
    [[ "$output" == *"Unknown command"* ]]
}

@test "unknown option exits with usage error (2)" {
    run "$REPO_ROOT/install.sh" audit --nonsense
    [ "$status" -eq 2 ]
    [[ "$output" == *"Unknown option"* ]]
}

@test "install with an unknown component exits 2 and names the component" {
    run "$REPO_ROOT/install.sh" install not-a-component
    [ "$status" -eq 2 ]
    [[ "$output" == *"Unknown component: not-a-component"* ]]
}

@test "config validate rejects an invalid file" {
    bad="$BATS_TEST_TMPDIR/bad.yml"
    cat >"$bad" <<'YAML'
vps_harden:
  ssh:
    port: 99999
    password_authentication: "maybe"
  ufw:
    default_incoming: maybe
YAML
    VH_CONFIG_FILE="$bad" run "$REPO_ROOT/install.sh" config validate
    [ "$status" -eq 5 ]
    [[ "$output" == *"ssh.port"* ]]
}

@test "config validate rejects unknown keys with a suggestion path" {
    bad="$BATS_TEST_TMPDIR/unknown.yml"
    cat >"$bad" <<'YAML'
vps_harden:
  ssh:
    prot: 2222
YAML
    VH_CONFIG_FILE="$bad" run "$REPO_ROOT/install.sh" config validate
    [ "$status" -eq 5 ]
    [[ "$output" == *"unknown option"* ]]
}

@test "config show merges defaults and user file" {
    cfg="$BATS_TEST_TMPDIR/user.yml"
    cat >"$cfg" <<'YAML'
vps_harden:
  ssh:
    port: 2222
YAML
    VH_CONFIG_FILE="$cfg" run "$REPO_ROOT/install.sh" config show
    [ "$status" -eq 0 ]
    [[ "$output" == *"port: 2222"* ]]
    [[ "$output" == *"fail2ban:"* ]]
}

@test "config path prints the configured path" {
    VH_CONFIG_FILE="/tmp/example.yml" run "$REPO_ROOT/install.sh" config path
    [ "$status" -eq 0 ]
    [ "$output" = "/tmp/example.yml" ]
}

@test "rollback --list runs without root and without snapshots" {
    export VH_BACKUP_DIR="$BATS_TEST_TMPDIR/backups"
    run "$REPO_ROOT/scripts/rollback.sh" --list
    [ "$status" -eq 0 ]
    [[ "$output" == *"No snapshots"* ]]
}

@test "rollback refuses to act when no snapshot exists" {
    export VH_BACKUP_DIR="$BATS_TEST_TMPDIR/empty"
    run "$REPO_ROOT/scripts/rollback.sh" --yes
    [ "$status" -ne 0 ]
    [[ "$output" == *"no snapshot"* ]]
}

@test "audit --json is rejected before root check? no: audit requires root" {
    # audit needs root for ufw/cscli; in CI we run as root, so accept 0 or 7.
    run "$REPO_ROOT/install.sh" audit --json
    [ "$status" -eq 0 ] || [ "$status" -eq 7 ] || [ "$status" -eq 3 ]
}
