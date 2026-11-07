# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-11-07

First release. Ansible-first Ubuntu VPS hardening with a thin Bash CLI, built for
adopting an existing server rather than only a blank one.

### Added

- **CLI** (`install.sh`): `check`, `discover`, `install`, `configure`, `audit`,
  `verify`, `status`, `backup`, `rollback`, `uninstall`, `config`, plus component
  shortcuts (`firewall`, `fail2ban`, `crowdsec`, `ssh`). Flags: `--check/--dry-run`,
  `--diff`, `--yes`, `--non-interactive`, `--config`, `--deadman`, `--json`,
  `--no-bootstrap`, `--no-color`, `-v/-vv`. Documented exit codes.
- **Configuration contract**: `config/defaults.yml` (schema + safe defaults),
  `config/example.yml`, merge layer, and a validator that rejects unknown keys,
  bad ranges, invalid CIDRs and the dangerous cross-field combinations
  (password auth without a key, SSH port not allowed by the firewall).
- **Roles**: `common`, `ssh_hardening`, `ufw`, `fail2ban`, `crowdsec`,
  `unattended_upgrades`, `tailscale`, `docker`, `monitoring`, `logging`,
  `hermes_agent`, `backup`, `security_audit` — each with install/configure phase
  gating and an effective-state verification.
- **Safety gates**: SSH refuses to disable password auth without an authorized
  key for a non-root user and proves the effective config with `sshd -T`; UFW
  refuses to enable without an `ufw show added` SSH allow rule; optional dead-man
  switch disables UFW after N minutes.
- **Snapshot engine** (`scripts/snapshot.py`): path-allowlisted capture with
  sha256/mode/uid/gid manifest, restore, pruning, traversal refusal.
- **Audit engine** (`scripts/vh_audit.py`): read-only, 30+ checks across system,
  firewall, listeners, Docker publishes, SSH, Fail2ban, CrowdSec, updates,
  permissions, kernel hardening, Tailscale; PASS/WARN/FAIL/NOT CONFIGURED/SKIPPED
  with severity, evidence and remediation; text and JSON output.
- **Hermes integration**: read-only MCP server (five tools, no shell, fixed argv)
  and an operational skill.
- **Tests**: 35 pytest (audit parsers, snapshot engine, config contract, MCP
  protocol), 31 Bats (CLI, configuration, snapshot/rollback), ShellCheck,
  ansible-lint, syntax checks, and a disposable Ubuntu 24.04 systemd container
  suite that proves the lockout gate and idempotency.
- **CI**: lint, unit, integration and Ubuntu 22.04/24.04 compatibility jobs; tag
  releases publish notes and never deploy.
- **Docs**: README plus architecture, installation, configuration, security model,
  firewall, troubleshooting, recovery, homelab and migration.

### Known limitations

- Single host only (`localhost` inventory); no fleet orchestration.
- CrowdSec bouncer, Tailscale authentication, the monitoring stack and restic to
  remote storage are implemented but not exercised by automated tests (they need
  external services); see `docs/troubleshooting.md#not-tested`.
- `audit` describes observed state, not a compliance certification.
- Automatic reboots are off by default and stay an operator decision.

[1.0.0]: https://github.com/hungpt99-dev/vps-harden/releases/tag/v1.0.0
