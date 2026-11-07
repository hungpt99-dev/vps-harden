# vps-harden

Security baseline and homelab control plane for a single Ubuntu VPS.

Ansible does the work, a small Bash CLI drives it, and every change is
snapshotted, validated, and verifiable afterwards. Built for the case that
actually bites people: an **existing** server with services, containers and
data on it — not a blank box.

```
sudo ./install.sh check      # what would this host need? (changes nothing)
sudo ./install.sh discover   # read-only inventory of what is already running
sudo ./install.sh audit      # PASS / WARN / FAIL / NOT CONFIGURED
sudo ./install.sh install --check   # dry run of the whole baseline
sudo ./install.sh configure  # apply, after a snapshot
sudo ./install.sh verify     # prove the controls are in effect
```

## What it does

| Area | Implementation | Default |
|---|---|---|
| Firewall | UFW: deny incoming/routed, allow outgoing, derived SSH + tailnet rules | on |
| SSH | Key-only auth, no root login, attempt limits, validated drop-in | on |
| Intrusion prevention | Fail2ban `sshd` jail, systemd backend, progressive bans | on |
| Threat detection | CrowdSec engine + SSH collection (enforcement opt-in) | on |
| Security updates | Unattended upgrades, security origins only, no auto-reboot | on |
| Baseline | Timezone, NTP, kernel sysctls, auditd rules, file permissions | on |
| Private admin | Tailscale (never auto-authenticated) | off |
| Containers | Docker Engine + Compose plugin, log rotation, merged `daemon.json` | off |
| Observability | Prometheus + Grafana + node_exporter, localhost-bound | off |
| Log retention | journald limits, optional Loki/Promtail | off |
| Backups | restic + systemd timer, excludes credentials | off |
| AI operations | Hermes Agent skill + read-only MCP server | off |

## What it deliberately is not

- Not a fleet manager. It manages the host it runs on.
- Not a container orchestrator. Compose stacks are rendered, not scheduled.
- Not an auto-remediation agent. The MCP server exposes **read-only** tools;
  applying changes stays a human-approved CLI action.
- Not a compliance scanner. The audit describes observed state, not a
  certification.

## Why each component

**UFW** is the only thing standing between a misconfigured service and the
internet — except for Docker, which publishes ports *around* UFW. That gap is
why `audit` compares container publishes against the firewall and why the
`DOCKER-USER` chain is a first-class, documented option (`docs/firewall.md`).

**Fail2ban** turns the SSH log into an enforcement decision. On Ubuntu the
shipped filter looks for `sshd.service` while the unit is `ssh.service`, so a
freshly installed jail often bans nobody and says nothing. vps-harden writes the
`journalmatch` fix and verifies the jail is actually listed.

**CrowdSec** adds community-sourced detection (scenarios, not just regexes).
Detection and enforcement are separate decisions: a bouncer is opt-in because
two enforcement points for the same traffic make incident response ambiguous.

**SSH hardening** is the change most likely to lock you out, so it is the most
gated: the role refuses to disable password auth until it can see an authorized
key for a non-root sudo user, then proves the *effective* configuration with
`sshd -T` — because a `99-*.conf` drop-in silently loses to cloud-init's
`50-cloud-init.conf` (sshd uses the first value it reads).

**Unattended upgrades** close the "installed in March, patched never" gap.
Reboots stay manual: an unattended reboot of a VPS with unattended containers is
an outage nobody is watching.

## Architecture

```
install.sh  (Bash: parse args, check prerequisites, pick playbook)
    │
    ├── scripts/common.sh        logging, exit codes, helpers
    ├── scripts/validate_config.py   schema + cross-field lockout checks
    ├── scripts/snapshot.py      managed-path snapshot / restore engine
    ├── scripts/vh_audit.py      read-only audit engine (pure parsers + probes)
    ├── scripts/bootstrap.sh     install ansible-core (no curl | sh)
    │
    └── ansible-playbook playbooks/{install,configure,audit,verify,uninstall}.yml
            │   pre_tasks: load_config → preflight → snapshot
            └── roles/
                common · ssh_hardening · ufw · fail2ban · crowdsec
                unattended_upgrades · tailscale · docker · monitoring
                logging · hermes_agent · backup · security_audit
```

One owner per file: everything vps-harden writes is listed in
`config/managed_paths.yml`, which drives snapshots, rollback and uninstall.
Roles never edit each other's files. See `docs/architecture.md`.

## Supported systems

- Ubuntu 22.04 LTS, Ubuntu 24.04 LTS (x86_64, aarch64)
- systemd required; root required for anything that changes state
- Python 3 with PyYAML, Ansible core ≥ 2.15 (installed automatically if missing)

Anything else fails pre-flight with a clear message rather than half-configuring
the host.

## Quick start

```bash
git clone https://github.com/hungpt99-dev/vps-harden
cd vps-harden

sudo ./install.sh check                 # prerequisites + config validation
sudo ./install.sh discover              # read-only inventory (reports/)
cp config/example.yml config/vps-harden.yml
$EDITOR config/vps-harden.yml           # start with your SSH port and admin IPs

sudo ./install.sh install --check       # dry run: read the diff
sudo ./install.sh install               # packages only
sudo ./install.sh configure             # configuration + verification
sudo ./install.sh audit
```

**Before you close your SSH session:** open a second session and confirm you can
log in. The tool prints the same warning; it cannot verify your keyboard.

## Configuration

`config/defaults.yml` is the schema (every option, with the safe value).
`config/example.yml` is a documented starting point. Your file
`config/vps-harden.yml` is merged on top and is gitignored.

```yaml
vps_harden:
  ssh:
    port: 22
    password_authentication: false   # only after a key login is proven
    permit_root_login: false
  ufw:
    deadman_minutes: 10              # auto-disable if you lose access
    extra_rules:
      - rule: allow
        port: "443"
        proto: tcp
  fail2ban:
    maxretry: 5
    bantime: 1h
    bantime_increment: true
  crowdsec:
    firewall_bouncer_enabled: false  # detection only
```

Every option is validated before Ansible runs: unknown keys are rejected with a
suggestion, ports and durations are range-checked, and cross-field rules catch
the dangerous combinations — "disable password auth with no key", "SSH port not
allowed by the firewall", "bantime shorter than findtime".

Full reference: `docs/configuration.md`.

## CLI reference

```
check                  prerequisites, dependencies, config — changes nothing
discover               read-only infrastructure inventory
install [component…]   packages and repositories
configure [component…] apply configuration to installed components
audit [--json]         read-only security report
verify                 prove the controls are in effect (non-zero on failure)
status                 component/service summary
backup [--reason R]    snapshot every managed path
rollback [--list|--id|--dry-run|--yes]
uninstall [--purge]    remove our configuration (packages kept)
config show|validate|path
firewall status|rules|cancel-deadman
fail2ban status|bans|unban <ip>
crowdsec status|decisions|bouncers|alerts
ssh status|validate
help [command] | version
```

Global options: `--check/--dry-run`, `--diff`, `-y/--yes`,
`--non-interactive`, `--config FILE`, `--deadman MINUTES`, `--json`,
`-e/--extra-vars`, `--vault-password-file`, `-v/-vv`, `--no-bootstrap`,
`--no-color`.

Components: `common ssh ufw fail2ban crowdsec unattended tailscale docker
monitoring logging hermes backup`. Exit codes: `0` ok, `2` usage,
`3` prerequisites, `4` unsupported system, `5` invalid configuration,
`6` apply/verify failed, `7` audit found FAIL.

## The audit

```
SUMMARY  FAIL: 2  WARN: 3  NOT CONFIGURED: 1  SKIPPED: 0  PASS: 12

-- FAIL ---------------------------------------------------------------
[FAIL] Password authentication (high)
    PasswordAuthentication yes
    fix: Set PasswordAuthentication no once key auth is verified
[FAIL] SSH port allowed through the firewall (critical)
    port 22/tcp has NO allow rule
```

Statuses are `PASS`, `WARN`, `FAIL`, `NOT CONFIGURED`, `SKIPPED`. Each finding
carries a severity, the evidence, and a remediation command. The report ends
with the sentence that matters: a passing audit means these controls were
observed in the expected state, not that the host is secure.

`audit --json` returns the same findings for automation. Exit code `7` when a
FAIL exists (configurable via `audit.fail_on`).

## Safety model

- Pre-flight asserts root, Ubuntu version, architecture and systemd **before the
  first write**
- Every apply takes a configuration snapshot first; `rollback` restores only
  managed paths and validates sshd before reloading it
- Dry-run is real Ansible check mode, not a printout
- No playbook flushes iptables/nftables, resets UFW, removes a security tool, or
  rewrites a config it does not own — conflicting owners are detected and
  reported, with `fail`/`adopt`/`ignore` policies
- UFW is enabled only after `ufw show added` proves an SSH allow rule exists
- SSH password auth is disabled only after an authorized key is found; the
  effective config is re-read and asserted after reload
- Services are reloaded (not restarted) where the daemon supports it, and only
  after their configuration validates

## Docker caveat

Docker publishes ports in `nat PREROUTING` and forwards them, so they never
traverse UFW's `INPUT` chain. `ufw status` showing only 22 open is compatible
with a dozen services on the internet. vps-harden reports the publishes, and
offers two fixes: bind to `127.0.0.1`, or let the role manage a `DOCKER-USER`
policy with an explicit allowlist (`ufw.manage_docker_user_chain`). Details and
rollback: `docs/firewall.md#docker`.

## Tailscale

Off by default and never authenticated for you. When enabled, the role installs
the package, enables `tailscaled`, adds an `allow in on tailscale0` firewall
rule, and exempts `100.64.0.0/10` + `fd7a:115c:a1e0::/48` from fail2ban and
CrowdSec. Without an auth key it prints the `tailscale up` instruction instead
of inventing one.

## Hermes Agent integration (optional)

`integrations/hermes/` contains:

- a **read-only** MCP server (`hermes mcp add vps-harden --command python3
  --args /usr/local/lib/vps-harden/vps_harden_mcp.py --root /path/to/repo`) with
  tools `vps_harden_status`, `vps_harden_audit`, `vps_harden_firewall`,
  `vps_harden_ssh`, `vps_harden_help`
- an operational skill that teaches the agent the read-first rules

The agent can observe and explain; it cannot change the host. That asymmetry is
intentional — an agent that can edit `/etc/ssh` can lock you out at 3 a.m.

## Backup and recovery

Two independent mechanisms:

1. **Configuration snapshots** (always on, `install.sh backup`/`rollback`):
   the handful of files vps-harden owns, restored with permissions and validated
   before any service reload.
2. **Scheduled data backup** (opt-in, `backup.enabled`): restic over
   `backup.paths`, credentials excluded, systemd timer, documented restore.

Lockout playbooks for SSH, firewall, fail2ban and CrowdSec:
`docs/recovery.md`.

## Testing

```bash
make test               # shellcheck + ansible-lint + syntax + bats + pytest
make test-integration   # disposable Ubuntu 24.04 container with systemd
make test-molecule      # baseline role, including the idempotence step
```

66 automated checks run locally: 31 Bats (CLI, configuration, snapshot,
rollback) and 35 pytest (audit parsers, snapshot engine, config contract, MCP
protocol). The integration suite additionally proves, inside a container, that
the SSH role refuses to disable password auth without a key, then applies and
verifies after a key is added, and that a second run reports `changed=0`.

Coverage boundaries are stated in `docs/troubleshooting.md#not-tested`.

## Documentation

- `docs/architecture.md` — layers, roles, execution and configuration flow
- `docs/installation.md` — fresh install and adoption of an existing VPS
- `docs/configuration.md` — every option, with defaults and implications
- `docs/security-model.md` — threat model, detection vs enforcement, trust boundaries
- `docs/firewall.md` — UFW, Docker publishes, DOCKER-USER, Tailscale
- `docs/troubleshooting.md` — symptom → cause → fix
- `docs/recovery.md` — lockout and rollback procedures
- `docs/homelab.md` — the AI-native operating model
- `docs/migration.md` — phased adoption plan

## Contributing

See `CONTRIBUTING.md`. Security reports: `SECURITY.md` (please do not open a
public issue for a lockout-class bug).

MIT licensed.
