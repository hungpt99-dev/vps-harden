# Architecture

## Layers

```
┌────────────────────────────────────────────────────────────────────┐
│ CLI — install.sh                                                   │
│   argument parsing · prerequisite checks · confirmation · output   │
│   exit codes · logging (no policy decisions, no /etc writes)        │
└───────────────┬────────────────────────────────────────────────────┘
                │  validates config, takes a snapshot, calls a playbook
┌───────────────▼────────────────────────────────────────────────────┐
│ Automation — Ansible (playbooks/ + roles/)                          │
│   all package, file, service and validation work                    │
└───────────────┬────────────────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────────────────┐
│ State owned by vps-harden — config/managed_paths.yml                │
│   every file we write · what uninstall removes · what rollback      │
│   restores · what the snapshot engine records                       │
└────────────────────────────────────────────────────────────────────┘
```

Bash never writes system configuration. It resolves arguments, refuses to run on
unsupported hosts, validates the configuration file, snapshots managed paths,
and translates Ansible's exit status into a documented exit code.

## Roles and responsibility

| Role | Owns | Verification |
|---|---|---|
| `common` | baseline packages, timezone, NTP, sysctls, auditd rules, sensitive file modes | re-reads each sysctl, reports what did not apply |
| `ssh_hardening` | `/etc/ssh/sshd_config.d/00-vps-harden.conf` (+ Include line if missing) | `sshd -T` compared field by field after reload |
| `ufw` | UFW policy, rules, `/etc/default/ufw`, optional `DOCKER-USER` block | `ufw status verbose` after enable; SSH rule asserted *before* enable |
| `fail2ban` | `/etc/fail2ban/jail.d/99-vps-harden.local` | `fail2ban-client -t`, then jail listed in `status` |
| `crowdsec` | repo, `/etc/crowdsec/acquis.d/vps-harden-ssh.yaml`, tailnet whitelist, optional bouncer | `cscli lapi status`, collection list assert |
| `unattended_upgrades` | `20auto-upgrades`, `51-vps-harden-unattended-upgrades` | `apt-config dump` parses the value |
| `tailscale` | repo, package, optional `tailscale up` with a vault key | `BackendState == Running` when a key was used |
| `docker` | repo, packages, merged `/etc/docker/daemon.json` | `docker info` answers; log opts reported |
| `monitoring` | `/opt/homelab/monitoring/*`, compose stack bound to localhost | Grafana `/api/health` returns 200 |
| `logging` | journald drop-in, optional Loki/Promtail stack | `journalctl --disk-usage`, Loki `/ready` |
| `hermes_agent` | read-only MCP server + operational skill | gateway state reported (not managed) |
| `backup` | restic repo, password file, script, systemd timer | timer `is-enabled`, repository readable |
| `security_audit` | reports directory | audit + verify tasks |

## Phase gating

One role serves both `install` and `configure`:

```yaml
- import_tasks: install.yml    when: vh_phase in ['install', 'all']
- import_tasks: configure.yml  when: vh_phase in ['configure', 'all']
```

`site.yml` sets `vh_phase: all`. `install.yml` installs packages and
repositories only; `configure.yml` writes files and restarts services. Running
`configure` on a host where a package is missing fails at the first
package-dependent task rather than silently doing nothing.

## Configuration flow

```
config/defaults.yml        schema + safe defaults (single source of truth)
        │
config/vps-harden.yml      user file, gitignored (optional)
        │
        ▼  playbooks/tasks/load_config.yml
vps_harden (merged dict)
        │
        ├── derived firewall rules (SSH port, tailscale0) — never typed by hand
        ▼
playbooks/group_vars/all.yml   mapping layer: vps_harden.* → role variables
        │
        ▼
roles/*/defaults/main.yml   standalone defaults (role usable without the repo)
```

Three layers exist because each answers a different question: *what may a user
set* (defaults.yml), *what does this role need* (role defaults), and *how does
the first become the second* (group_vars). Drift between them is the most common
maintenance bug in a project like this, so `tests/unit/test_config_contract.py`
fails when:

- a mapped key does not exist in `config/defaults.yml`
- an option in `config/defaults.yml` never reaches a role
- a role default disagrees with the documented default
- a role does not gate on `vh_phase`

## Execution flow (apply)

1. `install.sh` verifies root, Ubuntu release, architecture, systemd, and
   validates the configuration (unknown keys, ranges, cross-field lockouts).
2. Confirmation prompt (skipped with `--yes`; refused in non-interactive mode
   without it).
3. `preflight.yml` repeats the assertions inside Ansible so direct
   `ansible-playbook` use is equally safe.
4. `snapshot.yml` records every managed path that exists (and every one that does
   not, so rollback can delete what we created).
5. Roles run in a fixed order: baseline → SSH → firewall → fail2ban → CrowdSec →
   updates → optional components. SSH before firewall so the port is known;
   firewall before fail2ban so a ban action cannot race a missing rule.
6. Each role verifies its own result; the play fails if the effective state does
   not match.
7. `install.sh verify` re-checks the controls independently of the role that
   configured them.

## Failure semantics

- A role failure stops the play. The snapshot id is printed by the CLI.
- `rollback` restores only paths in the inventory, then validates sshd before
  reloading it; an invalid restored SSH config is never loaded.
- Idempotency: a second `configure` reports `changed=0`. Policy commands either
  compare state first (`ufw default …`), let the tool report the change
  (`'Rule added' in stdout`), or are guarded by `creates:`.

## Why snapshots are not backups

Snapshots are small, fast, and taken immediately before every change so a bad
merge can be undone in seconds. They are not a backup strategy: they live on the
same disk, cover only managed configuration, and are pruned to the last ten. The
`backup` role (restic) is the separate, scheduled mechanism for data — with
credentials excluded on purpose.
