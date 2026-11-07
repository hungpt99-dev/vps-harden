# Configuration reference

`config/defaults.yml` is authoritative — this page explains what each option
means and what happens when you change it. Your overrides live in
`config/vps-harden.yml` (gitignored), merged recursively over the defaults.

Validate before applying:

```bash
sudo ./install.sh config validate
sudo ./install.sh config show          # the effective, merged document
```

Unknown keys are rejected with a suggestion. Values are type-checked, and
cross-field rules catch lockout combinations. `--strict` promotes warnings to
errors (useful in CI).

## General

| Key | Default | Meaning |
|---|---|---|
| `timezone` | `Etc/UTC` | `timedatectl set-timezone`; must be a real zone |
| `log_dir` | `/var/log/vps-harden` | CLI/Ansible log destination (not syslog) |
| `backup_dir` | `/var/backups/vps-harden` | snapshots and the local restic repo |
| `reports_dir` | `/var/lib/vps-harden/reports` | audit `.txt` + `.json` output |

UTC is the default because log correlation across machines is easier when the
server agrees with the logs of everything else. Change it if your operational
life is simpler in local time — nothing else depends on it.

## SSH

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | run the role at all |
| `port` | `22` | single port, propagated to UFW, Fail2ban and the audit |
| `permit_root_login` | `false` | `false`/`true`/`prohibit-password`/`forced-commands-only` |
| `password_authentication` | `false` | disabling is gated on key presence |
| `pubkey_authentication` | `true` | keep it on; turning it off is not supported |
| `kbd_interactive_authentication` | `false` | closes a password path via PAM |
| `max_auth_tries` | `3` | 1–10 |
| `login_grace_time` | `30` | seconds |
| `client_alive_interval` | `300` | keepalive probe interval |
| `client_alive_count_max` | `2` | missed probes before disconnect |
| `x11_forwarding` | `false` | |
| `allow_tcp_forwarding` | `false` | enable if you use `ssh -L` tunnels |
| `allow_users` / `allow_groups` | `[]` | optional `AllowUsers`/`AllowGroups` |
| `admin_users` | `[]` | empty = auto-detect (sudo group + `SUDO_USER`) |
| `allow_no_keys` | `false` | escape hatch for console-only hosts |

Turning `allow_tcp_forwarding` off breaks SSH tunnels (`ssh -L 5432:…`). If you
administer databases that way, set it to `true` before applying.

Changing `port` updates the firewall rule and the Fail2ban jail in the same run.
Existing sessions survive; new ones need the new port. Verify from a second
session before closing the first.

## UFW

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | |
| `default_incoming` | `deny` | `allow`/`deny`/`reject` |
| `default_outgoing` | `allow` | |
| `default_routed` | `deny` | |
| `logging` | `low` | `off`/`low`/`medium`/`high`/`full` |
| `ipv6` | `true` | writes `IPV6=yes` in `/etc/default/ufw` |
| `allow_tailscale` | `true` | `allow in on tailscale0` |
| `auto_allow_ssh` | `true` | derive the SSH rule from `ssh.port` |
| `extra_rules` | `[]` | see schema below |
| `deadman_minutes` | `0` | auto-disable UFW after N minutes (0 = off) |
| `manage_docker_user_chain` | `false` | DOCKER-USER policy, see `firewall.md` |
| `docker_allowed_ports` | `[]` | ports still reachable when the chain is managed |

Rule schema:

```yaml
extra_rules:
  - rule: allow            # allow | deny | reject | limit
    port: "443"            # string or integer
    proto: tcp             # tcp | udp (default tcp)
    from: 203.0.113.0/24   # optional source
    interface: tailscale0  # optional interface (mutually useful with port)
    comment: "HTTPS"
```

A rule needs at least one of `port`, `interface`, `from`. `limit` is UFW's
rate-limited allow (useful for ports you cannot put behind Fail2ban).

## Fail2ban

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | |
| `backend` | `systemd` | `systemd` needs `python3-systemd` (installed) |
| `maxretry` | `5` | failures within `findtime` before a ban |
| `findtime` | `10m` | |
| `bantime` | `1h` | initial ban |
| `bantime_increment` | `true` | escalate repeat offenders |
| `bantime_factor` | `2` | 1h → 2h → 4h … |
| `bantime_maxtime` | `4w` | escalation cap |
| `ignoreip` | `[]` | extra never-ban addresses |
| `conflict_policy` | `fail` | `fail`/`adopt`/`ignore` for another `[sshd]` owner |

Loopback and `100.64.0.0/10` + `fd7a:115c:a1e0::/48` (Tailscale) are always
exempt. Do not add all of RFC1918: on a Docker host most private sources are
rewritten container traffic, and trusting them hides real attacks.

`adopt` renames the conflicting file to `*.pre-vps-harden.bak` (it is in the
snapshot, so rollback restores it).

## CrowdSec

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | |
| `manage_repo` | `true` | set `false` if the apt repo already exists |
| `collections` | `linux`, `sshd` | hub collections to install |
| `acquisition` | `auto` | `file` (auth.log) / `journalctl` / `auto` |
| `lapi_port` | `8081` | 8080 is commonly published by a container |
| `manage_lapi_port` | `true` | rewrite `listen_uri` and credentials URL |
| `firewall_bouncer_enabled` | `false` | enforcement, see below |
| `bouncer_conflict_policy` | `fail` | refuse a second enforcement point |
| `whitelist_tailnet` | `true` | postoverflow whitelist for the CGNAT ranges |

Enabling the bouncer while Fail2ban is enforcing SSH gives you two enforcement
points. Decide which one owns SSH bans. The role still installs the bouncer if
you insist (with `bouncer_conflict_policy: ignore` when one is registered), but
the trade-off is documented rather than hidden.

## Unattended upgrades

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | |
| `automatic_reboot` | `false` | keep it false on a VPS with workloads |
| `reboot_time` | `03:00` | used only when reboots are enabled |
| `remove_unused_dependencies` | `true` | runs `autoremove` after upgrades |
| `email` | `""` | optional `Unattended-Upgrade::Mail` |
| `origins` | `[security]` | `security`, `updates`, `esm-infra`, `esm-apps` |

`updates` pulls non-security updates too. That is a bigger blast radius than most
people want on a production box; the default is security only.

## Tailscale

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `manage_repo` | `true` | |
| `ssh` | `false` | `tailscale up --ssh` (ACL-controlled SSH) |
| `accept_routes` | `false` | |
| `advertise_exit_node` | `false` | |

Authentication is never automated. Provide `tailscale_auth_key` as an extra var
from Vault for a headless first login, or run `sudo tailscale up` and open the
URL. vps-harden does not create reusable auth keys.

## Docker

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | install/manage Docker Engine |
| `manage_repo` | `true` | |
| `log_max_size` | `10m` | `log-opts.max-size` |
| `log_max_file` | `"3"` | `log-opts.max-file` |
| `live_restore` | `true` | keeps containers running across daemon restarts |
| `no_new_privileges` | `true` | daemon-level `no-new-privileges` |

`daemon.json` is **merged**: your existing keys win, vps-harden only adds what is
missing. The handler reloads (SIGHUP) instead of restarting, so containers keep
running; `live-restore` takes effect on the next daemon restart.

## Hermes

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | deploy the MCP server and skill |
| `register_mcp` | `false` | run `hermes mcp add` for you |
| `gateway_service` | `hermes-gateway.service` | reported, not managed |
| `install` | `false` | run an upstream installer (requires URL + sha256) |

## Monitoring / logging

| Key | Default | Meaning |
|---|---|---|
| `monitoring.enabled` | `false` | Prometheus + Grafana + exporters |
| `monitoring.bind_address` | `127.0.0.1` | never bind observability publicly |
| `monitoring.grafana_port` | `3030` | |
| `monitoring.prometheus_port` | `9090` | |
| `logging.enabled` | `false` | journald + optional Loki |
| `logging.journald_max_use` | `500M` | caps disk growth |
| `logging.journald_retention` | `30d` | |
| `logging.loki_enabled` | `false` | Loki + Promtail stack |

## Backup

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `schedule` | `*-*-* 03:30:00` | systemd `OnCalendar` |
| `local_repo` | `/var/backups/vps-harden/restic` | restic repository |
| `paths` | `/etc`, `/opt/homelab` | what to back up |
| `exclude` | CrowdSec credentials, Hermes `.env` | never backed up |
| `keep_daily/weekly/monthly` | `7/4/3` | retention |

## Audit

| Key | Default | Meaning |
|---|---|---|
| `fail_on` | `fail` | `fail`/`warn`/`never` — exit code of `audit` |
| `include_docker` | `true` | include Docker publish checks |

## Environment-specific overrides

```bash
# One-off without touching the file:
sudo ./install.sh configure --config /etc/vps-harden/prod.yml

# Vault-protected value:
sudo ./install.sh configure --vault-password-file ~/.vault-pass
```

`VH_CONFIG_FILE` is honoured by the scripts (`backup`, `rollback`, `status`) too,
so a non-default path stays consistent across commands.
