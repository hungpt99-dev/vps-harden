# Migration plan — adopting an existing VPS

Target: an existing Ubuntu VPS already running workloads. Every phase has a gate
that must pass before the next one starts, and a rollback that does not depend on
the thing being changed. Run `sudo ./install.sh discover` first to record a local
baseline in `reports/` (gitignored).

Nothing here is applied automatically by this repository. Each phase is a
command an operator runs, after reading its verification step.

## Phase 0 — Baseline

- Repository built and unit checks green.
- Run `sudo ./install.sh discover` to record the current listeners, firewall and
  container publishes in `reports/` (gitignored).
- **No change to the host.**

## Phase 1 — An SSH key that actually works (no configuration change)

Ensure at least one working SSH public key is installed for the admin user before
hardening SSH.

```bash
# on your workstation
ssh-keygen -t ed25519 -C "admin@laptop"
ssh-copy-id -i ~/.ssh/id_ed25519.pub ubuntu@<host>

# on the host, as the sudo user
sudo ./install.sh check          # should now report "has N authorized key(s)"
```

**Gate:** log in from a second terminal with the key, then `sudo -v`.
**Rollback:** delete the key from `authorized_keys` (password auth is still on).

## Phase 2 — Baseline, no security policy yet

```bash
sudo ./install.sh install common
sudo ./install.sh configure common
```

Applies timezone/NTP, conservative sysctls, auditd rules, file modes. Takes a
snapshot first.

**Gate:** `sudo ./install.sh verify` (skips SSH/UFW checks if they are not
configured) and `systemctl is-active auditd`.
**Rollback:** `sudo ./install.sh rollback --id <snapshot>`.

## Phase 3 — SSH hardening

```bash
cp config/example.yml config/vps-harden.yml
# keep password_authentication: true for this first run
sudo ./install.sh configure ssh
sudo ./install.sh ssh status      # effective values, not the files
```

Then set `password_authentication: false` and `permit_root_login: false` and run
`configure ssh` again. The role refuses if it cannot see a non-root key — that is
the gate, not an error to work around.

**Gate:** new session with the key; `sshd -T` shows `passwordauthentication no`,
`permitrootlogin no`; existing session still alive.
**Rollback:** `sudo rm /etc/ssh/sshd_config.d/00-vps-harden.conf && sudo sshd -t
&& sudo systemctl reload ssh` from the console if needed (`docs/recovery.md`).

## Phase 4 — Firewall convergence

Review the existing UFW policy first. vps-harden's role is idempotent against what
is already there and only adds logging/IPv6 normalisation and the rules it needs.

```bash
sudo ./install.sh configure ufw --deadman 10
# verify from a second session, then:
sudo ./install.sh firewall cancel-deadman
```

Do **not** enable `manage_docker_user_chain` until you audit which container ports
are published on `0.0.0.0` / `::`. Enabling it blocks every published port that is
not on `docker_allowed_ports`. Decide the Docker exposure strategy first:

- preferred: bind each publish to `127.0.0.1` and reach it through Tailscale or a
  reverse proxy (no firewall rule needed);
- or: enable the chain with an explicit `docker_allowed_ports` list, accepting
  that unlisted services become unreachable.

**Gate:** `sudo ./install.sh firewall rules` shows the same rule set plus the
Docker publish list; a new SSH session works; containers still answer on
loopback.
**Rollback:** `sudo ./install.sh rollback --id <snapshot>` restores
`/etc/ufw/after.rules`/`/etc/default/ufw`; `sudo ufw reload`.

## Phase 5 — Fail2ban (one owner for the jail)

If an existing drop-in (such as `jail.d/sshd.local`) already declares `[sshd]`,
pick one owner:

- **Option A (recommended):** let vps-harden own it —
  `fail2ban.conflict_policy: adopt` renames `sshd.local` to
  `*.pre-vps-harden.bak` (snapshot included, so rollback restores it).
- **Option B:** keep `sshd.local` and set `conflict_policy: ignore`, accepting
  that the effective `maxretry` is whatever that file says. The audit will warn.

Before adopting, review any custom `ignoreip` entries for stale public IPs and
decide whether they still belong there. Prefer administering over Tailscale
instead of a static public IP allowlist.

```bash
sudo ./install.sh configure fail2ban
sudo ./install.sh fail2ban status
sudo ./install.sh fail2ban bans
```

**Gate:** `fail2ban-client status sshd` shows the jail and a `Journal matches`
line containing `ssh.service`; `Total failed` increases over a day.
**Rollback:** restore `jail.d/sshd.local` from the snapshot; `systemctl restart
fail2ban`.

## Phase 6 — CrowdSec

If CrowdSec is already installed with an existing SSH acquisition file in
`/etc/crowdsec/acquis.d/`, vps-harden detects it and **does not** add a duplicate
file.

```bash
sudo ./install.sh configure crowdsec
sudo ./install.sh crowdsec status
```

Keep `firewall_bouncer_enabled: false` while Fail2ban enforces SSH. If you later
want CrowdSec to enforce, disable the Fail2ban `sshd` jail in the same change and
say which one owns bans.

**Gate:** `cscli lapi status` succeeds, collections list contains `sshd`, and
`cscli decisions list` shows decisions.
**Rollback:** revert `/etc/crowdsec/config.yaml` changes from the snapshot;
`systemctl restart crowdsec`.

## Phase 7 — Optional layers, one at a time

| Change | Risk | Gate |
|---|---|---|
| `docker.enabled` (daemon.json merge, log rotation) | low, reload not restart | `docker info`, existing containers untouched |
| `backup.enabled` (restic timer) | low | `systemctl list-timers`, `restic snapshots` |
| `logging.enabled` (journald caps) | low | `journalctl --disk-usage` |
| `monitoring.enabled` (Grafana, localhost) | medium (new containers) | `/api/health` 200, no new public ports |
| `hermes.enabled` + `register_mcp` | low (read-only tools) | `hermes mcp list`, tool call returns audit JSON |

Each is a separate `configure <component>` and a separate verification.

## Phase 8 — Steady state

```bash
sudo ./install.sh audit            # weekly, or in cron with --json
sudo ./install.sh verify           # after any change
sudo ./install.sh backup --reason pre-upgrade
```

Remaining decisions that this repository deliberately does not make for you:

1. Whether database containers should stay published on public interfaces or bind
   to `127.0.0.1` (Phase 4).
2. Whether web and management UIs move behind Tailscale or a reverse proxy.
3. Whether CrowdSec or Fail2ban owns SSH enforcement.
4. Whether root SSH is disabled everywhere or restricted to the tailnet.

## Order rationale

SSH keys first, because every later phase can lock you out. Baseline second,
because it is reversible and changes nothing about reachability. SSH hardening
third, while the firewall is still permissive. Firewall fourth, once SSH is
known-good. Intrusion prevention after that, because a ban policy on a host you
cannot log in to is just noise. Optional layers last, each with its own gate.
