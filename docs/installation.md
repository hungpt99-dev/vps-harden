# Installation

Two paths: a fresh VPS, and an existing server with workloads (the common case
for this project). Both start read-only.

## Prerequisites

- Ubuntu 22.04 or 24.04 LTS, x86_64 or aarch64, systemd as PID 1
- root (or sudo) on the host
- outbound HTTPS for package repositories
- Python 3 with PyYAML — installed automatically by the bootstrap step if absent
- Ansible core ≥ 2.15 — installed automatically (`apt install ansible-core`, or a
  private venv at `~/.vps-harden/venv` when the distribution package is too old)

No `curl | sh` anywhere. The bootstrap uses apt or pip, and every downloaded key
is dearmored into `/usr/share/keyrings`.

## 1. Clone and check

```bash
git clone https://github.com/hungpt99-dev/vps-harden
cd vps-harden
sudo ./install.sh check
```

`check` verifies the OS, systemd, dependencies, the configuration file, and
whether an authorized key exists. It changes nothing and is safe to run as a
non-root user.

## 2. Inventory before you change anything

```bash
sudo ./install.sh discover
```

Writes `reports/inventory-<timestamp>.md` and prints it: listeners, firewall
state, Docker publishes, SSH effective config, Fail2ban/CrowdSec state,
Tailscale, enabled services, pending updates, and whether any file vps-harden
would own already exists.

Keep this file. It is the "before" half of every future incident review — and on
an adopted host it is the only record of what someone else had configured.

## 3. Configure

```bash
cp config/example.yml config/vps-harden.yml
$EDITOR config/vps-harden.yml
sudo ./install.sh config validate
sudo ./install.sh config show | head -30
```

Start with these three decisions:

1. **SSH port.** Leave 22 unless you have a reason; changing it is propagated
   automatically, but every client config must follow.
2. **`password_authentication`.** Keep it `true` for the first run, then disable
   it after you have confirmed a key login. The role refuses otherwise.
3. **`deadman_minutes`.** Set `10` for the first firewall apply.

## 4. Dry run

```bash
sudo ./install.sh install --check
sudo ./install.sh configure --check
```

This is Ansible check mode with `--diff`: it shows the exact file contents and
service actions it would take, and changes nothing. `command`-based policy tasks
are skipped in check mode by design — a dry run cannot predict `ufw allow`
output, only the file changes.

## 5. Apply

```bash
sudo ./install.sh install      # packages and repositories
sudo ./install.sh configure    # configuration + per-role verification
```

Each run:

1. re-validates the configuration,
2. asserts root/OS/arch/systemd,
3. snapshots every managed path (id printed at the end),
4. applies roles in a fixed order,
5. fails if a role's own verification does not match.

**Keep your current SSH session open.** Open a second one and log in before
closing it. No tool can verify your keyboard.

## 6. Verify and audit

```bash
sudo ./install.sh verify     # are the controls in effect? (non-zero if not)
sudo ./install.sh audit      # full posture report with remediation
sudo ./install.sh status     # component summary
```

`verify` is deliberately narrow: it asserts the controls vps-harden configured.
`audit` is broader and will report things outside its scope as WARN or NOT
CONFIGURED (for example a CrowdSec bouncer you have not enabled).

## 7. First 24 hours

- `sudo ./install.sh fail2ban bans` — confirm the jail is matching traffic.
  `Total failed: 0` after a day usually means the journal filter is wrong, not
  that the internet is polite.
- `sudo ./install.sh firewall rules` — compare publishes with what you intended.
- `sudo ./install.sh audit --json > /tmp/audit.json` — keep the baseline.
- If you enabled `deadman_minutes`, cancel it:
  `sudo ./install.sh firewall cancel-deadman`.

## Adopting an existing server

The order matters more than the flags:

1. `discover` and read the "files that vps-harden would own" section. Any
   `EXISTS` line is a file someone else already owns. vps-harden's SSH drop-in is
   `00-vps-harden.conf` and sorts first, so it wins — but confirm what the
   existing file does before you let that happen.
2. Run `install` (packages only). This is low risk and proves repositories work.
3. Run `configure` **one component at a time**, starting with `common`, then
   `ssh`, then `ufw`, then `fail2ban`, then `crowdsec`:
   ```bash
   sudo ./install.sh configure common
   sudo ./install.sh configure ssh
   ```
4. After each component: `sudo ./install.sh verify` and a new SSH session.
5. Only then run the full `configure` to converge everything.

Conflict policies exist for this path: `fail2ban.conflict_policy` and
`ssh.conflict_policy`. `fail` stops and names the file; `adopt` preserves it as
`*.pre-vps-harden.bak` (and snapshots it).

## Uninstall

```bash
sudo ./install.sh uninstall              # remove our config, keep packages
sudo ./install.sh uninstall --purge      # also remove fail2ban/crowdsec packages
```

Only paths in `config/managed_paths.yml` are touched. Modified system files
(`/etc/ssh/sshd_config`, `/etc/ufw/after.rules`, `/etc/docker/daemon.json`) are
left in place; `rollback` is what restores them. SSH is reloaded only if the
remaining configuration validates.

## Deploying to several hosts later

v1.0 manages the host it runs on: the inventory is `localhost`, the snapshot
engine reads absolute paths, and the firewall guarantees assume one machine. A
fleet mode is a deliberate non-goal until that model is proven — the roles are
reusable, the CLI is not yet a multi-host orchestrator.
