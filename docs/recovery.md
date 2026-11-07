# Recovery

The order is always: **regain access → restore configuration → understand what
happened**. Do not restart the VPS to "fix" a lockout: a reboot re-applies the
same broken state and destroys the evidence (and your chance at a running
dead-man switch).

## 1. SSH lockout

### If you have another working path

Tailnet (if enabled):

```bash
ssh root@<tailscale-ip>
```

Cloud provider's web console / serial console: every provider has one. This is
the reason the SSH role insists on a key for a non-root sudo user before it
disables password auth or root login.

### From the console

```bash
# 1. What does sshd actually think?
sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|port|allowusers'

# 2. Which drop-in is winning?
sudo ls -l /etc/ssh/sshd_config.d/
sudo ./install.sh ssh status

# 3a. Restore the last snapshot (recommended: validates before reloading)
sudo ./install.sh rollback --list
sudo ./install.sh rollback --dry-run
sudo ./install.sh rollback --id <snapshot>

# 3b. Or minimally: remove our drop-in and reload
sudo rm /etc/ssh/sshd_config.d/00-vps-harden.conf
sudo sshd -t && sudo systemctl reload ssh
```

If `sshd -t` passes but you still cannot log in, the problem is the firewall or
Fail2ban, not sshd.

### Emergency one-liner (console)

```bash
sudo ufw disable; sudo fail2ban-client unban --all; sudo systemctl reload ssh
```

Use it only to get back in, then fix the configuration and re-apply with
`sudo ./install.sh configure --check` first.

### If the dead-man switch is armed

`ufw.deadman_minutes` schedules `ufw --force disable` N minutes after enabling.
Wait for it, or cancel it after proving access:

```bash
sudo ./install.sh firewall cancel-deadman
```

Leaving it armed disables your firewall later. The CLI warns about this.

## 2. Firewall lockout

```bash
sudo ufw status verbose        # if you can still reach the host
sudo ufw disable               # immediate, from console only
```

Then compare intent with reality:

```bash
sudo ./install.sh firewall rules     # UFW rules + Docker publishes
sudo ./install.sh rollback --dry-run
```

Restoring `/etc/ufw/after.rules` via rollback is the clean fix for a
`DOCKER-USER` policy that blocked a service; `ufw reload` afterwards.

## 3. Fail2ban banned you

```bash
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip <your-ip>
sudo ./install.sh fail2ban unban <your-ip>
```

If you are behind a changing IP, add the range to `fail2ban.ignoreip` — but note
that trusting RFC1918 on a Docker host hides real attacks (see
`docs/configuration.md#fail2ban`). The better fix is to administer over Tailscale
and leave the public port allowed only until the tailnet path is proven.

## 4. CrowdSec banned you

Only possible when a bouncer is enabled (detection-only cannot block).

```bash
sudo cscli decisions list
sudo cscli decisions delete --ip <your-ip>
sudo cscli decisions delete --range 100.64.0.0/10   # if the whitelist is missing
```

The tailnet CGNAT ranges are whitelisted by the role (`whitelist_tailnet: true`).
If you disabled that, re-enable it before enforcement.

## 5. Configuration rollback

```bash
sudo ./install.sh rollback --list
sudo ./install.sh rollback --dry-run            # prints the plan, changes nothing
sudo ./install.sh rollback --id 20261107T061500Z-configure --yes
```

What happens:

1. Only paths in `config/managed_paths.yml` are considered; anything else in the
   snapshot is refused.
2. Files that existed are restored with their recorded mode and ownership.
3. Files vps-harden created (recorded as `existed: false`) are removed.
4. `/etc/ssh` changes → `sshd -t`; on failure SSH is **not** reloaded and the
   command exits non-zero.
5. Fail2ban → `fail2ban-client -t` before restart; CrowdSec → restart; UFW →
   reload.

Snapshots live in `/var/backups/vps-harden/snapshots/<id>/` (directory tree +
`manifest.json` with sha256, mode, uid/gid). Ten are kept.

### Manual restore from a snapshot

```bash
snap=/var/backups/vps-harden/snapshots/<id>
python3 -m json.tool "$snap/manifest.json" | less
sudo install -m 0644 -o root -g root \
  "$snap/files/etc/ssh/sshd_config.d/00-vps-harden.conf" \
  /etc/ssh/sshd_config.d/00-vps-harden.conf
sudo sshd -t && sudo systemctl reload ssh
```

## 6. Restoring data backups (restic)

```bash
export RESTIC_REPOSITORY=/var/backups/vps-harden/restic
export RESTIC_PASSWORD_FILE=/root/.vps-harden/restic-password
sudo -E restic snapshots
sudo -E restic restore latest --target /restore
# inspect, then copy back selectively
```

The repository password is generated once at
`/root/.vps-harden/restic-password`. **Without it the repository cannot be
opened.** Store a copy somewhere that is not this VPS.

CrowdSec credentials and Hermes `.env` are excluded from backups on purpose;
recreate them (CrowdSec: re-register the bouncer; Hermes: re-add the token).

## 7. Losing the configuration repository

The host keeps working: Ansible wrote files, nothing depends on the repo at
runtime. To recover management:

```bash
git clone https://github.com/hungpt99-dev/vps-harden
cd vps-harden
sudo ./install.sh discover     # what is actually configured now
sudo ./install.sh audit        # what deviates
```

Then bring `config/vps-harden.yml` back in line with reality before running
`configure` — otherwise the first apply will overwrite manual changes.

## 8. "Rollback restored a config that does not work"

The snapshot is a point in time, not a known-good state. If the snapshot was
taken while the system was already broken:

1. `sudo ./install.sh audit` to see which controls are off.
2. Fix the specific file by hand (console access), validating with the service's
   own test (`sshd -t`, `fail2ban-client -t`, `ufw --dry-run`).
3. Only then run `configure` again — it snapshots before writing, so you always
   have a new restore point.
