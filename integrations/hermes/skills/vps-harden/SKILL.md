---
name: vps-harden
description: Use when auditing or hardening this Ubuntu VPS with vps-harden.
version: 1.0.0
author: Hung Pham
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [security, ufw, fail2ban, crowdsec, ssh, hardening, homelab]
---

# vps-harden operations

The repository at `/root/vps-harden` is the single source of truth for this
host's security configuration. Configuration lives in
`config/vps-harden.yml`; everything under `/etc` is generated from it.

## Read first, change never

Default to read-only commands. They are safe and take seconds:

```bash
sudo /root/vps-harden/install.sh status
sudo /root/vps-harden/install.sh audit
sudo /root/vps-harden/install.sh verify
sudo /root/vps-harden/install.sh firewall rules
```

`audit` reports PASS / WARN / FAIL / NOT CONFIGURED / SKIPPED with remediation.
Never describe the host as "secure" from a passing audit: it means the listed
controls were observed in the expected state at that moment.

## Rules for an agent

1. **Never run `install`, `configure`, `uninstall` or `rollback` without the
   user's explicit approval in this conversation.** They change SSH, firewall or
   service state on a host you may be connecting through.
2. When the user approves a change, run it with `--check` first and paste the
   diff. `--check` reruns the same playbook in Ansible check mode.
3. If a change touches SSH or UFW, tell the user to keep their current session
   open and verify from a second one. The CLI prints the same warning.
4. Prefer `audit --json` when you need to filter findings programmatically.
5. Never edit files under `/etc` directly. Change `config/vps-harden.yml`, then
   run `configure`. Direct edits are reverted by the next run.

## Common tasks

```bash
# What is exposed, including Docker publishes UFW cannot see?
sudo ./install.sh firewall rules

# Why did password auth not turn off?
sudo ./install.sh ssh status                 # effective sshd -T values
sudo ./install.sh audit | grep -A2 password

# A banned admin address
sudo ./install.sh fail2ban bans
sudo ./install.sh fail2ban unban 203.0.113.5

# Undo the last configuration change
sudo ./install.sh rollback --list
sudo ./install.sh rollback --dry-run
```

## Interpretation notes

- Docker-published ports (`0.0.0.0:PORT->…`) bypass UFW's INPUT chain. Seeing
  them in `firewall rules` is expected on this host; `audit` warns unless a
  `DOCKER-USER` policy exists.
- CrowdSec decisions with no bouncer are detection-only. That is the intended
  default here because Fail2ban is the single SSH enforcement point.
- A Fail2ban jail showing `Total failed: 0` can mean the journal filter matches
  nothing. Check `journalmatch` before concluding the host is quiet.
