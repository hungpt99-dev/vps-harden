# Security model

## Threat model

**In scope**

| Threat | Control |
|---|---|
| Internet-wide SSH brute force and credential stuffing | key-only auth, Fail2ban jail, CrowdSec scenarios |
| Accidental exposure of a service | UFW deny-by-default, audit of listeners and Docker publishes |
| Operator lockout during hardening | pre-flight gates, dead-man switch, snapshots, validated reloads |
| A compromised service reaching the host | minimal open ports, no-new-privileges Docker default, kernel sysctls |
| Unpatched known vulnerabilities | unattended security upgrades, pending-update report |
| Silent configuration drift | effective-state verification after every apply, audit on demand |
| Losing configuration in a bad change | managed-path snapshots + rollback |

**Out of scope**

- Application-level vulnerabilities inside your containers.
- Kernel exploits (no LSM tuning beyond Ubuntu's AppArmor defaults).
- Rootkit detection (no AIDE/SAMHAIN integration).
- Multi-user privilege policy beyond sudo group detection.
- DDoS absorption, WAF, TLS termination.
- Secrets management (no vault deployment; only reading a key you provide).

A compromised root account defeats every control here. This toolkit reduces
exposure and makes drift visible; it does not make a host unbreakable.

## Detection vs enforcement (the important distinction)

```
auth.log / journal ──► CrowdSec engine ──► decision (ban 4h) ──► bouncer? ──► packet filter
        │                                                          ▲
        └──────────► Fail2ban jail ────────────────────────────────┘
```

- **Fail2ban enforces.** It parses the SSH journal and installs its own nftables
  set. One jail, one command to inspect (`fail2ban-client status sshd`).
- **CrowdSec detects.** It correlates scenarios and records decisions. Without a
  bouncer, a decision changes nothing on the wire — `cscli decisions list`
  non-empty with `cscli bouncers list` empty is *expected*, not broken.
- Turning on the CrowdSec bouncer while the Fail2ban SSH jail is active creates
  **two enforcement points for the same traffic**. Bans become unattributable
  and incident response gets harder. vps-harden defaults to detection-only and
  refuses to install a bouncer when one is already registered.

If you want CrowdSec enforcement, disable the Fail2ban jail in the same change
and say so in your runbook.

## Trust boundaries

| Boundary | Crossing it |
|---|---|
| Public internet → host | UFW deny incoming; only explicitly allowed ports |
| Tailnet → host | `allow in on tailscale0`; tailnet ranges are never banned |
| Docker → host | published ports bypass UFW (`docs/firewall.md#docker`); `no-new-privileges` in `daemon.json` |
| Agent → host | MCP server is read-only; no tool can write configuration |
| Repo → host | Ansible templates with `validate:`; unknown config keys rejected |

## Why SSH hardening is gated

The failure mode is not "hardening did not apply", it is "hardening applied and
the operator cannot get back in". Three independent guards:

1. **Key presence.** No authorized key found → refuse to disable password auth
   (unless `ssh.allow_no_keys=true`, an explicit console-only escape hatch).
2. **Non-root key.** If root is the only account with a key, disabling root login
   would remove the last access path → refuse.
3. **Effective-state proof.** After reload, `sshd -T` is compared field by field.
   A drop-in that loses to `50-cloud-init.conf` fails the run instead of quietly
   reverting.

The role also validates the snippet with `sshd -t` through a wrapper config
before installing it (`scripts/sshd-validate.sh`), so a bad template never lands.

## Why the firewall is gated

`ufw enable` with no SSH allow rule is a self-inflicted outage. The role:

1. derives an allow rule for `ssh.port` (the user never types it),
2. applies all rules while the firewall is still inactive,
3. reads `ufw show added` and asserts the SSH rule is present,
4. only then runs `ufw --force enable`,
5. verifies `Status: active` and the three default policies,
6. optionally arms a dead-man switch (`ufw.deadman_minutes`) that disables UFW
   if you do not cancel it after proving access.

## Logging and secrets

- No credentials in `config/`. The Tailscale auth key and any Hermes installer
  checksum come from Ansible Vault or extra vars.
- The restic password is generated at `/root/.vps-harden/restic-password`
  (0600), outside `/etc` so it is not inside the backup it protects.
- The CrowdSec bouncer key is written straight into a 0600 config and is
  excluded from scheduled backups; the snapshot engine includes it because a
  rollback without it would break the Local API — snapshots are 0700 root-only.
- Fail2ban/CrowdSec logs go to journald; vps-harden's own log is
  `/var/log/vps-harden/vps-harden.log`.

## Known limits of the guarantees

- `ufw status` does not describe what the internet can reach on a Docker host.
  The audit enumerates publishes, but only an external scan proves closure.
- A Fail2ban jail that matches nothing is silent. The role verifies the jail
  exists, not that it has ever matched; check `Total failed` over a few days.
- `verify` proves the controls listed in its tasks. It is not a pentest.
- Automatic reboots are off. Kernel updates that need a reboot stay pending
  until you schedule one.
