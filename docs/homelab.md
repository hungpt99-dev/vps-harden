# The AI-native homelab layer

The premise: an agent should be able to *see* and *explain* the infrastructure,
and a human should stay the only thing that can change it.

## Why read-only is a feature, not a limitation

An agent with write access to `/etc/ssh` or `ufw` has the same failure mode as a
tired operator at 3 a.m., except faster and with more confidence. The expensive
accidents in this domain are not "the agent did nothing" — they are "the agent
changed the firewall while I was connected over SSH".

vps-harden therefore splits the two roles:

```
 human ──approval──► install.sh ──► Ansible ──► /etc, services
   ▲                    │
   │                    └── snapshot, validate, verify
   │
 agent ◄── read-only ── MCP tools (status, audit, firewall, ssh, help)
```

The agent can answer "what is exposed", "why is password auth still on", "what
does the audit say", "which container ports bypass the firewall". It cannot run
`configure`. Asking the human to run one command is cheaper than an unplanned
outage.

## What ships

`integrations/hermes/`

- `mcp/vps_harden_mcp.py` — stdio MCP server, JSON-RPC 2.0, five read-only
  tools. No shell, fixed argv allowlists, 120 s timeouts, 48 KB output cap.
- `skills/vps-harden/SKILL.md` — the operating rules for the agent: read first,
  never apply without approval, always `--check` before a change, never edit
  `/etc` directly.

Registration (manual, or `hermes.register_mcp: true`):

```bash
hermes mcp add vps-harden \
  --command python3 \
  --args /usr/local/lib/vps-harden/vps_harden_mcp.py --root /root/vps-harden
hermes mcp list
```

## Observability without exposure

Monitoring and logging are optional and bound to `127.0.0.1`:

- Prometheus + node_exporter + cAdvisor + Grafana on `127.0.0.1:3030` /
  `:9090` (compose stack in `/opt/homelab/monitoring`)
- Reach Grafana through `ssh -L 3030:127.0.0.1:3030 host` or `tailscale serve`;
  never by publishing 3000/9090 "just for a minute"
- journald is bounded (500M / 30d) so a chatty container cannot fill the disk
- optional Loki + Promtail (`logging.loki_enabled`) for retention beyond journald

The audit does not depend on any of this. If the stack is down, `audit` still
reports the host's actual state — observability is a convenience, not a control.

## Operational workflows

**Daily / on-demand triage**

```bash
sudo ./install.sh status
sudo ./install.sh audit --json | jq '.summary'
```

**"Something looks wrong"**

```bash
sudo ./install.sh firewall rules     # includes Docker publishes
sudo ./install.sh audit | grep -A3 FAIL
sudo ./install.sh fail2ban bans
sudo ./install.sh crowdsec decisions
```

**Planned change**

```bash
$EDITOR config/vps-harden.yml
sudo ./install.sh config validate
sudo ./install.sh configure --check
sudo ./install.sh configure
sudo ./install.sh verify
```

**Undo**

```bash
sudo ./install.sh rollback --list
sudo ./install.sh rollback --id <last> --yes
```

## Division of labour

| Question | Owner | Mechanism |
|---|---|---|
| Is the host exposed? | agent (read) + human | `audit`, `firewall rules` |
| Why is a control off? | agent (read) | findings with evidence + fix |
| Change a port / rule / setting | human | `config/vps-harden.yml` + `configure` |
| Restore after a bad change | human | `rollback` |
| Scheduled data backup | host | systemd timer + restic |
| Kernel/package updates | host | unattended-upgrades |

## What this is not

- Not an autonomous remediation loop. Adding write tools would require an
  approval protocol and a lockout-proof transport (a second path such as a
  provider API or out-of-band console), which is a different product.
- Not a chat interface to Docker. Container lifecycle is Compose's job; the
  agent can read what is published, not restart stacks.
- Not a replacement for a runbook. `docs/recovery.md` exists because the agent
  may be the thing that is unreachable.
