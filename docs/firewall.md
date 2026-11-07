# Firewall: UFW, Docker and Tailscale

## What the role configures

| Setting | Value | Config key |
|---|---|---|
| Incoming default | deny | `ufw.default_incoming` |
| Outgoing default | allow | `ufw.default_outgoing` |
| Routed default | deny | `ufw.default_routed` |
| Logging | low | `ufw.logging` |
| IPv6 | yes | `ufw.ipv6` |
| SSH | allow `<ssh.port>/tcp` (derived) | `ufw.auto_allow_ssh` |
| Tailnet | allow in on `tailscale0` | `ufw.allow_tailscale` |

`SSH (vps-harden)` and `Tailnet admin access (vps-harden)` comments mark rules
the role owns, which makes them distinguishable in `ufw status numbered` from
rules you added by hand. The role never deletes a rule it did not add.

## Ordering guarantees

1. Rules are applied while UFW is still inactive — nobody is filtered out
   halfway through.
2. `ufw show added` is read and asserted to contain the SSH port before
   `ufw --force enable`.
3. Defaults and logging are set only when they differ from the current state.
4. After enabling, `ufw status verbose` is asserted: active, incoming deny,
   outgoing allow, routed deny.

If any assertion fails, the play stops. The firewall may be partially applied,
which is why a snapshot was taken first.

## Docker: the gap UFW cannot see

Docker publishes a container port by adding a DNAT rule in `nat PREROUTING`.
Forwarded traffic traverses `FORWARD` and `DOCKER-USER` — never `INPUT`, where
UFW's rules live. The practical consequence:

```
ufw status          →  22/tcp ALLOW, 443/tcp ALLOW
docker ps           →  0.0.0.0:5432->5432/tcp, 0.0.0.0:8080->80/tcp
internet            →  can reach 5432 and 8080
```

`install.sh firewall rules` prints both views side by side, and `audit` raises a
WARN with the publish list. Three ways to fix it, in increasing bluntness:

### 1. Bind publishes to loopback (best default)

```yaml
ports:
  - "127.0.0.1:5432:5432"
```

A reverse proxy on the host, or Tailscale, provides access. No firewall
interaction, no downtime beyond recreating the container.

### 2. Manage the `DOCKER-USER` chain (opt-in)

```yaml
vps_harden:
  ufw:
    manage_docker_user_chain: true
    docker_allowed_ports: ["443"]
```

The role writes a marked block into `/etc/ufw/after.rules`:

```
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -i tailscale0 -j RETURN
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -i docker0 -j RETURN
-A DOCKER-USER -p tcp --dport 443 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
```

Consequences you must accept before enabling it:

- **Every** published port not listed in `docker_allowed_ports` becomes
  unreachable from the internet. That includes stacks you add later.
- Inter-container traffic is preserved by the `docker0` RETURN and the
  established/related rule. Custom bridge networks (`br-*`) are *not* exempt:
  add a RETURN for each, or use the compose network name.
- `ufw reload` re-applies the file and flushes `DOCKER-USER` before re-adding
  your rules. Docker re-adds its own `RETURN` on restart; ours stays above it.

Rollback: `sudo ./install.sh rollback --id <snapshot>` restores
`/etc/ufw/after.rules`; or remove the marked block and run `ufw reload`.

### 3. `DEFAULT_FORWARD_POLICY="DROP"`

Not used by this project. It also blocks the forwarded traffic Docker relies on
for published ports, so containers stop being reachable — including the ones you
wanted to keep. If you set it manually, expect to add explicit `DOCKER-USER`
allows anyway.

## Tailscale

`allow in on tailscale0` grants the whole tailnet access to every host port.
That is the point — it is the administrative path — but it means **Tailscale ACLs
are your authorization layer**, not UFW. Restrict access in the tailnet policy;
do not rely on the interface rule to be selective.

The rule is written even before Tailscale is installed: it is an interface match,
so it is inert until `tailscale0` exists.

## The dead-man switch

```yaml
ufw:
  deadman_minutes: 10
```

On enable, the role schedules:

```
systemd-run --on-active=10m --unit=vh-ufw-deadman --collect ufw --force disable
```

If you lose access, the firewall disables itself and you get back in. After
proving access from a second session:

```bash
sudo ./install.sh firewall cancel-deadman
```

A dead-man switch left armed will disable your firewall ten minutes later. The
CLI prints this warning; do not dismiss it.

## Verification commands

```bash
sudo ./install.sh firewall status        # ufw status verbose
sudo ./install.sh firewall rules         # numbered rules + Docker publishes + DOCKER-USER
sudo ufw status numbered
sudo iptables -S DOCKER-USER && sudo ip6tables -S DOCKER-USER
sudo nft list ruleset | head -40         # on a host using iptables-nft
```

From outside the host, a port scan is the only proof of closure. The audit tells
you what is listening and published; it cannot tell you what your provider's
edge firewall does.
