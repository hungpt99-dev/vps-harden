# Troubleshooting

Symptom → cause → fix. Start every investigation with `sudo ./install.sh audit`
and `sudo ./install.sh verify`; they name the failed control.

## "Playbook failed" with no obvious task

```bash
sudo ./install.sh audit -vv
tail -50 /var/log/vps-harden/vps-harden.log
```

The CLI mirrors Ansible output to the project log. The failing task name and the
`changed=`/`failed=` counters are the fastest way to tell a policy problem from a
connectivity problem.

## SSH settings do not take effect

**Cause:** sshd uses the **first** value it reads. Drop-ins are included in glob
order, so `50-cloud-init.conf` (`PasswordAuthentication yes`) beats
`99-something.conf`.

```bash
sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|port'
sudo ls -l /etc/ssh/sshd_config.d/
```

**Fix:** vps-harden writes `00-vps-harden.conf`, which sorts first, and then
asserts the effective value. If verification still fails, another file is
included earlier (for example a line in `sshd_config` itself). `install.sh ssh
status` prints the effective set.

`sshd -t` failing with *"Missing privilege separation directory: /run/sshd"*
means the directory is missing (containers, broken tmpfiles). The role creates
it; if you run sshd by hand, `mkdir -p /run/sshd`.

## Locked out of SSH

See `docs/recovery.md`. The 10-second version: provider console → do **not**
restart → `sudo ./install.sh rollback --id <snapshot>` or
`sudo ./install.sh configure --deadman` is not available once you are out, so
the dead-man switch (if armed) is what saves you.

## UFW enabled and everything is unreachable

```bash
sudo ufw status verbose
sudo ufw disable            # immediate recovery, re-enable consciously
```

If you still have console access but no network, check whether your provider has
its own firewall in front: UFW being correct does not make a closed cloud
security group open.

## `ufw: command not found` during configure

The `ufw` role ran before its package was installed. This happens when you run
`configure` on a host where `install` never ran. Run
`sudo ./install.sh install ufw` first.

## Fail2ban jail is listed but nothing is ever banned

**Cause 1 — journal unit mismatch.** Ubuntu's unit is `ssh.service`; the shipped
filter expects `sshd.service`.

```bash
fail2ban-client status sshd          # look at "Journal matches"
journalctl -u ssh -o json -n 3 | python3 -c \
  'import sys,json;[print(json.loads(l)["_SYSTEMD_UNIT"], json.loads(l)["_COMM"]) for l in sys.stdin]'
```

The role writes `journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd`. If yours
differs, the filter matches nothing, silently.

**Cause 2 — another jail file owns `[sshd]`.** `grep -lE '^\[sshd\]'
/etc/fail2ban/jail.d/*` lists them; later filenames win. The role refuses to
write when it finds one (`conflict_policy: fail`).

**Cause 3 — the ban action is missing.** `fail2ban-client -t` validates the
config; `journalctl -u fail2ban -n 50` shows action errors (`nftables` needs the
`nft` binary, `iptables-multiport` needs iptables).

## CrowdSec restart-loops: "address already in use"

LAPI defaults to `127.0.0.1:8080`, which a container very often publishes.

```bash
sudo ss -ltnp | grep 8080
sudo journalctl -u crowdsec -n 30
```

Set `crowdsec.lapi_port: 8081` (the default in vps-harden) — the role rewrites
`listen_uri` and the agent credentials URL and refuses to start when the port is
owned by a non-CrowdSec process.

## CrowdSec decisions exist but nothing is blocked

That is detection-only mode. `cscli bouncers list` empty + `cscli decisions list`
non-empty is the intended default. Enabling
`crowdsec.firewall_bouncer_enabled` installs an enforcement point — decide
whether Fail2ban or CrowdSec owns SSH bans first (`docs/security-model.md`).

## Docker containers are unreachable after enabling the DOCKER-USER chain

Expected: the chain drops everything not in `docker_allowed_ports`.

```bash
sudo iptables -S DOCKER-USER
sudo ./install.sh rollback --id <snapshot>   # restores /etc/ufw/after.rules
sudo ufw reload
```

Then either add the ports to `ufw.docker_allowed_ports`, add a RETURN for the
compose bridge (`br-*`), or bind the publish to `127.0.0.1`.

## Tailscale says "not authenticated"

By design. vps-harden never creates auth keys.

```bash
sudo tailscale up        # open the URL it prints
sudo ./install.sh verify # BackendState must be Running
```

For headless automated setup, pass `--extra-vars tailscale_auth_key=...` from
Vault; the role marks the task `no_log`.

## `No Python interpreter with PyYAML`

```bash
sudo apt-get install -y python3-yaml
```

Ansible's own interpreter (`ansible_playbook_python`) is used inside the
playbooks, so the CLI's scripts are the only place this bites — `backup`,
`rollback` and `config`.

## Ansible not found / wrong version

```bash
./scripts/bootstrap.sh --check     # what would it do?
sudo ./scripts/bootstrap.sh        # apt, then a venv fallback
```

If you use the venv fallback, `install.sh` finds it at
`~/.vps-harden/venv/bin/ansible-playbook`. Set `VH_ANSIBLE=/path/to/ansible-playbook`
to pin a specific one.

## `install.sh` refuses with "Refusing to continue without confirmation"

Non-interactive session (CI, cron, `ssh host 'cmd'`). Add `--yes`. This is
deliberate: an unattended `configure` that changes SSH or the firewall must be an
explicit decision.

## Running inside a container

`preflight` fails with "systemd is not running". That is correct: the toolkit
manages services. Use `tests/integration/Dockerfile` (systemd-enabled), not a
plain `ubuntu:24.04`.

## Not tested (honest coverage boundaries)

These paths are implemented and lint-checked but **not** proven by this
repository's automated tests:

| Path | Why | How to prove it |
|---|---|---|
| CrowdSec package install from packagecloud | network + repository policy in CI | run `install crowdsec` on a disposable VPS |
| CrowdSec bouncer end to end | needs a second enforcement decision | enable on a test host, watch `cscli bouncers list` |
| Tailscale authentication | needs a real tailnet | `tailscale up`, then `verify` |
| Docker/prometheus/grafana stack | pulls images | `configure monitoring` on a test host |
| restic backups to remote storage | needs credentials | `systemctl start vps-harden-backup` then `restic snapshots` |
| UFW enable inside the container | needs NET_ADMIN + host modules | check-mode prediction only in CI; see `install --check` |
| Provider-level firewall | outside the host | external port scan |

Everything else — CLI, config validation, snapshot/rollback, audit parsing, the
SSH lockout gate, idempotency, ansible-lint, ShellCheck — runs in CI.
