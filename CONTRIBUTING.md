# Contributing

Thanks for taking the time. This project touches SSH and firewalls on live
servers, so the bar for a change is "prove it cannot lock someone out".

## Setup

```bash
git clone https://github.com/hungpt99-dev/vps-harden
cd vps-harden
python3 -m venv .venv && . .venv/bin/activate
pip install 'ansible-core==2.17.*' 'ansible-lint==26.6.0' pytest
# Bats (Ubuntu: apt install bats, or:)
git clone --depth 1 https://github.com/bats-core/bats-core /tmp/bats-core
sudo /tmp/bats-core/install.sh /usr/local
```

## Test loop

```bash
make lint              # shellcheck + ansible-lint + syntax
make test-unit         # pytest + bats
make test              # lint + unit
make test-integration  # disposable Ubuntu 24.04 container with systemd
```

`make test-integration` is the only proof that roles work on a real Ubuntu
userspace. It builds `tests/integration/Dockerfile`, runs inside a privileged
container, and asserts the SSH lockout gate, the apply, `verify`, and
idempotency. It never touches the host's firewall or SSH.

## Conventions

**Bash** (`install.sh`, `scripts/*.sh`)

- `set -Eeuo pipefail`, `shellcheck -x` clean.
- Every system path goes through `vh_path()` so tests can sandbox with `VH_ROOT`.
- Mutating commands need confirmation unless `--yes`; non-interactive runs must
  not guess.
- Exit codes are part of the interface (`0/2/3/4/5/6/7`, documented in `--help`).

**Ansible**

- FQCN everywhere (`ansible.builtin.*`); no collections beyond `ansible-core`.
- `ansible.builtin.command` needs `changed_when` always, and `check_mode: false`
  if it feeds a decision (otherwise `--check` breaks).
- Every role ends with a verification task that reads the daemon's effective
  state (`sshd -T`, `ufw status`, `fail2ban-client status`, `docker info`,
  `apt-config dump`). "The task succeeded" is not verification.
- Assert before the first write; the failure message must name the fix.
- Validate configs with the daemon's own parser (`sshd -t`, `fail2ban-client -t`,
  `python -m json.tool`, `apt-config dump`) before reloading.
- Reload, don't restart, where the service supports it.
- Templates start with `# {{ ansible_managed }}`.

**Configuration contract**

Adding an option is a four-part change:

1. `config/defaults.yml` — the schema and the safe default.
2. `playbooks/group_vars/all.yml` — the mapping to a role variable.
3. `roles/<role>/defaults/main.yml` — the standalone default (must match).
4. `docs/configuration.md` — what it does and what it breaks.

`tests/unit/test_config_contract.py` fails if any of those drift, if a role's
`tasks/install.yml` is never imported, or if a playbook's `pre_tasks` lose the
`always` tag.

**Managed paths**

Any file under `/etc`, `/usr`, `/opt` or `/var` that a role writes must be listed
in `config/managed_paths.yml` (`owned_files` for created files, `modified_files`
for edited system files). Otherwise rollback and uninstall cannot see it — and a
test fails.

## Adding a component

```
roles/<name>/
  defaults/main.yml      every variable, safe value
  tasks/main.yml         import install.yml / configure.yml by vh_phase
  tasks/install.yml      packages + repositories only
  tasks/configure.yml    files, services, verification
  handlers/main.yml      reload after validation
  templates/*.j2
```

Checklist:

- [ ] `install.yml` is imported by `main.yml` (test enforces it)
- [ ] `configure.yml` starts by checking the package/command exists and says how
      to install it
- [ ] conflicting owners are detected and reported, never silently overwritten
- [ ] `configure.yml` ends with an effective-state assertion
- [ ] every written path is in `config/managed_paths.yml`
- [ ] `config/defaults.yml`, mapping, role default, docs updated together
- [ ] `docs/configuration.md` and `docs/security-model.md` mention the trade-off
- [ ] idempotency proven: second run `changed=0`
- [ ] `make test` passes; `make test-integration` still passes

## Commit style

```
area: imperative summary

Body explains the failure mode being fixed, not the diff.
```

Areas: `cli`, `config`, `audit`, `snapshot`, `roles/<name>`, `docs`, `ci`.

## Reporting bugs

- Lockout-class bug (can remove access): see `SECURITY.md`, do not open a public
  issue.
- Otherwise: include `install.sh version`, the host OS, the command, and the
  relevant part of `/var/log/vps-harden/vps-harden.log` (redact IPs).
