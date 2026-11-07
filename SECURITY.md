# Security policy

## Reporting a vulnerability

This project configures SSH and firewalls on live servers. A bug here can remove
an operator's access to their own machine, so please do not open a public issue
for anything in these classes:

- a path where `configure` can disable SSH access (password auth or root login
  removed without a working key, wrong port allowed, firewall enabled without an
  SSH rule)
- an unintended write outside `config/managed_paths.yml`
- a rollback that can restore an invalid SSH configuration and reload it
- command injection through configuration values
- the MCP server executing anything beyond its fixed read-only commands

Report privately through GitHub Security Advisories
("Security" → "Report a vulnerability") on
`https://github.com/hungpt99-dev/vps-harden`. If that is unavailable, contact the
maintainer through the address on their GitHub profile.

Please include:

- affected version (`./install.sh version`) and OS
- the command and configuration that triggers it (redact IPs and keys)
- the relevant log excerpt from `/var/log/vps-harden/vps-harden.log`
- whether you still have access to the host

**Do not test on a production VPS you cannot recover.** Use
`tests/integration/` (a disposable container) or a throwaway VM.

## Response

Best effort, within 7 days for a lockout-class report. Fixes ship as a patch
release with a CHANGELOG entry; the advisory is published after users have had
time to upgrade.

## Scope

In scope: the CLI, snapshot/rollback engine, audit engine, Ansible roles and
templates, MCP server, CI workflows.

Out of scope: vulnerabilities in Ubuntu packages, Docker, CrowdSec, Fail2ban,
Tailscale or Hermes themselves (report those upstream); misconfiguration an
operator applies outside the tool (editing `/etc` by hand); attacks that already
require root.

## Design commitments

- No credential is stored in the repository; `.gitignore` excludes the user
  configuration file.
- Downloaded signing keys are verified by apt through `signed-by` keyrings; no
  `curl | sh`.
- The MCP server is read-only by construction (no tool can write configuration).
- Every change is snapshotted first, and destructive operations require explicit
  confirmation.
