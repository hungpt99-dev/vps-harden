#!/usr/bin/env python3
"""vps-harden security audit engine.

Read-only by construction: every check either reads a file or invokes a
read-only query (``sshd -T``, ``ufw status``, ``ss``, ``cscli ... list``,
``fail2ban-client status``, ``iptables -S``, ``systemctl is-active``).

The parsing functions are pure and unit-tested with literal fixtures
(tests/unit/test_audit_parsers.py); the collectors only worry about commands
being missing. That split is why an audit can be trusted on a host where half
the stack is not installed yet.

Usage:
    vh_audit.py [--json] [--report FILE] [--fail-on fail|warn|never]
                [--ssh-port N] [--expect-ufw BOOL] ...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
NOT_CONFIGURED = "NOT CONFIGURED"
SKIPPED = "SKIPPED"

STATUS_ORDER = [FAIL, WARN, NOT_CONFIGURED, SKIPPED, PASS]
SEVERITIES = ("info", "low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    id: str
    title: str
    status: str
    severity: str = "info"
    detail: str = ""
    remediation: str = ""
    evidence: str = ""


@dataclass
class Context:
    """Everything the checks need, collected once."""

    ssh_port: int = 22
    expect_ufw: bool = True
    expect_fail2ban: bool = True
    expect_crowdsec: bool = True
    expect_unattended: bool = True
    expect_tailscale: bool = False
    expect_docker: bool = False
    managed_paths: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


# ---------------------------------------------------------------------------
# Command / file helpers
# ---------------------------------------------------------------------------
def run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, PermissionError):
        return 127, "", "not available"
    except subprocess.SubprocessError as exc:  # timeout
        return 124, "", str(exc)


def read_text(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# ---------------------------------------------------------------------------
# Pure parsers (unit tested)
# ---------------------------------------------------------------------------
def parse_sshd_t(text: str) -> dict[str, str]:
    """Parse `sshd -T` output: lowercase keyword -> value."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower()] = parts[1].strip()
    return result


def parse_ufw_status(text: str) -> dict[str, Any]:
    """Parse `ufw status verbose` into the fields the audit cares about."""
    info: dict[str, Any] = {
        "installed": True,
        "active": False,
        "default_incoming": None,
        "default_outgoing": None,
        "default_routed": None,
        "logging": None,
        "ipv6_rules": 0,
        "rules": [],
    }
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Status:"):
            # "inactive" contains "active": anchor the match.
            info["active"] = bool(re.match(r"Status:\s*active\b", stripped, re.I))
        elif stripped.startswith("Default:"):
            match = re.search(
                r"([a-z]+)\s*\(incoming\),\s*([a-z]+)\s*\(outgoing\),\s*([a-z]+)\s*\(routed\)",
                stripped,
                re.I,
            )
            if match:
                info["default_incoming"] = match.group(1).lower()
                info["default_outgoing"] = match.group(2).lower()
                info["default_routed"] = match.group(3).lower()
        elif stripped.startswith("Logging:"):
            # "Logging: on (low)" -> the level is the parenthesised value.
            match = re.search(r"Logging:\s*\w+\s*\((\w+)\)", stripped, re.I)
            if not match:
                match = re.search(r"Logging:\s*(\w+)", stripped, re.I)
            if match:
                info["logging"] = match.group(1).lower()
        elif stripped.startswith("To ") or stripped.startswith("--"):
            continue
        elif stripped and not stripped.startswith("New profiles"):
            if stripped.endswith("(v6)") or "(v6)" in stripped:
                info["ipv6_rules"] += 1
            info["rules"].append(stripped)
    return info


def parse_ss(text: str) -> list[dict[str, Any]]:
    """Parse `ss -tulpnH` into listener records."""
    result = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        proto, _state, _rx, _tx, local = fields[0], fields[1], fields[2], fields[3], fields[4]
        process = ""
        match = re.search(r'users:\(\("([^"]+)"', line)
        if match:
            process = match.group(1)
        addr, _, port = local.rpartition(":")
        result.append(
            {
                "proto": proto,
                "addr": addr.strip("[]"),
                "port": port,
                "process": process,
                "raw": local,
            }
        )
    return result


def is_public_bind(addr: str) -> bool:
    """True when a listener is reachable from outside the host."""
    if addr in ("::", "*", ""):
        return True
    if addr in ("0.0.0.0",):
        return True
    if addr.startswith("127.") or addr == "::1":
        return False
    if addr.startswith("100.") or addr.startswith("fd7a:115c:a1e0:"):
        return False  # Tailscale
    if addr.startswith("172.17.") or addr.startswith("172.18.") or addr.startswith("172.19."):
        return False  # docker bridge
    return True


def parse_fail2ban_status(text: str) -> dict[str, Any]:
    info: dict[str, Any] = {"jails": [], "banned": None}
    for line in text.splitlines():
        if "Jail list:" in line:
            info["jails"] = [
                jail.strip() for jail in line.split("Jail list:", 1)[1].split(",") if jail.strip()
            ]
        if "Currently banned:" in line:
            match = re.search(r"Currently banned:\s*(\d+)", line)
            if match:
                info["banned"] = int(match.group(1))
    return info


def parse_fail2ban_jail(text: str) -> dict[str, Any]:
    info: dict[str, Any] = {"filter": None, "banned": [], "total": None}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|- Filter"):
            parts = stripped.split(":", 1)
            if len(parts) == 2:
                info["filter"] = parts[1].strip().split(",")[0].strip()
        match = re.search(r"Currently banned:\s*(\d+)", stripped)
        if match:
            info["total"] = int(match.group(1))
        banned = re.search(r"Banned IP list:\s*(.*)$", stripped)
        if banned:
            info["banned"] = banned.group(1).split()
    return info


def parse_apt_check(text: str) -> tuple[int | None, int | None]:
    """Parse apt-check output ('3;2' or human readable)."""
    match = re.search(r"(\d+)\s*;?\s*(\d+)?", text)
    if not match:
        return None, None
    total = int(match.group(1))
    security = int(match.group(2)) if match.group(2) else 0
    return total, security


def parse_cscli_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def cscli_list(data: Any, key: str) -> list[dict[str, Any]]:
    """cscli returns either a bare list or {"<key>": [...]} depending on command."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        value = data.get(key, [])
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def count_decisions(data: Any) -> int:
    """`cscli decisions list -o json` nests decisions inside alert objects."""
    if not isinstance(data, list):
        return 0
    total = 0
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("decisions"), list):
            total += len(item["decisions"])
        else:
            total += 1
    return total


def parse_iptables_chain(text: str) -> list[list[str]]:
    """Parse `iptables -S CHAIN` into rows of args."""
    rows = []
    for line in text.splitlines():
        if not line.startswith("-A"):
            continue
        rows.append(line.split())
    return rows


def mode_of(path: str) -> int | None:
    try:
        return Path(path).stat().st_mode & 0o777
    except OSError:
        return None


def owner_of(path: str) -> tuple[int, int] | None:
    try:
        st = Path(path).stat()
        return st.st_uid, st.st_gid
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def check_system(ctx: Context) -> None:
    osr = read_text("/etc/os-release")
    name = ""
    version = ""
    for line in osr.splitlines():
        if line.startswith("PRETTY_NAME="):
            name = line.split("=", 1)[1].strip().strip('"')
        if line.startswith("VERSION_ID="):
            version = line.split("=", 1)[1].strip().strip('"')
    supported = version in ("22.04", "24.04")
    ctx.add(
        Finding(
            "os.supported",
            "Supported operating system",
            PASS if supported else FAIL,
            "high" if not supported else "info",
            f"{name or 'unknown'} (VERSION_ID={version or '?'})",
            "" if supported else "Upgrade to Ubuntu 22.04 or 24.04 LTS.",
        )
    )
    ctx.add(
        Finding(
            "os.kernel",
            "Kernel version",
            PASS,
            "info",
            f"{os.uname().release} ({os.uname().machine})",
        )
    )

    rc, out, _ = run(["systemctl", "is-active", "systemd-timesyncd"])
    if rc != 0:
        rc, out, _ = run(["systemctl", "is-active", "chrony"])
    synced = out.strip()
    ctx.add(
        Finding(
            "system.time_sync",
            "Time synchronisation",
            PASS if synced == "active" else WARN,
            "low",
            f"ntp service state: {synced or 'unknown'}",
            "Enable systemd-timesyncd: systemctl enable --now systemd-timesyncd",
        )
    )

    total = security = None
    if os.access("/usr/lib/update-notifier/apt-check", os.X_OK):
        rc, out, _ = run(["/usr/lib/update-notifier/apt-check"], timeout=60)
        if rc == 0:
            total, security = parse_apt_check(out)
    if security is None:
        # Fallback: the package index knows the suites, so count security-pocket
        # upgrades from a simulated run (no changes, no download).
        rc, out, _ = run(["apt-get", "-s", "-q", "upgrade"], timeout=120)
        if rc == 0:
            upgraded = re.findall(
                r"(?m)^Inst\s+(\S+)(?:\s+\[[^\]]*\])?\s+\(([^)]*)\)", out
            )
            if upgraded:
                total = len(upgraded)
                security = sum(1 for _, version in upgraded if "-security" in version)
    if security is None:
        ctx.add(
            Finding(
                "system.pending_updates",
                "Pending security updates",
                SKIPPED,
                "info",
                "apt-check is unavailable; cannot determine pending updates",
                "Run: sudo apt-get update && sudo apt-get -s upgrade",
            )
        )
    else:
        ctx.add(
            Finding(
                "system.pending_updates",
                "Pending security updates",
                PASS if security == 0 else WARN,
                "medium" if security else "info",
                f"{security} security update(s) pending ({total} total)",
                "Apply with: sudo apt-get upgrade (or wait for unattended-upgrades)",
            )
        )


def check_firewall(ctx: Context) -> None:
    if not have("ufw"):
        ctx.add(
            Finding(
                "firewall.installed",
                "Firewall installed",
                NOT_CONFIGURED if ctx.expect_ufw else PASS,
                "high" if ctx.expect_ufw else "info",
                "ufw is not installed",
                "Install and configure with: sudo ./install.sh install ufw",
            )
        )
        return

    rc, out, err = run(["ufw", "status", "verbose"], timeout=20)
    info = parse_ufw_status(out if rc == 0 else "")
    if info["active"]:
        status = PASS
    else:
        # Inactive is a failure only when this host is supposed to be managed by
        # UFW; otherwise report the missing layer instead of raising a false alarm.
        status = FAIL if ctx.expect_ufw else NOT_CONFIGURED
    ctx.add(
        Finding(
            "firewall.active",
            "Firewall enabled",
            status,
            "critical" if not info["active"] else "info",
            "UFW is active" if info["active"] else f"UFW is inactive ({err.strip() or 'status: inactive'})",
            "" if info["active"] else "Enable with: sudo ./install.sh configure (after checking SSH rules)",
        )
    )
    if not info["active"]:
        return

    defaults_ok = (
        info["default_incoming"] in ("deny", "reject")
        and info["default_routed"] in ("deny", "reject")
        and info["default_outgoing"] == "allow"
    )
    ctx.add(
        Finding(
            "firewall.defaults",
            "Firewall default policies",
            PASS if defaults_ok else WARN,
            "high" if not defaults_ok else "info",
            "incoming={incoming}, outgoing={outgoing}, routed={routed}".format(
                incoming=info["default_incoming"],
                outgoing=info["default_outgoing"],
                routed=info["default_routed"],
            ),
            "" if defaults_ok else "Set: ufw default deny incoming; ufw default deny routed",
        )
    )

    ssh_allowed = any(
        re.search(rf"\b{ctx.ssh_port}/tcp\b", rule) and "ALLOW" in rule.upper()
        for rule in info["rules"]
    )
    ctx.add(
        Finding(
            "firewall.ssh_rule",
            "SSH port allowed through the firewall",
            PASS if ssh_allowed else FAIL,
            "critical",
            f"port {ctx.ssh_port}/tcp "
            + ("has an ALLOW rule" if ssh_allowed else "has NO allow rule"),
            "" if ssh_allowed else f"Run: sudo ufw allow {ctx.ssh_port}/tcp",
        )
    )

    if info["ipv6_rules"] == 0:
        ctx.add(
            Finding(
                "firewall.ipv6",
                "IPv6 rules present",
                WARN,
                "medium",
                "no IPv6 rules found in ufw status",
                "Set IPV6=yes in /etc/default/ufw and re-apply rules",
            )
        )
    else:
        ctx.add(
            Finding(
                "firewall.ipv6",
                "IPv6 rules present",
                PASS,
                "info",
                f"{info['ipv6_rules']} IPv6 rule(s)",
            )
        )

    # Docker publishes traverse the FORWARD chain, not ufw's INPUT chain.
    if have("docker"):
        rc, out, _ = run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"])
        published = []
        for line in out.splitlines():
            for match in re.finditer(r"(?:0\.0\.0\.0|\[::\]):(\d+)->", line):
                name = line.split("\t")[0]
                published.append(f"{name}:{match.group(1)}")
        if published:
            chain_rc, chain_out, _ = run(["iptables", "-S", "DOCKER-USER"])
            chain6_rc, chain6_out, _ = run(["ip6tables", "-S", "DOCKER-USER"])
            managed = "-j DROP" in chain_out + chain6_out
            ctx.add(
                Finding(
                    "firewall.docker_exposure",
                    "Docker-published ports bypass UFW",
                    PASS if managed else WARN,
                    "high" if not managed else "info",
                    f"{len(published)} container port(s) published on all interfaces: "
                    + ", ".join(sorted(set(published))[:12])
                    + ("…" if len(set(published)) > 12 else "")
                    + ("" if managed else " — no DOCKER-USER DROP policy is applied"),
                    ""
                    if managed
                    else "Bind publishes to 127.0.0.1, or set "
                    "ufw.manage_docker_user_chain=true (see docs/firewall.md#docker)",
                )
            )
        else:
            ctx.add(
                Finding(
                    "firewall.docker_exposure",
                    "Docker-published ports bypass UFW",
                    PASS,
                    "info",
                    "no container publishes on 0.0.0.0",
                )
            )


def check_listeners(ctx: Context) -> None:
    rc, out, _ = run(["ss", "-tulpnH"])
    if rc != 0:
        ctx.add(Finding("network.listeners", "Listening ports", SKIPPED, "info", "ss unavailable"))
        return
    listeners = parse_ss(out)
    public_tcp = sorted(
        {
            entry["port"]
            for entry in listeners
            if entry["proto"] == "tcp" and is_public_bind(entry["addr"])
        },
        key=lambda p: int(p) if p.isdigit() else 0,
    )
    ctx.add(
        Finding(
            "network.listeners",
            "Publicly bound TCP ports",
            PASS,
            "info",
            ", ".join(public_tcp) or "none",
            "",
            evidence=", ".join(sorted({e["process"] for e in listeners if e["process"]})[:20]),
        )
    )
    unexpected = [p for p in public_tcp if p != str(ctx.ssh_port) and p not in ("80", "443")]
    if unexpected and ctx.expect_docker:
        ctx.add(
            Finding(
                "network.unexpected_ports",
                "Ports reachable beyond SSH/HTTP(S)",
                WARN,
                "medium",
                f"public ports: {', '.join(unexpected)}",
                "Confirm each port is intentional; move admin services behind Tailscale",
            )
        )


def check_ssh(ctx: Context) -> None:
    if not have("sshd"):
        ctx.add(Finding("ssh.installed", "OpenSSH server", NOT_CONFIGURED, "high", "sshd not found"))
        return
    rc, out, err = run(["/usr/sbin/sshd", "-T"], timeout=20)
    if rc != 0:
        ctx.add(
            Finding(
                "ssh.effective_config",
                "SSH effective configuration",
                FAIL,
                "critical",
                f"sshd -T failed: {err.strip()[:300]}",
                "Fix /etc/ssh/sshd_config before restarting SSH",
            )
        )
        return
    cfg = parse_sshd_t(out)
    port = cfg.get("port", "22")
    ctx.add(
        Finding("ssh.port", "SSH port", PASS, "info", f"port {port} ({cfg.get('addressfamily', 'any')})")
    )

    root_login = cfg.get("permitrootlogin", "unknown")
    if root_login in ("no", "forced-commands-only"):
        ctx.add(Finding("ssh.root_login", "Root login over SSH", PASS, "info", f"PermitRootLogin {root_login}"))
    elif root_login == "prohibit-password":
        ctx.add(
            Finding(
                "ssh.root_login",
                "Root login over SSH",
                WARN,
                "medium",
                "PermitRootLogin prohibit-password (key-only root access still allowed)",
                "Prefer PermitRootLogin no and a sudo user",
            )
        )
    else:
        ctx.add(
            Finding(
                "ssh.root_login",
                "Root login over SSH",
                FAIL,
                "high",
                f"PermitRootLogin {root_login}",
                "Set PermitRootLogin no after verifying a sudo user's key login",
            )
        )

    pw = cfg.get("passwordauthentication", "unknown")
    ctx.add(
        Finding(
            "ssh.password_auth",
            "Password authentication",
            PASS if pw == "no" else FAIL,
            "high" if pw != "no" else "info",
            f"PasswordAuthentication {pw}",
            "" if pw == "no" else "Set PasswordAuthentication no once key auth is verified",
        )
    )
    pubkey = cfg.get("pubkeyauthentication", "unknown")
    ctx.add(
        Finding(
            "ssh.pubkey_auth",
            "Public-key authentication",
            PASS if pubkey == "yes" else FAIL,
            "high",
            f"PubkeyAuthentication {pubkey}",
        )
    )
    attempts = cfg.get("maxauthtries", "6")
    try:
        attempts_int = int(attempts)
    except ValueError:
        attempts_int = 6
    ctx.add(
        Finding(
            "ssh.max_auth_tries",
            "Authentication attempt limit",
            PASS if attempts_int <= 4 else WARN,
            "low",
            f"MaxAuthTries {attempts}",
            "" if attempts_int <= 4 else "Set MaxAuthTries 3",
        )
    )

    key_users = []
    for home in ["/root", *sorted(str(p) for p in Path("/home").glob("*"))]:
        auth = Path(home) / ".ssh" / "authorized_keys"
        try:
            keys = [ln for ln in auth.read_text().splitlines() if ln.startswith(("ssh-", "ecdsa-", "sk-"))]
        except OSError:
            continue
        if keys:
            key_users.append(f"{Path(home).name}({len(keys)})")
    if key_users:
        ctx.add(Finding("ssh.authorized_keys", "Authorized SSH keys", PASS, "info", ", ".join(key_users)))
    else:
        ctx.add(
            Finding(
                "ssh.authorized_keys",
                "Authorized SSH keys",
                FAIL if pw == "no" else WARN,
                "critical" if pw == "no" else "medium",
                "no authorized_keys found for root or any /home user",
                "Add your public key before disabling password authentication",
            )
        )


def check_fail2ban(ctx: Context) -> None:
    if not have("fail2ban-client"):
        ctx.add(
            Finding(
                "fail2ban.installed",
                "Fail2ban installed",
                NOT_CONFIGURED if ctx.expect_fail2ban else PASS,
                "high" if ctx.expect_fail2ban else "info",
                "fail2ban-client not found",
                "Install with: sudo ./install.sh install fail2ban",
            )
        )
        return
    rc, out, _ = run(["systemctl", "is-active", "fail2ban"])
    ctx.add(
        Finding(
            "fail2ban.active",
            "Fail2ban service",
            PASS if out.strip() == "active" else FAIL,
            "high",
            f"state: {out.strip() or 'unknown'}",
            "Start with: sudo systemctl enable --now fail2ban",
        )
    )
    rc, out, err = run(["fail2ban-client", "status"], timeout=20)
    info = parse_fail2ban_status(out)
    if rc != 0:
        ctx.add(
            Finding(
                "fail2ban.jails",
                "Fail2ban jails",
                WARN,
                "medium",
                f"cannot query jails: {err.strip()[:200]}",
                "Check journalctl -u fail2ban",
            )
        )
        return
    has_ssh = "sshd" in info["jails"]
    ctx.add(
        Finding(
            "fail2ban.ssh_jail",
            "SSH jail enabled",
            PASS if has_ssh else FAIL,
            "high" if not has_ssh else "info",
            "jails: " + (", ".join(info["jails"]) or "none"),
            "" if has_ssh else "Run: sudo ./install.sh configure fail2ban",
        )
    )
    rc, out, _ = run(["fail2ban-client", "status", "sshd"])
    jail = parse_fail2ban_jail(out)
    ctx.add(
        Finding(
            "fail2ban.ssh_bans",
            "Banned SSH offenders",
            PASS,
            "info",
            f"{jail['total'] if jail['total'] is not None else '?'} currently banned"
            + (f" ({', '.join(jail['banned'][:5])})" if jail["banned"] else ""),
        )
    )


def check_crowdsec(ctx: Context) -> None:
    if not have("cscli"):
        ctx.add(
            Finding(
                "crowdsec.installed",
                "CrowdSec installed",
                NOT_CONFIGURED if ctx.expect_crowdsec else PASS,
                "medium" if ctx.expect_crowdsec else "info",
                "cscli not found",
                "Install with: sudo ./install.sh install crowdsec",
            )
        )
        return
    rc, out, _ = run(["systemctl", "is-active", "crowdsec"])
    ctx.add(
        Finding(
            "crowdsec.active",
            "CrowdSec service",
            PASS if out.strip() == "active" else FAIL,
            "high",
            f"state: {out.strip() or 'unknown'}",
        )
    )
    rc, out, err = run(["cscli", "lapi", "status"], timeout=20)
    ctx.add(
        Finding(
            "crowdsec.lapi",
            "CrowdSec Local API",
            PASS if rc == 0 else WARN,
            "medium",
            (out.strip().splitlines()[-1] if rc == 0 and out.strip() else err.strip()[:200] or "no response"),
            "Check journalctl -u crowdsec and /etc/crowdsec/local_api_credentials.yaml",
        )
    )

    rc, out, _ = run(["cscli", "collections", "list", "-o", "json"], timeout=25)
    collections = cscli_list(parse_cscli_json(out), "collections")
    if collections:
        enabled = [
            c.get("name")
            for c in collections
            if str(c.get("status", "")).lower() in ("enabled", "true")
        ]
        has_ssh = any("sshd" in (name or "") for name in enabled)
        ctx.add(
            Finding(
                "crowdsec.collections",
                "CrowdSec collections",
                PASS if has_ssh else WARN,
                "medium" if not has_ssh else "info",
                ", ".join(sorted(enabled)) or "none enabled",
                "" if has_ssh else "Install the SSH collection: cscli collections install crowdsecurity/sshd",
            )
        )
    else:
        ctx.add(
            Finding(
                "crowdsec.collections",
                "CrowdSec collections",
                SKIPPED,
                "info",
                "could not parse cscli collections output",
            )
        )

    acqui = Path("/etc/crowdsec/acquis.d")
    sources = []
    if acqui.is_dir():
        for entry in sorted(acqui.glob("*.y*ml")):
            text = read_text(str(entry))
            if "auth.log" in text or "journalctl" in text or "sshd" in text:
                sources.append(entry.name)
    ctx.add(
        Finding(
            "crowdsec.acquisition",
            "SSH log acquisition",
            PASS if sources else WARN,
            "high" if not sources else "info",
            f"{len(sources)} acquisition file(s) cover SSH logs" if sources else "no SSH log source configured",
            "" if sources else "Add an acquis file for /var/log/auth.log (see roles/crowdsec)",
            evidence=", ".join(sources),
        )
    )

    rc, out, _ = run(["cscli", "decisions", "list", "-o", "json"], timeout=25)
    count = count_decisions(parse_cscli_json(out))
    rc, out, _ = run(["cscli", "bouncers", "list", "-o", "json"], timeout=25)
    bouncer_count = len(cscli_list(parse_cscli_json(out), "bouncers"))

    ctx.add(
        Finding(
            "crowdsec.decisions",
            "Active CrowdSec decisions",
            PASS,
            "info",
            f"{count} decision(s)",
        )
    )
    if bouncer_count == 0:
        ctx.add(
            Finding(
                "crowdsec.bouncer",
                "Enforcement (firewall bouncer)",
                NOT_CONFIGURED,
                "medium",
                f"detection only: {count} decision(s) are recorded but not enforced"
                if count
                else "detection only: no bouncer registered",
                "Enable remediation deliberately: crowdsec.firewall_bouncer_enabled=true "
                "(see docs/security-model.md#detection-vs-enforcement)",
            )
        )
    else:
        ctx.add(
            Finding(
                "crowdsec.bouncer",
                "Enforcement (firewall bouncer)",
                PASS,
                "info",
                f"{bouncer_count} bouncer(s) registered",
            )
        )


def check_updates(ctx: Context) -> None:
    installed = Path("/var/lib/dpkg/info/unattended-upgrades.list").is_file()
    if not installed:
        ctx.add(
            Finding(
                "updates.unattended_installed",
                "Unattended upgrades installed",
                NOT_CONFIGURED if ctx.expect_unattended else PASS,
                "medium",
                "package not installed",
                "Install with: sudo ./install.sh install unattended",
            )
        )
        return
    auto = read_text("/etc/apt/apt.conf.d/20auto-upgrades")
    periodic = "APT::Periodic::Unattended-Upgrade \"1\"" in auto
    ctx.add(
        Finding(
            "updates.periodic",
            "Automatic security updates enabled",
            PASS if periodic else FAIL,
            "high" if not periodic else "info",
            "20auto-upgrades: " + ("periodic upgrade enabled" if periodic else "not enabled"),
            "" if periodic else "Run: sudo ./install.sh configure unattended",
        )
    )
    rc, out, _ = run(["systemctl", "is-enabled", "apt-daily-upgrade.timer"])
    ctx.add(
        Finding(
            "updates.timer",
            "Update timer",
            PASS if out.strip() in ("enabled", "static") else WARN,
            "low",
            f"apt-daily-upgrade.timer: {out.strip() or 'unknown'}",
        )
    )
    policy = read_text("/etc/apt/apt.conf.d/51-vps-harden-unattended-upgrades")
    if policy:
        ctx.add(
            Finding(
                "updates.allowed_origins",
                "Security-only upgrade policy",
                PASS,
                "info",
                "vps-harden policy file present",
            )
        )


def check_config_permissions(ctx: Context) -> None:
    checks = [
        ("/etc/ssh/sshd_config", 0o644, "SSH server configuration"),
        ("/etc/shadow", 0o640, "shadow password database"),
        ("/etc/fail2ban/jail.local", 0o644, "fail2ban local configuration"),
        ("/etc/crowdsec/local_api_credentials.yaml", 0o600, "CrowdSec API credentials"),
    ]
    for path, max_mode, label in checks:
        mode = mode_of(path)
        if mode is None:
            continue
        too_open = mode & ~max_mode & 0o777
        ctx.add(
            Finding(
                f"perms.{Path(path).name}",
                f"Permissions: {label}",
                PASS if not too_open else FAIL,
                "medium" if too_open else "info",
                f"{path} mode {mode:04o} (expected at most {max_mode:04o})",
                "" if not too_open else f"Run: chmod {max_mode:04o} {path}",
            )
        )

    for path in ctx.managed_paths:
        if not path.startswith("/etc/"):
            continue
        mode = mode_of(path)
        if mode is None:
            continue
        if mode & 0o002:
            ctx.add(
                Finding(
                    f"perms.{Path(path).name}",
                    f"World-writable managed file: {path}",
                    FAIL,
                    "high",
                    f"mode {mode:04o}",
                    f"chmod o-w {path}",
                )
            )


def check_hardening(ctx: Context) -> None:
    wanted = {
        "kernel.kptr_restrict": ("kernel.kptr_restrict", 1),
        "kernel.dmesg_restrict": ("kernel.dmesg_restrict", 1),
        "kernel.yama.ptrace_scope": ("kernel.yama.ptrace_scope", 1),
    }
    values = {}
    for key in wanted:
        rc, out, _ = run(["sysctl", "-n", key])
        values[key] = out.strip() if rc == 0 else None
    missing = []
    for key, (_, minimum) in wanted.items():
        try:
            if values[key] is None or int(values[key]) < minimum:
                missing.append(f"{key}={values[key]}")
        except (TypeError, ValueError):
            missing.append(f"{key}={values[key]}")
    ctx.add(
        Finding(
            "hardening.kernel_sysctl",
            "Kernel hardening sysctls",
            PASS if not missing else WARN,
            "low",
            "applied" if not missing else "not applied: " + ", ".join(missing),
            "" if not missing else "Run: sudo ./install.sh configure common",
        )
    )

    if have("systemctl"):
        rc, out, _ = run(["systemctl", "is-active", "auditd"])
        ctx.add(
            Finding(
                "hardening.auditd",
                "System auditing (auditd)",
                PASS if out.strip() == "active" else NOT_CONFIGURED,
                "low",
                f"state: {out.strip() or 'unknown'}",
                "" if out.strip() == "active" else "Enable with: sudo ./install.sh configure common",
            )
        )


def check_tailscale(ctx: Context) -> None:
    if not have("tailscale"):
        ctx.add(
            Finding(
                "tailscale.installed",
                "Tailscale",
                NOT_CONFIGURED if ctx.expect_tailscale else SKIPPED,
                "medium" if ctx.expect_tailscale else "info",
                "not installed",
                "Install with: sudo ./install.sh install tailscale",
            )
        )
        return
    rc, out, err = run(["tailscale", "status"], timeout=20)
    if rc != 0:
        ctx.add(
            Finding(
                "tailscale.status",
                "Tailscale connectivity",
                WARN,
                "medium",
                f"tailscale status failed: {(err or out).strip()[:200]}",
                "Authenticate with: sudo tailscale up",
            )
        )
        return
    online = "offline" not in out.splitlines()[0].lower() if out.strip() else False
    peers = max(len(out.strip().splitlines()) - 1, 0)
    ctx.add(
        Finding(
            "tailscale.status",
            "Tailscale connectivity",
            PASS if online else WARN,
            "medium",
            f"authenticated, {peers} peer(s) visible" if online else "node appears offline",
            "" if online else "Check: sudo tailscale status --json",
        )
    )


def check_docker_host(ctx: Context) -> None:
    if not have("docker"):
        return
    rc, out, _ = run(["systemctl", "is-active", "docker"])
    ctx.add(
        Finding("docker.service", "Docker daemon", PASS if out.strip() == "active" else FAIL, "medium",
                f"state: {out.strip() or 'unknown'}")
    )
    daemon = read_text("/etc/docker/daemon.json")
    if daemon:
        try:
            config = json.loads(daemon)
        except ValueError:
            config = {}
        rotation = "max-size" in json.dumps(config.get("log-opts", {}))
        ctx.add(
            Finding(
                "docker.log_rotation",
                "Container log rotation configured",
                PASS if rotation else WARN,
                "medium" if not rotation else "info",
                "log-opts present" if rotation else "no max-size in /etc/docker/daemon.json",
                "" if rotation else "Set log-opts max-size/max-file to avoid filling the disk",
            )
        )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {status: 0 for status in STATUS_ORDER}
    for finding in findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1
    return counts


def render_text(findings: list[Finding], host: str, version: str) -> str:
    counts = summarize(findings)
    width = 78
    lines = [
        "=" * width,
        f"vps-harden security audit — {host}",
        f"{time.strftime('%Y-%m-%d %H:%M:%S %Z')} · vps-harden {version}",
        "=" * width,
        "",
        "SUMMARY  "
        + "  ".join(f"{status}: {counts.get(status, 0)}" for status in STATUS_ORDER),
        "",
    ]
    for status in STATUS_ORDER:
        group = [f for f in findings if f.status == status]
        if not group:
            continue
        lines.append(f"-- {status} " + "-" * (width - len(status) - 4))
        for finding in group:
            lines.append(f"[{finding.status}] {finding.title} ({finding.severity})")
            if finding.detail:
                lines.append(f"    {finding.detail}")
            if finding.remediation and finding.status != PASS:
                lines.append(f"    fix: {finding.remediation}")
            lines.append("")
    lines.append("-" * width)
    lines.append(
        "This report describes the checks that ran. A passing report does not mean "
        "the host is secure: it means the controls above were observed in the "
        "expected state at this moment."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only security audit")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--json-out", type=Path, help="write the JSON report here")
    parser.add_argument("--report", type=Path, help="write the text report here")
    parser.add_argument("--fail-on", choices=("fail", "warn", "never"), default="fail")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--expect-ufw", default="true")
    parser.add_argument("--expect-fail2ban", default="true")
    parser.add_argument("--expect-crowdsec", default="true")
    parser.add_argument("--expect-unattended", default="true")
    parser.add_argument("--expect-tailscale", default="false")
    parser.add_argument("--expect-docker", default="false")
    parser.add_argument("--paths-file", type=Path)
    parser.add_argument("--version", default="0.0.0")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    def truthy(value: str) -> bool:
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    managed: list[str] = []
    if args.paths_file and args.paths_file.is_file():
        try:
            import yaml

            data = yaml.safe_load(args.paths_file.read_text()) or {}
            managed = [
                *data.get("vh_managed", {}).get("owned_files", []),
                *data.get("vh_managed", {}).get("modified_files", []),
            ]
        except Exception:  # noqa: BLE001 - audit must never crash on this
            managed = []

    ctx = Context(
        ssh_port=args.ssh_port,
        expect_ufw=truthy(args.expect_ufw),
        expect_fail2ban=truthy(args.expect_fail2ban),
        expect_crowdsec=truthy(args.expect_crowdsec),
        expect_unattended=truthy(args.expect_unattended),
        expect_tailscale=truthy(args.expect_tailscale),
        expect_docker=truthy(args.expect_docker),
        managed_paths=managed,
    )

    for check in (
        check_system,
        check_firewall,
        check_listeners,
        check_ssh,
        check_fail2ban,
        check_crowdsec,
        check_updates,
        check_config_permissions,
        check_hardening,
        check_tailscale,
        check_docker_host,
    ):
        try:
            check(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken probe must not abort the audit
            ctx.add(
                Finding(
                    f"internal.{check.__name__}",
                    f"Check failed to run: {check.__name__}",
                    SKIPPED,
                    "info",
                    f"{type(exc).__name__}: {exc}",
                )
            )

    host = os.uname().nodename
    text = render_text(ctx.findings, host, args.version)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")

    document = {
        "host": host,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": args.version,
        "summary": summarize(ctx.findings),
        "findings": [asdict(f) for f in ctx.findings],
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(document, indent=2))
    elif not args.quiet:
        print(text)

    counts = summarize(ctx.findings)
    if args.fail_on == "never":
        return 0
    if args.fail_on == "warn":
        return 1 if counts[FAIL] or counts[WARN] else 0
    return 1 if counts[FAIL] else 0


if __name__ == "__main__":
    sys.exit(main())
