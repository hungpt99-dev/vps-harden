#!/usr/bin/env bash
# Validate a vps-harden YAML configuration file.
#
#   validate_config.py --defaults config/defaults.yml [--user config/vps-harden.yml]
#                      [--strict] [--json]
#
# Exit codes: 0 valid, 1 invalid, 2 usage error.
#
# The validator is intentionally dependency-free apart from PyYAML so it can run
# before Ansible is installed and inside CI.
from __future__ import annotations

import argparse
import difflib
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on broken hosts
    sys.stderr.write(
        "ERROR: PyYAML is required (sudo apt-get install -y python3-yaml)\n"
    )
    sys.exit(2)

DURATION_RE = re.compile(r"^\d+[smhdw]?$")
NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]*$")
IFACE_RE = re.compile(r"^[a-zA-Z0-9_.@-]{1,15}$")
PORT_MIN, PORT_MAX = 1, 65535

POLICIES = ("allow", "deny", "reject")
LOG_LEVELS = ("off", "low", "medium", "high", "full")
RULES = ("allow", "deny", "reject", "limit")
PROTOS = ("tcp", "udp")
BACKENDS = ("systemd", "auto", "pyinotify", "polling", "gamin")
CONFLICT_POLICIES = ("fail", "adopt", "ignore")
ACQUISITION_MODES = ("auto", "file", "journalctl")
APT_ORIGINS = ("security", "updates", "esm-infra", "esm-apps")
FAIL_ON = ("fail", "warn", "never")

RULE_KEYS = {
    "rule",
    "port",
    "proto",
    "from",
    "interface",
    "comment",
    "to_port",
}


class Report:
    """Collects validation findings."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, path: str, message: str) -> None:
        self.errors.append(f"{path}: {message}")

    def warn(self, path: str, message: str) -> None:
        self.warnings.append(f"{path}: {message}")

    @property
    def ok(self) -> bool:
        return not self.errors


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "yes", "on", "1"):
        return True
    if isinstance(value, str) and value.lower() in ("false", "no", "off", "0"):
        return False
    return None


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_duration(value: Any) -> bool:
    return isinstance(value, (str, int)) and bool(DURATION_RE.match(str(value)))


def _valid_ip_list(value: Any) -> str | None:
    """Return an error message, or None when every entry is an IP/CIDR."""
    if not isinstance(value, list):
        return "must be a list of IP addresses or CIDR ranges"
    for item in value:
        try:
            ipaddress.ip_network(str(item), strict=False)
        except ValueError:
            return f"invalid IP address or CIDR: {item!r}"
    return None


def _valid_port(value: Any) -> bool:
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    return _is_int(value) and PORT_MIN <= value <= PORT_MAX


def _suggest(key: str, known: set[str]) -> str:
    matches = difflib.get_close_matches(key, sorted(known), n=1, cutoff=0.7)
    return f" (did you mean {matches[0]!r}?)" if matches else ""


def _check_unknown_keys(
    report: Report, data: dict[str, Any], schema: dict[str, Any], path: str
) -> None:
    for key in data:
        if key not in schema:
            report.error(f"{path}.{key}", f"unknown option{_suggest(key, set(schema))}")


def validate_rule(report: Report, rule: Any, path: str) -> None:
    if not isinstance(rule, dict):
        report.error(path, "each firewall rule must be a mapping")
        return
    for key in rule:
        if key not in RULE_KEYS:
            report.error(f"{path}.{key}", f"unknown rule key{_suggest(key, RULE_KEYS)}")
    action = rule.get("rule", "allow")
    if action not in RULES:
        report.error(f"{path}.rule", f"must be one of {', '.join(RULES)}")
    if "port" in rule and not _valid_port(rule["port"]):
        report.error(f"{path}.port", "must be an integer between 1 and 65535")
    if "to_port" in rule and not _valid_port(rule["to_port"]):
        report.error(f"{path}.to_port", "must be an integer between 1 and 65535")
    if "proto" in rule and rule["proto"] not in PROTOS:
        report.error(f"{path}.proto", f"must be one of {', '.join(PROTOS)}")
    if "from" in rule:
        try:
            ipaddress.ip_network(str(rule["from"]), strict=False)
        except ValueError:
            report.error(f"{path}.from", f"invalid IP address or CIDR: {rule['from']!r}")
    if "interface" in rule and not IFACE_RE.match(str(rule["interface"])):
        report.error(f"{path}.interface", "invalid interface name")
    if not any(k in rule for k in ("port", "interface", "from")):
        report.error(path, "a rule needs at least one of: port, interface, from")


def validate(user: dict[str, Any], defaults: dict[str, Any]) -> Report:
    """Validate a user document against the schema implied by the defaults."""
    report = Report()
    if not isinstance(user, dict):
        report.error("vps_harden", "configuration must be a YAML mapping")
        return report
    if set(user) - {"vps_harden"}:
        extra = sorted(set(user) - {"vps_harden"})
        report.error("root", f"unknown top-level key(s): {', '.join(extra)}")
    cfg = user.get("vps_harden", {})
    if not isinstance(cfg, dict):
        report.error("vps_harden", "must be a mapping")
        return report
    base = defaults.get("vps_harden", {})
    _check_unknown_keys(report, cfg, base, "vps_harden")

    def section(name: str) -> dict[str, Any]:
        value = cfg.get(name, {})
        if not isinstance(value, dict):
            report.error(f"vps_harden.{name}", "must be a mapping")
            return {}
        _check_unknown_keys(report, value, base.get(name, {}), f"vps_harden.{name}")
        return value

    # ------------------------------------------------------------- general
    tz = cfg.get("timezone")
    if tz is not None:
        if not isinstance(tz, str) or not re.match(r"^[A-Za-z0-9_+\-/]+$", tz):
            report.error("vps_harden.timezone", "invalid timezone name")
        else:
            try:
                from zoneinfo import ZoneInfo

                ZoneInfo(tz)
            except Exception:  # noqa: BLE001 - any failure means unknown zone
                report.error("vps_harden.timezone", f"unknown timezone {tz!r}")
    for key in ("log_dir", "backup_dir", "reports_dir"):
        if key in cfg and (not isinstance(cfg[key], str) or not cfg[key].startswith("/")):
            report.error(f"vps_harden.{key}", "must be an absolute path")

    # ----------------------------------------------------------------- ssh
    ssh = section("ssh")
    port = ssh.get("port", base.get("ssh", {}).get("port"))
    if "port" in ssh and not _valid_port(ssh["port"]):
        report.error("vps_harden.ssh.port", "must be an integer between 1 and 65535")
    for key in (
        "enabled",
        "password_authentication",
        "pubkey_authentication",
        "kbd_interactive_authentication",
        "x11_forwarding",
        "allow_tcp_forwarding",
        "allow_no_keys",
    ):
        if key in ssh and _as_bool(ssh[key]) is None:
            report.error(f"vps_harden.ssh.{key}", "must be a boolean")
    root_login = ssh.get("permit_root_login")
    if root_login is not None:
        allowed = (True, False, "yes", "no", "prohibit-password", "forced-commands-only")
        if root_login not in allowed:
            report.error(
                "vps_harden.ssh.permit_root_login",
                'must be true, false, "no", "yes", "prohibit-password" or '
                '"forced-commands-only"',
            )
    if "max_auth_tries" in ssh and not (
        _is_int(ssh["max_auth_tries"]) and 1 <= ssh["max_auth_tries"] <= 10
    ):
        report.error("vps_harden.ssh.max_auth_tries", "must be an integer between 1 and 10")
    for key in ("login_grace_time", "client_alive_interval", "client_alive_count_max"):
        if key in ssh and not (_is_int(ssh[key]) and ssh[key] >= 0):
            report.error(f"vps_harden.ssh.{key}", "must be a non-negative integer")
    for key in ("allow_users", "allow_groups", "admin_users"):
        if key in ssh:
            if not isinstance(ssh[key], list):
                report.error(f"vps_harden.ssh.{key}", "must be a list")
            else:
                for name in ssh[key]:
                    if not isinstance(name, str) or not NAME_RE.match(name):
                        report.error(f"vps_harden.ssh.{key}", f"invalid user/group name: {name!r}")

    # ----------------------------------------------------------------- ufw
    ufw = section("ufw")
    for key in ("enabled", "ipv6", "allow_tailscale", "auto_allow_ssh",
                "manage_docker_user_chain"):
        if key in ufw and _as_bool(ufw[key]) is None:
            report.error(f"vps_harden.ufw.{key}", "must be a boolean")
    for key in ("default_incoming", "default_outgoing", "default_routed"):
        if key in ufw and ufw[key] not in POLICIES:
            report.error(f"vps_harden.ufw.{key}", f"must be one of {', '.join(POLICIES)}")
    if "logging" in ufw and ufw["logging"] not in LOG_LEVELS:
        report.error("vps_harden.ufw.logging", f"must be one of {', '.join(LOG_LEVELS)}")
    if "extra_rules" in ufw:
        if not isinstance(ufw["extra_rules"], list):
            report.error("vps_harden.ufw.extra_rules", "must be a list of rules")
        else:
            for idx, rule in enumerate(ufw["extra_rules"]):
                validate_rule(report, rule, f"vps_harden.ufw.extra_rules[{idx}]")
    if "deadman_minutes" in ufw and not (
        _is_int(ufw["deadman_minutes"]) and 0 <= ufw["deadman_minutes"] <= 1440
    ):
        report.error("vps_harden.ufw.deadman_minutes", "must be an integer between 0 and 1440")
    if "docker_allowed_ports" in ufw:
        if not isinstance(ufw["docker_allowed_ports"], list) or not all(
            _valid_port(p) for p in ufw["docker_allowed_ports"]
        ):
            report.error(
                "vps_harden.ufw.docker_allowed_ports",
                "must be a list of ports between 1 and 65535",
            )

    # ------------------------------------------------------------ fail2ban
    f2b = section("fail2ban")
    if "enabled" in f2b and _as_bool(f2b["enabled"]) is None:
        report.error("vps_harden.fail2ban.enabled", "must be a boolean")
    if "maxretry" in f2b and not (_is_int(f2b["maxretry"]) and 1 <= f2b["maxretry"] <= 100):
        report.error("vps_harden.fail2ban.maxretry", "must be an integer between 1 and 100")
    for key in ("findtime", "bantime", "bantime_maxtime"):
        if key in f2b and not _valid_duration(f2b[key]):
            report.error(f"vps_harden.fail2ban.{key}", "must look like 10m, 1h, 4w or 300")
    if "bantime_factor" in f2b and not (
        _is_int(f2b["bantime_factor"]) and 1 <= f2b["bantime_factor"] <= 10
    ):
        report.error("vps_harden.fail2ban.bantime_factor", "must be an integer between 1 and 10")
    if "bantime_increment" in f2b and _as_bool(f2b["bantime_increment"]) is None:
        report.error("vps_harden.fail2ban.bantime_increment", "must be a boolean")
    if "backend" in f2b and f2b["backend"] not in BACKENDS:
        report.error("vps_harden.fail2ban.backend", f"must be one of {', '.join(BACKENDS)}")
    if "conflict_policy" in f2b and f2b["conflict_policy"] not in CONFLICT_POLICIES:
        report.error(
            "vps_harden.fail2ban.conflict_policy",
            f"must be one of {', '.join(CONFLICT_POLICIES)}",
        )
    if "ignoreip" in f2b:
        err = _valid_ip_list(f2b["ignoreip"])
        if err:
            report.error("vps_harden.fail2ban.ignoreip", err)

    # ------------------------------------------------------------- crowdsec
    cs = section("crowdsec")
    for key in ("enabled", "manage_repo", "firewall_bouncer_enabled", "whitelist_tailnet"):
        if key in cs and _as_bool(cs[key]) is None:
            report.error(f"vps_harden.crowdsec.{key}", "must be a boolean")
    if "collections" in cs:
        if not isinstance(cs["collections"], list):
            report.error("vps_harden.crowdsec.collections", "must be a list")
        else:
            for name in cs["collections"]:
                if not isinstance(name, str) or not re.match(r"^[\w.-]+/[\w.-]+$", name):
                    report.error(
                        "vps_harden.crowdsec.collections",
                        f"invalid collection name: {name!r} (expected namespace/name)",
                    )
    if "acquisition" in cs and cs["acquisition"] not in ACQUISITION_MODES:
        report.error(
            "vps_harden.crowdsec.acquisition",
            f"must be one of {', '.join(ACQUISITION_MODES)}",
        )
    if "lapi_port" in cs and not _valid_port(cs["lapi_port"]):
        report.error("vps_harden.crowdsec.lapi_port", "must be a port between 1 and 65535")
    if "manage_lapi_port" in cs and _as_bool(cs["manage_lapi_port"]) is None:
        report.error("vps_harden.crowdsec.manage_lapi_port", "must be a boolean")
    if "bouncer_conflict_policy" in cs and cs["bouncer_conflict_policy"] not in CONFLICT_POLICIES:
        report.error(
            "vps_harden.crowdsec.bouncer_conflict_policy",
            f"must be one of {', '.join(CONFLICT_POLICIES)}",
        )

    # ------------------------------------------------------ unattended upgrades
    uu = section("unattended_upgrades")
    if "enabled" in uu and _as_bool(uu["enabled"]) is None:
        report.error("vps_harden.unattended_upgrades.enabled", "must be a boolean")
    for key in ("automatic_reboot", "remove_unused_dependencies"):
        if key in uu and _as_bool(uu[key]) is None:
            report.error(f"vps_harden.unattended_upgrades.{key}", "must be a boolean")
    if "reboot_time" in uu and not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", str(uu["reboot_time"])):
        report.error("vps_harden.unattended_upgrades.reboot_time", "must look like 03:00")
    if "email" in uu and not isinstance(uu["email"], str):
        report.error("vps_harden.unattended_upgrades.email", "must be a string")
    if "origins" in uu:
        if not isinstance(uu["origins"], list):
            report.error("vps_harden.unattended_upgrades.origins", "must be a list")
        else:
            for origin in uu["origins"]:
                if origin not in APT_ORIGINS:
                    report.error(
                        "vps_harden.unattended_upgrades.origins",
                        f"unsupported origin {origin!r}; use one of {', '.join(APT_ORIGINS)}",
                    )

    # ------------------------------------------------------------- tailscale
    ts = section("tailscale")
    for key in ("enabled", "manage_repo", "ssh", "accept_routes", "advertise_exit_node"):
        if key in ts and _as_bool(ts[key]) is None:
            report.error(f"vps_harden.tailscale.{key}", "must be a boolean")

    # ---------------------------------------------------------------- docker
    dk = section("docker")
    for key in ("enabled", "manage_repo", "live_restore", "no_new_privileges"):
        if key in dk and _as_bool(dk[key]) is None:
            report.error(f"vps_harden.docker.{key}", "must be a boolean")
    if "log_max_size" in dk and not _valid_duration(dk["log_max_size"]):
        report.error("vps_harden.docker.log_max_size", "must look like 10m or 100m")
    if "log_max_file" in dk and not re.match(r"^\d{1,2}$", str(dk["log_max_file"])):
        report.error("vps_harden.docker.log_max_file", "must be a small integer as a string")

    # ---------------------------------------------------------------- hermes
    hm = section("hermes")
    for key in ("enabled", "register_mcp"):
        if key in hm and _as_bool(hm[key]) is None:
            report.error(f"vps_harden.hermes.{key}", "must be a boolean")
    if "gateway_service" in hm and not re.match(r"^[\w.-]+\.service$", str(hm["gateway_service"])):
        report.error("vps_harden.hermes.gateway_service", "must be a systemd unit name")

    # ------------------------------------------------------------ monitoring
    mon = section("monitoring")
    if "enabled" in mon and _as_bool(mon["enabled"]) is None:
        report.error("vps_harden.monitoring.enabled", "must be a boolean")
    if "bind_address" in mon:
        try:
            ipaddress.ip_address(str(mon["bind_address"]))
        except ValueError:
            report.error("vps_harden.monitoring.bind_address", "must be an IP address")
        else:
            if mon["bind_address"] in ("0.0.0.0", "::"):
                report.warn(
                    "vps_harden.monitoring.bind_address",
                    "binding to all interfaces exposes Grafana/Prometheus publicly; "
                    "use 127.0.0.1 and reach it over Tailscale",
                )
    for key in ("grafana_port", "prometheus_port"):
        if key in mon and not _valid_port(mon[key]):
            report.error(f"vps_harden.monitoring.{key}", "must be a port between 1 and 65535")

    # --------------------------------------------------------------- logging
    lg = section("logging")
    if "enabled" in lg and _as_bool(lg["enabled"]) is None:
        report.error("vps_harden.logging.enabled", "must be a boolean")
    if "manage_journald" in lg and _as_bool(lg["manage_journald"]) is None:
        report.error("vps_harden.logging.manage_journald", "must be a boolean")
    if "loki_enabled" in lg and _as_bool(lg["loki_enabled"]) is None:
        report.error("vps_harden.logging.loki_enabled", "must be a boolean")
    for key in ("journald_max_use",):
        if key in lg and not _valid_duration(lg[key]):
            report.error(f"vps_harden.logging.{key}", "must look like 500M or 2G")
    if "journald_retention" in lg and not _valid_duration(lg["journald_retention"]):
        report.error("vps_harden.logging.journald_retention", "must look like 30d or 2w")
    if "loki_port" in lg and not _valid_port(lg["loki_port"]):
        report.error("vps_harden.logging.loki_port", "must be a port between 1 and 65535")

    # ---------------------------------------------------------------- backup
    bk = section("backup")
    if "enabled" in bk and _as_bool(bk["enabled"]) is None:
        report.error("vps_harden.backup.enabled", "must be a boolean")
    if "local_repo" in bk and (
        not isinstance(bk["local_repo"], str) or not bk["local_repo"].startswith("/")
    ):
        report.error("vps_harden.backup.local_repo", "must be an absolute path")
    for key in ("paths", "exclude"):
        if key in bk:
            value = bk[key]
            if not isinstance(value, list) or not all(
                isinstance(p, str) and p.startswith("/") for p in value
            ):
                report.error(f"vps_harden.backup.{key}", "must be a list of absolute paths")
    for key in ("keep_daily", "keep_weekly", "keep_monthly"):
        if key in bk and not (_is_int(bk[key]) and 0 <= bk[key] <= 365):
            report.error(f"vps_harden.backup.{key}", "must be an integer between 0 and 365")

    # ----------------------------------------------------------------- audit
    au = section("audit")
    if "fail_on" in au and au["fail_on"] not in FAIL_ON:
        report.error("vps_harden.audit.fail_on", f"must be one of {', '.join(FAIL_ON)}")
    if "include_docker" in au and _as_bool(au["include_docker"]) is None:
        report.error("vps_harden.audit.include_docker", "must be a boolean")

    # ------------------------------------------------------- cross-field checks
    effective = _merge(defaults, {"vps_harden": cfg})
    e_ssh = effective["vps_harden"]["ssh"]
    e_ufw = effective["vps_harden"]["ufw"]
    e_f2b = effective["vps_harden"]["fail2ban"]

    if e_ssh.get("enabled"):
        if _as_bool(e_ssh.get("password_authentication")) is False and _as_bool(
            e_ssh.get("allow_no_keys")
        ):
            report.warn(
                "vps_harden.ssh.allow_no_keys",
                "password authentication is disabled while no key is verified: "
                "verify a key login before applying, or you will be locked out",
            )
        if str(e_ssh.get("permit_root_login")).lower() in ("true", "yes"):
            report.warn(
                "vps_harden.ssh.permit_root_login",
                "root login over SSH stays enabled; prefer false and a sudo user",
            )
        if _as_bool(e_ssh.get("password_authentication")) is True:
            report.warn(
                "vps_harden.ssh.password_authentication",
                "password authentication stays enabled; brute-force exposure remains",
            )
    if e_ufw.get("enabled"):
        # Mirror the rule derivation done by playbooks/tasks/load_config.yml:
        # the SSH allow rule is generated from ssh.port, not typed by the user.
        effective_rules = list(e_ufw.get("rules") or [])
        if _as_bool(e_ufw.get("auto_allow_ssh")):
            effective_rules.append(
                {"rule": "allow", "port": str(e_ssh.get("port", 22)), "proto": "tcp"}
            )
        if _as_bool(e_ufw.get("allow_tailscale")):
            effective_rules.append({"rule": "allow", "interface": "tailscale0"})
        effective_rules.extend(e_ufw.get("extra_rules") or [])

        ssh_port = str(e_ssh.get("port", 22))
        allowed = any(str(r.get("port")) == ssh_port for r in effective_rules)
        if not allowed:
            report.error(
                "vps_harden.ssh.port",
                f"port {ssh_port} is not allowed by any firewall rule; enabling UFW "
                "would cut your SSH access",
            )
        elif not any(
            str(r.get("port")) == ssh_port and "interface" not in r
            for r in effective_rules
        ):
            report.warn(
                "vps_harden.ssh.port",
                f"port {ssh_port} is only allowed from a restricted source; confirm "
                "that source is reachable before enabling the firewall",
            )
    if e_f2b.get("enabled"):
        find = _duration_seconds(e_f2b.get("findtime", "10m"))
        ban = _duration_seconds(e_f2b.get("bantime", "1h"))
        if find and ban and ban < find:
            report.warn(
                "vps_harden.fail2ban.bantime",
                "bantime is shorter than findtime; repeat offenders will rarely be banned",
            )
    if not _as_bool(e_ufw.get("enabled")) and _is_int(e_ufw.get("deadman_minutes")):
        if e_ufw["deadman_minutes"] > 0:
            report.warn(
                "vps_harden.ufw.deadman_minutes",
                "dead-man switch is configured but UFW is disabled; it will do nothing",
            )
    return report


def _duration_seconds(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value:
        return None
    match = re.match(r"^(\d+)([smhdw]?)$", value)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    return amount * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]


def _merge(defaults: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
    result = {k: (dict(v) if isinstance(v, dict) else v) for k, v in defaults.items()}
    for key, value in user.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a vps-harden configuration file.",
        epilog="Exit codes: 0 valid, 1 invalid, 2 usage error.",
    )
    parser.add_argument("--defaults", required=True, type=Path, help="config/defaults.yml")
    parser.add_argument("--user", type=Path, help="user configuration to validate")
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    try:
        defaults = load_yaml(args.defaults)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        sys.stderr.write(f"ERROR: cannot read defaults: {exc}\n")
        return 2

    if args.user is None or not args.user.exists():
        report = Report()
        if args.user is not None:
            report.warn("config", f"{args.user} does not exist; built-in defaults apply")
    else:
        try:
            user = load_yaml(args.user)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            sys.stderr.write(f"ERROR: cannot parse {args.user}: {exc}\n")
            return 1
        report = validate(user, defaults)

    failed = not report.ok or (args.strict and report.warnings)
    if args.json:
        json.dump(
            {
                "valid": not failed,
                "errors": report.errors,
                "warnings": report.warnings,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        for warning in report.warnings:
            sys.stdout.write(f"WARN  {warning}\n")
        for error in report.errors:
            sys.stdout.write(f"ERROR {error}\n")
        if failed:
            sys.stdout.write(
                f"\nConfiguration is invalid: {len(report.errors)} error(s), "
                f"{len(report.warnings)} warning(s).\n"
            )
        else:
            sys.stdout.write(
                f"Configuration OK ({len(report.warnings)} warning(s)).\n"
            )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
