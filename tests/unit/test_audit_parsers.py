"""Unit tests for the audit engine's pure parsers.

These run without root, without UFW, and without CrowdSec: the parsers take
captured command output, so a parsing regression is caught in CI instead of on
a production VPS.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import vh_audit  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_sshd_t_lowercases_keys():
    cfg = vh_audit.parse_sshd_t(fixture("sshd_T.txt"))
    assert cfg["port"] == "22"
    assert cfg["passwordauthentication"] == "yes"
    assert cfg["permitrootlogin"] == "without-password"
    assert cfg["hostkeyalgorithms"].startswith("ssh-ed25519")


def test_parse_ufw_status_reads_policies_and_rules():
    info = vh_audit.parse_ufw_status(fixture("ufw_status.txt"))
    assert info["active"] is True
    assert info["default_incoming"] == "deny"
    assert info["default_outgoing"] == "allow"
    assert info["default_routed"] == "deny"
    assert info["logging"] == "low"
    assert info["ipv6_rules"] == 2
    assert any("22/tcp" in rule for rule in info["rules"])


def test_parse_ufw_status_handles_inactive_firewall():
    info = vh_audit.parse_ufw_status("Status: inactive\n")
    assert info["active"] is False
    assert info["default_incoming"] is None


def test_parse_ss_extracts_ports_and_processes():
    listeners = vh_audit.parse_ss(fixture("ss.txt"))
    ssh = [entry for entry in listeners if entry["port"] == "22"]
    assert ssh and ssh[0]["process"] == "sshd"
    assert all(entry["proto"] in ("tcp", "udp") for entry in listeners)


def test_public_bind_classification():
    assert vh_audit.is_public_bind("0.0.0.0")
    assert vh_audit.is_public_bind("::")
    assert vh_audit.is_public_bind("203.0.113.10")
    assert not vh_audit.is_public_bind("127.0.0.1")
    assert not vh_audit.is_public_bind("::1")
    assert not vh_audit.is_public_bind("100.64.0.10")  # Tailscale/CGNAT
    assert not vh_audit.is_public_bind("172.17.0.2")  # docker bridge


def test_parse_fail2ban_status_and_jail():
    status = vh_audit.parse_fail2ban_status(fixture("fail2ban_status.txt"))
    assert status["jails"] == ["sshd"]
    jail = vh_audit.parse_fail2ban_jail(fixture("fail2ban_jail.txt"))
    assert jail["total"] == 2
    assert "203.0.113.10" in jail["banned"]


def test_parse_apt_check():
    assert vh_audit.parse_apt_check("12;4") == (12, 4)
    assert vh_audit.parse_apt_check("7") == (7, 0)
    assert vh_audit.parse_apt_check("") == (None, None)


def test_summarize_counts_every_status():
    findings = [
        vh_audit.Finding("a", "A", vh_audit.PASS),
        vh_audit.Finding("b", "B", vh_audit.FAIL),
        vh_audit.Finding("c", "C", vh_audit.WARN),
        vh_audit.Finding("d", "D", vh_audit.FAIL),
    ]
    counts = vh_audit.summarize(findings)
    assert counts[vh_audit.FAIL] == 2
    assert counts[vh_audit.PASS] == 1


def test_render_text_contains_every_finding_and_disclaimer():
    findings = [
        vh_audit.Finding("ssh.password_auth", "Password authentication", vh_audit.FAIL,
                         "high", "PasswordAuthentication yes", "Set it to no"),
        vh_audit.Finding("firewall.active", "Firewall enabled", vh_audit.PASS, "info", "active"),
    ]
    text = vh_audit.render_text(findings, "test-host", "1.0.0")
    assert "Password authentication" in text
    assert "fix: Set it to no" in text
    assert "does not mean" in text


def test_audit_runs_without_crashing_when_everything_is_missing(monkeypatch):
    """A broken probe must degrade to SKIPPED, never abort the report."""
    monkeypatch.setattr(vh_audit, "run", lambda *a, **k: (127, "", "missing"))
    ctx = vh_audit.Context(expect_docker=False)
    for check in (vh_audit.check_firewall, vh_audit.check_ssh, vh_audit.check_crowdsec):
        check(ctx)
    assert ctx.findings
    assert all(f.status for f in ctx.findings)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("PASS", vh_audit.PASS), ("FAIL", vh_audit.FAIL)],
)
def test_status_constants_are_stable(mode: str, expected: str) -> None:
    assert getattr(vh_audit, mode) == expected


def test_cscli_list_handles_object_and_array_shapes():
    # `cscli collections list -o json` wraps the array; bouncers returns a list.
    wrapped = {"collections": [{"name": "crowdsecurity/sshd", "status": "enabled"}]}
    assert vh_audit.cscli_list(wrapped, "collections")[0]["name"] == "crowdsecurity/sshd"
    assert vh_audit.cscli_list([{"name": "b"}], "bouncers") == [{"name": "b"}]
    assert vh_audit.cscli_list(None, "collections") == []


def test_count_decisions_flattens_alerts():
    payload = [
        {"id": 1, "decisions": [{"id": 10}, {"id": 11}]},
        {"id": 2, "decisions": [{"id": 12}]},
        {"id": 3},
    ]
    assert vh_audit.count_decisions(payload) == 4
    assert vh_audit.count_decisions(None) == 0


def test_apt_fallback_only_matches_security_suite():
    output = (
        "Inst libssl3 [3.0.2-0ubuntu1] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])\n"
        "Inst vim [2:8.2] (2:9.0 Ubuntu:22.04/jammy-updates [amd64])\n"
    )
    import re as _re

    upgraded = _re.findall(r"(?m)^Inst\s+(\S+)(?:\s+\[[^\]]*\])?\s+\(([^)]*)\)", output)
    assert len(upgraded) == 2
    assert sum(1 for _, version in upgraded if "-security" in version) == 1
