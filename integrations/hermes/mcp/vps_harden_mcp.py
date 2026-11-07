#!/usr/bin/env python3
"""Read-only MCP server exposing vps-harden to Hermes Agent.

Design constraints:

* **Read-only.** There is no tool that writes configuration. Applying changes
  stays a human-approved CLI action (`install.sh configure`), because an agent
  must not be able to lock the operator out of the VPS.
* **No shell.** Every external command is an argv list with a fixed allowlist.
* **No secrets.** Outputs are truncated and never include environment dumps.

Protocol: JSON-RPC 2.0 over stdin/stdout (MCP 2024-11-05), one message per line.
Anything that is not a protocol message goes to stderr.

Usage:
    hermes mcp add vps-harden \
      --command python3 --args /usr/local/lib/vps-harden/vps_harden_mcp.py --root /root/vps-harden
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "vps-harden", "version": "1.0.0"}
MAX_OUTPUT = 48_000
TIMEOUT = 120


def log(message: str) -> None:
    sys.stderr.write(f"[vps-harden-mcp] {message}\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Root discovery
# ---------------------------------------------------------------------------
def find_root(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get("VPS_HARDEN_ROOT"):
        candidates.append(Path(os.environ["VPS_HARDEN_ROOT"]))
    candidates.append(Path(__file__).resolve().parent)
    candidates.extend(Path(__file__).resolve().parents)
    candidates.append(Path("/opt/vps-harden"))
    for candidate in candidates:
        if (candidate / "config" / "defaults.yml").is_file() and (
            candidate / "install.sh"
        ).is_file():
            return candidate
    raise SystemExit(
        "vps-harden MCP: cannot locate the repository. Pass --root /path/to/vps-harden "
        "or set VPS_HARDEN_ROOT."
    )


def run(argv: list[str], timeout: int = TIMEOUT) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except FileNotFoundError:
        return 127, f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s: {' '.join(argv)}"
    output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    return proc.returncode, output[:MAX_OUTPUT]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
class Tools:
    def __init__(self, root: Path) -> None:
        self.root = root

    # -- handlers ----------------------------------------------------------
    def status(self, _args: dict[str, Any]) -> str:
        rc, out = run(["bash", str(self.root / "scripts" / "status.sh")], timeout=60)
        return out

    def audit(self, args: dict[str, Any]) -> str:
        argv = [
            sys.executable,
            str(self.root / "scripts" / "vh_audit.py"),
            "--json",
            "--paths-file",
            str(self.root / "config" / "managed_paths.yml"),
            "--version",
            "1.0.0",
            "--fail-on",
            "never",
        ]
        port = args.get("ssh_port")
        if isinstance(port, int) and 1 <= port <= 65535:
            argv += ["--ssh-port", str(port)]
        _, out = run(argv)
        return out

    def firewall(self, _args: dict[str, Any]) -> str:
        rc, out = run(["ufw", "status", "verbose"], timeout=30)
        if rc == 127:
            return "ufw is not installed."
        chain_rc, chain = run(["iptables", "-S", "DOCKER-USER"], timeout=15)
        docker_block = chain if chain_rc == 0 else "(DOCKER-USER chain absent)"
        return f"{out}\n\nDOCKER-USER chain:\n{docker_block}"

    def ssh(self, _args: dict[str, Any]) -> str:
        rc, out = run(["/usr/sbin/sshd", "-T"], timeout=30)
        if rc != 0:
            return out or "sshd -T failed"
        keys = [
            "port",
            "permitrootlogin",
            "passwordauthentication",
            "pubkeyauthentication",
            "kbdinteractiveauthentication",
            "maxauthtries",
            "x11forwarding",
            "allowtcpforwarding",
            "clientaliveinterval",
        ]
        wanted = {}
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0] in keys:
                wanted[parts[0]] = parts[1]
        return "\n".join(f"{k}: {wanted.get(k, '(unset)')}" for k in keys)

    def help(self, _args: dict[str, Any]) -> str:
        return (
            "vps-harden commands (run as root on the VPS):\n"
            "  ./install.sh check                 verify prerequisites, no changes\n"
            "  ./install.sh discover              read-only infrastructure inventory\n"
            "  ./install.sh audit                 security report (PASS/WARN/FAIL)\n"
            "  ./install.sh verify                are the controls actually in effect?\n"
            "  ./install.sh status                component summary\n"
            "  ./install.sh install [component]   install packages\n"
            "  ./install.sh configure             apply configuration\n"
            "  ./install.sh backup | rollback     snapshot / restore managed config\n\n"
            "This MCP server is read-only by design. Ask the human to run any\n"
            "command that changes the system, and never run configure or install\n"
            "on their behalf without explicit approval."
        )

    # -- registry ----------------------------------------------------------
    def registry(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "vps_harden_status",
                "description": "Component and service status summary for this VPS "
                "(firewall, fail2ban, CrowdSec, updates, Docker, Tailscale, Hermes).",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "handler": self.status,
            },
            {
                "name": "vps_harden_audit",
                "description": "Run the read-only security audit and return JSON findings "
                "(PASS/WARN/FAIL/NOT CONFIGURED/SKIPPED with remediation).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ssh_port": {
                            "type": "integer",
                            "description": "SSH port to check the firewall rule against (default 22).",
                        }
                    },
                    "additionalProperties": False,
                },
                "handler": self.audit,
            },
            {
                "name": "vps_harden_firewall",
                "description": "Show UFW status and the DOCKER-USER chain, so container "
                "exposure that bypasses UFW is visible.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "handler": self.firewall,
            },
            {
                "name": "vps_harden_ssh",
                "description": "Show the EFFECTIVE sshd configuration (sshd -T), not the files.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "handler": self.ssh,
            },
            {
                "name": "vps_harden_help",
                "description": "List vps-harden CLI commands and the read-only safety contract.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "handler": self.help,
            },
        ]


# ---------------------------------------------------------------------------
# JSON-RPC plumbing
# ---------------------------------------------------------------------------
def send(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def error(msg_id: Any, code: int, message: str) -> None:
    send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def handle(tools: Tools, request: dict[str, Any]) -> None:
    method = request.get("method", "")
    msg_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        send(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO,
                    "instructions": (
                        "Read-only view of a vps-harden managed host. Use the audit tool "
                        "before recommending changes; apply changes only through the CLI "
                        "with explicit human approval."
                    ),
                },
            }
        )
        return

    if method.startswith("notifications/"):
        return

    if method == "ping":
        send({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        return

    if method == "tools/list":
        send(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {k: v for k, v in tool.items() if k != "handler"}
                        for tool in tools.registry()
                    ]
                },
            }
        )
        return

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        entry = next((t for t in tools.registry() if t["name"] == name), None)
        if entry is None:
            error(msg_id, -32602, f"unknown tool: {name}")
            return
        try:
            text = entry["handler"](arguments)
        except Exception as exc:  # noqa: BLE001 - report, never crash the server
            send(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                        "isError": True,
                    },
                }
            )
            return
        send(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            }
        )
        return

    error(msg_id, -32601, f"method not found: {method}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="vps-harden read-only MCP server")
    parser.add_argument("--root", help="path to the vps-harden repository")
    args = parser.parse_args(argv)

    tools = Tools(find_root(args.root))
    log(f"serving read-only tools from {tools.root}")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            error(None, -32700, "parse error")
            continue
        if isinstance(request, list):  # batch
            for item in request:
                handle(tools, item)
        else:
            handle(tools, request)
    return 0


if __name__ == "__main__":
    sys.exit(main())
