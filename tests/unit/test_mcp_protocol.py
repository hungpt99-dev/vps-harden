"""Protocol test for the read-only MCP server.

Speaks JSON-RPC over stdio exactly as an MCP client does, instead of importing
the module: the handshake and tool discovery are what Hermes depends on.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "integrations" / "hermes" / "mcp" / "vps_harden_mcp.py"


class Client:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER), "--root", str(ROOT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0

    def send(self, method: str, params: dict | None = None) -> dict | None:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            payload["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        if method.startswith("notifications/"):
            return None
        assert self.proc.stdout is not None
        return json.loads(self.proc.stdout.readline())

    def notify(self, method: str) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": {}}
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)


def test_initialize_handshake() -> None:
    client = Client()
    try:
        response = client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
        assert response is not None
        result = response["result"]
        assert result["serverInfo"]["name"] == "vps-harden"
        assert "tools" in result["capabilities"]
        client.notify("notifications/initialized")
    finally:
        client.close()


def test_tools_are_listed_and_read_only() -> None:
    client = Client()
    try:
        client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
        response = client.send("tools/list")
        assert response is not None
        tools = response["result"]["tools"]
        names = {tool["name"] for tool in tools}
        assert {"vps_harden_status", "vps_harden_audit", "vps_harden_help"} <= names
        # No tool may be able to change the host.
        for tool in tools:
            assert not any(
                word in tool["name"] for word in ("install", "configure", "apply", "write")
            )
            assert tool["inputSchema"]["type"] == "object"
    finally:
        client.close()


def test_help_tool_returns_text() -> None:
    client = Client()
    try:
        client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
        response = client.send("tools/call", {"name": "vps_harden_help", "arguments": {}})
        assert response is not None
        result = response["result"]
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "./install.sh audit" in text
        assert "read-only" in text
    finally:
        client.close()


def test_unknown_tool_is_a_protocol_error() -> None:
    client = Client()
    try:
        client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
        response = client.send("tools/call", {"name": "nope", "arguments": {}})
        assert response is not None
        assert response["error"]["code"] == -32602
    finally:
        client.close()


def test_ping() -> None:
    client = Client()
    try:
        client.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
        response = client.send("ping")
        assert response is not None
        assert response["result"] == {}
    finally:
        client.close()
