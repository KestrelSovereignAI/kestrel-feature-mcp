"""Unit tests for the gateway --long-lived flag (#12 follow-up).

Without long-lived containers the gateway runs a throwaway container per tool
call, so stateful MCP servers lose in-process state between calls. We default
to long-lived; these assert the flag wiring (the stateful behaviour itself is
covered by the live integration probe).
"""

from kestrel_feature_mcp.gateway import DockerMCPGateway
from kestrel_feature_mcp.manager import MCPGatewayManager


def test_long_lived_defaults_on():
    assert DockerMCPGateway().long_lived is True
    assert MCPGatewayManager().gateway.long_lived is True


def test_long_lived_can_be_disabled():
    gw = DockerMCPGateway(long_lived=False)
    assert gw.long_lived is False
    assert MCPGatewayManager(long_lived=False).gateway.long_lived is False


def test_start_cmd_includes_long_lived_when_enabled(monkeypatch):
    captured = {}

    class _FakePopen:
        def __init__(self, cmd, **kw):
            captured["cmd"] = cmd
            self.returncode = None
            self.stdout = self

        def readline(self):
            return "> Start streaming server on port 12345\n"

        def poll(self):
            return None

    monkeypatch.setattr("kestrel_feature_mcp.gateway.subprocess.Popen", _FakePopen)
    monkeypatch.setattr(DockerMCPGateway, "check_docker_mcp_available", staticmethod(lambda: True))

    async def _ok_enable(self, server):
        self.enabled_servers.add(server)
        return True

    monkeypatch.setattr(DockerMCPGateway, "_enable_server", _ok_enable)

    async def _ready(self, timeout=10.0):
        return True

    monkeypatch.setattr(DockerMCPGateway, "_wait_port_listening", _ready)

    import asyncio

    gw = DockerMCPGateway(port=12345)
    asyncio.run(gw.start(["sequentialthinking"]))
    assert "--long-lived" in captured["cmd"]

    gw2 = DockerMCPGateway(port=12346, long_lived=False)
    asyncio.run(gw2.start(["sequentialthinking"]))
    assert "--long-lived" not in captured["cmd"]
