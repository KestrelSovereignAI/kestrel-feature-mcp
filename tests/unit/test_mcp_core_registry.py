"""Catalog refresh against Core's canonical registry, with no model or network."""

from copy import deepcopy
import logging

import pytest
from pydantic import ValidationError
from kestrel_sovereign.agent.orchestrator_engine import OrchestratorEngineMixin
from kestrel_sovereign.agent.tool_registry import ToolRegistryMixin

from kestrel_feature_mcp.connection import MCPConnection
from kestrel_feature_mcp.feature import MCPAgent


class CoreRegistryHost(OrchestratorEngineMixin, ToolRegistryMixin):
    """Use the production execution and registry implementations for the host contract."""

    def __init__(self):
        self.did = "did:test:registry-catalog"
        self.features = {}
        self._direct_tools, self._tool_to_feature, self._explored_features = {}, {}, {}
        self._direct_tool_defs, self._pinned_features = [], set()


def native_tool(name="original", **updates):
    return {"name": name, "inputSchema": {"type": "object"}, **updates}


@pytest.mark.parametrize("invalid", [
    native_tool("invalid-ui", _meta={"ui": {"visibility": ["unrecognized"]}}),
    {"name": "invalid-native-record", "inputSchema": "not a schema"},
])
def test_invalid_refresh_leaves_actual_core_registrations_and_identity_intact(invalid):
    host = CoreRegistryHost()
    feature = MCPAgent(host)
    caller = MCPConnection("http://127.0.0.1:1/mcp").call_tool
    owner = "mcp:catalog-refresh"
    assert feature._mount_tools(owner, "catalog", [native_tool()], caller) == 1
    original = dict(host._direct_tools)
    registration = host._explored_features[owner]
    schemas = deepcopy(host._build_all_tools())
    with pytest.raises((ValueError, ValidationError)):
        feature._mount_tools(owner, "catalog", [native_tool("replacement"), invalid], caller)
    assert host._direct_tools == original, "invalid metadata removed the original Core tools"
    assert host._explored_features[owner] is registration, "invalid refresh replaced Core's registration identity"
    assert host._build_all_tools() == schemas


def test_app_visibility_is_honored_in_actual_core_model_projections():
    host = CoreRegistryHost()
    feature = MCPAgent(host)
    caller = MCPConnection("http://127.0.0.1:1/mcp").call_tool
    records = [native_tool("visible"), native_tool("private", _meta={"ui": {"visibility": ["app"]}})]
    assert feature._mount_tools("mcp:visibility", "catalog", records, caller) == 2
    assert len(host._direct_tools) == 2
    for schemas in [host._build_all_tools(), host.build_progressive_tool_schemas()]:
        assert [item["function"]["name"] for item in schemas] == ["mcp__catalog__visible"]


def test_tools_require_the_explicit_governed_host_contract_before_refresh():
    host = CoreRegistryHost()
    feature = MCPAgent(host)
    caller = MCPConnection("http://127.0.0.1:1/mcp").call_tool
    owner = "mcp:host-projection"
    feature._mount_tools(owner, "catalog", [native_tool()], caller)
    original = dict(host._direct_tools)
    registration = host._explored_features[owner]
    register = host.register_dynamic_tools

    def missing_governed_contract(owner, tools, *, pin=False):
        return register(owner, tools, pin=pin)

    host.register_dynamic_tools = missing_governed_contract
    with pytest.raises(RuntimeError, match="Core 0.55.0"):
        feature._mount_tools(owner, "catalog", [native_tool("private", _meta={
            "ui": {"visibility": ["app"]},
        })], caller)
    assert host._direct_tools == original
    assert host._explored_features[owner] is registration


@pytest.mark.asyncio
@pytest.mark.parametrize("already_connected", [False, True])
@pytest.mark.parametrize("producer", ["load", "restore"])
async def test_bad_native_catalog_never_reaches_gateway_enablement_storage(
    mcp_http_server, monkeypatch, already_connected, producer, caplog,
):
    """Substitute Docker selection/process; discovery uses the real SDK/HTTP."""
    from kestrel_sdk.tools.result import ToolResultStatus
    from kestrel_feature_mcp.manager import MCPGatewayManager

    class OwnedHTTPGateway:
        endpoint_url = mcp_http_server.url
        is_running = True
        requested_servers = set()

        async def validate_servers(self, servers):
            assert servers

        async def start(self, servers):
            self.requested_servers = set(servers)
            return "test-token"

        async def add_server(self, server):
            self.requested_servers.add(server)
            return "test-token"

        async def stop(self):
            self.is_running = False

    async def unexpected_persist(*args, **kwargs):
        raise AssertionError("An invalid native catalog reached durable enablement storage")

    async def approved_catalog_names(requested):
        return None

    host = CoreRegistryHost()
    host.persist_feature_enablement = unexpected_persist
    feature = MCPAgent(host)
    feature._reject_unknown_servers = approved_catalog_names
    managers = []

    def owned_manager(**kwargs):
        manager = MCPGatewayManager(**kwargs)
        manager.gateway = OwnedHTTPGateway()
        managers.append(manager)
        return manager

    manager = owned_manager()
    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    monkeypatch.setattr("kestrel_feature_mcp.manager.MCPGatewayManager", owned_manager)
    if already_connected:
        await manager.start(["known-good"])
        feature.gateway_manager = manager
        assert feature._mount_gateway_tools() == 2
        assert len(host._direct_tools) == 2
    mcp_http_server.settings["advertised_contract"] = {
        "meta": {"ui": {"visibility": ["invalid-audience"]}},
    }
    try:
        if producer == "restore":
            async def read_saved(kind):
                assert kind == "mcp_server"
                return [{"name": "invalid-app", "state": "enabled", "metadata": {"mode": "gateway"}}]

            host.get_enablement_deltas = read_saved
            caplog.set_level(logging.INFO, logger="kestrel_feature_mcp.feature")
            await feature.on_agent_ready()
            assert "Failed to restore MCP gateway" in caplog.text
            assert "echo" in caplog.text and "visibility" in caplog.text
            assert "Restored" not in caplog.text
        else:
            result = await feature._load_via_gateway("invalid-app")
            assert result.status is ToolResultStatus.ERROR
            assert "echo" in result.error and "visibility" in result.error
            assert "handles are unavailable" in result.error
            assert "remains saved" not in result.error
        assert not host._direct_tools, "Retired transport handles must not survive a failed discovery"
        assert all(item.connection is None and not item.tools for item in managers)
        assert not mcp_http_server.witness
    finally:
        for item in managers:
            await item.stop()
