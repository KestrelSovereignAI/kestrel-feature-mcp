"""Catalog refresh against Core's canonical registry, with no model or network."""

from copy import deepcopy

import pytest
from pydantic import ValidationError
from kestrel_sovereign.agent.tool_registry import ToolRegistryMixin

from kestrel_feature_mcp.connection import MCPConnection
from kestrel_feature_mcp.feature import MCPAgent


class CoreRegistryHost(ToolRegistryMixin):
    """Inject registry state into the real production implementation."""

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


def test_hidden_tools_require_the_explicit_host_projection_contract_before_refresh():
    class EarlierRegistryAPI(CoreRegistryHost):
        def register_dynamic_tools(self, owner, tools, *, pin=False):
            return super().register_dynamic_tools(owner, tools, pin=pin)

    host = EarlierRegistryAPI()
    feature = MCPAgent(host)
    caller = MCPConnection("http://127.0.0.1:1/mcp").call_tool
    owner = "mcp:host-projection"
    feature._mount_tools(owner, "catalog", [native_tool()], caller)
    original = dict(host._direct_tools)
    registration = host._explored_features[owner]
    with pytest.raises(RuntimeError, match="Core 0.55.0"):
        feature._mount_tools(owner, "catalog", [native_tool("private", _meta={
            "ui": {"visibility": ["app"]},
        })], caller)
    assert host._direct_tools == original
    assert host._explored_features[owner] is registration


@pytest.mark.asyncio
@pytest.mark.parametrize("already_connected", [False, True])
async def test_bad_native_catalog_never_reaches_gateway_enablement_storage(
    mcp_http_server, monkeypatch, already_connected,
):
    """Only substitute the Docker process; discovery uses the real SDK/HTTP."""
    from kestrel_sdk.tools.result import ToolResultStatus
    from kestrel_feature_mcp.manager import MCPGatewayManager

    class OwnedHTTPGateway:
        endpoint_url = mcp_http_server.url
        is_running = True
        requested_servers = set()

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
    manager = MCPGatewayManager()
    manager.gateway = OwnedHTTPGateway()
    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    monkeypatch.setattr("kestrel_feature_mcp.manager.MCPGatewayManager", lambda: manager)
    if already_connected:
        await manager.start(["known-good"])
        feature.gateway_manager = manager
        assert feature._mount_gateway_tools() == 2
        assert len(host._direct_tools) == 2
    mcp_http_server.settings["advertised_contract"] = {
        "meta": {"ui": {"visibility": ["invalid-audience"]}},
    }
    try:
        result = await feature._load_via_gateway("invalid-app")
        assert result.status is ToolResultStatus.ERROR
        assert "echo" in result.error and "visibility" in result.error
        assert "handles were withdrawn" in result.error
        assert "remains saved" not in result.error
        assert not host._direct_tools, "Retired transport handles must not survive a failed discovery"
        assert manager.connection is None
        assert not manager.tools
        assert not mcp_http_server.witness
    finally:
        await manager.stop()
