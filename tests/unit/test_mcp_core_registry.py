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
