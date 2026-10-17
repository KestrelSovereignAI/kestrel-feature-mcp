"""MCP transport calls are reachable only through registered dynamic handles."""

import inspect
from types import SimpleNamespace

import pytest

from kestrel_feature_mcp.feature import MCPAgent


def test_generic_transport_dispatchers_are_not_exposed():
    schemas = [method._tool_schema for _, method in inspect.getmembers(MCPAgent, inspect.isfunction)
               if hasattr(method, '_tool_schema')]
    assert not {'mcp_call_tool', 'mcp_gateway_call'} & {schema['name'] for schema in schemas}
    assert not {'!mcp-call', '!mcp-gateway-call'} & {schema.get('command_prefix') for schema in schemas}
    assert not hasattr(MCPAgent, 'call_tool')
    assert not hasattr(MCPAgent, 'gateway_call')


@pytest.mark.parametrize('methods', [
    {}, {'register_dynamic_tools': None, 'unregister_dynamic_tools': None},
    {'register_dynamic_tools': lambda *args: 0, 'unregister_dynamic_tools': None},
    {'register_dynamic_tools': None, 'unregister_dynamic_tools': lambda *args: 0},
])
def test_mounting_without_the_governed_host_registry_is_refused(methods):
    feature = MCPAgent(SimpleNamespace(**methods))
    with pytest.raises(RuntimeError, match='dynamic tool registry'):
        feature._mount_tools('mcp:peer', 'peer', [{'name': 'privileged'}], None)
