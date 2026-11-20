"""Public native MCP transport remains ordinary when it has no OAuth owner."""
from contextlib import AsyncExitStack
from uuid import uuid4
import pytest

from kestrel_feature_mcp.connection import bind_tool_caller
from kestrel_feature_mcp.feature import MCPAgent
from tests.unit.test_tasks_native_peer import NativeTasksPeer


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
async def test_private_task_composition_does_not_declare_tasks_on_an_ordinary_public_connection(
        native_tool_effect_agent, mcp_http_server):
    agent = await native_tool_effect_agent(did='did:test:public-task-transport')
    feature = MCPAgent(agent)
    async with AsyncExitStack() as cleanup:
        await agent._register_feature(feature)
        cleanup.push_async_callback(agent._unregister_feature_runtime, feature, unload=True)
        await feature.set_config({'inputs': {'enabled': True}})
        await feature._start_tasks({})
        peer = mcp_http_server.settings['extensions'][0]
        peer.return_ordinary = True
        connection = feature._new_mcp_connection(mcp_http_server.url)
        cleanup.push_async_callback(connection.close)
        tools = await connection.connect()
        assert not connection.supports_task_claims, 'A connection without an OAuth identity advertised Task custody'
        caller = bind_tool_caller(connection, lambda: connection.is_connected, 'owned-public',
            tool_names=[tool.name for tool in tools])
        feature._mount_tools('mcp:owned-public', 'owned_public',
            [tool.model_dump(mode='json', by_alias=True) for tool in tools], caller)
        registered = next(item for item in feature._task_runtime._registrations['mcp:owned-public']
            if item.tool.native_tool.name == 'echo')
        result = await registered.binding.invoke({'text': 'ordinary-public-native-effect'},
            session_id='owned-public-session', operation_id=uuid4().hex, source='external')
        assert result['status'] == 'ok' and mcp_http_server.witness == ['ordinary-public-native-effect']
        assert await feature._task_host.store.list_retained() == ()
        feature._unmount_tools('mcp:owned-public')
