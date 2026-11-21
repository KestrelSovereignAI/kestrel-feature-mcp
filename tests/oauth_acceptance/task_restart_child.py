"""Fresh process for the owned OAuth Task restart acceptance test."""

import asyncio
from contextlib import aclosing, AsyncExitStack
import json
import logging
from pathlib import Path
import sys

from fastapi import FastAPI
import httpx2
import pytest

from kestrel_feature_mcp.feature import MCPAgent
from kestrel_sovereign import server
from kestrel_sovereign.a2a.stores.unified.feature_enablement_store import FeatureEnablementStore
from kestrel_sovereign.mcp_oauth import MCPOAuthHostPolicy
from kestrel_sovereign.security.private_delivery import PrivateDeliveryMiddleware
from kestrel_sovereign.security.request_auth import (
    InteractiveAuthenticationLifetimeMiddleware, RequestAuthenticationService,
)
from kestrel_sovereign.storage.db import SQLiteBackend
from kestrel_sovereign.testing.fixtures import native_tool_effect_agent

from refresh_child import install_owned_tls


async def main(configuration):
    root, path = Path(configuration['root']), Path(configuration['database'])
    assert path.is_relative_to(root) and path.is_file()
    install_owned_tls(configuration['server_url'], configuration['issuer'], configuration['certificate'])
    with pytest.MonkeyPatch.context() as guard:
        fixture = native_tool_effect_agent.__wrapped__(root, guard)
        async with aclosing(fixture), AsyncExitStack() as owned:
            create_agent = await anext(fixture)
            backend = SQLiteBackend(str(path))
            agent = await create_agent(did=configuration['agent_did'], connected_backend=backend)
            agent._mcp_oauth_host_policy = MCPOAuthHostPolicy.model_validate(configuration['oauth_policy'])
            enablement = FeatureEnablementStore(backend, owns_backend=False)
            await enablement.initialize()
            owned.push_async_callback(enablement.close)
            agent._feature_enablement_store = enablement
            feature = MCPAgent(agent)
            await agent._register_feature(feature)
            owned.push_async_callback(agent._unregister_feature_runtime, feature, unload=True)
            await feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0},
                'inputs': {'enabled': True}})
            await feature._start_tasks({'maintenance_seconds': 60.0})
            assert not feature._remote_connections
            runtime = feature._task_runtime
            original = await runtime.host.store.read_handle(configuration['handle'])
            assert original.phase == 'ATTACHED' and original.observation is None
            settled = original
            async with asyncio.timeout(5):
                while settled.phase != 'SETTLED':
                    await runtime.maintain(observe=True)
                    settled = await runtime.host.store.read_handle(original.handle)
                    if settled.phase != 'SETTLED':
                        await asyncio.sleep(0.05)
            assert settled.phase == 'SETTLED'
            assert not feature._remote_connections

            app = FastAPI()
            app.state.agent = agent
            app.state.request_authentication = RequestAuthenticationService(
                api_key=lambda: server.get_api_key(generate_if_missing=False))
            app.add_middleware(InteractiveAuthenticationLifetimeMiddleware)
            app.middleware('http')(server.auth_middleware)
            app.add_middleware(PrivateDeliveryMiddleware)
            app.include_router(feature.get_router())
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
                    base_url='https://console.example') as client:
                response = await client.get(f'/api/mcp/task-results/{original.handle}',
                    params={'session_id': configuration['session_id']}, headers={
                        'X-API-Key': server.get_api_key(generate_if_missing=False),
                        'X-Kestrel-Task-Result': configuration['reference'],
                    })
                assert response.status_code == 200, response.text
                return response.json()


if __name__ == '__main__':
    logging.disable(logging.CRITICAL)
    sys.stdout.write(json.dumps(asyncio.run(main(json.load(sys.stdin)))))
