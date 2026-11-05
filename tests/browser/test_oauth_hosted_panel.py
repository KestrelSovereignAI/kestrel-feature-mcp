"""Native Console selection and callback keep the original Unicode agent."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from kestrel_sovereign.multi_agent.route_name import encode_agent_route_name

from tests.browser.test_oauth_panel import native_console_browser as native_console_browser
from tests.unit.conftest import owned_oauth_key as owned_oauth_key
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_runtime_http import oauth_runtime as oauth_runtime

pytestmark = [pytest.mark.apps_browser, pytest.mark.timeout(60),
    pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True}], indirect=True)]


@pytest.mark.parametrize('name', ['Owned bird ☃', 'Owned bird/☃'])
async def test_unicode_hosted_agent_selection_completes_its_original_native_authorization(native_console_browser, name):
    b = native_console_browser
    # Both are native Core agent addresses. Mount the original controller at
    # each address without changing its host, authentication or operation owner.
    router = b.feature.get_router()
    b.app.include_router(router, prefix='/api/agents/' + name)
    b.app.include_router(router, prefix='/api/agent-routes/' + encode_agent_route_name(name))
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'PLAYWRIGHT_BROWSERS_PATH') if key in os.environ}
    child = await asyncio.create_subprocess_exec('node', 'web/test-support/oauth-browser-driver.mjs',
        b.app.state.mcp_oauth_policy.console_origin, cwd=Path(__file__).resolve().parents[2], env=env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        configuration = {'key': b.key, 'server': b.peer.selection.server_url,
            'mode': 'hosted-consent', 'agent_name': name,
            'agent_prefix': '/api/agent-routes/' + encode_agent_route_name(name)}
        output, errors = await asyncio.wait_for(child.communicate((json.dumps(configuration) + '\n').encode()), 25)
        assert child.returncode == 0, (output + errors).decode()[-6000:]
        assert all(json.loads(output).values())
        assert b.peer.requests.count(('POST', '/token')) == 1
        assert b.peer.requests.count(('GET', '/authorize')) == 1
        row = await b.host.database.fetch_one('SELECT state FROM mcp_oauth_credential_slots')
        assert row[0] == 'active'
        assert not b.peer.resource.witness and not b.feature._remote_connections
    finally:
        if child.returncode is None:
            child.terminate()
            await asyncio.wait_for(child.wait(), 5)
