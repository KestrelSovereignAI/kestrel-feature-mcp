"""A real AS failure leaves a visible, non-replaying native Console return."""

import asyncio
import json
import os
from pathlib import Path

import pytest

from tests.browser.test_oauth_panel import native_console_browser as native_console_browser
from tests.unit.conftest import owned_oauth_key as owned_oauth_key
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_runtime_http import oauth_runtime as oauth_runtime


pytestmark = [pytest.mark.apps_browser, pytest.mark.timeout(60),
    pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True,
        'token_error_status': 503}], indirect=True)]


async def test_failed_exchange_returns_to_console_without_replaying_callback(native_console_browser):
    b = native_console_browser
    repository = Path(__file__).resolve().parents[2]
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'PLAYWRIGHT_BROWSERS_PATH') if key in os.environ}
    child = await asyncio.create_subprocess_exec('node', 'web/test-support/oauth-browser-driver.mjs',
        b.app.state.mcp_oauth_policy.console_origin, cwd=repository, env=env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        configuration = {'key': b.key, 'server': b.peer.selection.server_url, 'mode': 'exchange-error'}
        output, errors = await asyncio.wait_for(child.communicate((json.dumps(configuration) + '\n').encode()), 25)
        assert child.returncode == 0, (output + errors).decode()[-6000:]
        assert all(json.loads(output).values())
        assert b.peer.requests.count(('GET', '/authorize')) == 1
        assert b.peer.requests.count(('POST', '/token')) == 1
        assert not b.peer.resource.witness
        assert not b.feature._remote_connections
        row = await b.host.database.fetch_one('SELECT state,ciphertext FROM mcp_oauth_credential_slots')
        assert tuple(row) == ('exchanging', None)
        assert not await b.host.database.fetch_all('SELECT session_id FROM a2a_tool_dispatches')
    finally:
        if child.returncode is None:
            child.terminate()
            await asyncio.wait_for(child.wait(), 5)
