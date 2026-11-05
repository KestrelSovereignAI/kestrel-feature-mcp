"""Real browser consent through native Core, independent AS and MCP TLS peers."""

import asyncio
import json
import os
from pathlib import Path

import kestrel_sovereign
from kestrel_sovereign import server
from kestrel_sovereign.features.security.permissions import PermissionLevel
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
import pytest

from kestrel_feature_mcp.remote import remote_owner
from tests.unit.conftest import owned_oauth_key as owned_oauth_key
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_runtime_http import oauth_runtime as oauth_runtime


pytestmark = [pytest.mark.apps_browser, pytest.mark.timeout(60),
    pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True}], indirect=True)]


@pytest.fixture
async def native_console_browser(oauth_runtime, monkeypatch):
    b = oauth_runtime
    monkeypatch.setattr(server, 'SERVE_UI', True)

    @b.app.get('/')
    async def page():
        return HTMLResponse('<!doctype html><meta charset="utf-8"><title>Owned native MCP Console</title>'
            '<link rel="stylesheet" href="/static/index.css">'
            '<link rel="stylesheet" href="/features/mcpagent/static/oauth-panel.css">'
            '<nav id="owned-nav"></nav><main id="owned-panels"></main>'
            '<script type="module" src="/js/owned-oauth-entry.js"></script>',
            headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'})

    @b.app.get('/js/owned-oauth-entry.js')
    async def entry():
        return Response('''
            const { default: api } = await import('/js/api.js');
            await api.init();
            const { renderNav, activate } = await import('/js/ui-ext/panels.js');
            await import('/features/mcpagent/static/oauth-panel.js');
            renderNav({ navEl: document.getElementById('owned-nav'),
                hostEl: document.getElementById('owned-panels'), ctx: { api } });
            activate('mcp-connectors', { api });
            document.getElementById('panel-mcp-connectors').classList.add('active');
            window.ownedOAuthReady = true;
        ''', media_type='text/javascript')

    static = Path(kestrel_sovereign.__file__).parent / 'static'
    b.app.mount('/js', StaticFiles(directory=static / 'js'))
    b.app.mount('/static', StaticFiles(directory=static))
    server._mount_feature_ui_assets(b.app)
    return b


async def test_console_panel_native_consent_refresh_governed_effect_and_local_disconnect(
    native_console_browser, tmp_path,
):
    b = native_console_browser
    repository = Path(__file__).resolve().parents[2]
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'PLAYWRIGHT_BROWSERS_PATH') if key in os.environ}
    screenshot = tmp_path / 'native-oauth-panel.png'
    child = await asyncio.create_subprocess_exec('node', 'web/test-support/oauth-browser-driver.mjs',
        b.app.state.mcp_oauth_policy.console_origin, str(screenshot), cwd=repository, env=env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        child.stdin.write((json.dumps({'key': b.key, 'server': b.peer.selection.server_url}) + '\n').encode())
        await child.stdin.drain()
        phase = await asyncio.wait_for(child.stdout.readline(), 25)
        if not phase:
            output, errors = await child.communicate()
            pytest.fail((output + errors).decode()[-6000:])
        connected = json.loads(phase)
        assert connected['phase'] == 'connected'
        owner = remote_owner(connected['name'])
        b.handle = next(name for name, feature in b.agent._tool_to_feature.items()
            if feature == owner and name.endswith('__echo'))
        await b.permissions.set_permission(owner, b.handle, PermissionLevel.ALLOW)
        child.stdin.write(b'{"approved":true}\n')
        await child.stdin.drain()
        output, errors = await asyncio.wait_for(child.communicate(), 25)
        assert child.returncode == 0, (output + errors).decode()[-6000:]
        assert all(json.loads(output).values())
        assert b.peer.resource.witness == ['owned-effect']
        rows = await b.host.database.fetch_all('SELECT session_id,result_status FROM a2a_tool_dispatches')
        assert [tuple(row) for row in rows] == [('credential-chat', 'success')]
        assert b.peer.requests.count(('GET', '/authorize')) == 1
        assert b.peer.requests.count(('POST', '/token')) == 2
        assert not b.feature._remote_connections
        assert (await b.host.database.fetch_one('SELECT ciphertext FROM mcp_oauth_credential_slots'))[0] is None
        assert screenshot.stat().st_size > 0
    finally:
        if child.returncode is None:
            child.terminate()
            await asyncio.wait_for(child.wait(), 5)
