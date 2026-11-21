"""Chromium, installed Console renderer, real authenticated Task routes and a TLS peer."""

import asyncio
import json
import os
from pathlib import Path

from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from kestrel_sovereign import server
import kestrel_sovereign
import pytest

from tests.unit.conftest import owned_oauth_key as owned_oauth_key
from tests.unit.test_oauth_runtime_http import authorize, connect
from tests.unit.test_task_observation import (
    credential_boundary as credential_boundary, oauth_peers as oauth_peers, oauth_runtime as oauth_runtime,
    pytestmark as native_task_marks,
)


pytestmark = [*native_task_marks, pytest.mark.apps_browser]


async def checkpoint(child):
    line = await asyncio.wait_for(child.stdout.readline(), 13)
    if not line:
        _, errors = await child.communicate()
        pytest.fail(errors.decode()[-6000:])
    return json.loads(line)


async def send(child, message):
    child.stdin.write((message + '\n').encode())
    await child.stdin.drain()


@pytest.mark.parametrize('kind', ['update', 'cancel'])
async def test_real_console_task_recovers_from_unknown_acknowledgement(oauth_runtime, monkeypatch, kind):
    b = oauth_runtime
    b.agent._mcp_oauth_host_policy = b.app.state.mcp_oauth_policy
    await b.feature.set_config({'inputs': {'enabled': True},
        'oauth': {'enabled': True, 'close_seconds': 2.0, 'maintenance_seconds': 60.0}})
    await b.feature._start_tasks({'maintenance_seconds': 60.0})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    peer = b.peer.resource.settings['extensions'][0]
    runtime = b.feature._task_runtime
    monkeypatch.setattr(server, 'SERVE_UI', True)
    static = Path(kestrel_sovereign.__file__).parent / 'static'
    root = Path(__file__).resolve().parents[2]
    build = await asyncio.create_subprocess_exec('node', 'web/test-support/parent-browser-build.mjs',
        'task', cwd=root, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    entry, build_errors = await asyncio.wait_for(build.communicate(), 10)
    assert build.returncode == 0, build_errors.decode()

    @b.app.get('/')
    async def page():
        return HTMLResponse('<!doctype html><body><script type="module" src="/js/task-fixture.js"></script>')

    @b.app.get('/js/task-fixture.js')
    async def fixture_entry():
        return Response(entry, media_type='text/javascript')

    b.app.mount('/js', StaticFiles(directory=static / 'js'))
    b.app.mount('/shared', StaticFiles(directory=static / 'shared'))
    server._mount_feature_ui_assets(b.app)
    active = await b.store.read_tokens(b.runtime._credentials[name].snapshot)
    claim = None

    async def suspend_grant(result):
        nonlocal claim
        claim = await b.store.begin_refresh(active)
        return result

    child = await asyncio.create_subprocess_exec('node', 'web/test-support/task-activation-driver.mjs',
        b.app.state.mcp_oauth_policy.console_origin, kind, cwd=root,
        env={key: os.environ[key] for key in ('PATH', 'HOME', 'PLAYWRIGHT_BROWSERS_PATH') if key in os.environ},
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        await send(child, json.dumps(b.key))
        assert await checkpoint(child) == {'event': 'rendered'}
        record, = await runtime.host.store.list_retained()
        assert record.phase == 'ATTACHED' and peer.calls == ['started']
        if kind == 'update':
            peer.status = 'input_required'
            observed = await runtime.observe(record.handle)
            assert observed.pending_inputs.keys() == {'form'}
        peer.before_response = suspend_grant
        await send(child, 'continue')
        assert await checkpoint(child) == {'event': 'unknown', 'status': 503}
        assert claim is not None and peer.calls[-1] == kind
        pending = await runtime.host.store.read_handle(record.handle)
        receipt, = pending.control['mutations'].values()
        assert receipt['acknowledgement'] is None and receipt['claim_hash'] is not None
        peer.before_response = None
        await b.store.abandon_refresh(claim)
        claim = None
        peer.status = 'completed' if kind == 'update' else 'cancelled'
        settled = await runtime.observe(record.handle)
        assert settled.phase == 'SETTLED' and settled.observation['status'] == peer.status
        await send(child, 'continue')
        assert await checkpoint(child) == {'event': 'settled', 'posts': 1}
        _, errors = await asyncio.wait_for(child.communicate(), 5)
        assert child.returncode == 0, errors.decode()[-6000:]
        assert peer.calls == (['started', 'get', 'update', 'get'] if kind == 'update'
                              else ['started', 'cancel', 'get'])
    finally:
        peer.before_response = None
        if child.returncode is None:
            child.terminate()
            await asyncio.wait_for(child.communicate(), 5)
        if claim is not None:
            await b.store.abandon_refresh(claim)
