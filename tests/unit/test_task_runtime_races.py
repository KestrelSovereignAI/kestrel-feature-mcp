"""Actual Core/native HTTPS regression oracles for H1 review findings."""
import asyncio
from datetime import timedelta
import pytest
from kestrel_sovereign.mcp_task_store import MCPTaskConflict
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_task_runtime import start, pytestmark


async def test_shutdown_cancels_task_maintenance_before_waiting_for_feature_gate(
        credential_boundary, monkeypatch):
    b = credential_boundary
    host = await start(b)
    original = host.maintain
    started, release = asyncio.Event(), asyncio.Event()

    async def scheduled(*, observe):
        started.set()
        await release.wait()
        return await original(observe=observe)

    monkeypatch.setattr(host, 'maintain', scheduled)
    maintenance = b.feature._task_maintenance
    await asyncio.wait_for(started.wait(), 5)
    shutdown = None
    try:
        async with b.feature._lifecycle_transition:
            shutdown = asyncio.create_task(b.feature.shutdown())
            while not b.feature._closing:
                await asyncio.sleep(0)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(maintenance), 5)
            assert not shutdown.done()
    finally:
        release.set()
        if shutdown is not None:
            await asyncio.gather(shutdown, return_exceptions=True)
    await shutdown
    assert host.retired
    assert b.feature._task_host is None and b.feature._input_host is None


@pytest.mark.parametrize('ordinary', [False, True])
async def test_postcommit_registration_retirement_cannot_be_a_known_tool_failure(
        credential_boundary, mcp_http_server, monkeypatch, ordinary):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.return_ordinary = ordinary
    host = await start(b)
    name = 'settle_initial' if ordinary else 'attach_task'
    original = getattr(host.store, name)
    async def retired_after_real_commit(*args, **kwargs):
        result = await original(*args, **kwargs)
        b.feature._unmount_tools('mcp:credential')
        return result
    monkeypatch.setattr(host.store, name, retired_after_real_commit)
    response = await b.client.post('/api/owned-credential-call')
    row, = await host.store.list_retained()
    assert row.phase == ('SETTLED' if ordinary else 'ATTACHED') and peer.calls == ['started']
    assert response.status_code != 200, 'A real post-commit authority loss was returned as a known tool error'


async def test_maintenance_cannot_release_a_still_running_reservation(
        credential_boundary, monkeypatch):
    b = credential_boundary
    host = await start(b)
    entered, release = asyncio.Event(), asyncio.Event()
    reserve = host.store.reserve
    async def pending(*args, **kwargs):
        entered.set()
        await release.wait()
        return await reserve(*args, **kwargs)
    monkeypatch.setattr(host.store, 'reserve', pending)
    operation = asyncio.create_task(b.client.post('/api/owned-credential-call'))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        assert await host.store.database.fetchone('SELECT COUNT(*) FROM mcp_task_records') == (0,)
        await host.maintain()
        retained_during_admission = len(b.agent._explored_features['mcp:credential'].task_holds)
        release.set()
        result = await asyncio.wait_for(operation, 5)
        assert result.status_code == 200, result.text
        assert retained_during_admission == 1, 'Maintenance released an in-flight pre-record owner hold'
        assert len(b.agent._explored_features['mcp:credential'].task_holds) == 1
    finally:
        release.set()
        await asyncio.gather(operation, return_exceptions=True)


async def test_terminal_sweep_cannot_release_a_commit_before_its_publication_lease_transfer(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    mcp_http_server.settings['extensions'][0].return_ordinary = True
    host = await start(b)
    settle = host.store.settle_initial
    retained = []
    async def maintenance_after_real_commit(*args, **kwargs):
        actual = await settle(*args, **kwargs)
        await host.maintain()
        retained.append(len(b.agent._explored_features['mcp:credential'].task_holds))
        return actual
    monkeypatch.setattr(host.store, 'settle_initial', maintenance_after_real_commit)
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200, response.text
    assert retained == [1], 'Terminal sweep released an active commit before its actual engine lease transfer'
    assert not b.agent._explored_features['mcp:credential'].task_holds


async def test_an_admitted_response_winning_expiry_does_not_withdraw_the_native_host(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    await b.feature.set_config({'inputs': {'enabled': True, 'host': {'retention_seconds': 1.0}}})
    await b.feature._start_tasks({'maintenance_seconds': 0.1})
    b.app.include_router(b.feature.get_router())
    host = b.feature._task_host
    clock = [host.input_host.authority.clock()]
    host.input_host.authority.clock = lambda: clock[0]
    assert (await b.client.post('/api/owned-credential-connect')).status_code == 200
    assert (await b.client.post('/api/owned-credential-call')).status_code == 200
    pending = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
    row, = pending.json()['inputs']
    resumed, let_resume = asyncio.Event(), asyncio.Event()
    expiring, let_expire, cycle = asyncio.Event(), asyncio.Event(), asyncio.Event()
    original_resume, original_expire, original_maintain = host.joint.resume, host.joint.close_expired, host.maintain
    async def held_resume(*args, **kwargs):
        resumed.set()
        await let_resume.wait()
        return await original_resume(*args, **kwargs)
    async def held_expire(*args, **kwargs):
        expiring.set()
        await let_expire.wait()
        return await original_expire(*args, **kwargs)
    async def observed_maintain(*, observe):
        try:
            return await original_maintain(observe=observe)
        finally:
            if expiring.is_set():
                cycle.set()
    monkeypatch.setattr(host.joint, 'resume', held_resume)
    monkeypatch.setattr(host.joint, 'close_expired', held_expire)
    monkeypatch.setattr(host, 'maintain', observed_maintain)
    operation = asyncio.create_task(b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
        params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
            'operation_id': 'owned-before-expiry-response',
            'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}}))
    maintenance = b.feature._task_maintenance
    try:
        await asyncio.wait_for(resumed.wait(), 5)
        clock[0] += timedelta(seconds=2)
        await asyncio.wait_for(expiring.wait(), 5)
        let_resume.set()
        result = await asyncio.wait_for(operation, 5)
        assert result.status_code == 200 and result.json()['state'] == 'RESOLVED', result.text
        let_expire.set()
        await asyncio.wait_for(cycle.wait(), 5)
        assert not maintenance.done(), 'A benign committed response/expiry race terminated the native Task host'
        host.require_current()
    finally:
        let_resume.set()
        let_expire.set()
        await asyncio.gather(operation, return_exceptions=True)
        failure = maintenance.exception() if maintenance.done() and not maintenance.cancelled() else None
        try:
            await b.feature._close_tasks()
        except MCPTaskConflict as error:
            # Observe precisely this reproduction's original worker error;
            # it must not become a second teardown error masking the oracle.
            assert error is failure
