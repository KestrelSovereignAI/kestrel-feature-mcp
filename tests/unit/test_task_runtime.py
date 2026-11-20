"""Real Core governance and encrypted OAuth generation across native Task HTTP.

The existing credential fixture installs an owned synthetic issuer grant. These
tests prove its native lease, original dispatch and Task/MRTR wire integration;
they do not claim new vendor consent or READY/model cognition acceptance.
"""

import pytest
import asyncio
from contextlib import AsyncExitStack
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import time
import os
from mcp import types
from kestrel_sdk.security.outbound import assert_safe_url
from kestrel_sovereign.features.security.permissions import PermissionLevel
from kestrel_feature_mcp.connection import bind_tool_caller
from fastapi import Request
from kestrel_sovereign.auth import caller_context_scope
from kestrel_feature_mcp.oauth_grants import OAuthGrantTokens
from tests.unit.test_oauth_grants import install_grant

from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_tasks_native_peer import NativeTasksPeer

pytestmark = [pytest.mark.asyncio, pytest.mark.timeout(30),
    pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {},
        'extensions': [NativeTasksPeer()]}], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True}], indirect=True)]


async def start(boundary, *, input_host=None, task_host=None):
    b = boundary
    await b.feature.set_config({'inputs': {'enabled': True, 'host': input_host or {}}})
    await b.feature._start_tasks({'host': task_host or {}})
    b.app.include_router(b.feature.get_router())
    response = await b.client.post('/api/owned-credential-connect')
    assert response.status_code == 200, response.text
    return b.feature._task_host


async def test_declaring_native_call_reserves_before_wire_and_retains_the_exact_task_claim(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.calls.clear()
    host = await start(b)
    identity = b.credential.authorization_identity
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200, response.text
    assert peer.calls == ['started']
    record, = await host.store.list_retained()
    assert record.phase == 'ATTACHED' and record.remote_task_id == peer.task_id
    assert record.binding.authorization_id == identity
    assert record.envelope['native']['resultType'] == 'task'
    assert record.envelope['native']['ttlMs'] == peer.ttl_ms
    assert record.binding.origin.kind == 'interactive'
    assert (await host.store.open_submission(record)).arguments == {'text': 'owned-effect'}
    assert response.json()['status'] == 'partial' and response.json()['data']['mcp_task'] == record.handle
    assert not b.feature.config_schema['properties'].get('tasks')
    assert not getattr(b.agent, 'supports_mcp_task_host', False)


@pytest.mark.parametrize('ordinary', [False, True])
async def test_original_method_input_commits_both_rows_then_resumes_to_a_native_outcome(
        credential_boundary, mcp_http_server, ordinary):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.calls.clear()
    previous_input = peer.require_input
    peer.require_input = True
    peer.return_ordinary = ordinary
    try:
        host = await start(b)
        response = await b.client.post('/api/owned-credential-call')
        assert response.status_code == 200, response.text
        task, = await host.store.list_retained()
        assert task.phase == 'INPUT_WAITING' and peer.calls == []
        waiting = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
        assert waiting.status_code == 200, waiting.text
        row, = waiting.json()['inputs']
        assert task.continuity['input']['request_id'] == row['request_id']
        result = await b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
            params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
                'operation_id': 'owned-new-governed-response',
                'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}})
        assert result.status_code == 200, result.text
        updated, = await host.store.list_retained()
        assert updated.handle == task.handle and updated.phase == ('SETTLED' if ordinary else 'ATTACHED')
        assert len(updated.continuity['operations']) == 1
        assert result.json()['state'] == 'RESOLVED' and peer.calls == ['started']
    finally:
        peer.require_input = previous_input


@pytest.mark.parametrize('is_error', [False, True])
async def test_declaring_call_can_finish_with_an_actual_native_ordinary_result(
        credential_boundary, mcp_http_server, is_error):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.return_error, peer.return_ordinary = is_error, not is_error
    host = await start(b)
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200, response.text
    record, = await host.store.list_retained()
    assert record.phase == 'SETTLED' and record.remote_task_id is None
    assert record.envelope['native']['resultType'] == 'complete'
    assert record.envelope['native'].get('isError', False) == is_error
    assert peer.calls == ['started']
    assert not b.agent._explored_features['mcp:credential'].task_holds


async def test_two_real_responders_can_start_only_one_native_continuation(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    host = await start(b)
    initial = await b.client.post('/api/owned-credential-call')
    assert initial.status_code == 200, initial.text
    waiting = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
    row, = waiting.json()['inputs']
    async def respond(operation):
        return await b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
            params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
                'operation_id': operation,
                'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}})
    responses = await asyncio.gather(respond('owned-first-responder'), respond('owned-second-responder'))
    assert any(result.status_code == 200 and result.json().get('state') == 'RESOLVED' for result in responses)
    assert peer.calls == ['started'], 'Concurrent human responses dispatched the original MCP continuation twice'
    record, = await host.store.list_retained()
    assert record.phase == 'ATTACHED' and len(record.continuity['operations']) == 1


async def test_public_tasks_configuration_remains_unavailable(credential_boundary):
    with pytest.raises(ValueError, match='configuration accepts'):
        await credential_boundary.feature.set_config({'tasks': {'enabled': True}})


@pytest.mark.parametrize('code', [types.METHOD_NOT_FOUND, types.INVALID_PARAMS, types.HEADER_MISMATCH])
async def test_actual_native_preexecution_rejection_retires_the_reserved_issuer(
        credential_boundary, mcp_http_server, code):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.tool_reject_code = code
    host = await start(b)
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'error'
    row, = await host.store.list_retained()
    assert row.phase == 'NOT_SENT' and row.remote_task_id is None
    assert row.envelope['refusal']['native_errors'][0]['code'] == code
    assert not peer.calls and not b.agent._explored_features['mcp:credential'].task_holds


@pytest.mark.parametrize('limit', ['capacity', 'payload'])
async def test_known_joint_input_refusal_retains_the_actual_native_disposition_and_no_issuing_strand(
        credential_boundary, mcp_http_server, limit, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    host = await start(b, input_host={'max_pending': 1} if limit == 'capacity' else {'max_payload_bytes': 64})
    native = []
    suspend = host.input_host.suspend
    async def observed(*args, **kwargs):
        native.append(deepcopy(kwargs['payload']['native']))
        return await suspend(*args, **kwargs)
    monkeypatch.setattr(host.input_host, 'suspend', observed)
    if limit == 'capacity':
        first = await b.client.post('/api/owned-credential-call')
        assert first.status_code == 200, first.text
    refused = await b.client.post('/api/owned-credential-call')
    assert refused.status_code == 502, refused.text
    rows = await host.store.list_retained()
    settled = [row for row in rows if row.phase == 'SETTLED']
    assert len(settled) == 1 and all(row.phase != 'ISSUING' for row in rows)
    assert settled[0].envelope['native']['resultType'] == 'input_required'
    assert settled[0].envelope['native'] == native[-1]
    assert not peer.calls
    assert await host.store.database.fetchone('SELECT COUNT(*) FROM mcp_inputs') == (1 if limit == 'capacity' else 0,)


async def test_a_new_real_encrypted_oauth_generation_cannot_adopt_an_old_input_task(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    host = await start(b)
    first = await b.client.post('/api/owned-credential-call')
    assert first.status_code == 200, first.text
    original, = await host.store.list_retained()
    previous = b.credential.snapshot
    revoked = await b.store.revoke_local(previous)
    snapshot = await install_grant(b.store, previous.binding, OAuthGrantTokens(
        'native-fixture-access', 'native-fixture-refresh', time.time() + 3600, frozenset({'read'})),
        expected=revoked)
    b.credential.snapshot = replace(snapshot, tokens=None)
    assert b.credential.authorization_identity != original.binding.authorization_id
    pending = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
    row, = pending.json()['inputs']
    refused = await b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
        params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
            'operation_id': 'owned-different-authorization-response',
            'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}})
    assert refused.status_code == 200, refused.text
    assert refused.json()['state'] == 'WAITING' and refused.json()['tool_result']['success'] is False
    actual, = await host.store.list_retained()
    assert actual.phase == 'INPUT_WAITING' and actual.revision == original.revision
    assert actual.binding.authorization_id == original.binding.authorization_id and not peer.calls
    assert await host.store.database.fetchone('SELECT state FROM mcp_inputs') == ('WAITING',)


async def test_owned_local_maintenance_expires_both_original_waits_without_task_wire_or_a_principal(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    host = await start(b)
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200, response.text
    task, = await host.store.list_retained()
    assert task.phase == 'INPUT_WAITING'
    clock = b.feature._input_host.authority.clock()
    b.feature._input_host.authority.clock = lambda: clock + timedelta(days=1)
    async with asyncio.timeout(5):
        while True:
            actual, = await host.store.list_retained()
            if actual.phase == 'INPUT_CLOSED':
                break
            await asyncio.sleep(.01)
    assert not b.feature._task_maintenance.done()
    assert peer.calls == [] and actual.remote_task_id is None
    assert not b.agent._explored_features['mcp:credential'].task_holds
    assert await host.store.database.fetchone('SELECT state FROM mcp_inputs') == ('NON_RESUMABLE',)


async def test_reopened_hosts_resume_original_sql_custody_on_a_fresh_binding_and_once_approval(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    old_host = await start(b)
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200, response.text
    original, = await old_host.store.list_retained()
    old_binding = b.feature._task_runtime._registrations['mcp:credential'][0].binding
    b.feature._unmount_tools('mcp:credential')
    await b.connection.close()
    await b.feature._close_inputs()
    assert old_host.retired and not old_binding.is_current
    await b.feature._start_inputs()
    await b.feature._start_tasks({})
    host = b.feature._task_host
    assert not host._owners, 'Reopening custody eagerly minted execution retention'
    async with AsyncExitStack() as cleanup:
        @b.app.post('/api/owned-task-restore-connection')
        async def restore(request: Request):
            service = b.app.state.request_authentication
            with service.bind(request) as authentication, caller_context_scope(authentication.caller):
                await b.credential.admit()
                endpoint = await assert_safe_url(b.peer.selection.server_url, allowed_schemes=('https',))
                connection = b.feature._new_mcp_connection(endpoint, auth=b.credential.bearer_auth(),
                    connect_timeout=2, call_timeout=2, close_timeout=2)
                cleanup.push_async_callback(connection.close)
                tools = await connection.connect()
                caller = bind_tool_caller(connection, lambda: connection.is_connected, 'original-connection',
                    tool_names=[tool.name for tool in tools], admit=b.credential.admit,
                    continuation_check=b.credential.lease.require_principal,
                    authorization_identity=lambda: b.credential.authorization_identity)
                b.feature._mount_tools('mcp:credential', 'owned_credential',
                    [tool.model_dump(mode='json', by_alias=True) for tool in tools], caller)
                return {'restored': True}
        restored = await b.client.post('/api/owned-task-restore-connection')
        assert restored.status_code == 200, restored.text
        await b.permissions.set_permission('mcp:credential', b.handle, PermissionLevel.ASK)
        pending = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
        assert pending.status_code == 200, pending.text
        row, = pending.json()['inputs']
        operation = asyncio.create_task(b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
            params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
                'operation_id': 'owned-fresh-binding-response',
                'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}}))
        try:
            approval = await asyncio.wait_for(b.approval_requests.get(), 5)
            assert not operation.done() and peer.calls == []
            assert await b.approvals.submit_decision(approval.id, True, scope='once')
            result = await asyncio.wait_for(operation, 5)
            assert result.status_code == 200 and result.json()['state'] == 'RESOLVED', result.text
            assert not await b.approvals.submit_decision(approval.id, True, scope='once')
        finally:
            b.approvals.cancel_all()
            await asyncio.gather(operation, return_exceptions=True)
        actual, = await host.store.list_retained()
        assert actual.handle == original.handle and actual.phase == 'ATTACHED'
        assert (await host.store.open_submission(actual)).canonical_json == (
            await host.store.open_submission(original)).canonical_json
        assert len(actual.continuity['operations']) == 1 and peer.calls == ['started']


async def test_a_missing_required_discriminator_remains_an_uncertain_native_outcome(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.return_ordinary = peer.omit_complete_discriminator = True
    host = await start(b)
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 502, response.text
    assert 'resultType' not in peer.last_complete_body
    actual, = await host.store.list_retained()
    assert actual.phase == 'ISSUING' and actual.envelope is None
    assert b.peer.resource.witness == ['owned-effect']


async def test_zero_continuations_cannot_offer_an_unresumable_operator_wait(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    host = await start(b, task_host={'max_continuations': 0})
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 502, response.text
    row, = await host.store.list_retained()
    assert row.phase == 'SETTLED' and row.envelope['native']['resultType'] == 'input_required'
    assert await host.store.database.fetchone('SELECT COUNT(*) FROM mcp_inputs') == (0,)


async def test_the_last_allowed_response_cannot_publish_another_unresumable_wait(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input, peer.input_rounds = True, 2
    host = await start(b, task_host={'max_continuations': 1})
    assert (await b.client.post('/api/owned-credential-call')).status_code == 200
    pending = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
    row, = pending.json()['inputs']
    response = await b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
        params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
            'operation_id': 'owned-last-allowed-response',
            'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}})
    assert response.status_code == 503, response.text
    actual, = await host.store.list_retained()
    assert actual.phase == 'SETTLED' and len(actual.continuity['operations']) == 1
    assert actual.envelope['native']['resultType'] == 'input_required'
    assert await host.store.database.fetchone('SELECT COUNT(*) FROM mcp_inputs') == (1,)
    assert not peer.calls


async def test_oversize_native_input_claim_is_explicitly_unknown_instead_of_a_known_tool_error(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    mcp_http_server.settings['extensions'][0].require_input = True
    host = await start(b, task_host={'max_native_claim_bytes': 64})
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 502, response.text
    row, = await host.store.list_retained()
    assert row.phase == 'ISSUING' and row.envelope is None
    assert await host.store.database.fetchone('SELECT COUNT(*) FROM mcp_inputs') == (0,)


@pytest.mark.parametrize('retire_registration', [False, True])
async def test_actual_admission_failure_before_the_sdk_request_retires_its_unsent_issuer(
        credential_boundary, mcp_http_server, monkeypatch, retire_registration):
    b = credential_boundary
    host = await start(b)
    wrapper = b.agent._direct_tools[b.handle]
    caller = wrapper.bound_caller
    admissions = []
    async def fail_second_admission():
        await caller.admit()
        admissions.append(True)
        if len(admissions) == 2:
            if retire_registration:
                b.feature._unmount_tools('mcp:credential')
            descriptor = os.open(os.devnull, os.O_WRONLY)
            try:
                os.read(descriptor, 1)
            finally:
                os.close(descriptor)
    monkeypatch.setattr(wrapper, '_caller', replace(caller, _admit=fail_second_admission))
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200, response.text
    actual, = await host.store.list_retained()
    assert actual.phase == 'NOT_SENT', 'A proven failure before native request entry stranded its issuer'
    assert len(admissions) == 2 and not mcp_http_server.settings['extensions'][0].calls


async def test_two_native_input_rounds_keep_one_original_task_and_submission(
        credential_boundary, mcp_http_server):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input, peer.input_rounds = True, 2
    host = await start(b, task_host={'max_continuations': 2})
    assert (await b.client.post('/api/owned-credential-call')).status_code == 200
    original, = await host.store.list_retained()
    sealed = (await host.store.open_submission(original)).canonical_json
    for index in range(2):
        listed = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
        row, = listed.json()['inputs']
        response = await b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
            params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
                'operation_id': 'owned-successive-response-' + str(index),
                'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}})
        assert response.status_code == 200 and response.json()['state'] == 'RESOLVED', response.text
        actual, = await host.store.list_retained()
        assert actual.handle == original.handle and len(actual.continuity['operations']) == index + 1
        assert actual.phase == ('INPUT_WAITING' if index == 0 else 'ATTACHED')
        assert (await host.store.open_submission(actual)).canonical_json == sealed
    assert peer.calls == ['started']
