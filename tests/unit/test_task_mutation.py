"""Actual governed native Task updates and cancellations over OAuth and TLS."""

import asyncio
import json
from uuid import uuid4

import pytest

from tests.unit.test_task_observation import (
    credential_boundary as credential_boundary, oauth_peers as oauth_peers,
    oauth_runtime as oauth_runtime, pytestmark, start_task,
)


@pytest.mark.parametrize('kind', ['update', 'cancel'])
async def test_governed_task_mutation_retains_one_native_acknowledgement(oauth_runtime, kind):
    b = oauth_runtime
    _, original = await start_task(b)
    part, = b.task_parts
    peer = b.peer.resource.settings['extensions'][0]
    runtime = b.feature._task_runtime
    if kind == 'update':
        peer.status = 'input_required'
        observed = await runtime.observe(original.handle)
        assert observed.pending_inputs.keys() == {'form'}
    arguments = ({'inputResponses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}}
        if kind == 'update' else {})
    body = {'operation_id': uuid4().hex}
    if kind == 'update':
        body['input_responses'] = arguments['inputResponses']
    url = f'/api/mcp/task-results/{original.handle}/' + ('responses' if kind == 'update' else 'cancel')
    query = {'session_id': 'credential-chat'}
    wrong = await b.client.post(url, params=query, json=body,
        headers={'X-Kestrel-Task-Result': '0' * 64})
    assert wrong.status_code == 403
    assert not (await runtime.host.store.read_handle(original.handle)).control['mutations']
    returned = await b.client.post(url, params=query, json=body,
        headers={'X-Kestrel-Task-Result': part['data']['reference']})
    assert returned.status_code == 200 and returned.json().get('status') == 'ok', returned.text
    retained = await runtime.host.store.read_handle(original.handle)
    receipt, = retained.control['mutations'].values()
    assert receipt['claim_hash'] is None
    assert receipt['acknowledgement'] == {'resultType': 'complete',
        '_meta': {'io.modelcontextprotocol/serverInfo': {'name': 'native-connection-test', 'version': ''}}}
    assert retained.phase == 'ATTACHED'
    assert receipt['intent'] == {'method': 'tasks/' + kind, 'params': {'taskId': peer.task_id, **arguments}}
    (scope, message), = [(scope, json.loads(body)) for scope, body in b.peer.resource.requests
        if body and json.loads(body).get('method') == 'tasks/' + kind]
    assert dict(scope['headers'])[b'mcp-name'].decode() == peer.task_id
    assert {key: value for key, value in message['params'].items() if key != '_meta'} == receipt['intent']['params']
    assert peer.calls == (['started', 'get', 'update'] if kind == 'update' else ['started', 'cancel'])
    if kind == 'cancel':
        before = list(b.peer.resource.requests), list(b.peer.requests)
        for operation_id in [body['operation_id'], uuid4().hex]:
            duplicate = await b.client.post(url, params=query, json={'operation_id': operation_id},
                headers={'X-Kestrel-Task-Result': part['data']['reference']})
            assert duplicate.status_code == 404
        assert (b.peer.resource.requests, b.peer.requests) == before
        assert (await runtime.host.store.read_handle(original.handle)).control == retained.control
    assert not runtime.has_observation_owners


@pytest.mark.parametrize('kind', ['update', 'cancel'])
async def test_post_reply_grant_conflict_retains_unconfirmed_mutation_without_replay(oauth_runtime, kind):
    b = oauth_runtime
    name, original = await start_task(b)
    part, = b.task_parts
    peer = b.peer.resource.settings['extensions'][0]
    runtime = b.feature._task_runtime
    body = {'operation_id': uuid4().hex}
    if kind == 'update':
        peer.status = 'input_required'
        observed = await runtime.observe(original.handle)
        assert observed.pending_inputs.keys() == {'form'}
        body['input_responses'] = {'form': {'action': 'accept', 'content': {'label': 'native input'}}}
    route = 'responses' if kind == 'update' else 'cancel'
    url = f'/api/mcp/task-results/{original.handle}/{route}'
    query = {'session_id': 'credential-chat'}
    headers = {'X-Kestrel-Task-Result': part['data']['reference']}
    active = await b.store.read_tokens(b.runtime._credentials[name].snapshot)
    claim = None

    async def begin_refresh_before_reply(result):
        nonlocal claim
        claim = await b.store.begin_refresh(active)
        return result

    journal = 'SELECT claim_id, state FROM tool_effect_claims'
    before = {tuple(row) for row in await b.host.database.fetch_all(journal)}
    peer.before_response = begin_refresh_before_reply
    try:
        response = await b.client.post(url, params=query, headers=headers, json=body)
        assert claim is not None and peer.calls[-1] == kind
        assert response.status_code == 503, response.text
        assert response.json() == {'error': {'code': 'mcp_task_mutation_outcome_unknown'}}
        after = {tuple(row) for row in await b.host.database.fetch_all(journal)}
        assert before <= after
        (_, state), = after - before
        assert state == 'UNCONFIRMED'
    finally:
        peer.before_response = None
        if claim is not None:
            await b.store.abandon_refresh(claim)

    retained = await runtime.host.store.read_handle(original.handle)
    receipt, = retained.control['mutations'].values()
    assert retained.phase == 'ATTACHED' and not retained.pending_inputs
    assert retained.cancel_requested == (kind == 'cancel')
    assert receipt['intent']['method'] == f'tasks/{kind}'
    assert receipt['acknowledgement'] is None and receipt['claim_hash'] is not None

    requests = list(b.peer.resource.requests), list(b.peer.requests)
    for operation_id in [body['operation_id'], uuid4().hex]:
        retry = await b.client.post(url, params=query, headers=headers,
            json=body | {'operation_id': operation_id})
        assert retry.status_code >= 400 or retry.json().get('success') is False, retry.text
    assert (b.peer.resource.requests, b.peer.requests) == requests
    assert (await runtime.host.store.read_handle(original.handle)).control == retained.control
    assert not runtime.has_observation_owners


async def test_lost_native_cancel_acknowledgement_preserves_custody_without_replay(oauth_runtime):
    b = oauth_runtime
    _, original = await start_task(b)
    part, = b.task_parts
    peer = b.peer.resource.settings['extensions'][0]
    release_acknowledgement = asyncio.Event()

    async def hold_native_response(result):
        await release_acknowledgement.wait()
        return result

    peer.before_response = hold_native_response
    runtime = b.feature._task_runtime
    url = f'/api/mcp/task-results/{original.handle}/cancel'
    query = {'session_id': 'credential-chat'}
    headers = {'X-Kestrel-Task-Result': part['data']['reference']}
    operation_id = uuid4().hex
    try:
        timed_out = await b.client.post(url, params=query, headers=headers,
            json={'operation_id': operation_id})
        assert timed_out.status_code == 503, timed_out.text
        assert peer.calls == ['started', 'cancel']
        retained = await runtime.host.store.read_handle(original.handle)
        assert retained.phase == 'ATTACHED' and retained.cancel_requested
        receipt, = retained.control['mutations'].values()
        assert receipt['acknowledgement'] is None and receipt['claim_hash'] is not None

        requests = list(b.peer.resource.requests), list(b.peer.requests)
        for retry in [operation_id, uuid4().hex]:
            response = await b.client.post(url, params=query, headers=headers, json={'operation_id': retry})
            assert response.status_code == 404
        assert (b.peer.resource.requests, b.peer.requests) == requests
        assert (await runtime.host.store.read_handle(original.handle)).control == retained.control
    finally:
        release_acknowledgement.set()
        peer.before_response = None

    peer.status = 'cancelled'
    observed = await runtime.observe(original.handle)
    assert observed.phase == 'SETTLED' and observed.observation['status'] == 'cancelled'
    assert peer.calls == ['started', 'cancel', 'get']
    assert not runtime.has_observation_owners
