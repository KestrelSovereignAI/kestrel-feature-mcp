"""Native OAuth Task delivery through the App's original authenticated View."""

from uuid import uuid4

import pytest

from kestrel_feature_mcp.remote import remote_owner
from kestrel_sovereign.features.security.permissions import PermissionLevel
from tests.unit.test_oauth_runtime_http import authorize, connect
from tests.unit.test_task_observation import (
    credential_boundary as credential_boundary, oauth_peers as oauth_peers, oauth_runtime as oauth_runtime,
)
from tests.unit.test_tasks_native_peer import NativeTasksPeer


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.timeout(30),
    pytest.mark.parametrize('mcp_http_server', [{
        'tls': True, 'oauth': {}, 'extensions': [NativeTasksPeer()], 'apps_tools': True,
        'apps_execution_tools': True, 'app_mutate_visibility': ['model', 'app'],
    }], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True}], indirect=True),
]


async def test_actual_app_task_completes_through_its_original_view(oauth_runtime, apps_sandbox_url):
    b = oauth_runtime
    b.agent._mcp_oauth_host_policy = b.app.state.mcp_oauth_policy
    await b.feature.set_config({
        'oauth': {'enabled': True, 'close_seconds': 2.0},
        'inputs': {'enabled': True},
        'apps': {'enabled': True, 'host': {'sandbox_url': apps_sandbox_url,
                                           'host_origin': 'https://console.example'}},
    })
    await b.feature._start_tasks({'maintenance_seconds': 60.0})
    name = await authorize(b)
    await connect(b, name)
    owner = remote_owner(name)
    b.handle = next(handle for handle, feature in b.agent._tool_to_feature.items()
                    if feature == owner and handle.endswith('__app_mutate'))
    await b.permissions.set_permission(owner, b.handle, PermissionLevel.ALLOW)

    initial = await b.client.post('/api/owned-credential-call')
    assert initial.status_code == 200, initial.text
    publication, = [part['data']['reference'] for part in initial.json()['parts'] if part['type'] == 'mcp_app']
    query = {'session_id': 'credential-chat'}
    views_url = f'/api/mcp/apps/publications/{publication}/views'
    first = await b.client.post(views_url, params=query, json={})
    second = await b.client.post(views_url, params=query, json={})
    assert first.status_code == second.status_code == 200, (first.text, second.text)
    original, replacement = first.json()['view_id'], second.json()['view_id']
    peer = b.peer.resource.settings['extensions'][0]
    peer.tool_name = 'app_mutate'
    tool = await b.client.post(f'/api/mcp/apps/views/{original}/tools/call', params=query, json={
        'name': 'app_mutate', 'operation_id': uuid4().hex, 'arguments': {'text': 'deferred View work'},
    })
    assert tool.status_code == 202, tool.text
    task = tool.json()['task']
    assert peer.calls == ['started']
    assert peer.tool_requests[0]['arguments'] == {'text': 'deferred View work'}

    runtime = b.feature._task_runtime
    record = await runtime.host.store.read_handle(task['handle'])
    delivery = (await runtime.host.store.open_submission(record)).delivery
    assert (delivery.kind, delivery.session_id, delivery.view_token) == ('app', 'credential-chat', original)
    peer.status = 'input_required'
    awaiting_input = await runtime.observe(record.handle)
    assert awaiting_input.pending_inputs.keys() == {'form'}
    headers = {'X-Kestrel-Task-Result': task['reference']}
    url = f'/api/mcp/apps/views/{original}/tasks/{record.handle}'
    other_url = f'/api/mcp/apps/views/{replacement}/tasks/{record.handle}'
    submitted = {
        'operation_id': uuid4().hex,
        'input_responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}},
    }
    foreign = await b.client.post(other_url + '/responses', params=query, headers=headers, json=submitted)
    assert foreign.status_code == 403
    assert peer.calls == ['started', 'get']
    accepted = await b.client.post(url + '/responses', params=query, headers=headers, json=submitted)
    assert accepted.status_code == 200 and accepted.json()['status'] == 'ok', accepted.text
    settled = await runtime.observe(record.handle)
    assert settled.phase == 'SETTLED'
    assert peer.calls == ['started', 'get', 'update', 'get']

    result = await b.client.get(url, params=query, headers=headers)
    assert result.status_code == 200, result.text
    assert result.json() == {'status': 'completed', 'result': settled.observation['result']}
    assert result.json()['result']['content'] == [{'type': 'text', 'text': 'actual deferred result'}]
    foreign = await b.client.get(other_url, params=query, headers=headers)
    assert foreign.status_code == 403
    chat = await b.client.get(f'/api/mcp/task-results/{record.handle}', params=query, headers=headers)
    assert chat.status_code == 403
