"""Native Task result delivery uses the original audited conversation."""

import pytest

from kestrel_sdk.hooks.base import Hook, HookEvent, HookOutput
from kestrel_sovereign.endpoints.auth_oauth import _create_jwt
from tests.unit.test_task_observation import (
    credential_boundary as credential_boundary, oauth_peers as oauth_peers,
    oauth_runtime as oauth_runtime, pytestmark, start_task,
)


@pytest.mark.parametrize('withheld', [False, True])
async def test_original_chat_reads_only_its_authorized_native_task_result(oauth_runtime, withheld):
    b = oauth_runtime
    schema = {'type': 'object', 'properties': {'result': {'type': 'integer'}}, 'required': ['result']}
    _, original = await start_task(b, schema=schema if withheld else None)
    part, = b.task_parts
    assert part['data']['handle'] == original.handle
    peer = b.peer.resource.settings['extensions'][0]
    peer.status = 'completed'
    observed = await b.feature._task_runtime.observe(original.handle)
    assert observed.phase == 'SETTLED'
    url = '/api/mcp/task-results/' + original.handle
    headers = {'X-Kestrel-Task-Result': part['data']['reference']}
    response = await b.client.get(url, params={'session_id': 'credential-chat'}, headers=headers)
    assert response.status_code == 200, response.text
    if withheld:
        assert response.json() == {'status': 'completed', 'result_withheld': True}
    else:
        assert response.json() == {'status': 'completed', 'result': observed.observation['result']}
    for session_id, authority in [
        ('another-chat', headers),
        ('credential-chat', {}),
        ('credential-chat', {'X-Kestrel-Task-Result': '0' * 64}),
        ('credential-chat', headers | {'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)}),
    ]:
        response = await b.client.get(url, params={'session_id': session_id}, headers=authority)
        assert response.status_code == 403
        assert 'actual deferred result' not in response.text


async def test_post_tool_policy_withholds_the_task_reference(oauth_runtime):
    class DenyPrivateResult(Hook):
        def __init__(self):
            super().__init__('deny-deferred-task-publication', [HookEvent.POST_TOOL_USE])

        async def execute(self, value):
            assert value.tool_response['status'] == 'partial'
            return HookOutput.deny('Original native Tool publication denied')

    b = oauth_runtime
    b.agent.hooks_manager.register(DenyPrivateResult())
    _, original = await start_task(b)
    assert b.task_parts == []
    peer = b.peer.resource.settings['extensions'][0]
    peer.status = 'completed'
    settled = await b.feature._task_runtime.observe(original.handle)
    assert settled.phase == 'SETTLED'
    result = await b.client.get(f'/api/mcp/task-results/{original.handle}',
        params={'session_id': 'credential-chat'})
    assert result.status_code == 403
    assert 'actual deferred result' not in result.text
