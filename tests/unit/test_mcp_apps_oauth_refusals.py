"""Actual Core lease, encrypted grant revocation and native App dispatch."""

from uuid import uuid4

from fastapi import Request
import pytest
from starlette.responses import JSONResponse

from kestrel_sdk.resources import ResourceConflict, ResourceOutcomeUnknown
from kestrel_sovereign.api_errors import tool_effect_api_error
from kestrel_sovereign.auth import caller_context_scope
from kestrel_sovereign.features.security.permissions import PermissionLevel
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_feature_mcp.oauth_grants import OAuthGrantStore
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary


pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize('mcp_http_server', [{
    'tls': True, 'oauth': {}, 'apps_tools': True, 'apps_execution_tools': True,
    'app_mutate_visibility': ['model', 'app'],
}], indirect=True), pytest.mark.parametrize('oauth_peers', [{
    'web_identity': True, 'refresh': True,
}], indirect=True)]


async def test_revoked_original_grant_is_a_known_app_refusal_before_rpc(credential_boundary):
    b = credential_boundary
    await b.feature.set_config({'apps': {'enabled': True, 'host': {
        'sandbox_url': 'https://sandbox.composition.test/',
        'host_origin': 'https://console.example',
    }}})
    connected = await b.client.post('/api/owned-credential-connect')
    assert connected.status_code == 200, connected.text
    publications = b.feature._apps_publications
    batch = publications._batches['mcp:credential']
    source = next(item for item in batch.tools if item.tool.native_tool.name == 'app_mutate')
    await b.permissions.set_permission('mcp:credential', source.binding.name, PermissionLevel.ALLOW)
    view = publications.executor.open_view(source, list(batch.tools), session_id='owned-grant-app',
        owner_is_current=batch.is_live)
    try:
        @b.app.post('/api/owned-app-credential-call')
        async def invoke(request: Request):
            with b.app.state.request_authentication.bind(request) as authentication, caller_context_scope(authentication.caller):
                try:
                    result = await publications.executor.invoke(view, 'app_mutate',
                        {'text': 'must-not-execute'}, operation_id=uuid4().hex)
                    return result.model_dump(mode='json', by_alias=True)
                except ResourceConflict:
                    return JSONResponse({'error': 'original_revision_changed'}, status_code=409)
                except ResourceOutcomeUnknown as error:
                    raise tool_effect_api_error(error)

        other = SQLiteBackend(str(b.path))
        await other.connect()
        try:
            store = OAuthGrantStore(other, b.agent.did, max_token_bytes=4096)
            await store.revoke_local(await store.read(b.credential.snapshot.binding))
        finally:
            await other.close()
        before = list(b.peer.resource.requests)
        result = await b.client.post('/api/owned-app-credential-call')
        assert result.status_code == 409, result.text
        assert result.json() == {'error': 'original_revision_changed'}
        assert b.peer.resource.requests == before and b.peer.resource.witness == []
        assert await b.agent.tool_effect_store.database.fetchone(
            'SELECT state FROM tool_effect_claims') == ('RETURNED_ERROR',)
        assert await b.agent.tool_effect_store.database.fetchone(
            'SELECT state FROM tool_effect_operations') == ('CLOSED',)
    finally:
        await view.close()
