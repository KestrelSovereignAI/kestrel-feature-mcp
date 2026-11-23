"""Production role policy tests; no vendor or host-authority claims."""

from dataclasses import replace
from urllib.parse import urlencode

import httpx2
import pytest
from mcp_types.version import LATEST_MODERN_VERSION

from kestrel_feature_mcp.oauth_policy import (
    BootstrapPolicy, ClientIdentity, DISCOVERY_PROBE_BODY, DISCOVERY_PROBE_METHOD, GrantRejected,
    RefreshPolicy, resource_envelope, resource_lane,
)
from tests.unit.test_oauth_acceptance_policy import selection, discover, authorization


def bootstrap(selected, hook):
    return BootstrapPolicy(selected.server_url,
        ClientIdentity(selected.client_id, 'https://client.example/oauth/callback'),
        selected.scopes, on_exchange=hook)


def discovery_probe(server_url):
    return httpx2.Request('POST', server_url, content=DISCOVERY_PROBE_BODY,
                          headers={'MCP-Method': DISCOVERY_PROBE_METHOD,
                                   'MCP-Protocol-Version': LATEST_MODERN_VERSION})


async def acquire_metadata(policy, selected):
    request = discovery_probe(selected.server_url)
    await policy.request(request)
    await policy.response(httpx2.Response(401, request=request, headers={
        'WWW-Authenticate': f'Bearer resource_metadata="{selected.protected_metadata}", scope="read"'}))
    # Supply the same independent metadata fixture through production role hooks.
    class Discovery:
        selection = selected
        request = policy.request
        response = policy.response
    await discover(Discovery())


async def test_native_discovery_selects_exact_prm_issuer_and_metadata_before_consent(selection):
    async def hook():
        raise AssertionError('no exchange during discovery')
    policy = bootstrap(selection, hook)
    with pytest.raises(GrantRejected, match='not complete'):
        policy.redirect('https://issuer.example/authorize')
    assert policy.approved_origins == {'https://resource.example'}
    await acquire_metadata(policy, selection)
    assert policy.approved_origins == {'https://resource.example', 'https://issuer.example'}
    assert policy.selection == replace(selection, redirect_uri=policy.identity.redirect_uri)
    assert policy.redirect(authorization(policy._verified)) == 'a-native-opaque-attempt-state'


@pytest.mark.parametrize('method', ['GET', 'POST', 'DELETE', 'PUT'])
async def test_acquisition_never_dispatches_an_mcp_operation(selection, method):
    async def hook():
        raise AssertionError('no token request')
    policy = bootstrap(selection, hook)
    with pytest.raises(GrantRejected, match='MCP discovery probe'):
        await policy.request(httpx2.Request(method, selection.server_url,
            headers={'MCP-Method': DISCOVERY_PROBE_METHOD,
                     'MCP-Protocol-Version': LATEST_MODERN_VERSION},
            json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call'}))


@pytest.mark.parametrize('endpoint_query,reported_query', [
    ('?login', ''), ('?login', '?other=true'), ('', '?other=true'),
])
def test_query_scoped_resource_cannot_change_its_binding(selection, endpoint_query, reported_query):
    with pytest.raises(GrantRejected, match='exact resource identifier'):
        replace(selection, server_url=selection.server_url + endpoint_query,
                resource=selection.resource + reported_query)


@pytest.mark.parametrize('field', ['server_url', 'resource', 'protected_metadata'])
def test_query_cannot_embed_oauth_credentials(selection, field):
    with pytest.raises(GrantRejected, match='credential query parameters'):
        replace(selection, **{field: getattr(selection, field) + '?access%5Ftoken=test'})


@pytest.mark.parametrize('field', ['server_url', 'protected_metadata'])
def test_query_scoped_urls_must_use_the_exact_http_wire_spelling(selection, field):
    with pytest.raises(GrantRejected, match='HTTP-canonical'):
        replace(selection, **{field: getattr(selection, field) + '?query=a b'})


@pytest.mark.parametrize('header,value', [
    ('MCP-Method', 'tools/call'), ('MCP-Protocol-Version', '2025-11-25'),
])
async def test_discovery_probe_rejects_wrong_routing_headers(selection, header, value):
    async def hook():
        raise AssertionError('no exchange during discovery')
    policy = bootstrap(selection, hook)
    request = discovery_probe(selection.server_url)
    request.headers[header] = value
    with pytest.raises(GrantRejected, match='original MCP discovery probe'):
        await policy.request(request)


async def test_discovery_allows_only_one_probe_in_each_phase(selection):
    async def hook():
        raise AssertionError('no exchange during discovery')
    policy = bootstrap(selection, hook)
    request = discovery_probe(selection.server_url)
    await policy.request(request)
    with pytest.raises(GrantRejected, match='unauthenticated probe'):
        await policy.request(request)
    policy.grant_ready = True
    with pytest.raises(GrantRejected, match='original MCP discovery probe'):
        await policy.request(request)
    request.headers['Authorization'] = 'Bearer fixture'
    await policy.request(request)
    with pytest.raises(GrantRejected, match='completed probe'):
        await policy.request(request)


@pytest.mark.parametrize('kind', ['refresh_token', 'client_credentials'])
async def test_interactive_provider_cannot_refresh_or_switch_token_roles(selection, kind):
    calls = []
    async def hook():
        calls.append('intent')
    policy = bootstrap(selection, hook)
    await acquire_metadata(policy, selection)
    policy.redirect(authorization(policy._verified))
    with pytest.raises(GrantRejected):
        await policy.request(httpx2.Request('POST', policy._verified.token_endpoint, data={
            'grant_type': kind, 'refresh_token': 'synthetic', 'resource': selection.resource,
            'client_id': selection.client_id}))
    assert calls == [] and not policy.exchange_started


async def test_durable_exchange_hook_precedes_dispatch_and_cannot_be_replayed(selection):
    calls = []
    async def hook():
        calls.append('intent')
        raise TimeoutError('commit acknowledgment lost')
    policy = bootstrap(selection, hook)
    await acquire_metadata(policy, selection)
    policy.redirect(authorization(policy._verified))
    request = httpx2.Request('POST', policy._verified.token_endpoint, data={
        'grant_type': 'authorization_code', 'client_id': selection.client_id,
        'redirect_uri': policy.identity.redirect_uri, 'resource': selection.resource,
        'code': 'synthetic', 'code_verifier': 'synthetic-verifier'})
    with pytest.raises(TimeoutError):
        await policy.request(request)
    with pytest.raises(GrantRejected, match='unused consent'):
        await policy.request(request)
    assert calls == ['intent'] and policy.exchange_started


async def test_off_origin_challenge_does_not_approve_dns_or_transport(selection):
    async def hook():
        raise AssertionError('no exchange')
    policy = bootstrap(selection, hook)
    request = discovery_probe(selection.server_url)
    await policy.request(request)
    with pytest.raises(GrantRejected, match='resource origin'):
        await policy.response(httpx2.Response(401, request=request, headers={
            'WWW-Authenticate': 'Bearer resource_metadata="https://other.example/metadata"'}))
    assert policy.approved_origins == {'https://resource.example'}


async def test_standard_discovery_not_found_allows_only_sdk_candidates(selection):
    async def hook():
        raise AssertionError('no exchange')
    policy = bootstrap(selection, hook)
    request = discovery_probe(selection.server_url)
    await policy.request(request)
    await policy.response(httpx2.Response(401, request=request))
    request = httpx2.Request('GET', selection.protected_metadata)
    await policy.request(request)
    await policy.response(httpx2.Response(404, request=request))
    with pytest.raises(GrantRejected, match='unexpected'):
        await policy.request(httpx2.Request('GET', 'https://resource.example/register'))
    with pytest.raises(GrantRejected, match='discovery did not'):
        await policy.response(httpx2.Response(503, request=request))


@pytest.mark.parametrize('envelope,lane', [
    ({'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call', 'params': {'name': 'write'}}, 'principal'),
    ({'jsonrpc': '2.0', 'id': 8, 'method': 'resources/read', 'params': {'uri': 'x'}}, 'principal'),
    ({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, 'background'),
    ({'jsonrpc': '2.0', 'id': 9, 'result': {}}, 'background'),
    ({'jsonrpc': '2.0', 'id': 9, 'error': {'code': -1, 'message': 'synthetic'}}, 'background'),
])
async def test_actual_native_envelope_shape_determines_authority_lane(selection, envelope, lane):
    request = httpx2.Request('POST', selection.server_url, json=envelope)
    original = request.content
    assert await resource_lane(request, selection.server_url) == lane
    parsed = await resource_envelope(request, selection.server_url)
    assert parsed.model_dump(mode='json', by_alias=True, exclude_unset=True) == envelope
    assert request.content == original


@pytest.mark.parametrize('envelope', [
    {'jsonrpc': '2.0', 'id': 9, 'result': {}, 'method': 'tools/call'},
    {'jsonrpc': '2.0', 'id': 9, 'result': {}, 'unapproved': True},
    [{'jsonrpc': '2.0', 'id': 9, 'method': 'tools/call'}],
])
async def test_malformed_or_ambiguous_envelope_cannot_use_background_lane(selection, envelope):
    with pytest.raises(GrantRejected):
        await resource_lane(httpx2.Request('POST', selection.server_url, json=envelope), selection.server_url)


@pytest.mark.parametrize('content', [
    b'{"jsonrpc":"2.0","id":7,"id":8,"method":"tasks/get","params":{"taskId":"owned"}}',
    b'{"jsonrpc":"2.0","id":7,"method":"tasks/get","params":{"taskId":"owned","taskId":"owned"}}',
])
async def test_resource_policy_refuses_duplicate_fields_in_native_envelopes(selection, content):
    request = httpx2.Request('POST', selection.server_url, content=content)
    with pytest.raises(GrantRejected, match='unique JSON object fields'):
        await resource_envelope(request, selection.server_url)
    assert request.content == content


async def test_refresh_is_separate_from_interactive_consent_and_runs_once(selection):
    calls = []
    async def hook():
        calls.append('intent')
    policy = RefreshPolicy(selection, on_exchange=hook)
    request = httpx2.Request('POST', selection.issuer + '/token', data={
        'grant_type': 'refresh_token', 'refresh_token': 'synthetic',
        'resource': selection.resource, 'client_id': selection.client_id, 'scope': 'read'})
    with pytest.raises(GrantRejected):
        await policy.request(request)
    await discover(policy)
    await policy.request(request)
    assert calls == ['intent'] and policy.exchange_started
    with pytest.raises(GrantRejected):
        await policy.request(request)


async def test_native_offline_access_prompt_is_accepted_only_with_offline_scope(selection):
    async def hook():
        raise AssertionError('no exchange')
    selected = replace(selection, scopes=frozenset({'read', 'offline_access'}))
    policy = bootstrap(selected, hook)
    await acquire_metadata(policy, selected)
    url = authorization(policy._verified, {'scope': 'read offline_access', 'prompt': 'consent'})
    assert policy.redirect(url) == 'a-native-opaque-attempt-state'
    assert policy.requested_scopes == selected.scopes


async def test_operation_cannot_hide_as_an_untyped_background_notification(selection):
    with pytest.raises(GrantRejected):
        await resource_lane(httpx2.Request('POST', selection.server_url,
            json={'jsonrpc': '2.0', 'method': 'tools/call', 'params': {'name': 'write'}}),
            selection.server_url)
