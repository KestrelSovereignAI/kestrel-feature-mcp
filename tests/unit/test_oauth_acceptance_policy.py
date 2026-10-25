"""Policy-only checks; these do not claim a vendor grant or wire acceptance."""

from dataclasses import replace
from urllib.parse import urlencode

import httpx2
import pytest
from mcp.shared.auth import OAuthToken

from tests.oauth_acceptance.policy import GrantPolicy, GrantRejected, GrantSelection, MemoryGrant


@pytest.mark.parametrize("scope", ['read"write', r"read\write"])
def test_selected_scope_uses_rfc6749_scope_tokens(selection, scope):
    with pytest.raises(GrantRejected, match="OAuth scopes"):
        replace(selection, scopes=frozenset({scope}))


@pytest.fixture
def selection():
    return GrantSelection(
        server_url="https://resource.example/mcp",
        resource="https://resource.example/mcp", issuer="https://issuer.example",
        protected_metadata="https://resource.example/.well-known/oauth-protected-resource/mcp",
        authorization_metadata="https://issuer.example/.well-known/oauth-authorization-server",
        client_id="https://client.example/kestrel.json",
        redirect_uri="http://127.0.0.1:44721/oauth/callback", scopes=frozenset({"read"}),
    )


async def discover(policy, *, metadata_changes=None, resource_changes=None):
    selected = policy.selection
    resource = {"resource": selected.resource, "authorization_servers": [selected.issuer],
                "scopes_supported": ["read", "write"], **(resource_changes or {})}
    metadata = {
        "issuer": selected.issuer, "authorization_endpoint": selected.issuer + "/authorize",
        "token_endpoint": selected.issuer + "/token", "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": True,
        **(metadata_changes or {}),
    }
    for url, document in [(selected.protected_metadata, resource),
                          (selected.authorization_metadata, metadata)]:
        request = httpx2.Request("GET", url)
        await policy.request(request)
        await policy.response(httpx2.Response(200, request=request, json=document))


def authorization(policy, changes=None):
    selected = policy.selection
    fields = {"client_id": selected.client_id, "redirect_uri": selected.redirect_uri,
              "resource": selected.resource, "response_type": "code",
              "code_challenge_method": "S256", "code_challenge": "A" * 43,
              "state": "a-native-opaque-attempt-state", "scope": "read"}
    fields.update(changes or {})
    return policy.authorization_endpoint + "?" + urlencode(fields)


async def test_public_sdk_hooks_retain_one_approved_client_and_grant(selection):
    policy = GrantPolicy(selection)
    storage = MemoryGrant(policy)
    await discover(policy)
    state = policy.redirect(authorization(policy))
    assert state == "a-native-opaque-attempt-state"
    client = await storage.get_client_info()
    assert client.client_id == selection.client_id and client.issuer == selection.issuer
    assert client.client_secret is None and client.token_endpoint_auth_method == "none"
    await storage.set_client_info(client)
    await policy.request(httpx2.Request("POST", policy.token_endpoint, data={
        "grant_type": "authorization_code", "client_id": selection.client_id,
        "redirect_uri": selection.redirect_uri, "resource": selection.resource,
        "code": "synthetic-code", "code_verifier": "native-verifier",
    }))
    tokens = OAuthToken(access_token="synthetic-access", refresh_token="synthetic-refresh",
                        token_type="Bearer", expires_in=3600, scope="read")
    await storage.set_tokens(tokens)
    tokens.access_token = "caller-mutated"
    assert (await storage.get_tokens()).access_token == "synthetic-access"
    returned = await storage.get_tokens()
    returned.scope = "write"
    assert (await storage.get_tokens()).scope == "read"
    with pytest.raises(GrantRejected, match="another consent"):
        policy.redirect(authorization(policy))


@pytest.mark.parametrize("changes", [
    {"scope": "read write"}, {"scope": "write"}, {"scope": ""},
    {"client_id": "https://other-client.example/client.json"},
    {"redirect_uri": "http://127.0.0.1:44722/oauth/callback"},
    {"resource": "https://resource.example/another-tenant"},
    {"code_challenge_method": "plain"}, {"code_challenge": "short"},
    {"state": ""}, {"extra": "unreviewed"},
])
async def test_redirect_guard_rejects_expansion_before_the_browser(selection, changes):
    policy = GrantPolicy(selection)
    await discover(policy)
    with pytest.raises(GrantRejected):
        policy.redirect(authorization(policy, changes))
    assert not policy.redirected


@pytest.mark.parametrize("changes", [
    {"client_id_metadata_document_supported": False},
    {"client_id_metadata_document_supported": "true"},
    {"issuer": "https://other-issuer.example"},
    {"code_challenge_methods_supported": ["plain"]},
    {"authorization_response_iss_parameter_supported": False},
    {"authorization_response_iss_parameter_supported": "true"},
    {"token_endpoint_auth_methods_supported": ["client_secret_post"]},
    {"token_endpoint_auth_methods_supported": None},
    {"authorization_endpoint": "https://other-issuer.example/authorize"},
    {"token_endpoint": "https://other-issuer.example/token"},
])
async def test_metadata_cannot_switch_issuer_or_client_identity_mode(selection, changes):
    policy = GrantPolicy(selection)
    with pytest.raises(GrantRejected):
        await discover(policy, metadata_changes=changes)
    assert policy.authorization_endpoint is None and not policy.redirected


@pytest.mark.parametrize("changes", [
    {"resource": "https://resource.example/other"},
    {"authorization_servers": ["https://other-issuer.example"]},
])
async def test_resource_metadata_is_bound_to_the_selected_grant(selection, changes):
    policy = GrantPolicy(selection)
    with pytest.raises(GrantRejected):
        await discover(policy, resource_changes=changes)
    assert not policy.resource_verified


@pytest.mark.parametrize("scope", [None, "", "write", "read write"])
async def test_token_scope_is_checked_before_memory_storage(selection, scope):
    policy = GrantPolicy(selection)
    storage = MemoryGrant(policy)
    await discover(policy)
    policy.redirect(authorization(policy))
    tokens = OAuthToken(access_token="synthetic-access", token_type="Bearer", scope=scope)
    with pytest.raises(GrantRejected, match="approved grant"):
        await storage.set_tokens(tokens)
    assert await storage.get_tokens() is None


@pytest.mark.parametrize("field,value", [
    ("client_id", "https://other-client.example/client.json"),
    ("issuer", "https://other-issuer.example"),
    ("client_secret", "synthetic-secret"),
    ("token_endpoint_auth_method", "client_secret_post"),
    ("redirect_uris", ["http://127.0.0.1:44722/oauth/callback"]),
])
async def test_stored_client_cannot_be_replaced(selection, field, value):
    storage = MemoryGrant(GrantPolicy(selection))
    original = await storage.get_client_info()
    with pytest.raises(GrantRejected, match="replace"):
        await storage.set_client_info(original.model_copy(update={field: value}))
    assert await storage.get_client_info() == original


@pytest.mark.parametrize("url,method,headers", [
    ("https://issuer.example/register", "POST", {}),
    ("https://resource.example/private", "GET", {}),
    ("https://other-issuer.example/token", "POST", {}),
    ("https://resource.example/.well-known/oauth-protected-resource/mcp", "GET",
     {"Authorization": "Bearer synthetic-access"}),
    ("https://issuer.example/token", "POST", {"Authorization": "Basic synthetic-secret"}),
])
async def test_unapproved_requests_fail_before_network_io(selection, url, method, headers):
    policy = GrantPolicy(selection)
    await discover(policy)
    policy.redirect(authorization(policy))
    with pytest.raises(GrantRejected):
        await policy.request(httpx2.Request(method, url, headers=headers))


@pytest.mark.parametrize("reply", [
    {"result": {}}, {"error": {"code": -32601, "message": "Method not found"}},
])
async def test_standard_sdk_replies_are_allowed_without_a_new_operation(selection, reply):
    policy = GrantPolicy(selection)
    request = httpx2.Request("POST", selection.server_url,
                            json={"jsonrpc": "2.0", "id": 7, **reply})
    before = await request.aread()
    await policy.request(request)
    assert await request.aread() == before


@pytest.mark.parametrize("fields", [
    {"method": "tools/call", "result": {}},
    {"method": "tools/call", "error": {"code": -32601, "message": "Method not found"}},
    {"result": {}, "error": {"code": -32601, "message": "Ambiguous response"}},
])
async def test_a_response_shape_cannot_hide_an_unapproved_operation(selection, fields):
    policy = GrantPolicy(selection)
    with pytest.raises(GrantRejected, match="only discovers and lists"):
        await policy.request(httpx2.Request("POST", selection.server_url,
                                           json={"jsonrpc": "2.0", "id": 7, **fields}))


@pytest.mark.parametrize("change", ["client_id", "resource", "client_secret", "redirect_uri",
                                    "scope", "client_assertion", "audience"])
async def test_token_request_cannot_change_the_native_binding(selection, change):
    policy = GrantPolicy(selection)
    await discover(policy)
    policy.redirect(authorization(policy))
    values = {"grant_type": "authorization_code", "client_id": selection.client_id,
              "resource": selection.resource, "redirect_uri": selection.redirect_uri,
              "code": "synthetic-code", "code_verifier": "native-verifier"}
    values[change] = "changed"
    with pytest.raises(GrantRejected):
        await policy.request(httpx2.Request("POST", policy.token_endpoint, data=values))


@pytest.mark.parametrize("change", [None, "scope", "refresh_token", "client_assertion"])
async def test_in_memory_refresh_request_profile_is_bound_without_claiming_restart(selection, change):
    policy = GrantPolicy(selection)
    await discover(policy)
    policy.redirect(authorization(policy))
    values = {"grant_type": "refresh_token", "client_id": selection.client_id,
              "resource": selection.resource, "refresh_token": "synthetic-refresh", "scope": "read"}
    if change is not None:
        values[change] = "" if change == "refresh_token" else "unapproved"
    request = httpx2.Request("POST", policy.token_endpoint, data=values)
    if change is None:
        await policy.request(request)
    else:
        with pytest.raises(GrantRejected):
            await policy.request(request)
