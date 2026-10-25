"""Native SDK OAuth and canonical MCP against independent real HTTPS peers.

The authorization server owns code/PKCE/token validation. No real accounts or
vendor credentials are involved; actual vendor acceptance remains a manual gate.
"""

import base64
import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
import socket
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import httpcore2
import httpx2
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse, StreamingResponse
from starlette.routing import Route
from mcp.client.auth import OAuthTokenError
from mcp.shared.exceptions import MCPError

from kestrel_sdk.security.outbound import assert_safe_url, pinned_httpx2_async_transport
from kestrel_feature_mcp.connection import MCPConnection
from tests.http_peers import serve_http
from tests.oauth_acceptance.client import run
from tests.oauth_acceptance.policy import GrantRejected, GrantSelection, GuardedAuth


@dataclass
class OAuthPeers:
    selection: GrantSelection
    options: dict
    issuer: object
    resource: object
    requests: list
    browser_requests: list
    release_body: asyncio.Event

    async def browser(self, url):
        self.browser_requests.append(url)
        await asyncio.sleep(self.options.get("browser_delay", 0))
        approved = await assert_safe_url(url, allowed_schemes=("https",))
        async with httpx2.AsyncClient(
            transport=pinned_httpx2_async_transport(approved), follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(url)
            assert response.status_code == 302
            callback = response.headers["Location"]
        assert callback.split("?", 1)[0] == self.selection.redirect_uri
        async with httpx2.AsyncClient(trust_env=False, follow_redirects=False) as client:
            delivered = await client.get(callback)
        expected = 400 if self.options.get("wrong_callback_state") else 200
        assert delivered.status_code == expected


@pytest.fixture
async def oauth_peers(mcp_http_server, request, tmp_path, monkeypatch):
    options = getattr(request, "param", {})
    resource_peer = mcp_http_server
    resource_port = urlsplit(resource_peer.url).port
    resource_url = f"https://remote.example:{resource_port}/mcp"
    resource_id = resource_url.rsplit("/mcp", 1)[0] if options.get("parent_resource") else resource_url
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        callback_port = reservation.getsockname()[1]
    callback = f"http://127.0.0.1:{callback_port}/oauth/callback"
    state = SimpleNamespace(issuer=None, client_id=None, access_token="native-fixture-access",
                            codes={}, requests=[], release_body=asyncio.Event())

    async def held_body(content):
        # Only the test/fixture releases EOF; refusal must finish first.
        yield content
        await state.release_body.wait()

    async def identity(_request):
        state.requests.append(("GET", "/client.json"))
        if options.get("oversized") == "identity":
            return StreamingResponse(held_body(b"X" * 65537), media_type="application/json")
        return JSONResponse({
            "client_id": state.client_id, "client_name": "Kestrel OAuth wire fixture",
            "application_type": "native", "redirect_uris": [callback],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none",
        })

    async def metadata(_request):
        state.requests.append(("GET", "/.well-known/oauth-authorization-server"))
        if options.get("oversized") == "authorization":
            return StreamingResponse(held_body(b"X" * 65537), media_type="application/json")
        document = {
            "issuer": (state.issuer.replace("issuer.example", "ISSUER.example")
                       if options.get("wrong_issuer_spelling") else state.issuer),
            "authorization_endpoint": state.issuer + "/authorize",
            "token_endpoint": state.issuer + "/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": (["client_secret_post"]
                                                       if options.get("confidential_only") else ["none"]),
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": not options.get("no_cimd", False),
        }
        if options.get("stall_metadata"):
            return StreamingResponse(held_body(json.dumps(document).encode()),
                                     media_type="application/json")
        return JSONResponse(document)

    async def authorize(request):
        state.requests.append(("GET", "/authorize"))
        fields = parse_qs(request.url.query, strict_parsing=True)
        assert fields["client_id"] == [state.client_id]
        assert fields["redirect_uri"] == [callback]
        assert fields["resource"] == [resource_id]
        assert fields["code_challenge_method"] == ["S256"]
        assert fields["scope"] == ["read"]
        # The independent AS fetches the actual CIMD over HTTPS as well.
        endpoint = await assert_safe_url(state.client_id, allowed_schemes=("https",))
        async with httpx2.AsyncClient(transport=pinned_httpx2_async_transport(endpoint),
                                     trust_env=False) as client:
            identity_response = await client.get(state.client_id)
            assert identity_response.status_code == 200
            assert identity_response.json()["redirect_uris"] == fields["redirect_uri"]
        code = secrets.token_urlsafe(32)
        state.codes[code] = fields
        returned = "wrong-attempt" if options.get("wrong_callback_state") else fields["state"][0]
        parameters = {
            "code": code, "state": returned, "iss": state.issuer,
        }
        if options.get("extra_callback_fields"):
            parameters.update(session_state="opaque-session", scope="read")
        return RedirectResponse(callback + "?" + urlencode(parameters), status_code=302)

    async def token(request):
        state.requests.append(("POST", "/token"))
        fields = parse_qs((await request.body()).decode("ascii"), strict_parsing=True)
        assert fields["grant_type"] == ["authorization_code"]
        assert fields["client_id"] == [state.client_id]
        assert fields["redirect_uri"] == [callback]
        assert fields["resource"] == [resource_id]
        assert "client_secret" not in fields and "authorization" not in request.headers
        original = state.codes.pop(fields["code"][0])
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(fields["code_verifier"][0].encode("ascii")).digest(),
        ).rstrip(b"=").decode("ascii")
        assert original["code_challenge"] == [challenge]
        return JSONResponse({"access_token": state.access_token, "refresh_token": "native-fixture-refresh",
                             "token_type": "Bearer", "expires_in": 3600,
                             "scope": "read write" if options.get("overgrant") else "read"})

    app = Starlette(routes=[Route("/client.json", identity),
                           Route("/.well-known/oauth-authorization-server", metadata),
                           Route("/authorize", authorize), Route("/token", token, methods=["POST"])])
    async with serve_http(app, tmp_path / "issuer", certificate_host="issuer.example") as issuer_peer:
        issuer_port = urlsplit(issuer_peer.url).port
        state.issuer = f"https://issuer.example:{issuer_port}"
        state.client_id = state.issuer + "/client.json"
        resource_peer.settings["oauth"].update(
            resource=resource_id, issuer=state.issuer, access_token=state.access_token,
            metadata=resource_url.replace("/mcp", "/.well-known/oauth-protected-resource/mcp"),
            challenge_scope=options.get("challenge_scope", "read"),
            denied_authenticated_get=options.get("denied_authenticated_get"),
        )
        if options.get("redirect_resource"):
            resource_peer.settings["oauth"]["redirect_to"] = resource_url
        if options.get("wrong_resource_issuer_spelling"):
            resource_peer.settings["oauth"]["advertised_issuer"] = state.issuer.replace(
                "issuer.example", "ISSUER.example")
        if options.get("wrong_resource_spelling"):
            resource_peer.settings["oauth"]["advertised_resource"] = resource_id.replace(
                "remote.example", "REMOTE.example")
        selection = GrantSelection(
            server_url=resource_url, resource=resource_id, issuer=state.issuer,
            protected_metadata=resource_peer.settings["oauth"]["metadata"],
            authorization_metadata=state.issuer + "/.well-known/oauth-authorization-server",
            client_id=state.client_id, redirect_uri=callback, scopes=frozenset({"read"}),
        )
        authorities = {("remote.example", resource_port), ("issuer.example", issuer_port)}
        original_dns = socket.getaddrinfo
        original_dial = httpcore2.AnyIOBackend.connect_tcp

        def resolve(host, port, *, type, proto):
            if host == "127.0.0.1":
                assert port == callback_port
                return original_dns(host, port, type=type, proto=proto)
            assert (host, port) in authorities
            return [(socket.AF_INET, type, proto, "", ("8.8.8.8", port))]

        async def dial(backend, host, port, **kwargs):
            if host == "8.8.8.8":
                assert port in {resource_port, issuer_port}
            else:
                assert host == "127.0.0.1" and port == callback_port
            return await original_dial(backend, "127.0.0.1", port, **kwargs)

        bundle = tmp_path / "fixture-authorities.pem"
        bundle.write_bytes(Path(resource_peer.settings["certificate_file"]).read_bytes()
                           + Path(issuer_peer.certificate_file).read_bytes())
        monkeypatch.setattr(socket, "getaddrinfo", resolve)
        monkeypatch.setattr(httpcore2.AnyIOBackend, "connect_tcp", dial)
        monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("NO_PROXY", "")
        try:
            yield OAuthPeers(selection, options, issuer_peer, resource_peer, state.requests, [],
                             state.release_body)
        finally:
            state.release_body.set()


async def drive(peers, mode="authorize", *, network_timeout=5):
    return await run(peers.selection, mode=mode, browser_timeout=0.3 if peers.options.get(
        "wrong_callback_state") else 5, network_timeout=network_timeout, connect_timeout=5,
        call_timeout=5, close_timeout=5, browser_opener=peers.browser)


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{}, {"extra_callback_fields": True},
                                         {"parent_resource": True}], indirect=True)
async def test_actual_native_initial_grant_and_canonical_mcp_discovery(oauth_peers):
    result = await drive(oauth_peers)
    assert result["grant_obtained"] and result["stage"] == "authorized_and_discovered"
    assert result["tools"] == 2 and result["protocol_version"] == "2026-07-28"
    assert result["tool_calls"] == 0 and not result["persistent_tokens"]
    assert result["server_url"] == oauth_peers.selection.server_url
    assert result["resource"] == oauth_peers.selection.resource
    assert not result["restart_refresh_verified"]
    assert oauth_peers.requests.count(("GET", "/authorize")) == 1
    assert oauth_peers.requests.count(("POST", "/token")) == 1
    assert oauth_peers.requests.count(("GET", "/client.json")) == 2
    assert set(oauth_peers.issuer.server_names) == {"issuer.example"}
    assert set(oauth_peers.resource.server_names) == {"remote.example"}
    assert oauth_peers.resource.witness == []
    methods = [json.loads(body)["method"] for _, body in oauth_peers.resource.requests if body]
    assert methods == ["server/discover", "tools/list"]
    assert "native-fixture-access" not in json.dumps(result)


@pytest.mark.parametrize("mcp_http_server,protocol,get_status", [
    ({"tls": True, "oauth": {}}, "2026-07-28", 405),
    ({"tls": True, "oauth": {}, "legacy": True}, "2025-11-25", 406),
], indirect=["mcp_http_server"])
async def test_native_get_status_does_not_replace_mcp_negotiation(oauth_peers, protocol, get_status):
    result = error = None
    try:
        result = await drive(oauth_peers)
    except GrantRejected as caught:
        error = caught
    # Observe the actual SDK transport's response and real token exchange
    # before inspecting the acceptance result.
    assert ("GET", "/mcp", get_status) in oauth_peers.resource.settings["responses"]
    assert oauth_peers.requests.count(("POST", "/token")) == 1
    assert error is None
    assert result["stage"] == "authorized_and_discovered"
    assert result["protocol_version"] == protocol and result["tools"] == 2
    assert result["tool_calls"] == 0 and oauth_peers.resource.witness == []
    methods = [json.loads(body)["method"] for _, body in oauth_peers.resource.requests if body]
    assert ("initialize" in methods) == (protocol == "2025-11-25")


@pytest.mark.parametrize("mcp_http_server", [
    {"tls": True, "oauth": {}, "bootstrap_event_stream": True},
], indirect=True)
async def test_bootstrap_hands_off_without_waiting_for_event_stream_eof(oauth_peers):
    settings = oauth_peers.resource.settings
    task = asyncio.create_task(drive(oauth_peers))
    try:
        done, _ = await asyncio.wait({task}, timeout=2)
        assert task in done, "Initial OAuth waited for the bootstrap event stream to end"
        result = await task
        assert settings["bootstrap_body_started"].is_set()
        assert not settings["release_bootstrap_body"].is_set()
        assert result["stage"] == "authorized_and_discovered" and result["tools"] == 2
        assert oauth_peers.requests.count(("POST", "/token")) == 1
        assert result["tool_calls"] == 0 and oauth_peers.resource.witness == []
    finally:
        settings["release_bootstrap_body"].set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{"oversized": "identity"},
                                         {"oversized": "authorization"}], indirect=True)
async def test_oversized_stream_is_refused_before_waiting_for_its_end(oauth_peers):
    async def attempt():
        with pytest.raises(GrantRejected, match="response budget"):
            await drive(oauth_peers)

    task = asyncio.create_task(attempt())
    try:
        # A missing byte guard fails this test deadline, not pytest's timeout.
        # Always release the independent peer and join the original attempt.
        async with asyncio.timeout(2):
            await asyncio.shield(task)
    finally:
        oauth_peers.release_body.set()
        await task
    assert oauth_peers.browser_requests == []
    assert ("GET", "/authorize") not in oauth_peers.requests
    assert ("POST", "/token") not in oauth_peers.requests


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{"stall_metadata": True}], indirect=True)
async def test_native_auth_metadata_body_has_its_own_network_deadline(oauth_peers):
    task = asyncio.create_task(drive(oauth_peers, network_timeout=2))
    try:
        done, _ = await asyncio.wait({task}, timeout=4)
        assert task in done, "Native metadata response outlived its network deadline"
        with pytest.raises(TimeoutError):
            await task
        assert ("GET", "/.well-known/oauth-authorization-server") in oauth_peers.requests
        assert oauth_peers.browser_requests == []
        assert ("POST", "/token") not in oauth_peers.requests
    finally:
        oauth_peers.release_body.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{"browser_delay": 2.5}], indirect=True)
async def test_human_consent_wait_is_separate_from_each_network_exchange(oauth_peers):
    result = await drive(oauth_peers, network_timeout=2)
    assert result["stage"] == "authorized_and_discovered" and result["grant_obtained"]
    assert oauth_peers.requests.count(("POST", "/token")) == 1


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{"denied_authenticated_get": 401},
                                         {"denied_authenticated_get": 403}], indirect=True)
async def test_completed_exchange_does_not_hide_resource_authorization_denial(oauth_peers):
    with pytest.raises(GrantRejected, match="resource rejected the completed initial authorization"):
        await drive(oauth_peers)
    assert oauth_peers.requests.count(("POST", "/token")) == 1
    assert len(oauth_peers.browser_requests) == 1
    assert all(not body for _, body in oauth_peers.resource.requests)
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize("mcp_http_server", [
    {"tls": True, "oauth": {}, "legacy": True, "server_ping": True},
], indirect=True)
@pytest.mark.parametrize("with_oauth_guard", [False, True])
async def test_actual_sdk_server_ping_is_answered_during_discovery(oauth_peers, with_oauth_guard):
    if with_oauth_guard:
        result = await drive(oauth_peers)
        assert result["stage"] == "authorized_and_discovered"
    else:
        # First prove the independent SDK server/GET stream/ping fixture with
        # only its synthetic bearer token, without the application's guard.
        endpoint = await assert_safe_url(oauth_peers.selection.server_url, allowed_schemes=("https",))
        connection = MCPConnection(endpoint, headers={
            "Authorization": "Bearer " + oauth_peers.resource.settings["oauth"]["access_token"]},
            connect_timeout=5, call_timeout=5, close_timeout=5)
        try:
            assert len(await connection.connect()) == 2
        finally:
            await connection.close()
    assert oauth_peers.resource.settings["ping_requested"].is_set()
    assert oauth_peers.resource.settings["ping_answered"].is_set()
    messages = [json.loads(body) for _, body in oauth_peers.resource.requests if body]
    replies = [message for message in messages if "result" in message and "method" not in message]
    assert len(replies) == 1 and replies[0]["result"] == {}
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
async def test_discovery_mode_never_opens_authorization_or_exchanges_a_token(oauth_peers):
    result = await drive(oauth_peers, mode="discover")
    assert result["stage"] == "authorization_ready" and not result["grant_obtained"]
    assert oauth_peers.browser_requests == []
    assert ("GET", "/authorize") not in oauth_peers.requests
    assert ("POST", "/token") not in oauth_peers.requests
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{"redirect_resource": True}], indirect=True)
async def test_actual_resource_redirect_is_rejected_without_another_request(oauth_peers):
    with pytest.raises(GrantRejected, match="Redirects are refused"):
        await drive(oauth_peers)
    assert len(oauth_peers.resource.requests) == 1
    assert oauth_peers.browser_requests == []
    assert ("GET", "/authorize") not in oauth_peers.requests
    assert ("POST", "/token") not in oauth_peers.requests


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers,reason", [
    ({"no_cimd": True}, "does not advertise CIMD"),
    ({"challenge_scope": "read write"}, "outside the approved grant"),
    pytest.param({"wrong_issuer_spelling": True}, "changed the selected issuer", id="issuer_literal"),
    pytest.param({"wrong_resource_issuer_spelling": True}, "Resource metadata changed", id="resource_issuer_literal"),
    pytest.param({"wrong_resource_spelling": True}, "Resource metadata changed", id="resource_literal"),
    ({"confidential_only": True}, "public-client token authentication"),
], indirect=["oauth_peers"])
async def test_native_sdk_refusals_happen_before_the_browser_or_token_post(oauth_peers, reason):
    with pytest.raises(GrantRejected, match=reason):
        await drive(oauth_peers)
    assert oauth_peers.browser_requests == []
    assert ("GET", "/authorize") not in oauth_peers.requests
    assert ("POST", "/token") not in oauth_peers.requests
    assert all(b"authorization" not in dict(scope["headers"])
               for scope, _ in oauth_peers.resource.requests)


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{"overgrant": True}], indirect=True)
async def test_overgranted_token_never_reaches_the_resource(oauth_peers):
    with pytest.raises(GrantRejected, match="token exceeded"):
        await drive(oauth_peers)
    assert oauth_peers.requests.count(("POST", "/token")) == 1
    assert all(b"authorization" not in dict(scope["headers"])
               for scope, _ in oauth_peers.resource.requests)
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("oauth_peers", [{"wrong_callback_state": True}], indirect=True)
async def test_wrong_actual_loopback_state_never_reaches_token_exchange(oauth_peers):
    with pytest.raises(TimeoutError):
        await drive(oauth_peers)
    assert oauth_peers.requests.count(("GET", "/authorize")) == 1
    assert ("POST", "/token") not in oauth_peers.requests
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
async def test_the_actual_sdk_request_pipeline_applies_policy_before_network(oauth_peers, monkeypatch):
    from tests.oauth_acceptance import client as client_module
    native_provider = client_module.OAuthClientProvider

    class PoisonTokenHeader:
        async def request(self, outgoing):
            if str(outgoing.url) == oauth_peers.selection.issuer + "/token":
                outgoing.headers["Authorization"] = "Basic synthetic-foreign-credential"

        async def response(self, incoming):
            pass

    def corrupted_public_sdk_output(*args, **kwargs):
        # Adversarial public HTTP auth output, not a mocked grant: the actual
        # SDK still performs discovery, callback and PKCE. Only its outgoing
        # token request is poisoned, before the application's outer guard.
        return GuardedAuth(native_provider(*args, **kwargs), PoisonTokenHeader())

    monkeypatch.setattr(client_module, "OAuthClientProvider", corrupted_public_sdk_output)
    error = None
    try:
        await drive(oauth_peers)
    except (GrantRejected, OAuthTokenError) as caught:
        error = caught
    # Observe the independent server first; an error result alone cannot prove
    # a credential never crossed the network.
    assert ("POST", "/token") not in oauth_peers.requests
    assert isinstance(error, GrantRejected)
    assert "Credentials cannot leave" in str(error)
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "oauth": {}}], indirect=True)
@pytest.mark.parametrize("enforce_guard", [False, True])
async def test_resource_auth_policy_stops_an_unapproved_native_request(
        oauth_peers, monkeypatch, caplog, enforce_guard):
    from tests.oauth_acceptance import client as client_module
    corrupted = []

    async def poison_resource_output(_auth, outgoing):
        # Corrupt the public pass-through auth output, before the outer guard.
        # Native OAuth, MCP discovery, and the independent server remain real.
        if outgoing.method == "POST":
            body = json.loads(await outgoing.aread())
            if body.get("method") == "tools/list":
                # Keep the complete native envelope and routing headers. Change
                # only the HTTP verb, which this discovery role must refuse.
                outgoing = httpx2.Request("PATCH", outgoing.url, headers=outgoing.headers,
                                         content=await outgoing.aread())
                corrupted.append(True)
        yield outgoing

    monkeypatch.setattr(httpx2.Auth, "async_auth_flow", poison_resource_output)
    if not enforce_guard:
        guarded_auth = client_module.GuardedAuth

        def remove_resource_guard(provider, policy):
            return provider if type(provider) is httpx2.Auth else guarded_auth(provider, policy)

        monkeypatch.setattr(client_module, "GuardedAuth", remove_resource_guard)
    error = None
    try:
        await drive(oauth_peers)
    except (ValueError, ExceptionGroup, MCPError, ConnectionError, httpx2.HTTPError) as caught:
        error = caught
    assert corrupted == [True]
    assert oauth_peers.requests.count(("POST", "/token")) == 1
    sent = [json.loads(body) for scope, body in oauth_peers.resource.requests
            if scope["method"] == "PATCH" and body]
    assert error is not None
    assert oauth_peers.resource.witness == []
    if enforce_guard:
        assert sent == []
        assert "only discovers and lists MCP tools" in caplog.text or isinstance(error, GrantRejected)
    else:
        # Positive control: removing only this wiring sends the refused verb
        # to the independent server. Its 405 response is not a policy refusal.
        assert len(sent) == 1 and sent[0]["method"] == "tools/list"
