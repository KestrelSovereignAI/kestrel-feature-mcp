"""Frozen grant policy for the manual spike's public SDK callbacks and hooks."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from urllib.parse import parse_qs, urlsplit

import httpx2
from mcp.client.auth.utils import create_client_info_from_metadata_url
from mcp.shared.auth import OAuthClientInformationFull, OAuthMetadata, OAuthToken, ProtectedResourceMetadata
from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url


class GrantRejected(ValueError):
    """Safe diagnostic; never interpolate a token, callback or response body."""


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError:
        raise GrantRejected("Malformed OAuth endpoint") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or parsed.query):
        raise GrantRejected("Grant endpoints must be exact HTTPS URLs without credentials")
    return parsed.scheme + "://" + parsed.netloc


def _fields(query: str, *, limit: int) -> dict[str, list[str]]:
    try:
        return parse_qs(query, keep_blank_values=True, strict_parsing=True,
                        max_num_fields=limit)
    except ValueError:
        raise GrantRejected("Malformed OAuth request parameters") from None


@dataclass(frozen=True)
class GrantSelection:
    server_url: str
    resource: str
    issuer: str
    protected_metadata: str
    authorization_metadata: str
    client_id: str
    redirect_uri: str
    scopes: frozenset[str]

    def __post_init__(self):
        server_origin, issuer_origin = _origin(self.server_url), _origin(self.issuer)
        _origin(self.resource)
        if not check_resource_allowed(resource_url_from_server_url(self.server_url), self.resource):
            raise GrantRejected("The selected resource must be a valid parent of the MCP endpoint")
        if _origin(self.protected_metadata) != server_origin:
            raise GrantRejected("Resource metadata must belong to the selected resource origin")
        if _origin(self.authorization_metadata) != issuer_origin:
            raise GrantRejected("Authorization metadata must belong to the selected issuer origin")
        _origin(self.client_id)
        if not urlsplit(self.client_id).path.strip("/"):
            raise GrantRejected("The public CIMD client ID must name a document")
        if (not self.scopes or not isinstance(self.scopes, frozenset)
                or any(not isinstance(scope, str) or not scope
                       or any(c.isspace() or ord(c) < 33 or ord(c) > 126
                                        for c in scope) for scope in self.scopes)):
            raise GrantRejected("Select explicit immutable OAuth scopes")


class GrantPolicy:
    """No client identity, resource, issuer or scope switch during one attempt."""

    def __init__(self, selection: GrantSelection):
        self.selection = selection
        self.authorization_endpoint: str | None = None
        self.token_endpoint: str | None = None
        self.resource_verified = False
        self.redirected = False

    async def request(self, request: httpx2.Request) -> None:
        url = str(request.url)
        selected = self.selection
        if request.headers.get("Authorization"):
            # A bearer token is for this exact resource, never discovery or AS I/O.
            if url != selected.server_url:
                raise GrantRejected("Credentials cannot leave the selected resource")
        if url in {selected.protected_metadata, selected.authorization_metadata}:
            if request.method != "GET" or request.headers.get("Authorization"):
                raise GrantRejected("Metadata discovery must be an unauthenticated GET")
            return
        if url == selected.server_url:
            if request.method in {"GET", "DELETE"}:
                return
            if request.method == "POST":
                message = json.loads(await request.aread())
                if message.get("method") in {
                    "server/discover", "initialize", "notifications/initialized", "tools/list",
                    "ping", "notifications/cancelled",
                }:
                    return
            raise GrantRejected("The acceptance spike only discovers and lists MCP tools")
        if url == self.token_endpoint and request.method == "POST":
            if not self.redirected or request.headers.get("Authorization"):
                raise GrantRejected("Token exchange requires the approved public-client attempt")
            # The native SDK owns code/verifier construction and token exchange.
            fields = _fields((await request.aread()).decode("ascii"), limit=8)
            required = {"client_id": [selected.client_id], "resource": [selected.resource]}
            if (any(fields.get(key) != value for key, value in required.items())
                    or fields.get("grant_type") not in [["authorization_code"], ["refresh_token"]]
                    or any(len(value) != 1 for value in fields.values())):
                raise GrantRejected("Native token request changed its approved binding")
            allowed = {"grant_type", "client_id", "resource", "scope"}
            allowed |= ({"code", "code_verifier", "redirect_uri"}
                        if fields["grant_type"] == ["authorization_code"] else {"refresh_token"})
            if set(fields) - allowed:
                raise GrantRejected("Native token request contains fields outside this public client profile")
            if frozenset(fields.get("scope", [""])[0].split()) - selected.scopes:
                raise GrantRejected("Native token request exceeded the approved scopes")
            if fields["grant_type"] == ["authorization_code"] and (
                    fields.get("redirect_uri") != [selected.redirect_uri]
                    or not fields.get("code", [""])[0] or not fields.get("code_verifier", [""])[0]):
                raise GrantRejected("Native authorization-code exchange is incomplete")
            if fields["grant_type"] == ["refresh_token"] and not fields.get("refresh_token", [""])[0]:
                raise GrantRejected("Native refresh exchange is missing its grant")
            return
        raise GrantRejected("An unexpected request was refused before network I/O")

    async def response(self, response: httpx2.Response) -> None:
        if response.is_redirect:
            raise GrantRejected("Redirects are refused for MCP and OAuth HTTP requests")
        url = str(response.request.url)
        selected = self.selection
        if url not in {selected.protected_metadata, selected.authorization_metadata}:
            return
        if response.status_code != 200:
            raise GrantRejected("The selected OAuth metadata endpoint did not return 200")
        body = await response.aread()
        if len(body) > 65536:
            raise GrantRejected("OAuth metadata exceeded the spike's response budget")
        document = json.loads(body)
        if url == selected.protected_metadata:
            resource = ProtectedResourceMetadata.model_validate(document)
            issuers = document.get("authorization_servers")
            if (str(resource.resource) != selected.resource
                    or not issuers or issuers[0] != selected.issuer):
                raise GrantRejected("Resource metadata changed the selected resource or issuer")
            self.resource_verified = True
            return
        metadata = OAuthMetadata.model_validate(document)
        # RFC 9207 compares issuer identity strings, not URL-normalized values.
        if not self.resource_verified or document.get("issuer") != selected.issuer:
            raise GrantRejected("Authorization metadata changed the selected issuer")
        if document.get("client_id_metadata_document_supported") is not True:
            raise GrantRejected("The selected issuer does not advertise CIMD; its own registered client is required")
        if ("S256" not in (metadata.code_challenge_methods_supported or [])
                or "code" not in metadata.response_types_supported
                or not metadata.authorization_endpoint or not metadata.token_endpoint):
            raise GrantRejected("The selected issuer does not support this PKCE code flow")
        if document.get("authorization_response_iss_parameter_supported") is not True:
            raise GrantRejected("The selected issuer does not advertise authorization-response issuer validation")
        if "none" not in (metadata.token_endpoint_auth_methods_supported or []):
            raise GrantRejected("The selected issuer does not advertise public-client token authentication")
        authorization, token = str(metadata.authorization_endpoint), str(metadata.token_endpoint)
        if _origin(authorization) != _origin(selected.issuer) or _origin(token) != _origin(selected.issuer):
            raise GrantRejected("OAuth endpoints left the selected issuer origin")
        if (self.authorization_endpoint not in {None, authorization}
                or self.token_endpoint not in {None, token}):
            raise GrantRejected("Issuer endpoints changed during the authorization attempt")
        self.authorization_endpoint, self.token_endpoint = authorization, token

    def redirect(self, url: str) -> str:
        selected = self.selection
        parsed = urlsplit(url)
        if parsed.fragment or parsed.scheme + "://" + parsed.netloc + parsed.path != self.authorization_endpoint:
            raise GrantRejected("Authorization changed its verified endpoint")
        query = _fields(parsed.query, limit=8)
        expected = {"client_id": [selected.client_id], "redirect_uri": [selected.redirect_uri],
                    "resource": [selected.resource], "response_type": ["code"],
                    "code_challenge_method": ["S256"]}
        if (set(query) != set(expected) | {"scope", "state", "code_challenge"}
                or any(query.get(key) != value for key, value in expected.items())
                or any(len(value) != 1 for value in query.values())
                or len(query["state"][0]) < 16
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", query["code_challenge"][0])):
            raise GrantRejected("Authorization changed its approved PKCE/client/resource binding")
        scopes = frozenset(query["scope"][0].split())
        if not scopes or not scopes <= selected.scopes:
            raise GrantRejected("The SDK requested scopes outside the approved grant")
        if self.redirected:
            raise GrantRejected("This spike cannot silently start another consent attempt")
        self.redirected = True
        return query["state"][0]


class MemoryGrant:
    """Initial consent only: secrets are never written to files or host storage."""

    def __init__(self, policy: GrantPolicy):
        self.policy = policy
        selected = policy.selection
        self._client = create_client_info_from_metadata_url(
            selected.client_id, [selected.redirect_uri],
        ).model_copy(update={"issuer": selected.issuer})
        self._tokens: OAuthToken | None = None

    async def get_client_info(self):
        return self._client.model_copy(deep=True)

    async def set_client_info(self, client: OAuthClientInformationFull):
        selected = self.policy.selection
        if (client.client_id != selected.client_id or client.issuer != selected.issuer
                or client.client_secret is not None or client.token_endpoint_auth_method != "none"
                or [str(uri) for uri in client.redirect_uris or []] != [selected.redirect_uri]):
            raise GrantRejected("The SDK attempted to replace the approved public client identity")
        self._client = client.model_copy(deep=True)

    async def get_tokens(self):
        return None if self._tokens is None else self._tokens.model_copy(deep=True)

    async def set_tokens(self, tokens: OAuthToken):
        if (not self.policy.redirected or not tokens.scope
                or not frozenset(tokens.scope.split()) <= self.policy.selection.scopes):
            raise GrantRejected("A token exceeded the operator-approved grant")
        self._tokens = tokens.model_copy(deep=True)


class GuardedAuth(httpx2.Auth):
    """Apply role policy around the SDK's public HTTP authentication generator.

    The original requests and responses pass through unchanged. The SDK owns
    discovery, PKCE, callback validation, token exchange and authentication.
    This guard also follows the same provider into the production connection.
    """

    def __init__(self, provider: httpx2.Auth, policy: GrantPolicy):
        self.provider = provider
        self.policy = policy

    async def async_auth_flow(self, request: httpx2.Request):
        flow = self.provider.async_auth_flow(request)
        try:
            try:
                outgoing = await anext(flow)
            except StopAsyncIteration:
                return
            while True:
                await self.policy.request(outgoing)
                incoming = yield outgoing
                await self.policy.response(incoming)
                try:
                    outgoing = await flow.asend(incoming)
                except StopAsyncIteration:
                    return
        finally:
            await flow.aclose()
