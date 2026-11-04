"""Shared safe refusals and budgets for native OAuth roles."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math
import sys
import re
from urllib.parse import parse_qs, urlsplit

import httpx2
from mcp.client.auth.utils import (
    build_oauth_authorization_server_metadata_discovery_urls,
    build_protected_resource_metadata_discovery_urls,
    extract_resource_metadata_from_www_auth,
)
from mcp.shared.auth import OAuthMetadata, OAuthToken, ProtectedResourceMetadata
from mcp_types import JSONRPCNotification, JSONRPCRequest, client_notification_adapter, jsonrpc_message_adapter
from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url
from pydantic import ValidationError

DEFAULT_RESPONSE_MAX_BYTES = 65536


class GrantRejected(ValueError):
    """Safe diagnostic; never interpolate a token, callback or response body."""


def response_budget(value: int) -> int:
    if type(value) is not int or value < 1:
        raise GrantRejected("OAuth response budget must be a positive integer")
    return value


def positive_seconds(value):
    if (type(value) not in (int, float) or value <= 0
            or value > sys.float_info.max or not math.isfinite(value)):
        raise GrantRejected("OAuth timeout must be finite and positive")
    return value


def metadata_document(body: bytes) -> dict:
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GrantRejected("OAuth metadata is not valid JSON") from None
    if not isinstance(document, dict):
        raise GrantRejected("OAuth metadata must be an object")
    return document


def validate_metadata(model, document):
    try:
        return model.model_validate(document)
    except ValidationError:
        raise GrantRejected("OAuth metadata does not match its protocol schema") from None


async def validate_token_request(request, selected, *, grant_type):
    if request.method != "POST" or request.headers.get("Authorization"):
        raise GrantRejected("Token exchange requires the approved public-client attempt")
    try:
        body = (await request.aread()).decode("ascii")
    except UnicodeDecodeError:
        raise GrantRejected("Malformed OAuth request parameters") from None
    fields = _fields(body, limit=8)
    required = {"client_id": [selected.client_id], "resource": [selected.resource],
                "grant_type": [grant_type]}
    if (any(fields.get(key) != value for key, value in required.items())
            or any(len(value) != 1 for value in fields.values())):
        raise GrantRejected("Native token request changed its approved binding")
    allowed = {"grant_type", "client_id", "resource", "scope"}
    if grant_type == "authorization_code":
        allowed |= {"code", "code_verifier", "redirect_uri"}
        if (fields.get("redirect_uri") != [selected.redirect_uri]
                or not fields.get("code", [""])[0] or not fields.get("code_verifier", [""])[0]):
            raise GrantRejected("Native authorization-code exchange is incomplete")
    elif grant_type == "refresh_token":
        allowed.add("refresh_token")
        if not fields.get("refresh_token", [""])[0]:
            raise GrantRejected("Native refresh exchange is missing its grant")
    else:
        raise GrantRejected("Unsupported OAuth token role")
    if set(fields) - allowed:
        raise GrantRejected("Native token request contains fields outside this public client profile")
    if frozenset(fields.get("scope", [""])[0].split()) - selected.scopes:
        raise GrantRejected("Native token request exceeded the approved scopes")


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
                       or any(c in {'"', '\\'} or c.isspace() or ord(c) < 33 or ord(c) > 126
                                        for c in scope) for scope in self.scopes)):
            raise GrantRejected("Select explicit immutable OAuth scopes")


class VerifiedGrantPolicy:
    """No client identity, resource, issuer or scope switch during one attempt."""

    def __init__(self, selection: GrantSelection, *, response_max_bytes=DEFAULT_RESPONSE_MAX_BYTES):
        self.selection = selection
        self.response_max_bytes = response_budget(response_max_bytes)
        self.authorization_endpoint: str | None = None
        self.token_endpoint: str | None = None
        self.resource_verified = False
        self.redirected = False
        self.requested_scopes: frozenset[str] | None = None

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
        if len(body) > self.response_max_bytes:
            raise GrantRejected("OAuth metadata exceeded its response budget")
        document = metadata_document(body)
        if url == selected.protected_metadata:
            validate_metadata(ProtectedResourceMetadata, document)
            issuers = document.get("authorization_servers")
            if (document.get("resource") != selected.resource
                    or not issuers or issuers[0] != selected.issuer):
                raise GrantRejected("Resource metadata changed the selected resource or issuer")
            self.resource_verified = True
            return
        metadata = validate_metadata(OAuthMetadata, document)
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
        query = _fields(parsed.query, limit=9)
        expected = {"client_id": [selected.client_id], "redirect_uri": [selected.redirect_uri],
                    "resource": [selected.resource], "response_type": ["code"],
                    "code_challenge_method": ["S256"]}
        if "prompt" in query and "offline_access" in query.get("scope", [""])[0].split():
            expected["prompt"] = ["consent"]
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
            raise GrantRejected("Cannot silently start another consent attempt")
        self.requested_scopes = scopes
        self.redirected = True
        return query["state"][0]


@dataclass(frozen=True)
class ClientIdentity:
    """Public web identity supplied by the authenticated Core host operation."""

    client_id: str
    redirect_uri: str

    def __post_init__(self):
        if (_origin(self.client_id) != _origin(self.redirect_uri)
                or not urlsplit(self.client_id).path.strip('/')
                or not urlsplit(self.redirect_uri).path.strip('/')):
            raise GrantRejected('OAuth web identity requires exact same-origin document and callback URLs')


class BootstrapPolicy:
    """Native SDK discovery and one code exchange, using only a harmless GET.

    Standard discovery candidates come from the SDK. A 404 or 405 permits
    the next standard candidate; malformed metadata or another failure stops
    the attempt. Only verified PRM may approve the issuer's origin.
    """

    def __init__(self, server_url: str, identity: ClientIdentity, scopes: frozenset[str],
                 *, on_exchange, on_rejection=None, response_max_bytes=DEFAULT_RESPONSE_MAX_BYTES):
        self.server_url, self.identity, self.scopes = server_url, identity, scopes
        self.response_max_bytes = response_budget(response_max_bytes)
        self.approved_origins = {_origin(server_url)}
        self.on_exchange, self.on_rejection = on_exchange, on_rejection
        self._resource_urls: set[str] = set()
        self._authorization_urls: set[str] = set()
        self._verified: VerifiedGrantPolicy | None = None
        self.exchange_started = False
        self.grant_ready = False
        self._probe_seen = False

    @property
    def selection(self):
        if self._verified is None or self._verified.authorization_endpoint is None:
            raise GrantRejected('OAuth metadata discovery is not complete')
        return self._verified.selection

    @property
    def requested_scopes(self):
        return None if self._verified is None else self._verified.requested_scopes

    async def request(self, request):
        url = str(request.url)
        bearer = request.headers.get('Authorization')
        if url == self.server_url:
            if request.method != 'GET' or (bearer and not self.grant_ready):
                raise GrantRejected('OAuth acquisition permits only its original GET probe')
            if self._probe_seen and not self.grant_ready:
                raise GrantRejected('OAuth acquisition cannot replay an unauthenticated probe')
            self._probe_seen = True
            return
        if bearer:
            raise GrantRejected('Credentials cannot leave the selected resource')
        if url in self._resource_urls | self._authorization_urls:
            if request.method != 'GET':
                raise GrantRejected('Metadata discovery must be an unauthenticated GET')
            if url in self._authorization_urls:
                self._verified.selection = replace(self._verified.selection, authorization_metadata=url)
            return
        if self._verified is not None and url == self._verified.token_endpoint:
            if not self._verified.redirected or self.exchange_started:
                raise GrantRejected('OAuth code exchange requires its original unused consent attempt')
            selected = replace(self.selection, scopes=self.requested_scopes)
            await validate_token_request(request, selected, grant_type='authorization_code')
            # Reserve before the durable-intent hook. An unacknowledged hook
            # must never make this operation replayable.
            self.exchange_started = True
            await self.on_exchange()
            return
        raise GrantRejected('An unexpected OAuth acquisition request was refused before network I/O')

    async def response(self, response):
        if response.is_redirect:
            raise GrantRejected('Redirects are refused for MCP and OAuth HTTP requests')
        url = str(response.request.url)
        if url == self.server_url:
            if self.grant_ready:
                return
            if response.status_code != 401:
                raise GrantRejected('The selected resource did not request OAuth authorization')
            advertised = extract_resource_metadata_from_www_auth(response)
            urls = build_protected_resource_metadata_discovery_urls(advertised, self.server_url)
            if any(_origin(candidate) != _origin(self.server_url) for candidate in urls):
                raise GrantRejected('Resource metadata must belong to the selected resource origin')
            self._resource_urls = set(urls)
            return
        if self._verified is not None and url == self._verified.token_endpoint:
            await reject_token_response(response, self.on_rejection)
            return
        if url not in self._resource_urls | self._authorization_urls:
            return
        if response.status_code in {404, 405}:
            return
        if response.status_code != 200:
            raise GrantRejected('OAuth metadata discovery did not return 200')
        body = await response.aread()
        if len(body) > self.response_max_bytes:
            raise GrantRejected('OAuth metadata exceeded its response budget')
        if url in self._resource_urls:
            document = metadata_document(body)
            metadata = validate_metadata(ProtectedResourceMetadata, document)
            issuers = document.get('authorization_servers')
            if not metadata.authorization_servers or not issuers:
                raise GrantRejected('Resource metadata does not identify an authorization server')
            issuer, resource = issuers[0], document.get('resource')
            _origin(issuer)
            urls = build_oauth_authorization_server_metadata_discovery_urls(issuer, self.server_url)
            selected = GrantSelection(self.server_url, resource, issuer, url, urls[0],
                self.identity.client_id, self.identity.redirect_uri, self.scopes)
            if self._verified is not None and self._verified.selection != selected:
                raise GrantRejected('Resource metadata changed during the authorization attempt')
            self._verified = VerifiedGrantPolicy(selected, response_max_bytes=self.response_max_bytes)
            await self._verified.response(response)
            self.approved_origins.add(_origin(issuer))
            self._authorization_urls = set(urls)
            return
        await self._verified.response(response)

    def redirect(self, url):
        self.selection
        return self._verified.redirect(url)


async def resource_lane(request: httpx2.Request, server_url: str) -> str:
    """Classify the original native envelope without rewriting its contents."""
    if str(request.url) != server_url:
        raise GrantRejected('Credentials cannot leave the selected resource')
    if request.method in {'GET', 'DELETE'}:
        return 'background'
    if request.method != 'POST':
        raise GrantRejected('Unsupported MCP resource HTTP method')
    try:
        message = json.loads(await request.aread())
        envelope = jsonrpc_message_adapter.validate_python(message)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
        raise GrantRejected('MCP requests require a valid JSON-RPC envelope') from None
    if set(message) - type(envelope).model_fields.keys():
        raise GrantRejected('MCP envelope contains fields outside its protocol shape')
    if isinstance(envelope, JSONRPCNotification):
        try:
            client_notification_adapter.validate_python(message)
        except ValidationError:
            raise GrantRejected('Only native client notifications may use background authority') from None
    return 'principal' if isinstance(envelope, JSONRPCRequest) else 'background'


class RefreshPolicy(VerifiedGrantPolicy):
    """Reverify the recorded metadata and allow one explicit Authlib refresh."""

    def __init__(self, selection, *, on_exchange, on_rejection=None, response_max_bytes=DEFAULT_RESPONSE_MAX_BYTES):
        super().__init__(selection, response_max_bytes=response_max_bytes)
        self.on_exchange, self.on_rejection = on_exchange, on_rejection
        self.exchange_started = False

    async def request(self, request):
        selected = self.selection
        url = str(request.url)
        if url in {selected.protected_metadata, selected.authorization_metadata}:
            if request.method != 'GET' or request.headers.get('Authorization'):
                raise GrantRejected('Metadata discovery must be an unauthenticated GET')
            return
        if url == self.token_endpoint and not self.exchange_started:
            await validate_token_request(request, selected, grant_type='refresh_token')
            self.exchange_started = True
            await self.on_exchange()
            return
        raise GrantRejected('An unexpected OAuth refresh request was refused before network I/O')

    async def response(self, response):
        await super().response(response)
        if str(response.request.url) == self.token_endpoint:
            await reject_token_response(response, self.on_rejection)


async def reject_token_response(response, on_rejection):
    """Never pass an AS error body into native SDK/Authlib exception text."""
    if response.status_code in {200, 201}:
        document = metadata_document(await response.aread())
        validate_metadata(OAuthToken, document)
        if 'error' in document:
            raise GrantRejected('OAuth token receipt contains an authorization error')
        return
    if response.status_code in {400, 401}:
        document = metadata_document(await response.aread())
        if isinstance(document.get('error'), str) and document['error'] and on_rejection is not None:
            await on_rejection()
    raise GrantRejected('OAuth token request failed; do not replay the exchange')
