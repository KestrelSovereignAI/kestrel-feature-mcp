"""Manual acceptance role: discovery only, never the production MCP policy."""

from __future__ import annotations

import json

import httpx2
from mcp.client.auth.utils import create_client_info_from_metadata_url
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp_types import JSONRPCError, JSONRPCResponse, jsonrpc_message_adapter
from pydantic import ValidationError

from kestrel_feature_mcp.oauth_policy import (
    DEFAULT_RESPONSE_MAX_BYTES, GrantRejected, GrantSelection, VerifiedGrantPolicy,
    _fields, response_budget, validate_token_request,
)
from kestrel_feature_mcp.oauth_http import GuardedAuth


class GrantPolicy(VerifiedGrantPolicy):
    """Frozen manual profile, with a deliberate discovery-only resource phase."""

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
                try:
                    message = json.loads(await request.aread())
                    envelope = jsonrpc_message_adapter.validate_python(message)
                except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
                    raise GrantRejected("Discovery requests require a valid JSON-RPC envelope") from None
                if ("method" not in message and isinstance(envelope, (JSONRPCResponse, JSONRPCError))
                        and set(message) <= type(envelope).model_fields.keys()):
                    # Standard SDK replies (for example a server ping) do not
                    # initiate a tool call. Keep the exact envelope unchanged.
                    return
                if message.get("method") in {
                    "server/discover", "initialize", "notifications/initialized", "tools/list",
                    "ping", "notifications/cancelled",
                }:
                    return
            raise GrantRejected("The acceptance spike only discovers and lists MCP tools")
        if url == self.token_endpoint and request.method == "POST":
            if not self.redirected or request.headers.get("Authorization"):
                raise GrantRejected("Token exchange requires the approved public-client attempt")
            fields = _fields((await request.aread()).decode("ascii"), limit=8)
            kind = fields.get("grant_type", [""])[0]
            await validate_token_request(request, selected, grant_type=kind)
            return
        raise GrantRejected("An unexpected request was refused before network I/O")


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
        requested = self.policy.requested_scopes
        granted = requested if tokens.scope is None else frozenset(tokens.scope.split())
        if (not self.policy.redirected or requested is None or not granted
                or not granted <= requested):
            raise GrantRejected("A token exceeded the operator-approved grant")
        # RFC 6749 section 5.1: omitted scope is the actual request, not the profile ceiling.
        self._tokens = tokens.model_copy(update={"scope": " ".join(sorted(granted))}, deep=True)


