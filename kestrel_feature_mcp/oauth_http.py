"""Shared native HTTPX OAuth transport budgets and public authentication hooks."""

from __future__ import annotations

import asyncio
from typing import Protocol

import httpx2

from .http_limits import MCPResponseBudget, MCPResponseLimitError, identity_accept_encoding
from .oauth_policy import GrantRejected, positive_seconds, response_budget


class AuthFlowPolicy(Protocol):
    async def request(self, request: httpx2.Request) -> None: ...
    async def response(self, response: httpx2.Response) -> None: ...


class _DeadlineStream(httpx2.AsyncByteStream):
    def __init__(self, stream, deadline):
        self.stream, self.deadline, self.closed = stream, deadline, False

    async def __aiter__(self):
        try:
            async with asyncio.timeout_at(self.deadline):
                async for chunk in self.stream:
                    yield chunk
        except MCPResponseLimitError:
            raise GrantRejected("OAuth HTTP response budget or content encoding refused") from None
        finally:
            await self.aclose()

    async def aclose(self):
        if not self.closed:
            self.closed = True
            await self.stream.aclose()


class BudgetedTransport(httpx2.AsyncBaseTransport):
    """Keep original HTTP objects and pinning, bounding each exchange separately.

    Auth-generated requests get a fresh network deadline. Browser consent has
    its own lifetime. The canonical response budget refuses decompression and
    counts every OAuth body, including a misleading event-stream MIME type.
    Standard Accept-Encoding negotiation is set to identity before dispatch;
    credential headers and protocol payloads are never translated.
    """

    def __init__(self, transport, limit, timeout):
        self.transport, self.limit = transport, response_budget(limit)
        self.timeout = positive_seconds(timeout)

    async def handle_async_request(self, request):
        try:
            request.headers['Accept-Encoding'] = identity_accept_encoding(request.headers.get('accept-encoding'))
        except ValueError:
            raise GrantRejected("OAuth HTTP requires identity Accept-Encoding") from None
        deadline = asyncio.get_running_loop().time() + self.timeout
        async with asyncio.timeout_at(deadline):
            response = await self.transport.handle_async_request(request)
        await MCPResponseBudget(self.limit, allow_sse=False)(response)
        response.stream = _DeadlineStream(response.stream, deadline)
        return response

    async def aclose(self):
        await self.transport.aclose()


class GuardedAuth(httpx2.Auth):
    """Apply role policy around the SDK's public HTTP authentication generator.

    The original request and response objects are retained. The SDK owns
    discovery, PKCE, callback validation, token exchange and authentication.
    Interactive acquisition and resource credentials use separate policies.
    This wrapper never interprets or rewrites native request/response payloads.
    """

    def __init__(self, provider: httpx2.Auth, policy: AuthFlowPolicy):
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


class OriginPinnedTransport(httpx2.AsyncBaseTransport):
    """Resolve only policy-approved origins, retaining one native pinned owner."""

    def __init__(self, approved_origins):
        self._approved_origins = approved_origins
        self._transports = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def handle_async_request(self, request):
        from kestrel_sdk.security.outbound import assert_safe_url, pinned_httpx2_async_transport
        from .oauth_policy import _origin

        url = str(request.url)
        origin = _origin(url)
        async with self._lock:
            if self._closed or origin not in self._approved_origins():
                raise GrantRejected('OAuth origin is not currently approved for network I/O')
            if origin not in self._transports:
                endpoint = await assert_safe_url(url, allowed_schemes=('https',))
                if self._closed or origin not in self._approved_origins():
                    raise GrantRejected('OAuth origin approval ended before transport creation')
                self._transports[origin] = pinned_httpx2_async_transport(endpoint)
            transport = self._transports[origin]
        return await transport.handle_async_request(request)

    async def aclose(self):
        async with self._lock:
            self._closed = True
            for origin, transport in tuple(self._transports.items()):
                await transport.aclose()
                del self._transports[origin]


async def fetch_client_document(identity, expected, *, transport, timeout):
    """Verify the public web CIMD matches Core's single rendering exactly."""
    from .http_limits import IDENTITY_ACCEPT_ENCODING
    from .oauth_policy import metadata_document

    async with httpx2.AsyncClient(transport=transport, trust_env=False,
            follow_redirects=False, timeout=timeout,
            headers={'Accept-Encoding': IDENTITY_ACCEPT_ENCODING}) as client:
        response = await client.get(identity.client_id)
        if (response.status_code != 200
                or response.headers.get('Content-Type', '').split(';', 1)[0] != 'application/json'):
            raise GrantRejected('The public web CIMD did not return 200 application/json')
        document = metadata_document(await response.aread())
    if (document != expected or document.get('client_id') != identity.client_id
            or document.get('redirect_uris') != [identity.redirect_uri]
            or document.get('application_type') != 'web'
            or document.get('token_endpoint_auth_method') != 'none'
            or document.get('grant_types') != ['authorization_code', 'refresh_token']
            or document.get('response_types') != ['code']
            or any(field in document for field in ('client_secret', 'jwks', 'jwks_uri'))):
        raise GrantRejected('The published identity changed the exact Core web client')
    return document
