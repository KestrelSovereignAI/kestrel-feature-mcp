"""Shared native HTTPX OAuth transport budgets and public authentication hooks."""

from __future__ import annotations

import asyncio
import math
import sys
from typing import Protocol

import httpx2

from .http_limits import MCPResponseBudget, MCPResponseLimitError, identity_accept_encoding
from .oauth_policy import GrantRejected, response_budget


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
        if (type(timeout) not in (int, float) or timeout <= 0
                or timeout > sys.float_info.max or not math.isfinite(timeout)):
            raise GrantRejected("OAuth network timeout must be finite and positive")
        self.timeout = timeout

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
