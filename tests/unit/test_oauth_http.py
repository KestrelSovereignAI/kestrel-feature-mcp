"""Native HTTPX response contracts shared by OAuth and ordinary MCP."""

import httpx2
import pytest

from kestrel_feature_mcp.http_limits import MCPResponseBudget, MCPResponseLimitError
from kestrel_feature_mcp.oauth_http import BudgetedTransport
from kestrel_feature_mcp.oauth_policy import GrantRejected
from tests.unit.test_mcp_response_limits import CountedBody


@pytest.mark.parametrize('timeout', [0, -1, True, None, '20', float('inf'), float('nan'), 10**400])
async def test_oauth_transport_refuses_invalid_deadlines_before_io(timeout):
    native = httpx2.AsyncHTTPTransport()
    try:
        with pytest.raises(GrantRejected, match='finite and positive'):
            BudgetedTransport(native, 4096, timeout)
    finally:
        await native.aclose()


async def test_oauth_total_body_budget_cannot_be_bypassed_with_sse_mime():
    body = CountedBody([b'data: ' + b'x' * 4097])
    response = httpx2.Response(200, headers={'Content-Type': 'text/event-stream'}, stream=body)
    await MCPResponseBudget(4096, allow_sse=False)(response)
    with pytest.raises(MCPResponseLimitError, match='byte limit'):
        await response.aread()
    await response.aclose()
    assert body.closes == 1


@pytest.mark.parametrize('value', [None, 0, 1, 'false'])
def test_body_streaming_policy_must_be_an_explicit_boolean(value):
    with pytest.raises(ValueError, match='SSE policy'):
        MCPResponseBudget(4096, allow_sse=value)


async def test_unapproved_oauth_origin_is_refused_before_any_dns(monkeypatch):
    import socket
    from kestrel_feature_mcp.oauth_http import OriginPinnedTransport
    def forbidden(*args, **kwargs):
        raise AssertionError('no DNS before policy approval')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    transport = OriginPinnedTransport(lambda: {'https://resource.example'})
    try:
        with pytest.raises(GrantRejected, match='currently approved'):
            await transport.handle_async_request(httpx2.Request('GET', 'https://issuer.example/token'))
    finally:
        await transport.aclose()
    with pytest.raises(GrantRejected, match='currently approved'):
        await transport.handle_async_request(httpx2.Request('GET', 'https://resource.example/mcp'))
