"""Untrusted wire budgets through the actual native SDK and owned HTTP peer."""

import asyncio
import tracemalloc

import pytest
import httpx2
from mcp.shared.exceptions import MCPError

from kestrel_feature_mcp.connection import MCPConnection


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True,
    "resource_wire_mode": "held"}], indirect=True)
async def test_oversized_native_json_is_refused_without_waiting_for_stream_eof(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url, call_timeout=1)
    try:
        await connection.connect()
        with pytest.raises(MCPError, match="MCP response byte limit"):
            await connection.read_resource("ui://status/view.html", incarnation=connection.incarnation)
        await asyncio.wait_for(mcp_http_server.settings["resource_wire_closed"].wait(), 1)
        assert mcp_http_server.settings["resource_reads"] == ["resources/read"]
    finally:
        mcp_http_server.settings["release_resource_wire"].set()
        await connection.close()


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True,
    "resource_wire_mode": "gzip"}], indirect=True)
async def test_compressed_response_cannot_allocate_decoded_resource_before_refusal(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url, call_timeout=1)
    try:
        await connection.connect()
        tracemalloc.start()
        try:
            with pytest.raises(MCPError) as caught:
                await connection.read_resource("ui://status/view.html", incarnation=connection.incarnation)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 1024 * 1024, "wire response allocated decompressed content before checking its encoding"
        assert "MCP response content encoding" in str(caught.value)
        assert mcp_http_server.settings["resource_reads"] == ["resources/read"]
    finally:
        await connection.close()


@pytest.mark.parametrize("mcp_http_server", [{"resource_wire_mode": mode,
    "resource_wire_method": "tools/call"} for mode in ["held", "gzip"]], indirect=True)
async def test_a_bounded_reply_after_real_tool_effects_is_reported_unknown(mcp_http_server):
    from kestrel_feature_mcp.dynamic_tools import build_wrappers
    connection = MCPConnection(mcp_http_server.url, call_timeout=1)
    try:
        tools = await connection.connect()
        native = next(tool for tool in tools if tool.name == "echo")
        wrapper = build_wrappers("wire", [native.model_dump(by_alias=True)], connection.call_tool)[0]
        result = await wrapper.execute(text="performed once")
        assert mcp_http_server.witness == ["performed once"]
        assert result["status"] == "error"
        assert result.get("data", {}).get("execution_outcome") == "unknown"
        assert "Do not replay" in result["error"]
    finally:
        mcp_http_server.settings["release_resource_wire"].set()
        await connection.close()


@pytest.mark.parametrize("value", [0, -1, True, False, 1.5, float("inf"), "4096", None])
def test_invalid_response_budgets_fail_before_connect(value):
    with pytest.raises(ValueError, match="positive integer"):
        MCPConnection("http://127.0.0.1:1/mcp", response_max_bytes=value)


@pytest.mark.parametrize("headers", [{"Accept-Encoding": "gzip"}, {"accept-encoding": "br"}])
def test_compressed_request_configuration_is_refused(headers):
    with pytest.raises(ValueError, match="identity Accept-Encoding"):
        MCPConnection("http://127.0.0.1:1/mcp", headers=headers)


class CountedBody(httpx2.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks, self.reads, self.closes = chunks, 0, 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closes += 1


@pytest.mark.parametrize("length", ["4097", "-1", "invalid"])
async def test_declared_body_refusals_read_no_bytes_and_close_once(length):
    from kestrel_feature_mcp.http_limits import MCPResponseBudget, MCPResponseLimitError
    body = CountedBody([b"not consumed"])
    response = httpx2.Response(200, headers={"Content-Length": length}, stream=body)
    await MCPResponseBudget(4096)(response)
    with pytest.raises(MCPResponseLimitError):
        await response.aread()
    await response.aclose()
    assert (body.reads, body.closes) == (0, 1)


@pytest.mark.parametrize("size", [4, 5])
async def test_finite_bodies_enforce_the_exact_raw_byte_boundary(size):
    from kestrel_feature_mcp.http_limits import MCPResponseBudget, MCPResponseLimitError
    body = CountedBody(["字".encode("utf-8"), b"a" * (size - 3)])
    response = httpx2.Response(200, stream=body)
    await MCPResponseBudget(4)(response)
    if size == 4:
        assert await response.aread() == "字a".encode("utf-8")
    else:
        with pytest.raises(MCPResponseLimitError, match="byte limit"):
            await response.aread()
    await response.aclose()
    assert body.closes == 1


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True,
    "resource_wire_mode": "sse-many"}], indirect=True)
async def test_native_sse_can_outlive_the_total_body_budget_with_bounded_events(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url, response_max_bytes=4096, call_timeout=1)
    try:
        await connection.connect()
        result = await connection.read_resource("ui://status/view.html", incarnation=connection.incarnation)
        assert result.contents[0].text == "<!doctype html><p>Status</p>"
        assert mcp_http_server.settings["wire_comments_sent"] == 10
    finally:
        await connection.close()
    for scope, _ in mcp_http_server.requests:
        assert dict(scope["headers"])[b"accept-encoding"] == b"identity;q=1, *;q=0"


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True,
    "resource_wire_mode": "sse-oversized"}], indirect=True)
async def test_native_sdk_enforces_the_configured_per_event_sse_limit(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url, response_max_bytes=4096, call_timeout=1)
    try:
        await connection.connect()
        with pytest.raises(MCPError, match="(?i)exceed|event.*(?:size|limit)") as caught:
            await connection.read_resource("ui://status/view.html", incarnation=connection.incarnation)
        assert "4096" in str(caught.value)
        assert mcp_http_server.settings["resource_reads"] == ["resources/read"]
    finally:
        await connection.close()
