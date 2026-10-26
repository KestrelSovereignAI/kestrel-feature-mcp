"""Untrusted wire budgets through the actual native SDK and owned HTTP peer."""

import asyncio
import tracemalloc

import pytest
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
