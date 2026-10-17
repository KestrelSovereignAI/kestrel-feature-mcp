"""The official-scenario driver fails clearly and closes real SDK resources."""

import json
from unittest.mock import MagicMock

import pytest

from tests.conformance import client


@pytest.fixture
def tracked_connections(monkeypatch):
    connections = []
    real_connection = client.MCPConnection

    def track(*args, **kwargs):
        connection = real_connection(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(client, "MCPConnection", track)
    return connections


@pytest.mark.parametrize("scenario,version", [
    ("", "2026-07-28"), ("unknown", "2026-07-28"),
    ("tools_call", "2025-11-25"), ("request-metadata", ""),
])
async def test_invalid_harness_contract_fails_before_connection_io(monkeypatch, scenario, version):
    connect = MagicMock(side_effect=AssertionError("invalid harness contract reached network"))
    monkeypatch.setattr(client, "MCPConnection", connect)
    with pytest.raises(ValueError, match="scenario|wire"):
        await client.run_scenario("http://127.0.0.1:1", scenario, version)
    connect.assert_not_called()


@pytest.mark.parametrize("mcp_http_server,message", [
    ({}, "did not advertise add_numbers"), ({"legacy": True}, "negotiated 2025-11-25"),
], indirect=["mcp_http_server"])
async def test_fixture_or_version_mismatch_closes_real_native_connection(tracked_connections, mcp_http_server, message):
    with pytest.raises(RuntimeError, match=message):
        await client.run_scenario(mcp_http_server.url, "tools_call", "2026-07-28")
    assert len(tracked_connections) == 1
    assert not tracked_connections[0].is_connected and tracked_connections[0]._task is None
    assert not any(json.loads(body).get("method") == "tools/call" for _, body in mcp_http_server.requests if body)


@pytest.mark.parametrize("arguments", [[], ["http://fixture.invalid", "extra"]])
def test_cli_requires_exactly_one_server_url(monkeypatch, arguments):
    monkeypatch.setattr(client.sys, "argv", ["client.py", *arguments])
    with pytest.raises(ValueError, match="only argument"):
        client.main()


@pytest.mark.parametrize("scenario", ["tools_call", "request-metadata"])
@pytest.mark.parametrize("tool_error", [False, True])
async def test_driver_calls_real_peer_and_closes_after_success_or_error(tracked_connections, mcp_http_server, scenario, tool_error):
    @mcp_http_server.mcp.tool()
    async def add_numbers(a: int, b: int) -> int:
        if tool_error:
            raise ValueError("conformance peer rejected addition")
        return a + b

    if tool_error:
        with pytest.raises(RuntimeError, match="conformance tool call failed"):
            await client.run_scenario(mcp_http_server.url, scenario, "2026-07-28")
    else:
        await client.run_scenario(mcp_http_server.url, scenario, "2026-07-28")
    assert len(tracked_connections) == 1
    assert not tracked_connections[0].is_connected and tracked_connections[0]._task is None
    calls = [json.loads(body) for _, body in mcp_http_server.requests
             if body and json.loads(body).get("method") == "tools/call"]
    assert len(calls) == 1
    assert calls[0]["params"]["name"] == "add_numbers"
    assert calls[0]["params"]["arguments"] == {"a": 5, "b": 3}
