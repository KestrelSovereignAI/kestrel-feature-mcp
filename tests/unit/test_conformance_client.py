"""The official-scenario driver fails clearly and closes real SDK resources."""

import base64
import json
from pathlib import Path, PurePosixPath
from unittest.mock import MagicMock
from urllib.parse import urlsplit

import pytest
from mcp.server.mcpserver.resources import TextResource

from tests.conformance import client


def test_frozen_profile_covers_the_supported_native_transport_paths():
    profile = client.load_profile()
    assert profile["protocol_version"] == "2026-07-28"
    assert profile["scenarios"] == [
        "tools_call", "request-metadata", "http-standard-headers",
        "http-custom-headers", "http-invalid-tool-headers", "json-schema-ref-no-deref",
    ]


@pytest.mark.parametrize("profile", [
    [], {}, {"protocol_version": ""},
    {"protocol_version": "2026-07-28", "scenarios": []},
    {"protocol_version": "2026-07-28", "scenarios": [""]},
    {"protocol_version": "2026-07-28", "scenarios": [1]},
    {"protocol_version": "2026-07-28", "scenarios": ["tools_call", "tools_call"]},
])
def test_malformed_profile_fails_clearly(tmp_path, monkeypatch, profile):
    monkeypatch.setattr(client, "__file__", str(tmp_path / "client.py"))
    (tmp_path / "profile.json").write_text(json.dumps(profile))
    with pytest.raises(ValueError, match="profile"):
        client.load_profile()


def test_harness_lock_uses_only_portable_registry_packages():
    directory = Path(client.__file__).parent
    manifest = json.loads((directory / "package.json").read_text())
    lock = json.loads((directory / "package-lock.json").read_text())
    assert lock["name"] == manifest["name"]
    assert lock.get("version") == manifest.get("version"), "Lock metadata must describe the manifest, not a local install"
    assert lock["packages"][""]["dependencies"] == manifest["dependencies"]
    for name, package in lock["packages"].items():
        assert not package.get("link"), f"Conformance cannot require a local package link: {name}"
        if name:
            assert name.startswith("node_modules/"), f"Package lies outside the harness: {name}"
            assert ".." not in PurePosixPath(name).parts, f"Package escapes the harness: {name}"
        if "resolved" in package:
            assert urlsplit(package["resolved"]).scheme == "https", f"Package requires a non-registry source: {name}"


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


@pytest.mark.parametrize("scenario", [
    "http-standard-headers", "http-custom-headers", "json-schema-ref-no-deref",
])
async def test_added_scenarios_drive_native_io_and_close_the_original_connection(
    tracked_connections, mcp_http_server, monkeypatch, scenario,
):
    peer = mcp_http_server
    if scenario == "http-standard-headers":
        @peer.mcp.tool(name="test_headers")
        async def header_tool() -> str:
            return "headers"

        @peer.mcp.tool(name="my-hyphenated-tool")
        async def hyphenated_tool() -> str:
            return "hyphenated"

        peer.mcp.add_resource(TextResource(
            uri="file:///path/to/file%20name.txt", name="Header resource", text="native resource",
        ))
    elif scenario == "http-custom-headers":
        @peer.mcp.tool()
        async def test_custom_headers(region: str, priority: int, verbose: bool) -> str:
            return region

        @peer.mcp.tool()
        async def test_custom_headers_null(region: str, priority: int, verbose: bool | None) -> str:
            return region

        peer.settings["advertised_tool_contracts"] = {
            name: {"input_schema": {"type": "object", "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "priority": {"type": "integer", "x-mcp-header": "Priority"},
                "verbose": {"type": "boolean", "x-mcp-header": "Verbose"},
            }, "required": ["region", "priority"]}}
            for name in ["test_custom_headers", "test_custom_headers_null"]
        }
        monkeypatch.setenv("MCP_CONFORMANCE_CONTEXT", json.dumps({"toolCalls": [
            {"name": "test_custom_headers", "arguments": {"region": "Hello, 世界", "priority": 42, "verbose": False}},
            {"name": "test_custom_headers_null", "arguments": {"region": "us-east1", "priority": 1, "verbose": None}},
        ]}))
    else:
        @peer.mcp.tool()
        async def lookup_user(id: str) -> str:
            return id

        peer.settings["advertised_tool_contracts"] = {"lookup_user": {"input_schema": {
            "type": "object", "$defs": {"userId": {"type": "string"}},
            "properties": {"id": {"$ref": "#/$defs/userId"},
                           "profile": {"$ref": peer.url + "/schema"}},
            "required": ["id"],
        }}}

    await client.run_scenario(peer.url, scenario, "2026-07-28")
    assert len(tracked_connections) == 1
    assert not tracked_connections[0].is_connected and tracked_connections[0]._task is None
    calls = [(scope, json.loads(body)) for scope, body in peer.requests
             if body and json.loads(body).get("method") == "tools/call"]
    if scenario == "http-standard-headers":
        assert [body["params"]["name"] for _, body in calls] == ["my-hyphenated-tool", "test_headers"]
        for scope, body in calls:
            headers = dict(scope["headers"])
            assert headers[b"mcp-method"] == b"tools/call"
            assert headers[b"mcp-name"].decode() == body["params"]["name"]
        resources = [(scope, json.loads(body)) for scope, body in peer.requests
                     if body and json.loads(body).get("method") == "resources/read"]
        assert len(resources) == 1
        assert dict(resources[0][0]["headers"])[b"mcp-name"] == b"file:///path/to/file%20name.txt"
    elif scenario == "http-custom-headers":
        assert [body["params"]["name"] for _, body in calls] == ["test_custom_headers", "test_custom_headers_null"]
        first = dict(calls[0][0]["headers"])
        assert first[b"mcp-param-region"] == b"=?base64?" + base64.b64encode("Hello, 世界".encode()) + b"?="
        assert first[b"mcp-param-priority"] == b"42" and first[b"mcp-param-verbose"] == b"false"
        assert "verbose" in calls[1][1]["params"]["arguments"]
        assert b"mcp-param-verbose" not in dict(calls[1][0]["headers"])
    else:
        assert not calls
        assert not any(scope["path"].endswith("/schema") for scope, _ in peer.requests)


@pytest.mark.parametrize("context", [None, "{", "[]", "{}", '{"toolCalls":[]}',
    '{"toolCalls":[{"name":"tool","arguments":[]}]}',
    '{"toolCalls":[[]]}', '{"toolCalls":[{"arguments":{}}]}',
    '{"toolCalls":[{"name":"","arguments":{}}]}',
    '{"toolCalls":[{"name":1,"arguments":{}}]}'])
async def test_bad_custom_header_fixture_context_is_refused_before_io(monkeypatch, context):
    if context is None:
        monkeypatch.delenv("MCP_CONFORMANCE_CONTEXT", raising=False)
    else:
        monkeypatch.setenv("MCP_CONFORMANCE_CONTEXT", context)
    connect = MagicMock(side_effect=AssertionError("bad fixture context reached network"))
    monkeypatch.setattr(client, "MCPConnection", connect)
    with pytest.raises(ValueError, match="context|toolCalls|arguments"):
        await client.run_scenario("http://127.0.0.1:1", "http-custom-headers", "2026-07-28")
    connect.assert_not_called()


async def test_native_catalog_excludes_every_invalid_header_declaration_and_keeps_valid_tools(
    tracked_connections, mcp_http_server,
):
    peer = mcp_http_server

    peer.mcp.remove_tool("echo")
    peer.mcp.remove_tool("fail")

    @peer.mcp.tool()
    async def valid_tool(region: str) -> str:
        return region

    invalid = {
        "empty_header": {"value": {"type": "string", "x-mcp-header": ""}},
        **{kind + "_header": {"value": {"type": kind, "x-mcp-header": "Value"}}
           for kind in ["object", "array", "null", "number"]},
        **{"duplicate_" + name: {
            "first": {"type": "string", "x-mcp-header": "Region"},
            "second": {"type": "string", "x-mcp-header": header},
        } for name, header in [("same_case", "Region"), ("diff_case", "region")]},
        **{name + "_in_name": {"value": {"type": "string", "x-mcp-header": header}}
           for name, header in [("space", "bad name"), ("colon", "bad:name"),
                                ("non_ascii", "région"), ("control_char", "bad\x00name")]},
    }
    contracts = {"valid_tool": {"input_schema": {
        "type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
        "required": ["region"],
    }}}
    for suffix, properties in invalid.items():
        name = "invalid_" + suffix

        async def rejected_tool(value: str) -> str:
            raise AssertionError("A rejected tool reached the native server")

        peer.mcp.tool(name=name)(rejected_tool)
        contracts[name] = {"input_schema": {"type": "object", "properties": properties}}
    peer.settings["advertised_tool_contracts"] = contracts
    connection = client.MCPConnection(peer.url)
    try:
        # Assert the actual production catalog, rather than having the driver
        # filter fixture names before making a passing call.
        tools = await connection.connect()
        assert {tool.name for tool in tools} == {"valid_tool"}
    finally:
        await connection.close()
    await client.run_scenario(peer.url, "http-invalid-tool-headers", "2026-07-28")
    assert len(tracked_connections) == 2
    assert all(not conn.is_connected and conn._task is None for conn in tracked_connections)
    calls = [(scope, json.loads(body)) for scope, body in peer.requests
             if body and json.loads(body).get("method") == "tools/call"]
    assert len(calls) == 1 and calls[0][1]["params"]["name"] == "valid_tool"
    assert calls[0][1]["params"]["arguments"] == {"region": "us-west1"}
    assert dict(calls[0][0]["headers"])[b"mcp-param-region"] == b"us-west1"


async def test_invalid_header_scenario_refuses_an_unexpected_native_catalog(
    tracked_connections, mcp_http_server,
):
    @mcp_http_server.mcp.tool()
    async def valid_tool(region: str) -> str:
        return region

    # The normal fixture's echo/fail tools are valid but absent from the
    # official fixture. An unexpected catalog must fail before valid_tool is
    # called; otherwise the harness's valid-tool observation would turn green.
    with pytest.raises(RuntimeError, match="unexpected.*catalog"):
        await client.run_scenario(mcp_http_server.url, "http-invalid-tool-headers", "2026-07-28")
    assert len(tracked_connections) == 1
    assert not tracked_connections[0].is_connected and tracked_connections[0]._task is None
    assert not any(json.loads(body).get("method") == "tools/call"
                   for _, body in mcp_http_server.requests if body)


@pytest.mark.parametrize("scenario", [
    "http-standard-headers", "http-custom-headers", "http-invalid-tool-headers", "json-schema-ref-no-deref",
])
async def test_missing_added_fixture_tools_close_without_partial_calls(
    tracked_connections, mcp_http_server, monkeypatch, scenario,
):
    monkeypatch.setenv("MCP_CONFORMANCE_CONTEXT", json.dumps({"toolCalls": [
        {"name": "missing_tool", "arguments": {}},
    ]}))
    with pytest.raises(RuntimeError, match="did not advertise"):
        await client.run_scenario(mcp_http_server.url, scenario, "2026-07-28")
    assert len(tracked_connections) == 1
    assert not tracked_connections[0].is_connected and tracked_connections[0]._task is None
    assert not any(json.loads(body).get("method") == "tools/call"
                   for _, body in mcp_http_server.requests if body)
