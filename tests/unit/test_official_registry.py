"""Published Registry JSON remains intact through the native HTTPS boundary."""

import asyncio
import copy
import hashlib
from importlib.resources import files
import json
from pathlib import Path
import socket
import time
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx2
import pytest

from kestrel_feature_mcp import official_registry as module
from kestrel_feature_mcp.official_registry import (
    OfficialRegistryClient, OfficialRegistryError, RegistrySettings,
)
from kestrel_feature_mcp.feature import MCPAgent
from kestrel_sdk.tools.result import ToolResultStatus


@pytest.fixture
def page():
    return json.loads((Path(__file__).parents[1] / "fixtures/official_registry_v0_1.json").read_text())


@pytest.fixture
def registry_http(monkeypatch):
    state = SimpleNamespace(requests=[], approved=[], responses=[], closed=0)

    async def respond(request):
        state.requests.append(request)
        response = state.responses.pop(0)
        if callable(response):
            return await response(request)
        return response

    class ObservedTransport(httpx2.MockTransport):
        async def aclose(self):
            state.closed += 1
            await super().aclose()

    def transport(validated):
        state.approved.append(validated)
        return ObservedTransport(respond)

    def dns(host, port, *, type, proto):
        assert host == "registry.example" and port == 443
        assert type == socket.SOCK_STREAM and proto == socket.IPPROTO_TCP
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr(module, "pinned_httpx2_async_transport", transport)
    state.raw_dial = AsyncMock(side_effect=AssertionError("registry bypassed its pinned transport"))
    monkeypatch.setattr("httpcore2.AnyIOBackend.connect_tcp", state.raw_dial)
    state.client = OfficialRegistryClient(RegistrySettings(api_url="https://registry.example/v0.1"))
    return state


def test_registry_contract_is_the_pinned_published_openapi_snapshot():
    raw = files("kestrel_feature_mcp").joinpath("registry_openapi_2025_12_01.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "69a092a20321d6616d0e83933b1de39916bd0fa87975d7931ef3b92f825c7edc"
    contract = json.loads(raw)
    assert contract["info"]["version"] == "2025-12-01"
    assert "/v0.1/servers" in contract["paths"]


@pytest.mark.asyncio
async def test_search_preserves_published_records_source_and_opaque_cursor(registry_http, page):
    state = registry_http
    state.responses.append(httpx2.Response(200, json=page))
    result = await state.client.search("notes", cursor="opaque:+ /?&=", limit=1)
    assert result.registry_url == "https://registry.example/v0.1"
    assert result.payload == page
    assert result.servers[0] == page["servers"][0]
    assert result.next_cursor == page["metadata"]["nextCursor"]
    assert dict(state.requests[0].url.params) == {
        "search": "notes", "cursor": "opaque:+ /?&=", "limit": "1", "version": "latest",
    }
    assert state.approved[0].url == "https://registry.example/v0.1/servers"
    assert [str(ip) for ip in state.approved[0].ip_addresses] == ["8.8.8.8"]
    state.raw_dial.assert_not_awaited()
    assert state.closed == 1
    # A page never follows its own cursor or a remote endpoint automatically.
    assert len(state.requests) == len(state.approved) == 1


@pytest.mark.asyncio
async def test_each_explicit_next_page_preserves_its_cursor_exactly(registry_http, page):
    state = registry_http
    state.responses.extend([httpx2.Response(200, json=page), httpx2.Response(200, json={"servers": []})])
    first = await state.client.search("notes")
    second = await state.client.search("notes", cursor=first.next_cursor)
    assert state.requests[1].url.params["cursor"] == page["metadata"]["nextCursor"]
    assert second.servers == [] and second.next_cursor is None
    assert len(state.approved) == state.closed == 2


@pytest.mark.asyncio
async def test_repeated_cursor_is_an_error_instead_of_an_empty_success(registry_http, page):
    registry_http.responses.append(httpx2.Response(200, json=page))
    with pytest.raises(OfficialRegistryError, match="repeated.*cursor"):
        await registry_http.client.search(cursor=page["metadata"]["nextCursor"])


@pytest.mark.asyncio
async def test_a_page_cannot_exceed_the_requested_limit(registry_http, page):
    page["servers"].append(copy.deepcopy(page["servers"][0]))
    page["metadata"]["count"] = 2
    registry_http.responses.append(httpx2.Response(200, json=page))
    with pytest.raises(OfficialRegistryError, match="page size"):
        await registry_http.client.search(limit=1)


@pytest.mark.asyncio
async def test_page_count_must_describe_the_returned_page(registry_http, page):
    page["metadata"]["count"] = 20
    registry_http.responses.append(httpx2.Response(200, json=page))
    with pytest.raises(OfficialRegistryError, match="count"):
        await registry_http.client.search()


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["latest", "1.2.3", "..", "1.2.3+build/metadata"])
async def test_detail_lookup_encodes_each_path_segment_and_preserves_metadata(registry_http, page, version):
    response = copy.deepcopy(page["servers"][0])
    if version != "latest":
        response["server"]["version"] = version
    registry_http.responses.append(httpx2.Response(200, json=response))
    result = await registry_http.client.get("com.example/notes", version=version)
    assert result == response
    raw_path = registry_http.requests[0].url.raw_path
    assert b"com.example%2Fnotes/versions/" in raw_path
    if version == "..":
        assert raw_path.endswith(b"/%2E%2E")
    elif "/" in version:
        assert raw_path.endswith(b"/1.2.3%2Bbuild%2Fmetadata")


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("name", "com.example/other"), ("version", "9.0.0")])
async def test_detail_refuses_a_different_identity(registry_http, page, field, value):
    response = copy.deepcopy(page["servers"][0])
    response["server"][field] = value
    registry_http.responses.append(httpx2.Response(200, json=response))
    with pytest.raises(OfficialRegistryError, match="different server"):
        await registry_http.client.get("com.example/notes", version="1.2.3")


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {}, {"servers": "broken"}, {"servers": [{"server": {"name": "notes"}}]},
    {"servers": [], "metadata": {"nextCursor": 12}},
])
async def test_malformed_pages_fail_the_published_contract(registry_http, payload):
    registry_http.responses.append(httpx2.Response(200, json=payload))
    with pytest.raises(OfficialRegistryError, match="schema error at"):
        await registry_http.client.search()


@pytest.mark.asyncio
async def test_malformed_remote_metadata_is_not_silently_dropped(registry_http, page):
    page["servers"][0]["server"]["remotes"][0]["type"] = "private-protocol"
    registry_http.responses.append(httpx2.Response(200, json=page))
    with pytest.raises(OfficialRegistryError, match="schema error at"):
        await registry_http.client.search()


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    httpx2.Response(302, headers={"Location": "https://127.0.0.1/metadata"}),
    httpx2.Response(429), httpx2.Response(503), httpx2.Response(200, content=b"not JSON"),
])
async def test_failed_http_or_json_is_actionable_and_never_follows_redirects(registry_http, response):
    registry_http.responses.append(response)
    with pytest.raises(OfficialRegistryError, match="request failed"):
        await registry_http.client.search()
    assert len(registry_http.requests) == registry_http.closed == 1


@pytest.mark.asyncio
async def test_response_limit_is_enforced_before_json_parsing(registry_http):
    registry_http.client = OfficialRegistryClient(RegistrySettings(api_url="https://registry.example/v0.1", max_response_bytes=8))
    registry_http.responses.append(httpx2.Response(200, content=b" " * 100))
    with pytest.raises(OfficialRegistryError, match="byte limit"):
        await registry_http.client.search()
    assert registry_http.closed == 1


@pytest.mark.asyncio
async def test_streaming_limit_stops_before_reading_the_rest_of_the_body(registry_http):
    reads = []

    class BoundedBody(httpx2.AsyncByteStream):
        async def __aiter__(self):
            reads.append(1)
            yield b" " * 9
            pytest.fail("registry read beyond its byte budget")

    registry_http.client = OfficialRegistryClient(RegistrySettings(api_url="https://registry.example/v0.1", max_response_bytes=8))
    registry_http.responses.append(httpx2.Response(200, stream=BoundedBody()))
    with pytest.raises(OfficialRegistryError, match="byte limit"):
        await registry_http.client.search()
    assert reads == [1]
    assert registry_http.closed == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    b'{"servers":[],"_meta":{"invalid":NaN}}',
    b'{"servers":[],"_meta":{"invalid":Infinity}}',
    b"[" * 10000 + b"]" * 10000,
])
async def test_invalid_json_constants_and_excessive_nesting_fail_clearly(registry_http, body):
    registry_http.responses.append(httpx2.Response(200, content=body))
    with pytest.raises(OfficialRegistryError):
        await registry_http.client.search()
    assert registry_http.closed == 1


@pytest.mark.asyncio
async def test_total_deadline_closes_the_transport(registry_http):
    registry_http.client = OfficialRegistryClient(RegistrySettings(api_url="https://registry.example/v0.1", timeout=0.02))

    async def slow(_):
        await asyncio.sleep(10)
        return httpx2.Response(200)

    registry_http.responses.append(slow)
    started = time.monotonic()
    with pytest.raises(OfficialRegistryError, match="deadline"):
        await registry_http.client.search()
    assert time.monotonic() - started < 0.5
    assert registry_http.closed == 1


@pytest.mark.asyncio
async def test_schema_validation_does_not_block_the_host_event_loop(registry_http, page, monkeypatch):
    current_thread = threading.get_ident()
    validate = registry_http.client._validate

    def check(payload, component):
        assert threading.get_ident() != current_thread
        validate(payload, component)

    monkeypatch.setattr(registry_http.client, "_validate", check)
    registry_http.responses.append(httpx2.Response(200, json=page))
    assert (await registry_http.client.search()).servers == page["servers"]


@pytest.mark.asyncio
async def test_request_deadline_includes_schema_validation(registry_http, page, monkeypatch):
    client = OfficialRegistryClient(RegistrySettings(api_url="https://registry.example/v0.1", timeout=0.02))
    validate = client._validate

    def slow_validate(payload, component):
        time.sleep(0.15)
        validate(payload, component)

    monkeypatch.setattr(client, "_validate", slow_validate)
    registry_http.responses.append(httpx2.Response(200, json=page))
    with pytest.raises(OfficialRegistryError, match="deadline"):
        await client.search()
    assert registry_http.closed == 1


@pytest.mark.asyncio
async def test_caller_cancellation_propagates_and_closes_the_transport(registry_http):
    entered = asyncio.Event()

    async def slow(_):
        entered.set()
        await asyncio.sleep(10)
        return httpx2.Response(200)

    registry_http.responses.append(slow)
    task = asyncio.create_task(registry_http.client.search())
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert registry_http.closed == 1


@pytest.mark.asyncio
async def test_unexpected_transport_defects_propagate_after_cleanup(registry_http):
    async def broken(_):
        raise TypeError("invalid HTTP transport configuration")

    registry_http.responses.append(broken)
    with pytest.raises(TypeError, match="transport configuration"):
        await registry_http.client.search()
    assert registry_http.closed == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": 101}, {"limit": True}, {"cursor": ""}, {"query": " "}])
async def test_invalid_pagination_or_search_fails_before_io(registry_http, kwargs):
    with pytest.raises(OfficialRegistryError):
        await registry_http.client.search(**kwargs)
    assert registry_http.approved == registry_http.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name,version", [("plain", "latest"), ("../../notes", "latest"), ("com.example/notes", ""), ("com.example/notes", "bad\ud800")])
async def test_invalid_detail_selection_fails_before_io(registry_http, name, version):
    with pytest.raises(OfficialRegistryError, match="Invalid.*server"):
        await registry_http.client.get(name, version=version)
    assert registry_http.approved == registry_http.requests == []


@pytest.mark.asyncio
async def test_private_registry_address_is_refused_before_transport_creation(registry_http):
    client = OfficialRegistryClient(RegistrySettings(api_url="https://127.0.0.1/v0.1"))
    registry_http.responses.append(httpx2.Response(200, json={"servers": []}))
    with pytest.raises(OfficialRegistryError, match="request failed"):
        await client.search()
    assert registry_http.approved == registry_http.requests == []


@pytest.mark.parametrize("kwargs", [
    {"api_url": "http://registry.example/v0.1"}, {"api_url": "https://user:password@registry.example/v0.1"},
    {"api_url": "https://registry.example/v0.1?query=x"}, {"api_url": "https://registry.example:bad/v0.1"},
    {"timeout": 0}, {"timeout": float("inf")}, {"max_response_bytes": 0},
])
def test_invalid_registry_settings_fail_clearly(kwargs):
    with pytest.raises(OfficialRegistryError):
        RegistrySettings(**kwargs)


def test_registry_environment_configuration_is_explicit(monkeypatch):
    monkeypatch.setenv("KESTREL_MCP_REGISTRY_URL", "https://registry.example/v0.1")
    monkeypatch.setenv("KESTREL_MCP_REGISTRY_TIMEOUT", "12.5")
    monkeypatch.setenv("KESTREL_MCP_REGISTRY_MAX_BYTES", "4096")
    assert RegistrySettings.from_environment() == RegistrySettings(api_url="https://registry.example/v0.1", timeout=12.5, max_response_bytes=4096)


def test_invalid_registry_environment_is_not_ignored(monkeypatch):
    monkeypatch.setenv("KESTREL_MCP_REGISTRY_TIMEOUT", "invalid")
    with pytest.raises(OfficialRegistryError, match="Invalid.*timeout"):
        RegistrySettings.from_environment()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["search", "catalog", "detail"])
async def test_official_discovery_tools_work_without_docker_and_keep_standard_identity(
    registry_http, page, operation, monkeypatch,
):
    feature = MCPAgent(SimpleNamespace())
    feature.manager = None
    feature.gateway_manager = None
    feature._official_registry = registry_http.client

    def forbidden_local():
        pytest.fail("official discovery used a local catalog name fallback")

    monkeypatch.setattr("kestrel_feature_mcp.feature.get_registry", forbidden_local)
    if operation == "detail":
        payload = page["servers"][0]
        registry_http.responses.append(httpx2.Response(200, json=payload))
        result = await feature.server_info("com.example/notes", version="1.2.3")
        assert registry_http.requests[0].url.raw_path.endswith(b"/versions/1.2.3")
    else:
        payload = page
        registry_http.responses.append(httpx2.Response(200, json=payload))
        result = await (feature.search_servers("notes") if operation == "search" else feature.show_catalog())
        assert "Next cursor:" in result.confirmation
    assert result.status is ToolResultStatus.OK
    assert result.data == {"source": "official", "registry_url": "https://registry.example/v0.1", "result": payload}
    assert "com.example/notes @ 1.2.3" in result.confirmation
    assert "https://notes.example/{workspace}/mcp" in result.confirmation
    assert len(registry_http.requests) == 1
    assert registry_http.requests[0].url.host == "registry.example"


@pytest.mark.asyncio
async def test_feature_uses_its_configured_client_and_pagination_without_docker(registry_http, page, monkeypatch):
    monkeypatch.setenv("KESTREL_MCP_REGISTRY_URL", "https://registry.example/v0.1")
    feature = MCPAgent(SimpleNamespace())
    registry_http.responses.append(httpx2.Response(200, json=page))
    result = await feature.search_servers("notes", cursor="previous opaque cursor", limit=5)
    assert result.status is ToolResultStatus.OK
    assert registry_http.requests[0].url.params["cursor"] == "previous opaque cursor"
    assert registry_http.requests[0].url.params["limit"] == "5"
    assert registry_http.requests[0].url.params["search"] == "notes"
    assert feature._official_registry is feature._official_registry


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["search", "catalog", "detail"])
async def test_official_failure_never_falls_back_to_a_local_entry(registry_http, operation, monkeypatch):
    feature = MCPAgent(SimpleNamespace())
    feature._official_registry = registry_http.client

    def forbidden_local():
        pytest.fail("registry failure became a local catalog success")

    monkeypatch.setattr("kestrel_feature_mcp.feature.get_registry", forbidden_local)
    registry_http.responses.append(httpx2.Response(503))
    if operation == "detail":
        result = await feature.server_info("com.example/notes")
    else:
        result = await (feature.search_servers("notes") if operation == "search" else feature.show_catalog())
    assert result.status is ToolResultStatus.ERROR
    assert result.data == {"source": "official"}
    assert "503" in result.error


@pytest.mark.asyncio
async def test_local_and_official_names_do_not_override_each_other(registry_http, page, tmp_path, monkeypatch):
    from kestrel_feature_mcp.registry import MCPRegistry

    catalog = tmp_path / "catalog.toml"
    catalog.write_text('[servers."com.example/notes"]\ndescription = "Local counterpart"\nimage = "private/notes"\n')
    local = MCPRegistry(catalog)
    monkeypatch.setattr("kestrel_feature_mcp.feature.get_registry", lambda: local)
    feature = MCPAgent(SimpleNamespace())
    feature._official_registry = registry_http.client
    registry_http.responses.append(httpx2.Response(200, json=page["servers"][0]))
    official = await feature.server_info("com.example/notes")
    local_info = await feature.server_info("com.example/notes", source="local")
    local_search = await feature.search_servers("notes", source="local")
    assert official.data["source"] == "official"
    assert official.data["result"]["server"]["version"] == "1.2.3"
    assert "Local counterpart" not in official.confirmation
    assert local_info.data["source"] == local_search.data["source"] == "local"
    assert "Local counterpart" in local_info.confirmation
    assert local_search.data["matches"] == ["com.example/notes"]
    assert len(registry_http.requests) == 1


@pytest.mark.asyncio
async def test_discovery_labels_deprecated_transport_without_trying_to_load_it(registry_http, page):
    page["servers"][0]["server"]["remotes"].append({"type": "sse", "url": "https://old.example/sse"})
    registry_http.responses.append(httpx2.Response(200, json=page))
    feature = MCPAgent(SimpleNamespace())
    feature._official_registry = registry_http.client
    result = await feature.show_catalog()
    assert result.status is ToolResultStatus.OK
    assert "sse (unsupported transport)" in result.confirmation
    assert result.data["result"] == page
    assert len(registry_http.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["search", "catalog", "detail"])
async def test_invalid_catalog_source_fails_without_acquiring_a_client(operation):
    feature = MCPAgent(SimpleNamespace())
    if operation == "search":
        result = await feature.search_servers("notes", source="unknown")
    elif operation == "catalog":
        result = await feature.show_catalog(source="unknown")
    else:
        result = await feature.server_info("com.example/notes", source="unknown")
    assert result.status is ToolResultStatus.ERROR
    assert "_official_registry" not in feature.__dict__
