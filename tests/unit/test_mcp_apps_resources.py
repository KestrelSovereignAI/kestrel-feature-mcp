"""Native resource values and real SDK/HTTP reads, with no HTTP ui:// fetch."""

import base64
import tracemalloc
from dataclasses import FrozenInstanceError

import pytest
from mcp import types
from mcp.server.apps import APP_MIME_TYPE

from kestrel_feature_mcp.apps_resources import AppResourceError, decode_app_resource, read_app_resource
from kestrel_feature_mcp.connection import MCPConnection, bind_tool_caller


URI = "ui://status/view.html"
HTML = "<!doctype html><html><body>状态</body></html>"


def resource(*, blob=False, **updates):
    fields = dict(uri=URI, mime_type=APP_MIME_TYPE, _meta={"ui": {"csp": {"connectDomains": ["https://example.com"]}}})
    fields.update(blob=base64.b64encode(HTML.encode()).decode()) if blob else fields.update(text=HTML)
    fields.update(updates)
    content_type = types.BlobResourceContents if blob else types.TextResourceContents
    return types.ReadResourceResult(contents=[content_type(**fields)])


@pytest.mark.parametrize("blob", [False, True])
def test_native_text_and_blob_documents_preserve_html_and_snapshot_metadata(blob):
    native = resource(blob=blob)
    loaded = decode_app_resource(native, uri=URI, max_html_bytes=len(HTML.encode()))
    assert loaded.uri == URI and loaded.html == HTML
    native.contents[0].meta["ui"]["csp"]["connectDomains"].clear()
    exported = loaded.metadata
    exported["ui"]["csp"]["connectDomains"].clear()
    assert loaded.metadata["ui"]["csp"]["connectDomains"] == ["https://example.com"]
    with pytest.raises(FrozenInstanceError):
        loaded.html = "replacement"


@pytest.mark.parametrize("blob", [False, True])
def test_html_limits_count_utf8_bytes_and_apply_at_the_exact_boundary(blob):
    native = resource(blob=blob)
    with pytest.raises(AppResourceError, match="byte limit"):
        decode_app_resource(native, uri=URI, max_html_bytes=len(HTML.encode()) - 1)


def test_blob_encoding_is_bounded_before_allocating_its_decoded_html():
    native = types.ReadResourceResult(contents=[types.BlobResourceContents(
        uri=URI, mime_type=APP_MIME_TYPE, blob=base64.b64encode(b"x" * (2 * 1024 * 1024)).decode(),
    )])
    tracemalloc.start()
    try:
        with pytest.raises(AppResourceError, match="byte limit"):
            decode_app_resource(native, uri=URI, max_html_bytes=1024)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 256 * 1024, "oversized blob allocated its decoded HTML before the size check"


@pytest.mark.parametrize("changes, message", [
    ({"uri": "ui://other/view.html"}, "association"),
    ({"mime_type": "text/html"}, "MIME"),
    ({"mime_type": None}, "MIME"),
    ({"text": "\ud800"}, "UTF-8"),
])
def test_invalid_text_associations_and_encodings_are_refused(changes, message):
    with pytest.raises(AppResourceError, match=message):
        decode_app_resource(resource(**changes), uri=URI, max_html_bytes=4096)


@pytest.mark.parametrize("blob, message", [
    ("@@@", "base64"), ("é", "base64"), ("Zm9v\n", "base64"),
    ("/w==", "UTF-8"), ("Zg===", "base64"),
])
def test_malformed_blob_data_never_becomes_renderable_html(blob, message):
    native = types.ReadResourceResult(contents=[types.BlobResourceContents(
        uri=URI, mime_type=APP_MIME_TYPE, blob=blob,
    )])
    with pytest.raises(AppResourceError, match=message):
        decode_app_resource(native, uri=URI, max_html_bytes=4096)


@pytest.mark.parametrize("contents", [[], [resource().contents[0]] * 2])
def test_resource_cardinality_is_unambiguous(contents):
    with pytest.raises(AppResourceError, match="exactly one"):
        decode_app_resource(types.ReadResourceResult(contents=contents), uri=URI, max_html_bytes=4096)


def test_incomplete_resource_results_are_not_rendered():
    native = resource().model_copy(update={"result_type": "pending"})
    with pytest.raises(AppResourceError, match="complete native"):
        decode_app_resource(native, uri=URI, max_html_bytes=4096)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_byte_limit_is_refused(limit):
    with pytest.raises(ValueError, match="positive integer"):
        decode_app_resource(resource(), uri=URI, max_html_bytes=limit)


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [
    {"apps_tools": True, "apps_html": HTML},
    {"apps_tools": True, "apps_blob": True, "apps_html": HTML},
], indirect=True)
async def test_native_sdk_http_reads_both_server_encodings(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url)
    try:
        await connection.connect()
        caller = bind_tool_caller(connection, lambda: True, "original")
        loaded = await read_app_resource(caller, uri=URI, max_html_bytes=len(HTML.encode()))
        assert loaded.html == HTML and loaded.uri == URI
        assert mcp_http_server.settings["resource_reads"] == ["resources/read"]
        assert not mcp_http_server.witness
        await connection.close()
        await connection.connect()
        with pytest.raises(ValueError, match="changed"):
            await read_app_resource(caller, uri=URI, max_html_bytes=4096)
        assert mcp_http_server.settings["resource_reads"] == ["resources/read"]
    finally:
        await connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True}], indirect=True)
async def test_bad_resource_configuration_is_refused_before_native_io(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url)
    try:
        await connection.connect()
        caller = bind_tool_caller(connection, lambda: True, "original")
        for uri, limit in [("https://example.com/app.html", 4096), ("ui://", 4096), (URI, 0)]:
            with pytest.raises(ValueError):
                await read_app_resource(caller, uri=uri, max_html_bytes=limit)
        assert mcp_http_server.settings.get("resource_reads", []) == []
    finally:
        await connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_html": HTML}], indirect=True)
async def test_oversized_native_document_is_refused_without_retry_or_tool_call(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url)
    try:
        await connection.connect()
        caller = bind_tool_caller(connection, lambda: True, "original")
        with pytest.raises(AppResourceError, match="byte limit"):
            await read_app_resource(caller, uri=URI, max_html_bytes=3)
        assert mcp_http_server.settings["resource_reads"] == ["resources/read"]
        assert not mcp_http_server.witness
    finally:
        await connection.close()
