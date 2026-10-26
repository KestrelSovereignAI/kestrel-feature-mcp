"""Native Apps metadata controls audience, never host permission."""

from copy import deepcopy
import json

import pytest
from mcp import types

from kestrel_feature_mcp.dynamic_tools import build_wrappers
from kestrel_feature_mcp.connection import MCPConnection, describe_tools


def _metadata_caller():
    # Pure metadata tests never start this native connection or perform I/O.
    return MCPConnection("http://127.0.0.1:1/mcp").call_tool


def _record(ui=None):
    record = {
        "name": "refresh_dashboard", "title": "Refresh dashboard",
        "description": "Read dashboard state", "inputSchema": {"type": "object"},
        "outputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": True},
        "_meta": {"private-server-data": {"value": 3}},
    }
    if ui is not None:
        record["_meta"]["ui"] = ui
    return record


@pytest.mark.parametrize("visibility,visible", [
    (None, True), ([], False), (["model"], True), (["app"], False),
    (["model", "app"], True), (["app", "app"], False),
])
def test_native_tool_visibility_controls_only_model_projection(visibility, visible):
    ui = {"resourceUri": "ui://dashboard/app.html"}
    if visibility is not None:
        ui["visibility"] = visibility
    record = _record(ui)
    (wrapper,) = build_wrappers("dashboard", [record], _metadata_caller())
    assert wrapper.schema.model_visible is visible
    assert wrapper.resource_uri == "ui://dashboard/app.html"
    assert wrapper.visibility == frozenset(visibility if visibility is not None else ["model", "app"])
    assert wrapper.native_tool.model_dump(mode="json", by_alias=True, exclude_none=True) == (
        types.Tool.model_validate(record).model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    assert wrapper.schema.to_openai_format()["function"]["parameters"] == {"type": "object"}
    assert "model_visible" not in wrapper.schema.to_openai_format()["function"]["parameters"]


def test_app_helper_tool_does_not_need_to_declare_another_view():
    (wrapper,) = build_wrappers("dashboard", [_record({"visibility": ["app"]})], _metadata_caller())
    assert wrapper.resource_uri is None
    assert wrapper.schema.model_visible is False


@pytest.mark.parametrize("ui", [
    "ui://dashboard/app.html", [],
    {"visibility": "app"}, {"visibility": ["unknown"]}, {"visibility": [False]},
    {"visibility": None}, {"resourceUri": "https://example.com/ui"},
    {"resourceUri": 3}, {"resourceUri": "ui://"},
])
def test_invalid_native_ui_metadata_is_refused(ui):
    with pytest.raises(ValueError, match="MCP Apps"):
        build_wrappers("dashboard", [_record(ui)], _metadata_caller())


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [
    {"apps_tools": True, "apps_visibility": ["app"]},
    {"apps_tools": True, "apps_visibility": []},
], indirect=True)
async def test_hidden_tools_cannot_be_called_without_a_live_app_admission(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url)
    try:
        tools = await connection.connect()
        wrappers = build_wrappers("dashboard", describe_tools(connection, tools), connection.call_tool)
        wrapper = next(w for w in wrappers if w.native_tool.name == "status_view")
        result = await wrapper.execute()
        assert result["status"] == "error"
        assert "view" in result["error"].lower()
    finally:
        await connection.close()
    assert not [body for _, body in mcp_http_server.requests if body
                and json.loads(body).get("method") == "tools/call"]


def test_wrapper_retains_an_independent_native_tool_snapshot():
    record = _record({"resourceUri": "ui://dashboard/app.html", "visibility": ["model", "app"]})
    original = deepcopy(record)
    (wrapper,) = build_wrappers("dashboard", [record], _metadata_caller())
    record["_meta"]["ui"]["visibility"].clear()
    record["_meta"]["private-server-data"]["value"] = 9
    exported = wrapper.native_tool
    exported.meta["ui"]["visibility"].clear()
    exported.meta["private-server-data"]["value"] = 12
    assert wrapper.native_tool.model_dump(mode="json", by_alias=True, exclude_none=True) == (
        types.Tool.model_validate(original).model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    assert wrapper.schema.model_visible is True


def test_deprecated_flat_ui_metadata_does_not_create_a_view_binding():
    record = _record()
    record["_meta"]["ui/resourceUri"] = "ui://dashboard/app.html"
    (wrapper,) = build_wrappers("dashboard", [record], _metadata_caller())
    assert wrapper.resource_uri is None
    assert wrapper.schema.model_visible is True


def test_model_parameters_cannot_mutate_the_native_tool_contract():
    (wrapper,) = build_wrappers("dashboard", [_record()], _metadata_caller())
    wrapper.schema.parameters["properties"] = {"unexpected": {"type": "string"}}
    assert wrapper.native_tool.input_schema == {"type": "object"}


@pytest.mark.parametrize("schema", [{}, {"type": "array"}, {"type": ["object", "null"]}])
def test_mcp_input_schema_requires_the_standard_object_root(schema):
    record = _record()
    record["inputSchema"] = schema
    with pytest.raises(ValueError, match="inputSchema.*object"):
        build_wrappers("dashboard", [record], _metadata_caller())


@pytest.mark.parametrize("is_error", [False, True])
@pytest.mark.parametrize("kind", ["empty", "image", "resource"])
async def test_model_result_projection_keeps_structured_data_and_omits_native_private_metadata(kind, is_error):
    private = {"private-sentinel": {"value": 7}}
    blocks = []
    if kind == "image":
        blocks = [types.ImageContent(type="image", data="AA==", mimeType="image/png", _meta=private)]
    elif kind == "resource":
        blocks = [types.EmbeddedResource(type="resource", _meta=private,
            resource=types.TextResourceContents(uri="note://owned/result", text="Public resource text",
                mimeType="text/plain", _meta=private))]
    native = types.CallToolResult(content=blocks, isError=is_error, _meta=private,
        structuredContent={"message": "public data", "_meta": {"business-field": "preserved"}})

    async def caller(_name, _arguments):
        return native

    (wrapper,) = build_wrappers("dashboard", [_record()], caller)
    projected = await wrapper.execute()
    assert "private-sentinel" not in json.dumps(projected)
    assert projected["data"]["structuredContent"] == native.structured_content
    assert projected["data"]["structuredContent"]["_meta"] == {"business-field": "preserved"}
    projected["data"]["structuredContent"]["message"] = "mutated projection"
    assert native.structured_content["message"] == "public data"
    assert native.meta == private
    if kind == "resource":
        assert "Public resource text" in json.dumps(projected)
