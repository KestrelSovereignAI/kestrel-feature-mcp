"""Canonical native Tool contracts, validated before publishing a catalog."""

from mcp import types


class MCPToolContractError(ValueError):
    """A named native tool violates its schema or Apps metadata contract."""


def validate_tool_contract(tool: types.Tool) -> tuple[frozenset[str], str | None]:
    """Read the native Apps audience and resource association, without grants."""
    if tool.input_schema.get("type") != "object":
        raise MCPToolContractError(f"MCP tool {tool.name!r}: inputSchema must explicitly declare type object")
    meta = tool.meta or {}
    if "ui" not in meta:
        return frozenset({"model", "app"}), None
    ui = meta["ui"]
    if not isinstance(ui, dict):
        raise MCPToolContractError(f"MCP tool {tool.name!r}: MCP Apps _meta.ui must be an object")
    visibility = ui.get("visibility", ["model", "app"])
    if not isinstance(visibility, list) or any(
        value not in ("model", "app") for value in visibility
    ):
        raise MCPToolContractError(f"MCP tool {tool.name!r}: MCP Apps visibility must contain only model or app")
    uri = ui.get("resourceUri")
    if "resourceUri" in ui and (
        not isinstance(uri, str) or not uri.startswith("ui://") or len(uri) <= 5
    ):
        raise MCPToolContractError(f"MCP tool {tool.name!r}: MCP Apps resourceUri must be a ui:// resource")
    return frozenset(visibility), uri


