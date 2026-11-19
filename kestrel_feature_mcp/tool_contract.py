"""Canonical native Tool contracts, validated before publishing a catalog."""

from dataclasses import dataclass
import hashlib
import json

from mcp import types


class MCPToolContractError(ValueError):
    """A named native tool violates its schema or Apps metadata contract."""


def _canonical_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        raise MCPToolContractError('MCP tool contracts require finite JSON') from None


@dataclass(frozen=True, slots=True, repr=False)
class MCPToolContractSnapshot:
    """Sealed original metadata; matching it never grants execution authority."""

    canonical_json: bytes

    def __post_init__(self):
        if type(self.canonical_json) is not bytes:
            raise TypeError('MCP tool contracts require immutable canonical JSON bytes')
        try:
            value = json.loads(self.canonical_json)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise MCPToolContractError('Invalid MCP tool contract JSON') from None
        if (type(value) is not dict or set(value) != {'connection', 'url', 'protocol', 'tool'}
                or type(value['connection']) is not str
                or (value['url'] is not None and type(value['url']) is not str)
                or (value['protocol'] is not None and type(value['protocol']) is not str)
                or type(value['tool']) is not dict
                or _canonical_bytes(value) != self.canonical_json):
            raise MCPToolContractError('Invalid canonical MCP tool contract shape')

    @property
    def digest(self):
        return hashlib.sha256(self.canonical_json).hexdigest()

    @property
    def descriptor(self):
        """A detached original Tool descriptor for custody and validation."""
        return json.loads(self.canonical_json)['tool']


def capture_tool_contract(native_tool: types.Tool, *, connection_name: str,
                          url: str | None, protocol: str | None) -> MCPToolContractSnapshot:
    """Use the existing input-continuation fingerprint format in one place."""
    return MCPToolContractSnapshot(_canonical_bytes({
        'connection': connection_name, 'url': url, 'protocol': protocol,
        'tool': native_tool.model_dump(mode='json', by_alias=True, exclude_none=True),
    }))


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

