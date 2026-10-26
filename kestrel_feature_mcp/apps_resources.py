"""Bounded native MCP Apps resources; resource metadata never grants authority."""

from __future__ import annotations

import base64
import binascii
from copy import deepcopy
from dataclasses import dataclass, field

from mcp import types
from mcp.server.apps import APP_MIME_TYPE

from .connection import BoundMCPCaller


class AppResourceError(ValueError):
    """The originating server did not supply the associated bounded HTML."""


@dataclass(frozen=True)
class AppResource:
    uri: str
    html: str
    _metadata: dict = field(repr=False)

    @property
    def metadata(self) -> dict:
        return deepcopy(self._metadata)


def _require_resource_request(uri: str, max_html_bytes: int) -> None:
    if type(max_html_bytes) is not int or max_html_bytes <= 0:
        raise ValueError("MCP Apps HTML byte limit must be a positive integer")
    if not isinstance(uri, str) or not uri.startswith("ui://") or len(uri) <= 5:
        raise AppResourceError("MCP Apps resource association must use ui://")


def decode_app_resource(
    result: types.ReadResourceResult, *, uri: str, max_html_bytes: int,
) -> AppResource:
    """Accept either native text or base64 HTML for the exact association."""
    _require_resource_request(uri, max_html_bytes)
    if not isinstance(result, types.ReadResourceResult) or result.result_type != "complete":
        raise AppResourceError("MCP Apps resource read did not return a complete native resource")
    if len(result.contents) != 1:
        raise AppResourceError("MCP Apps resource must contain exactly one HTML document")
    content = result.contents[0]
    if content.uri != uri:
        raise AppResourceError("MCP Apps resource URI does not match its originating tool association")
    if content.mime_type != APP_MIME_TYPE:
        raise AppResourceError(f"MCP Apps resource MIME type must be {APP_MIME_TYPE}")
    if isinstance(content, types.BlobResourceContents):
        if len(content.blob) > 4 * ((max_html_bytes + 2) // 3):
            raise AppResourceError("MCP Apps HTML exceeds its byte limit")
        try:
            data = base64.b64decode(content.blob, validate=True)
        except (binascii.Error, ValueError) as error:
            raise AppResourceError("MCP Apps HTML blob must be valid base64") from error
        if len(data) > max_html_bytes:
            raise AppResourceError("MCP Apps HTML exceeds its byte limit")
        try:
            html = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AppResourceError("MCP Apps HTML must be valid UTF-8") from error
    else:
        html = content.text
        try:
            size = len(html.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise AppResourceError("MCP Apps HTML must be valid UTF-8") from error
        if size > max_html_bytes:
            raise AppResourceError("MCP Apps HTML exceeds its byte limit")
    return AppResource(uri=uri, html=html, _metadata=deepcopy(content.meta or {}))


async def read_app_resource(
    caller: BoundMCPCaller, *, uri: str, max_html_bytes: int,
) -> AppResource:
    """Read only through the captured owner and original connection lifetime."""
    # Validate the association and configuration before any network request.
    _require_resource_request(uri, max_html_bytes)
    result = await caller.read_resource(uri)
    return decode_app_resource(result, uri=uri, max_html_bytes=max_html_bytes)
