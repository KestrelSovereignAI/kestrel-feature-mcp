"""Adapt downstream MCP tools to the host's dynamic-tool registry (#1979 PR3).

The host (``KestrelAgent``/``ToolRegistryMixin.register_dynamic_tools``) mounts
any handle exposing the SDK ``AgentTool`` shape — ``.name``,
``.schema.to_openai_format()`` and an awaitable ``.execute(**kwargs)`` — as a
first-class, LLM-callable tool with progressive disclosure, eviction, and (via
``_dispatch_direct_tool``) ToolResult + ``a2a_tool_dispatches`` + hook +
permission treatment.

An MCP tool is not a Python ``@tool`` method; it is runtime-discovered metadata
(``name``/``description``/``inputSchema``) plus a transport to call it. These
wrappers bridge the two: the MCP ``inputSchema`` is already JSON Schema, so it
drops straight into a function def's ``parameters``, and ``.execute`` proxies to
the gateway/container via the bound ``caller`` and returns a ToolResult.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

from kestrel_sdk.tools.result import ToolResult

logger = logging.getLogger(__name__)

# An MCP call transport: ``await caller(real_tool_name, arguments) -> CallToolResult``.
MCPCaller = Callable[[str, Dict[str, Any]], Awaitable[Any]]


def extract_mcp_result(result) -> tuple[str, bool]:
    """Pull display text + error flag from an MCP ``CallToolResult``.

    MCP signals tool-level failures by returning a normal result with
    ``isError=True`` rather than raising, so callers must branch on the flag to
    keep the ToolResult status envelope honest. Multiple content blocks are all
    preserved (joined) — dropping the tail would silently truncate output.
    """
    if hasattr(result, "content") and result.content:
        parts = [
            block.text if hasattr(block, "text") else str(block)
            for block in result.content
        ]
        text = "\n".join(parts)
    else:
        text = str(result)
    return text, bool(getattr(result, "isError", False))


class _MCPToolSchema:
    """Minimal AgentTool-schema duck type the host tool registry consumes."""

    def __init__(self, name: str, description: str, input_schema: Optional[dict]):
        self.name = name
        self.description = description or ""
        # MCP inputSchema IS JSON Schema → use it verbatim as the function
        # parameters. Default to an open object when a server omits it.
        self.parameters = input_schema or {"type": "object", "properties": {}}
        self.command_prefix = None
        # MCP calls hit external servers/processes; keep them serialized rather
        # than letting the orchestrator batch them as concurrency-safe.
        self.is_concurrency_safe = False

    def to_openai_format(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class MCPToolWrapper:
    """One downstream MCP tool, presented to the host as an AgentTool.

    ``handle_name`` is the readable, namespaced name we propose to the registry
    (which sanitises/bounds/uniquifies it for the provider). ``real_name`` is
    the actual MCP tool name used against the server — the host never sees it,
    so the registry is free to rename the handle.
    """

    def __init__(
        self,
        *,
        handle_name: str,
        real_name: str,
        description: str,
        input_schema: Optional[dict],
        caller: MCPCaller,
    ):
        self.name = handle_name
        self._real_name = real_name
        self._caller = caller
        self.schema = _MCPToolSchema(handle_name, description, input_schema)

    async def execute(self, **kwargs) -> ToolResult:
        try:
            result = await self._caller(self._real_name, kwargs)
        except Exception as e:  # noqa: BLE001 - surface any transport failure
            logger.error(
                "MCP tool '%s' execution failed: %s", self._real_name, e, exc_info=True
            )
            return ToolResult.failed(f"MCP tool '{self._real_name}' failed: {e}")

        text, is_error = extract_mcp_result(result)
        if is_error:
            return ToolResult.failed(
                f"MCP tool '{self._real_name}' reported an error:\n{text}",
                data={"mcp_tool": self._real_name},
            )
        return ToolResult.ok(text, data={"mcp_tool": self._real_name})


def build_wrappers(
    handle_prefix: str,
    tool_dicts: List[Dict[str, Any]],
    caller: MCPCaller,
) -> List[MCPToolWrapper]:
    """Build wrappers from a list of ``{name, description, inputSchema}`` dicts.

    ``handle_prefix`` namespaces the proposed handle name (e.g. ``"fetch"`` →
    ``mcp__fetch__<tool>``) for readability; the registry guarantees final
    validity/uniqueness.
    """
    wrappers: List[MCPToolWrapper] = []
    for td in tool_dicts:
        real = td["name"]
        wrappers.append(
            MCPToolWrapper(
                handle_name=f"mcp__{handle_prefix}__{real}",
                real_name=real,
                description=td.get("description", ""),
                input_schema=td.get("inputSchema"),
                caller=caller,
            )
        )
    return wrappers
