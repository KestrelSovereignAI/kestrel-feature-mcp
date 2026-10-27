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
import json
from copy import deepcopy
from typing import Any, Awaitable, Callable, Dict, List, TYPE_CHECKING

from mcp import types

from kestrel_sdk.tools.result import ToolResult
from .connection import MCPCallOutcomeUnknownError, MCP_CONNECTION_ERRORS
from .tool_contract import validate_tool_contract

if TYPE_CHECKING:
    from .apps_execution import AppExecutor

logger = logging.getLogger(__name__)

# An MCP call transport: ``await caller(real_tool_name, arguments) -> CallToolResult``.
MCPCaller = Callable[[str, Dict[str, Any]], Awaitable[Any]]


def extract_mcp_result(result) -> tuple[str, bool]:
    """Pull display text + error flag from an MCP ``CallToolResult``.

    MCP signals tool-level failures by returning a normal result with
    ``is_error=True`` rather than raising, so callers must branch on the flag to
    keep the ToolResult status envelope honest. Multiple content blocks are all
    preserved (joined) — dropping the tail would silently truncate output.
    """
    if hasattr(result, "content") and result.content:
        parts = [
            block.text if hasattr(block, "text") else json.dumps(
                block.model_dump(mode="json", by_alias=True, exclude_none=True,
                    exclude={"meta": True, "resource": {"meta": True}}),
                ensure_ascii=False,
            )
            for block in result.content
        ]
        text = "\n".join(parts)
    else:
        # A native result may carry only structuredContent. Its repr also
        # contains private _meta and must never become model-visible text.
        text = ""
    return text, bool(getattr(result, "is_error", False))


class _MCPToolSchema:
    """Minimal AgentTool-schema duck type the host tool registry consumes."""

    def __init__(self, name: str, tool: types.Tool):
        self.name = name
        self.description = tool.description or ""
        visibility, _ = validate_tool_contract(tool)
        self.parameters = deepcopy(tool.input_schema)
        self.model_visible = "model" in visibility
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
                "parameters": deepcopy(self.parameters),
            },
        }


class MCPToolWrapper:
    """One downstream MCP tool, presented to the host as an AgentTool.

    ``handle_name`` is the readable, namespaced name proposed to the registry.
    The native SDK Tool is the canonical snapshot of the advertised contract;
    registry normalization never changes its downstream name or input schema.
    """

    def __init__(
        self,
        *,
        handle_name: str,
        tool: types.Tool,
        caller: MCPCaller,
        app_executor: AppExecutor | None = None,
    ):
        self.name = handle_name
        self._native_tool = tool.model_copy(deep=True)
        self.visibility, self.resource_uri = validate_tool_contract(self._native_tool)
        self._caller = caller
        self.app_executor = app_executor
        self.schema = _MCPToolSchema(handle_name, self._native_tool)

    @property
    def bound_caller(self) -> MCPCaller:
        return self._caller

    @property
    def native_tool(self) -> types.Tool:
        return self._native_tool.model_copy(deep=True)

    @property
    def _real_name(self) -> str:
        return self._native_tool.name

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Run the MCP tool and return the ToolResult **dict envelope**.

        Objects mounted in the host's ``_direct_tools`` must return the same
        serialized envelope the SDK ``AgentTool.execute`` produces
        (``ToolResult.to_dict()``), not the raw ``ToolResult``: the dispatch
        layer infers ``a2a_tool_dispatches`` status from the dict's ``status``
        key. Returning the raw object makes ``infer_tool_result_status`` read
        the ``ToolResult.failed`` *classmethod* (always truthy) and record every
        call as an error. (Caught by the #1979 DB-grounded dogfood.)
        """
        invocation = self.app_executor.admit(self) if self.app_executor is not None else None
        if invocation is None and not self.schema.model_visible:
            return ToolResult.failed(
                "MCP app-only tool requires a live authorized view",
            ).to_dict()
        try:
            result = await self._caller(self._real_name, kwargs)
        except MCPCallOutcomeUnknownError as error:
            logger.error("MCP tool %r has an unconfirmed outcome (%s)", self._real_name,
                type(error.__cause__).__name__)
            return ToolResult.failed(
                str(error), data={"mcp_tool": self._real_name, "execution_outcome": "unknown"},
            ).to_dict()
        except (ExceptionGroup, ValueError, *MCP_CONNECTION_ERRORS) as e:
            if isinstance(e, ExceptionGroup):
                _, unexpected = e.split((*MCP_CONNECTION_ERRORS, ValueError))
                if unexpected is not None:
                    raise
            logger.error(
                "MCP tool '%s' execution failed: %s", self._real_name, e, exc_info=True
            )
            return ToolResult.failed(f"MCP tool '{self._real_name}' failed: {e}").to_dict()

        text, is_error = extract_mcp_result(result)
        data = {"mcp_tool": self._real_name}
        if getattr(result, "structured_content", None) is not None:
            # This is business output, including any keys its own schema
            # defines. It is distinct from the native result/block _meta.
            data["structuredContent"] = deepcopy(result.structured_content)
        if is_error:
            projected = ToolResult.failed(
                f"MCP tool '{self._real_name}' reported an error:\n{text}",
                data=data,
            ).to_dict()
        else:
            # A complete native result may legitimately have no text content.
            projected = ToolResult.ok(text or "MCP tool completed", data=data).to_dict()
        if invocation is not None:
            return self.app_executor.capture(invocation, result, projected)
        return projected


def build_wrappers(
    handle_prefix: str,
    tool_dicts: List[Dict[str, Any]],
    caller: MCPCaller,
) -> List[MCPToolWrapper]:
    """Build wrappers from native SDK Tool records with host connection labels.

    ``handle_prefix`` namespaces the proposed handle name (e.g. ``"fetch"`` →
    ``mcp__fetch__<tool>``) for readability; the registry guarantees final
    validity/uniqueness.
    """
    wrappers: List[MCPToolWrapper] = []
    for td in tool_dicts:
        native = types.Tool.model_validate(td)
        wrappers.append(
            MCPToolWrapper(
                handle_name=f"mcp__{handle_prefix}__{native.name}",
                tool=native,
                caller=caller,
            )
        )
    return wrappers
