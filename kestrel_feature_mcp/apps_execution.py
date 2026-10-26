"""Native Apps calls under the originating View and Core's governed binding.

The View is an in-process lifetime, not a serialized authorization token. HTTP
identity and agent membership belong to the authenticated host controller.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Mapping, TYPE_CHECKING

from mcp import types
from kestrel_sdk.resources import ResourceConflict, ResourceOutcomeUnknown
from kestrel_sdk.tools import GovernedToolBinding

from .connection import BoundMCPCaller
from .apps_resources import AppResource, read_app_resource

if TYPE_CHECKING:
    from .dynamic_tools import MCPToolWrapper


@dataclass(frozen=True)
class RegisteredAppTool:
    tool: MCPToolWrapper
    binding: GovernedToolBinding


@dataclass
class _Invocation:
    view: AppView
    registered: RegisteredAppTool
    native: types.CallToolResult | None = None
    projection: dict | None = None
    started: bool = False
    finished: bool = False


@dataclass(eq=False, frozen=True)
class AppView:
    """One physical View, tied to its exact source tool and connection batch."""

    executor: AppExecutor
    source: RegisteredAppTool
    caller: BoundMCPCaller
    session_id: str
    _tools: Mapping[str, RegisteredAppTool] = field(repr=False)
    _owner_is_current: Callable[[], bool] = field(repr=False)
    _closed: bool = field(default=False, init=False)
    _calls: set[asyncio.Task] = field(default_factory=set, init=False, repr=False)

    def require_current(self) -> None:
        if self._closed or not self._owner_is_current():
            raise ResourceConflict("MCP App View expired; reopen it without replaying prior calls")
        for registered in self._tools.values():
            registered.binding.require_current()
        self.caller.require_current()

    def list_tools(self) -> list[types.Tool]:
        self.require_current()
        return [registered.tool.native_tool for registered in self._tools.values()
                if "app" in registered.tool.visibility]

    async def read_resource(self, uri: str, *, max_html_bytes: int) -> AppResource:
        self.require_current()
        if uri != self.source.tool.resource_uri:
            raise ResourceConflict("MCP App resource must match its originating tool association")

        async def read():
            loaded = await read_app_resource(self.caller, uri=uri, max_html_bytes=max_html_bytes)
            self.require_current()
            return loaded

        return await self._run_owned(read, name="mcp-app-native-resource")

    async def _run_owned(self, operation, *, name: str):
        self.require_current()
        if len(self._calls) >= self.executor._max_pending_calls:
            raise ResourceConflict("MCP App View reached its pending-call limit")
        call = asyncio.create_task(operation(), name=name)
        self._calls.add(call)
        try:
            return await call
        finally:
            self._calls.discard(call)

    def revoke(self) -> None:
        """Withdraw authority synchronously before any asynchronous cleanup."""
        if self._closed:
            return
        object.__setattr__(self, "_closed", True)
        for call in tuple(self._calls):
            if not call.done():
                call.cancel()

    async def close(self) -> None:
        """Join pending approvals, effects and their required Core audit writes."""
        self.revoke()
        calls = tuple(self._calls)
        pending = set(calls)
        cancellation = None
        while pending:
            try:
                _, pending = await asyncio.wait(pending)
            except asyncio.CancelledError as error:
                # wait() does not cancel the already-owned calls a second time.
                # Continue joining Core's final audit through caller cancellation.
                cancellation = error
        failures = [call.exception() for call in calls if not call.cancelled()
                    and call.exception() is not None]
        if cancellation is not None:
            failures.insert(0, cancellation)
        if failures:
            raise BaseExceptionGroup("MCP App View cleanup did not complete normally", failures)


class AppExecutor:
    """Per-feature admission context; source strings never confer authority."""

    def __init__(self, *, max_pending_calls: int):
        if type(max_pending_calls) is not int or max_pending_calls <= 0:
            raise ValueError("MCP Apps pending-call limit must be a positive integer")
        self._max_pending_calls = max_pending_calls
        self._invocation: ContextVar[_Invocation | None] = ContextVar(
            "mcp_app_invocation", default=None,
        )

    def open_view(
        self, source: RegisteredAppTool, registered: list[RegisteredAppTool], *,
        session_id: str, owner_is_current: Callable[[], bool],
    ) -> AppView:
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("An MCP App View requires a session_id")
        caller = source.tool.bound_caller
        if not isinstance(caller, BoundMCPCaller):
            raise TypeError("An MCP App View requires its originating bound native caller")
        if not source.tool.resource_uri:
            raise ValueError("An MCP App View requires an associated ui:// resource")
        tools = {}
        for item in registered:
            if item.tool.bound_caller is not caller or item.tool.app_executor is not self:
                raise ValueError("MCP App View tools must belong to the same executor and original connection")
            name = item.tool.native_tool.name
            if name in tools:
                raise ValueError(f"Duplicate MCP App tool name {name!r}")
            tools[name] = item
        if tools.get(source.tool.native_tool.name) is not source:
            raise ValueError("MCP App source must be retained in its original registration batch")
        if not callable(owner_is_current):
            raise TypeError("MCP App View requires a live owner predicate")
        view = AppView(self, source, caller, session_id, MappingProxyType(tools), owner_is_current)
        view.require_current()
        return view

    def admit(self, tool: MCPToolWrapper) -> _Invocation | None:
        """Recheck the actual View after approval, immediately before MCP I/O."""
        invocation = self._invocation.get()
        if invocation is None:
            return None
        if invocation.started or invocation.finished:
            raise ResourceConflict("MCP App invocation admission cannot be reused")
        if invocation.registered.tool is not tool or tool.app_executor is not self:
            raise ResourceConflict("MCP App invocation cannot change its admitted tool")
        invocation.view.require_current()
        invocation.registered.binding.require_current()
        if "app" not in tool.visibility:
            raise ResourceConflict("MCP tool is not available to Apps")
        invocation.started = True
        return invocation

    def capture(self, invocation: _Invocation, native: types.CallToolResult, projection: dict) -> None:
        if self._invocation.get() is not invocation or invocation.finished or not invocation.started:
            raise ResourceConflict("MCP App invocation context changed")
        if not isinstance(native, types.CallToolResult) or native.result_type != "complete":
            raise ResourceOutcomeUnknown("MCP App tool returned no complete native result; do not replay")
        invocation.native = native.model_copy(deep=True)
        invocation.projection = deepcopy(projection)

    async def invoke(self, view: AppView, name: str, arguments: dict) -> types.CallToolResult:
        if view.executor is not self:
            raise ResourceConflict("MCP App View belongs to another host")
        view.require_current()
        registered = view._tools.get(name)
        if registered is None or "app" not in registered.tool.visibility:
            raise ResourceConflict("MCP tool is not available to this App")
        registered.binding.require_current()
        if not isinstance(arguments, dict):
            raise TypeError("MCP App tool arguments must be an object")
        arguments = deepcopy(arguments)

        async def operation():
            invocation = _Invocation(view, registered)
            token = self._invocation.set(invocation)
            try:
                # This is the sole execution lane. Core owns permission hooks,
                # one-shot approvals, registry identity, cancellation and SQL audit.
                projected = await registered.binding.invoke(
                    arguments, session_id=view.session_id, source="mcp-app",
                )
                view.require_current()
                if invocation.native is None:
                    if isinstance(projected, dict) and (projected.get("data") or {}).get("execution_outcome") == "unknown":
                        raise ResourceOutcomeUnknown("MCP App tool outcome is unknown; do not replay without reconciliation")
                    return types.CallToolResult(is_error=True, content=[types.TextContent(
                        type="text", text="The host refused this MCP App invocation before a native result was confirmed",
                    )])
                if projected != invocation.projection:
                    raise ResourceConflict("The governed result changed; native MCP output was withheld")
                # Never forward the private native result before invoke returns:
                # at this point Core has confirmed its required structured audit.
                return invocation.native.model_copy(deep=True)
            finally:
                invocation.finished = True
                self._invocation.reset(token)

        return await view._run_owned(operation, name="mcp-app-governed-call")
