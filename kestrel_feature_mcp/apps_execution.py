"""Native Apps calls under the originating View and Core's governed binding.

The View is an in-process lifetime, not a serialized authorization token. HTTP
identity and agent membership belong to the authenticated host controller.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from inspect import (
    isasyncgen, isasyncgenfunction, isawaitable, isbuiltin, iscoroutine,
    iscoroutinefunction, isfunction, isgenerator, isgeneratorfunction, ismethod,
)
from types import MappingProxyType
from typing import Callable, Mapping, TYPE_CHECKING
from weakref import WeakSet

from mcp import types
from kestrel_sdk.resources import ResourceConflict, ResourceOutcomeUnknown, observed_outcome_unknown
from kestrel_sdk.tools import (
    DeferredToolResult, DeferredToolResultHost, GovernedToolBinding, ToolPublicationContext,
)

from .connection import BoundMCPCaller, _rejected_before_execution
from .oauth_grants import OAuthGrantChanged
from .apps_resources import AppResource, read_app_resource

if TYPE_CHECKING:
    from .dynamic_tools import MCPToolWrapper

InitialAppPublisher = Callable[
    ["MCPToolWrapper", ToolPublicationContext, types.CallToolResult, dict], list[dict]
]


def require_owned_call_host(host):
    """Validate before replacing any live host or constructing an executor."""
    if (getattr(host, 'supports_owned_mcp_app_calls', None) is not True
            or not callable(getattr(host, 'mcp_app_call_scope', None))):
        raise TypeError("MCP Apps require Core's host-owned task contract")
    return host.mcp_app_call_scope


def require_synchronous_callback(callback, *, label: str, allow_builtin: bool = False) -> None:
    """Private delivery callbacks run inline and cannot escape as awaitables."""
    if (not (isfunction(callback) or ismethod(callback) or (allow_builtin and isbuiltin(callback)))
            or iscoroutinefunction(callback) or isasyncgenfunction(callback) or isgeneratorfunction(callback)):
        raise TypeError(f"MCP Apps {label} requires a synchronous function or method")


def call_synchronous_callback(callback, *args, label: str):
    """Reject deferred work returned by an otherwise ordinary host callback."""
    value = callback(*args)
    if isawaitable(value) or isgenerator(value) or isasyncgen(value):
        if iscoroutine(value) or isgenerator(value):
            value.close()
        raise TypeError(f"MCP Apps {label} must complete synchronously")
    return value


class MCPAppResultWithheld(ResourceOutcomeUnknown):
    """The call completed, but native delivery was refused; never replay it."""


class MCPAppInputRequired(ResourceConflict):
    """The native operation is durably paused, with no final App result yet."""

    def __init__(self, view, suspension):
        super().__init__('MCP App is waiting for operator input; do not repeat its call')
        self.view, self.suspension = view, suspension


@dataclass(frozen=True)
class RegisteredAppTool:
    tool: MCPToolWrapper
    binding: GovernedToolBinding


@dataclass
class _Invocation:
    view: AppView
    registered: RegisteredAppTool
    input_reference: str | None = None
    native: types.CallToolResult | None = None
    projection: dict | None = None
    delivery_approved: bool = False
    started: bool = False
    finished: bool = False
    refusal: BaseException | None = None
    suspension: object | None = None


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
    _input_reference: str | None = field(default=None, init=False, repr=False)
    _calls: set[asyncio.Task] = field(default_factory=set, init=False, repr=False)
    _delivery_tasks: dict[asyncio.Task, asyncio.Future] = field(default_factory=dict, init=False, repr=False)
    _cancelled_calls: WeakSet[asyncio.Task] = field(default_factory=WeakSet, init=False, repr=False)

    @property
    def is_closed(self) -> bool:
        """Lifecycle state only; this observation confers no View authority."""
        return self._closed

    @property
    def _pending_count(self) -> int:
        return len(self._calls) + len(self._delivery_tasks)

    def require_current(self) -> None:
        if self._closed:
            raise ResourceConflict("MCP App View expired; reopen it without replaying prior calls")
        try:
            owner_current = call_synchronous_callback(self._owner_is_current, label="View authority")
        except ResourceConflict:
            raise
        except Exception as error:
            # This is the host's authority-check boundary, not tool execution.
            # A failed checker refuses this operation. Retain the exact cause so
            # Core's control/commit evidence remains discoverable, while the
            # owned-call boundary can classify an already admitted effect as
            # unknown/withheld. Cancellation and process control stay intact.
            raise ResourceConflict("MCP App View authority check failed; reopen without replaying prior calls") from error
        if self._closed or owner_current is not True:
            raise ResourceConflict("MCP App View expired; reopen it without replaying prior calls")
        for registered in self._tools.values():
            if not registered.binding.is_current:
                raise ResourceConflict("MCP App tool registration expired; reopen the originating View")
        try:
            self.caller.require_current()
        except ValueError as error:
            raise ResourceConflict("MCP App connection expired; reopen the originating View") from error

    def list_tools(self) -> list[types.Tool]:
        self.require_current()
        return [registered.tool.native_tool for registered in self._tools.values()
                if "app" in registered.tool.visibility]

    async def read_resource(self, uri: str, *, max_html_bytes: int) -> AppResource:
        self.require_current()
        if uri != self.source.tool.resource_uri:
            raise ResourceConflict("MCP App resource must match its originating tool association")

        async def read():
            loaded = await read_app_resource(self.caller, uri=uri, max_html_bytes=max_html_bytes,
                require_authority=self.require_current)
            self.require_current()
            return loaded

        return await self._run_owned(read, name="mcp-app-native-resource")

    async def _run_owned(self, operation, *, name: str,
                         revoked_outcome: Callable[[], BaseException] | None = None):
        self.require_current()
        if self._pending_count >= self.executor._max_pending_calls:
            raise ResourceConflict("MCP App View reached its pending-call limit")
        call = None
        try:
            async with self.executor._call_scope(operation, name=name, cancel=self._cancel_call) as owner:
                call = owner.task
                if not isinstance(call, asyncio.Task) or not callable(owner.wait):
                    raise TypeError('MCP Apps require the original host-owned task and waiter')
                self._calls.add(call)
                result = await owner.wait()
                # The child may finish before a queued lifecycle callback runs,
                # while this awaiting API task resumes after that callback.
                try:
                    self.require_current()
                except ResourceConflict as error:
                    if revoked_outcome is not None:
                        raise revoked_outcome() from error
                    raise
                return result
        except asyncio.CancelledError as error:
            caller = asyncio.current_task()
            if self._closed and caller is not None and caller.cancelling() == 0:
                # Withdrawal cancels our child, not the awaiting caller's task.
                # Preserve actual caller cancellation; otherwise report whether
                # this View had already admitted a native tool invocation.
                if revoked_outcome is not None:
                    raise revoked_outcome() from error
                raise ResourceConflict("MCP App View closed before resource delivery") from error
            raise
        finally:
            if call is not None:
                self._calls.discard(call)

    def revoke(self) -> None:
        """Withdraw authority synchronously before any asynchronous cleanup."""
        if self._closed:
            return
        object.__setattr__(self, "_closed", True)
        for call in (*self._calls, *self._delivery_tasks):
            self._cancel_call(call)

    def _cancel_call(self, call: asyncio.Task) -> None:
        if not call.done() and call not in self._cancelled_calls:
            self._cancelled_calls.add(call)
            call.cancel()

    @asynccontextmanager
    async def borrow_delivery(self):
        """Retain the original physical response task in this View's custody.

        The authenticated host enters this on its actual ASGI send child, never
        on a buffering middleware's acknowledgement. It checks before and after
        that send. A closed View cancels once and joins this same native owner.
        """
        self.require_current()
        task = asyncio.current_task()
        if (task is None or task.cancelling() or task in self._calls or task in self._delivery_tasks
                or self._pending_count >= self.executor._max_pending_calls):
            raise ResourceConflict("MCP App cannot admit this response delivery")
        settled = asyncio.get_running_loop().create_future()
        self._delivery_tasks[task] = settled
        active = True
        failure = None

        def current():
            if (not active or asyncio.current_task() is not task
                    or self._delivery_tasks.get(task) is not settled):
                raise ResourceConflict("MCP App response delivery ended or changed owner")
            self.require_current()

        try:
            yield current
        except BaseException as error:
            failure = error
            raise
        finally:
            active = False
            self._delivery_tasks.pop(task, None)
            self._cancelled_calls.discard(task)
            # Join the original transport borrow, never unrelated later work
            # performed by the host's reusable task. Store the outcome as a
            # value so an unobserved error cannot escape through Future GC.
            settled.set_result(failure)

    def cancel_delivery(self, task: asyncio.Task) -> None:
        """Cancel only an original delivery child, at most once."""
        if task not in self._delivery_tasks:
            raise ResourceConflict("MCP App response belongs to another View")
        self._cancel_call(task)

    async def close(self) -> None:
        """Join pending approvals, effects and their required Core audit writes."""
        if (asyncio.current_task() in self._calls
                or asyncio.current_task() in self._delivery_tasks):
            raise ResourceConflict("MCP App View must be closed by its external lifetime owner")
        self.revoke()
        calls = tuple(self._calls)
        deliveries = tuple(self._delivery_tasks.values())
        pending = {*calls, *deliveries}
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
        failures.extend(delivery.result() for delivery in deliveries
                        if delivery.result() is not None
                        and not isinstance(delivery.result(), asyncio.CancelledError))
        if cancellation is not None:
            if not failures:
                raise cancellation
            failures.insert(0, cancellation)
        if failures:
            raise BaseExceptionGroup("MCP App View cleanup did not complete normally", failures)


class AppExecutor:
    """Per-feature admission context; source strings never confer authority."""

    supports_owned_delivery = True

    @staticmethod
    def input_required(error, view):
        """Expose only an audited suspension from this exact physical View."""
        from .input_requests import MCPInputSuspension
        if type(error) is not MCPAppInputRequired or error.view is not view:
            return None
        view.require_current()
        suspension = error.suspension
        if type(suspension) is not MCPInputSuspension or suspension.session_id != view.session_id:
            raise ResourceConflict('Original MCP App input suspension changed')
        return {'reference': suspension.reference, 'session_id': suspension.session_id}

    def __init__(self, *, host: DeferredToolResultHost, max_pending_calls: int,
                 initial_publisher: InitialAppPublisher | None = None):
        if type(max_pending_calls) is not int or max_pending_calls <= 0:
            raise ValueError("MCP Apps pending-call limit must be a positive integer")
        if getattr(host, "supports_deferred_tool_results", False) is not True:
            raise ValueError("MCP Apps require a host that supports deferred tool results")
        if initial_publisher is not None:
            require_synchronous_callback(initial_publisher, label="initial publication")
            if (getattr(host, "supports_audited_deferred_tool_results", False) is not True
                    or getattr(host, "supports_tool_publication_context", False) is not True):
                raise ValueError("MCP Apps initial publication requires audited host-selected chat context")
        self._call_scope = require_owned_call_host(host)
        self._initial_publisher = initial_publisher
        self._max_pending_calls = max_pending_calls
        self._invocation: ContextVar[_Invocation | None] = ContextVar(
            "mcp_app_invocation", default=None,
        )

    def capture_initial(self, tool: MCPToolWrapper, native: types.CallToolResult,
                        projection: dict, arguments: dict) -> dict:
        """Keep native UI data private until the actual chat's audited callback.

        The controller resolves the original registration and authenticates
        readers independently. This callback supplies destination metadata,
        never an HTTP capability or evidence that rendering completed.
        """
        publisher = self._initial_publisher
        if publisher is None or tool.resource_uri is None:
            return projection
        try:
            self.require_initial_tool(tool)
        except ValueError as error:
            raise MCPAppResultWithheld("MCP App result lost its original connection; do not replay") from error
        if not isinstance(native, types.CallToolResult) or native.result_type != "complete":
            raise MCPAppResultWithheld("MCP App has no complete native result; do not replay")
        captured = native.model_copy(deep=True)
        arguments = deepcopy(arguments)

        def publish():
            context = deferred.publication_context
            if context is None:
                return []
            try:
                tool.bound_caller.require_current()
            except ValueError as error:
                raise MCPAppResultWithheld("MCP App connection expired before publication; do not replay") from error
            return call_synchronous_callback(publisher, tool, context, captured, arguments,
                label="initial publication")

        deferred = DeferredToolResult(projection, publish=publish)
        return deferred

    def require_initial_tool(self, tool: MCPToolWrapper) -> None:
        """Refuse unsupported initial publication setup before the native effect."""
        if self._initial_publisher is None or tool.resource_uri is None:
            return
        if tool.app_executor is not self or not isinstance(tool.bound_caller, BoundMCPCaller):
            raise ValueError("MCP App initial publication requires its original bound native caller")
        tool.bound_caller.require_current()

    def open_view(
        self, source: RegisteredAppTool, registered: list[RegisteredAppTool], *,
        session_id: str, owner_is_current: Callable[[], bool],
    ) -> AppView:
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("An MCP App View requires a session_id")
        tools = self.registration_tools(source, registered)
        require_synchronous_callback(owner_is_current, label="View owner predicate")
        view = AppView(self, source, source.tool.bound_caller, session_id, tools, owner_is_current)
        view.require_current()
        return view

    def registration_tools(self, source: RegisteredAppTool,
                           registered: list[RegisteredAppTool]) -> Mapping[str, RegisteredAppTool]:
        """Validate and seal the exact original batch, independently of a View."""
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
        return MappingProxyType(tools)

    def admit(self, tool: MCPToolWrapper) -> _Invocation | None:
        """Recheck the actual View after approval, immediately before MCP I/O."""
        invocation = self._invocation.get()
        if invocation is None:
            self.require_initial_tool(tool)
            return None
        if invocation.started or invocation.finished:
            raise ResourceConflict("MCP App invocation admission cannot be reused")
        if invocation.registered.tool is not tool or tool.app_executor is not self:
            raise ResourceConflict("MCP App invocation cannot change its admitted tool")
        invocation.view.require_current()
        if invocation.view._input_reference != invocation.input_reference:
            raise ResourceConflict('MCP App must finish its original operator input before another call')
        if "app" not in tool.visibility:
            raise ResourceConflict("MCP tool is not available to Apps")
        invocation.started = True
        return invocation

    def _require_capture(self, invocation: _Invocation) -> None:
        if self._invocation.get() is not invocation or invocation.finished or not invocation.started:
            raise ResourceOutcomeUnknown("MCP App invocation context changed after execution; do not replay")

    def capture_refusal(self, invocation: _Invocation, error: BaseException) -> None:
        """Retain the connection's canonical rejection separately from admission."""
        self._require_capture(invocation)
        if (_rejected_before_execution(error) or issubclass(type(error), OAuthGrantChanged)) and not observed_outcome_unknown(error):
            invocation.refusal = error

    def capture_suspension(self, invocation, suspension, projection):
        self._require_capture(invocation)
        invocation.suspension = suspension
        object.__setattr__(invocation.view, '_input_reference', suspension.reference)
        def approved():
            self._require_capture(invocation)
            invocation.view.require_current()
            invocation.delivery_approved = True
            return []
        return DeferredToolResult(projection, publish=approved)

    def capture(self, invocation: _Invocation, native: types.CallToolResult,
                projection: dict) -> DeferredToolResult:
        self._require_capture(invocation)
        if not isinstance(native, types.CallToolResult) or native.result_type != "complete":
            raise ResourceOutcomeUnknown("MCP App tool returned no complete native result; do not replay")
        invocation.native = native.model_copy(deep=True)
        invocation.projection = deepcopy(projection)

        def approve_delivery():
            # Core calls this once, only after complete, allowing post-tool
            # policy on the unchanged public envelope. It does not execute
            # tools or replace the required audit boundary below.
            if self._invocation.get() is not invocation or invocation.finished:
                raise MCPAppResultWithheld("MCP App policy context expired; delivery withheld. Do not replay")
            invocation.view.require_current()
            invocation.delivery_approved = True
            return []

        return DeferredToolResult(projection, publish=approve_delivery)

    async def invoke(self, view: AppView, name: str, arguments: dict,
                     *, operation_id: str, input_reference: str | None = None) -> types.CallToolResult:
        if view.executor is not self:
            raise ResourceConflict("MCP App View belongs to another host")
        view.require_current()
        if view._input_reference != input_reference:
            raise ResourceConflict('MCP App must finish its original operator input before another call')
        registered = view._tools.get(name)
        if registered is None or "app" not in registered.tool.visibility:
            raise ResourceConflict("MCP tool is not available to this App")
        if not isinstance(arguments, dict):
            raise TypeError("MCP App tool arguments must be an object")
        arguments = deepcopy(arguments)
        invocation = _Invocation(view, registered, input_reference=input_reference)

        def revoked_outcome():
            if not invocation.started:
                return ResourceConflict("MCP App authority expired before native execution")
            if invocation.native is not None:
                return MCPAppResultWithheld(
                    "Native MCP result received; delivery was withheld after authority expired. Do not replay",
                )
            return ResourceOutcomeUnknown(
                "MCP App authority expired after tool admission; reconcile before retrying. Do not replay",
            )

        async def operation():
            token = self._invocation.set(invocation)
            try:
                # This is the sole execution lane. Core owns permission hooks,
                # one-shot approvals, registry identity, cancellation and SQL audit.
                try:
                    projected = await registered.binding.invoke(
                        arguments, session_id=view.session_id, operation_id=operation_id, source="mcp-app",
                    )
                except ResourceConflict as error:
                    if invocation.started and (invocation.refusal is None or observed_outcome_unknown(error)):
                        raise ResourceOutcomeUnknown(
                            "MCP App call may have executed; reconcile before retrying",
                        ) from error
                    raise
                if invocation.suspension is not None and invocation.delivery_approved:
                    view.require_current()
                    raise MCPAppInputRequired(view, invocation.suspension)
                if invocation.native is None:
                    if invocation.refusal is not None:
                        view.require_current()
                        raise ResourceConflict("Native MCP request was rejected before tool execution") from invocation.refusal
                    # Hooks can redact the serialized result. Admission and the
                    # native capture are private execution facts, so missing
                    # output after admission stays unknown regardless of hooks.
                    if invocation.started:
                        raise ResourceOutcomeUnknown("MCP App tool outcome is unknown; do not replay without reconciliation")
                    view.require_current()
                    return types.CallToolResult(is_error=True, content=[types.TextContent(
                        type="text", text="The host refused this MCP App invocation before a native result was confirmed",
                    )])
                try:
                    view.require_current()
                except ResourceConflict as error:
                    raise MCPAppResultWithheld(
                        "MCP App call completed; result delivery was withheld. Do not replay",
                    ) from error
                if projected != invocation.projection:
                    raise MCPAppResultWithheld(
                        "The governed result changed after execution; native MCP output was withheld. Do not replay",
                    )
                if not invocation.delivery_approved:
                    raise MCPAppResultWithheld(
                        "Post-tool policy did not approve native MCP delivery; result withheld. Do not replay",
                    )
                # Never forward the private native result before invoke returns:
                # at this point Core has confirmed its required structured audit.
                object.__setattr__(view, '_input_reference', None)
                return invocation.native.model_copy(deep=True)
            finally:
                invocation.finished = True
                self._invocation.reset(token)

        return await view._run_owned(operation, name="mcp-app-governed-call", revoked_outcome=revoked_outcome)
