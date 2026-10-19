"""Lifecycle owner for the official MCP client's Streamable HTTP connections."""

from __future__ import annotations

import asyncio
import math
import logging
import hashlib
import json
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field

import httpx2
from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from pydantic import ValidationError
from mcp.shared.exceptions import MCPError
from mcp.client import InputRequiredRoundsExceededError
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client
from kestrel_sdk.security.outbound import ValidatedOutboundURL, pinned_httpx2_async_transport

from .constants import CALL_TOOL_TIMEOUT, SESSION_CONNECT_TIMEOUT_DEFAULT, SESSION_CLOSE_TIMEOUT_DEFAULT


logger = logging.getLogger(__name__)

MCP_CONNECTION_ERRORS = (
    MCPError, InputRequiredRoundsExceededError, httpx2.HTTPError, TimeoutError, OSError, ValidationError,
    BrokenResourceError, ClosedResourceError, EndOfStream,
)


class MCPCallOutcomeUnknownError(RuntimeError):
    """A call returned no valid result; its external effects are unconfirmed."""


def _rejected_before_execution(error: BaseException) -> bool:
    if isinstance(error, BaseExceptionGroup):
        return all(_rejected_before_execution(child) for child in error.exceptions)
    return isinstance(error, MCPError) and error.code in {
        types.PARSE_ERROR, types.INVALID_REQUEST, types.METHOD_NOT_FOUND, types.INVALID_PARAMS,
    }


def require_owner_did(owner_did: str) -> str:
    if (not isinstance(owner_did, str) or not owner_did.startswith("did:")
            or not owner_did[4:] or any(char.isspace() for char in owner_did)):
        raise ValueError("An agent DID is required for MCP connection ownership")
    return owner_did


def connection_digest(resource: str, owner_did: str) -> str:
    identity = json.dumps([require_owner_did(owner_did), resource], separators=(",", ":"))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


@dataclass
class ConnectionLifecycleGate:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


@asynccontextmanager
async def connection_lifecycle(gates: dict, name: str):
    """Keep one gate for holders and waiters; unrelated resources progress."""
    gate = gates.get(name)
    if gate is None:
        gate = ConnectionLifecycleGate()
        gates[name] = gate
    gate.users += 1
    try:
        async with gate.lock:
            yield
    finally:
        gate.users -= 1
        if gate.users == 0:
            del gates[name]


def bind_tool_caller(connection, is_current: Callable[[], bool], name: str, *, tool_names=None):
    """Bind the advertised connection, never a later replacement's transport."""
    async def call(tool_name: str, arguments: dict | None = None):
        if not is_current():
            raise ValueError(f"MCP connection {name} changed; rediscover its tools before calling")
        if tool_names is not None and tool_name not in tool_names:
            raise ValueError(f"Unknown tool: {tool_name}. Available: {list(tool_names)}")
        return await connection.call_tool(tool_name, arguments or {})
    return call


def describe_tools(client, tools, **labels) -> list[dict]:
    return [{**labels, "name": tool.name, "description": tool.description,
             "inputSchema": tool.input_schema, "protocol_version": client.protocol_version}
            for tool in tools]


class _ConnectionResources(AsyncExitStack):
    """Exit SDK resources on their owner task with a whole-shutdown deadline."""

    def __init__(self, timeout: float):
        super().__init__()
        self._timeout = timeout

    async def __aexit__(self, exc_type, exc_value, traceback):
        async with asyncio.timeout(self._timeout):
            return await super().__aexit__(exc_type, exc_value, traceback)


class _ShutdownDeadline:
    """A graceful deadline that outlives a cancelled shutdown caller."""

    def __init__(self, task: asyncio.Task, timeout: float):
        self.expired = False
        self._task = task
        self._timer = asyncio.get_running_loop().call_later(timeout, self._expire)

    def _expire(self):
        if not self._task.done():
            self.expired = True
            logger.warning("MCP graceful shutdown deadline expired; cancelling SDK cleanup")
            self._task.cancel()

    def cancel(self):
        self._timer.cancel()


class MCPConnection:
    """Keep the SDK's transport and client contexts in one owned task.

    AnyIO transport contexts must enter and exit on the same task. Callers may
    use the client from their turn, but connection teardown stays with its
    owner. Failed startup, timeout and caller cancellation all join that owner.
    """

    def __init__(
        self,
        url: str | ValidatedOutboundURL,
        *,
        headers: Mapping[str, str] | None = None,
        auth: httpx2.Auth | None = None,
        connect_timeout: float = SESSION_CONNECT_TIMEOUT_DEFAULT,
        call_timeout: float = CALL_TOOL_TIMEOUT,
        close_timeout: float = SESSION_CLOSE_TIMEOUT_DEFAULT,
    ) -> None:
        if not all(math.isfinite(value) and value > 0
                   for value in (connect_timeout, call_timeout, close_timeout)):
            raise ValueError("MCP connection, call and shutdown timeouts must be finite positive numbers")
        self._outbound = url if isinstance(url, ValidatedOutboundURL) else None
        self.url = url.url if self._outbound is not None else url
        self._headers = dict(headers or {})
        self._auth = auth
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self._close_timeout = close_timeout
        self._client: Client | None = None
        self._task: asyncio.Task[None] | None = None
        self._ready: asyncio.Future[Client] | None = None
        self._shutdown: _ShutdownDeadline | None = None

    @property
    def is_connected(self) -> bool:
        return (
            self._client is not None
            and self._task is not None
            and not self._task.done()
            and not self._task.cancelling()
            and self._shutdown is None
        )

    @property
    def protocol_version(self) -> str | None:
        """The published revision selected by the SDK's standard negotiation."""
        return self._client.protocol_version if self.is_connected else None

    def _owner_finished(self, task: asyncio.Task[None]) -> None:
        # Always observe the task outcome, including a failure after startup.
        # Deliver startup failures to connect immediately instead of waiting
        # for the connection timeout and hiding the original error.
        if self._shutdown is not None:
            self._shutdown.cancel()
        error = None if task.cancelled() else task.exception()
        if error is not None:
            logger.warning("MCP connection owner failed", exc_info=error)
        if self._ready is not None and not self._ready.done():
            if error is not None:
                self._ready.set_exception(error)
            else:
                self._ready.cancel()

    async def _run(self) -> None:
        try:
            async with _ConnectionResources(self._close_timeout) as resources:
                http_client = await resources.enter_async_context(httpx2.AsyncClient(
                    headers=self._headers,
                    auth=self._auth,
                    # Socket acquisition/writes are bounded; SDK/host deadlines
                    # own reads and pagination. Resource exit also has a whole
                    # deadline, including a handshake peer's session DELETE.
                    timeout=httpx2.Timeout(self._connect_timeout, read=None),
                    follow_redirects=False,
                    trust_env=False,
                    transport=(pinned_httpx2_async_transport(self._outbound)
                               if self._outbound is not None else None),
                ))
                transport = streamable_http_client(self.url, http_client=http_client)
                client = await resources.enter_async_context(Client(
                    transport,
                    cache=None,
                    # Operator-input continuations need the host's governed
                    # surface. Never let the SDK reissue a tool call implicitly.
                    input_required_max_rounds=0,
                ))
                self._client = client
                if self._ready is not None and not self._ready.done():
                    self._ready.set_result(client)
                await asyncio.Future()
        finally:
            self._client = None

    async def _close_failed_startup(self, exc_type, exc_value, traceback):
        if exc_type is not None and issubclass(exc_type, (TimeoutError, asyncio.CancelledError)):
            try:
                await self.close()
            except* MCP_CONNECTION_ERRORS as cleanup_error:
                # Preserve the operation deadline/caller cancellation. A late
                # SDK write into a closed transport is secondary cleanup evidence.
                logger.warning("MCP startup cleanup also failed", exc_info=cleanup_error)
        else:
            await self.close()
        return False

    async def connect(self) -> list[types.Tool]:
        if self._task is not None:
            raise RuntimeError("MCP connection already started; close it before reconnecting")
        self._ready = asyncio.get_running_loop().create_future()
        self._task = asyncio.create_task(self._run(), name="mcp-connection")
        self._task.add_done_callback(self._owner_finished)
        async with AsyncExitStack() as startup:
            startup.push_async_exit(self._close_failed_startup)
            try:
                async with asyncio.timeout(self._connect_timeout):
                    await self._ready
            except TimeoutError as error:
                raise TimeoutError("MCP connection deadline exceeded") from error
            tools = await self.list_tools()
            startup.pop_all()
            return tools

    def _require_client(self) -> Client:
        if not self.is_connected or self._client is None:
            raise ConnectionError("MCP connection is not connected")
        return self._client

    async def list_tools(self) -> list[types.Tool]:
        async def collect() -> list[types.Tool]:
            tools: list[types.Tool] = []
            cursor: str | None = None
            seen: set[str] = set()
            while True:
                result = await self._require_client().list_tools(cursor=cursor)
                tools.extend(result.tools)
                cursor = result.next_cursor
                if cursor is None:
                    return tools
                if cursor in seen:
                    raise ValueError("MCP server repeated its tools/list cursor")
                seen.add(cursor)

        return await asyncio.wait_for(collect(), timeout=self._call_timeout)

    async def call_tool(self, name: str, arguments: dict | None = None) -> types.CallToolResult:
        client = self._require_client()
        try:
            return await asyncio.wait_for(
                client.call_tool(name, arguments or {}), timeout=self._call_timeout,
            )
        except (ExceptionGroup, *MCP_CONNECTION_ERRORS) as error:
            if isinstance(error, ExceptionGroup):
                _, unexpected = error.split(MCP_CONNECTION_ERRORS)
                if unexpected is not None:
                    raise
            if _rejected_before_execution(error):
                raise
            raise MCPCallOutcomeUnknownError(
                f"MCP tool {name!r} returned no confirmed result; its execution outcome is unknown. "
                "Do not replay it without policy approval and an explicit idempotency or safe-repeat guarantee."
            ) from error

    async def close(self) -> None:
        task = self._task
        if task is None:
            return
        already_done = task.done()
        if not already_done and self._shutdown is None:
            # Task.cancelling() also counts SDK/AnyIO cancellation. Track OUR
            # shutdown explicitly, so its cleanup is never mistaken for ours.
            self._shutdown = _ShutdownDeadline(task, self._close_timeout)
            task.cancel()
        try:
            # A partially-entered SDK client can clean up inside __aenter__,
            # before our resource stack's __aexit__ starts. The independent
            # graceful timer interrupts that cleanup even if this caller
            # abandons the join. Forced cleanup gets one further bounded budget.
            await asyncio.wait(
                {task}, timeout=self._close_timeout + self._close_timeout,
            )
            expired = self._shutdown is not None and self._shutdown.expired
            if not task.done() or (expired and not already_done):
                error = TimeoutError(
                    "MCP shutdown deadline exceeded while closing SDK resources"
                )
                if task.done() and not task.cancelled():
                    raise error from task.exception()
                raise error
            # A historical transport failure is observed by the owner callback,
            # rather than masquerading as a new cleanup error.
            if not task.cancelled() and not already_done:
                task.result()
        finally:
            if task.done():
                if self._shutdown is not None:
                    self._shutdown.cancel()
                self._shutdown = None
                self._task = None
                self._ready = None
                self._client = None
