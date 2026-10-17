"""Lifecycle owner for the official MCP client's Streamable HTTP connections."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Mapping
from contextlib import AsyncExitStack

import httpx2
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client

from .constants import CALL_TOOL_TIMEOUT, SESSION_CONNECT_TIMEOUT_DEFAULT, SESSION_CLOSE_TIMEOUT_DEFAULT


class _ConnectionResources(AsyncExitStack):
    """Exit SDK resources on their owner task with a whole-shutdown deadline."""

    def __init__(self, timeout: float):
        super().__init__()
        self._timeout = timeout

    async def __aexit__(self, exc_type, exc_value, traceback):
        async with asyncio.timeout(self._timeout):
            return await super().__aexit__(exc_type, exc_value, traceback)


class MCPConnection:
    """Keep the SDK's transport and client contexts in one owned task.

    AnyIO transport contexts must enter and exit on the same task. Callers may
    use the client from their turn, but connection teardown stays with its
    owner. Failed startup, timeout and caller cancellation all join that owner.
    """

    def __init__(
        self,
        url: str,
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
        self.url = url
        self._headers = dict(headers or {})
        self._auth = auth
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self._close_timeout = close_timeout
        self._client: Client | None = None
        self._task: asyncio.Task[None] | None = None
        self._ready: asyncio.Future[Client] | None = None

    @property
    def is_connected(self) -> bool:
        return (
            self._client is not None
            and self._task is not None
            and not self._task.done()
            and not self._task.cancelling()
        )

    @property
    def protocol_version(self) -> str | None:
        """The published revision selected by the SDK's standard negotiation."""
        return self._client.protocol_version if self.is_connected else None

    def _owner_finished(self, task: asyncio.Task[None]) -> None:
        # Always observe the task outcome, including a failure after startup.
        # Deliver startup failures to connect immediately instead of waiting
        # for the connection timeout and hiding the original error.
        error = None if task.cancelled() else task.exception()
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
                ))
                transport = streamable_http_client(self.url, http_client=http_client)
                client = await resources.enter_async_context(Client(
                    transport,
                    cache=None,
                ))
                self._client = client
                if self._ready is not None and not self._ready.done():
                    self._ready.set_result(client)
                await asyncio.Future()
        finally:
            self._client = None

    async def connect(self) -> list[types.Tool]:
        if self._task is not None:
            raise RuntimeError("MCP connection already started; close it before reconnecting")
        self._ready = asyncio.get_running_loop().create_future()
        self._task = asyncio.create_task(self._run(), name="mcp-connection")
        self._task.add_done_callback(self._owner_finished)
        published = False
        try:
            async with asyncio.timeout(self._connect_timeout):
                await self._ready
            tools = await self.list_tools()
            published = True
            return tools
        finally:
            if not published:
                await self.close()

    def _require_client(self) -> Client:
        if not self.is_connected or self._client is None:
            raise RuntimeError("MCP connection is not connected")
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
        return await asyncio.wait_for(
            self._require_client().call_tool(name, arguments or {}),
            timeout=self._call_timeout,
        )

    async def close(self) -> None:
        task = self._task
        if task is None:
            return
        if not task.cancelling():
            task.cancel()
        try:
            # Waiting observes completion without confusing owner cancellation
            # with cancellation of this caller. A cancelled caller retains the
            # owner so shutdown can be rejoined; the owner bounds its cleanup.
            await asyncio.wait({task})
            if not task.cancelled():
                task.result()
        finally:
            if task.done():
                self._task = None
                self._ready = None
                self._client = None
