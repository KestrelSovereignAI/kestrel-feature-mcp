"""Lifecycle owner for native MCP 2026-07-28 Streamable HTTP connections."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Mapping

import httpx2
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client

from .constants import CALL_TOOL_TIMEOUT, SESSION_CONNECT_TIMEOUT_DEFAULT


MCP_PROTOCOL_VERSION = "2026-07-28"


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
    ) -> None:
        if not all(math.isfinite(value) and value > 0
                   for value in (connect_timeout, call_timeout)):
            raise ValueError("MCP connection and call timeouts must be finite positive numbers")
        self.url = url
        self._headers = dict(headers or {})
        self._auth = auth
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self._client: Client | None = None
        self._task: asyncio.Task[None] | None = None
        self._ready: asyncio.Future[Client] | None = None

    @property
    def is_connected(self) -> bool:
        return (
            self._client is not None
            and self._task is not None
            and not self._task.done()
        )

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
            async with httpx2.AsyncClient(
                headers=self._headers,
                auth=self._auth,
                # The SDK/host bound the whole operation, including pagination
                # and cancellation. An equal per-socket read timeout races that
                # deadline and can replace its error with a teardown group.
                timeout=None,
                follow_redirects=False,
            ) as http_client:
                transport = streamable_http_client(self.url, http_client=http_client)
                async with Client(
                    transport,
                    mode=MCP_PROTOCOL_VERSION,
                    read_timeout_seconds=self._call_timeout,
                    cache=None,
                ) as client:
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
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None
            self._ready = None
            self._client = None
