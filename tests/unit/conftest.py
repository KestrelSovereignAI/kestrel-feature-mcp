"""Real HTTP fixtures shared by native MCP lifecycle and deadline tests."""

import asyncio
from dataclasses import dataclass
import socket

import pytest_asyncio
import uvicorn
from mcp import types
from mcp_types.version import LATEST_PROTOCOL_VERSION
from mcp.server import MCPServer
from mcp.shared.exceptions import MCPError


@dataclass
class HTTPMCPServer:
    url: str
    requests: list
    server: uvicorn.Server
    task: asyncio.Task

    async def stop(self):
        self.server.should_exit = True
        await asyncio.wait_for(self.task, 5)


@pytest_asyncio.fixture
async def mcp_http_server(request):
    settings = getattr(request, "param", {})

    class TestServer(MCPServer):
        async def _handle_list_tools(self, ctx, params):
            await asyncio.sleep(settings.get("list_delay", 0))
            listed = await self.list_tools()
            if settings.get("repeat_cursor"):
                return types.ListToolsResult(tools=listed, next_cursor="repeated")
            if settings.get("paginate"):
                return types.ListToolsResult(
                    tools=listed[1:] if params and params.cursor else listed[:1],
                    next_cursor=None if params and params.cursor else "page-2",
                )
            return types.ListToolsResult(tools=listed)

    mcp = TestServer("native-connection-test")

    @mcp.tool()
    async def echo(text: str) -> str:
        await asyncio.sleep(settings.get("tool_delay", 0))
        return text

    @mcp.tool()
    async def fail() -> str:
        raise ValueError("test tool failure")

    async def discover_behavior(ctx, call_next):
        if ctx.method == "server/discover":
            await asyncio.sleep(settings.get("discover_delay", 0))
            if settings.get("legacy"):
                raise MCPError(types.METHOD_NOT_FOUND, "Method not found")
            if settings.get("unsupported_version"):
                raise MCPError(
                    types.UNSUPPORTED_PROTOCOL_VERSION,
                    "No common protocol revision",
                    types.UnsupportedProtocolVersionErrorData(
                        supported=["2099-01-01"], requested=LATEST_PROTOCOL_VERSION
                    ).model_dump(by_alias=True),
                )
        return await call_next(ctx)
    mcp.middleware.append(discover_behavior)

    app = mcp.streamable_http_app(
        stateless_http=not settings.get("legacy", False), json_response=True
    )
    requests = []

    async def recorded(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        body = bytearray()
        if scope["method"] == "DELETE":
            requests.append((scope, b""))
            await asyncio.sleep(settings.get("delete_delay", 0))

        async def read():
            message = await receive()
            body.extend(message.get("body", b""))
            return message

        async def write(message):
            await send(message)
            if (message["type"] == "http.response.start" and body
                    and b'"initialize"' in body):
                await asyncio.sleep(settings.get("initialize_body_delay", 0))

        try:
            await app(scope, read, write)
        finally:
            requests.append((scope, bytes(body)))

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(recorded, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def ready():
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("test HTTP server exited before startup")
            await asyncio.sleep(0.01)

    try:
        await asyncio.wait_for(ready(), 5)
        yield HTTPMCPServer(f"http://127.0.0.1:{port}/mcp", requests, server, task)
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        sock.close()

