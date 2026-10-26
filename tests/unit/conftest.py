"""Real HTTP fixtures shared by native MCP lifecycle and deadline tests."""

import asyncio
import gzip
from copy import deepcopy
from dataclasses import dataclass

import pytest_asyncio
import uvicorn
from mcp import types
from mcp_types.version import LATEST_PROTOCOL_VERSION
from mcp.server import MCPServer
from mcp.server.apps import APP_MIME_TYPE, Apps
from mcp.server.mcpserver.resources import BinaryResource
from mcp.server.streamable_http import StreamableHTTPServerTransport
from mcp.shared.exceptions import MCPError
from starlette.responses import JSONResponse, Response, StreamingResponse
from tests.http_peers import serve_http


@dataclass
class HTTPMCPServer:
    url: str
    requests: list
    server: uvicorn.Server
    task: asyncio.Task
    settings: dict
    mcp: MCPServer
    server_names: list
    witness: list

    async def stop(self):
        self.server.should_exit = True
        await asyncio.wait_for(self.task, 5)


@pytest_asyncio.fixture
async def mcp_http_server(request, tmp_path):
    settings = deepcopy(getattr(request, "param", {}))
    settings["discover_started"] = asyncio.Event()
    settings["standalone_ready"] = asyncio.Event()
    settings["ping_requested"] = asyncio.Event()
    settings["ping_answered"] = asyncio.Event()
    settings["bootstrap_body_started"] = asyncio.Event()
    settings["release_bootstrap_body"] = asyncio.Event()
    settings["input_witness_file"] = tmp_path / "input-execution-witness"
    settings["release_resource_wire"] = asyncio.Event()
    settings["resource_read_started"] = asyncio.Event()
    settings["app_reply_recorded"] = asyncio.Event()
    settings["resource_wire_closed"] = asyncio.Event()
    if settings.get("resource_wire_mode") == "gzip":
        # Construct the adversarial fixture before client allocation tracing.
        settings["compressed_resource_wire"] = gzip.compress(b"x" * (16 * 1024 * 1024))

    class TestServer(MCPServer):
        async def _handle_list_tools(self, ctx, params):
            await asyncio.sleep(settings.get("list_delay", 0))
            listed = [] if settings.get("empty_tools") else await self.list_tools()
            if settings.get("advertised_contract") is not None and listed:
                listed[0] = listed[0].model_copy(update=settings["advertised_contract"], deep=True)
            for index, tool in enumerate(listed):
                update = settings.get("advertised_tool_contracts", {}).get(tool.name)
                if update is not None:
                    listed[index] = tool.model_copy(update=update, deep=True)
            if settings.get("duplicate_tools") and listed:
                listed.append(listed[0].model_copy(deep=True))
            if settings.get("repeat_cursor"):
                return types.ListToolsResult(tools=listed, next_cursor="repeated")
            if settings.get("paginate"):
                return types.ListToolsResult(
                    tools=listed[1:] if params and params.cursor else listed[:1],
                    next_cursor=None if params and params.cursor else "page-2",
                )
            return types.ListToolsResult(tools=listed)

    extensions = []
    if settings.get("apps_tools"):
        apps = Apps()

        @apps.tool(
            resource_uri="ui://status/view.html",
            title="Status view",
            description="Display the server status",
            visibility=settings.get("apps_visibility", ["model", "app"]),
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
            icons=[types.Icon(src="https://example.com/status.svg", mimeType="image/svg+xml")],
            meta={"example.com/custom": {"nested": ["preserved", {"value": 42}]}},
        )
        async def status_view() -> dict[str, str]:
            return {"status": "ready"}

        if settings.get("apps_execution_tools"):
            @apps.tool(resource_uri="ui://status/view.html", visibility=["app"], description="Record one View action")
            async def app_mutate(text: str) -> types.CallToolResult:
                witness.append(text)
                await asyncio.sleep(settings.get("app_tool_delay", 0))
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=text,
                        _meta={"private-block": "view-only"})],
                    structured_content={"text": text},
                    _meta={"private-result": {"view": "only"}},
                )

        html = settings.get("apps_html", "<!doctype html><p>Status</p>")
        if settings.get("apps_blob"):
            apps.add_resource(BinaryResource(
                uri="ui://status/view.html", name="Status", mime_type=APP_MIME_TYPE,
                data=html.encode("utf-8"), meta=settings.get("apps_resource_meta"),
            ))
        else:
            apps.add_html_resource("ui://status/view.html", html)
        extensions.append(apps)
    mcp = TestServer("native-connection-test", extensions=extensions)
    witness = []

    @mcp.tool()
    async def echo(text: str) -> str:
        await asyncio.sleep(settings.get("tool_delay", 0))
        witness.append(text)
        return text

    @mcp.tool()
    async def fail() -> str:
        raise ValueError("test tool failure")

    async def discover_behavior(ctx, call_next):
        if ctx.method == "resources/read":
            settings.setdefault("resource_reads", []).append(ctx.method)
            settings["resource_read_started"].set()
            await asyncio.sleep(settings.get("resource_delay", 0))
        if ctx.method == "tools/call" and settings.get("input_required"):
            with settings["input_witness_file"].open("a") as stream:
                stream.write("executed-before-input\n")
            kind = settings["input_required"]
            requests = {}
            if kind == "sampling":
                requests["input"] = types.CreateMessageRequest(
                    method="sampling/createMessage",
                    params=types.CreateMessageRequestParams(
                        messages=[types.SamplingMessage(role="user", content=types.TextContent(type="text", text="input"))],
                        maxTokens=16))
            elif kind == "roots":
                requests["input"] = types.ListRootsRequest(method="roots/list")
            elif kind == "elicitation":
                requests["input"] = types.ElicitRequest(method="elicitation/create",
                    params=types.ElicitRequestParams(message="Input needed",
                        requestedSchema={"type": "object", "properties": {}}))
            else:
                assert kind == "state"
            return types.InputRequiredResult(input_requests=requests, request_state="peer-work-started")
        if ctx.method == "tools/call" and settings.get("reject_call"):
            raise MCPError(types.INVALID_PARAMS, "Tool arguments rejected before execution")
        if ctx.method == "tools/list" and settings.get("server_ping"):
            async with asyncio.timeout(3):
                await settings["standalone_ready"].wait()
                settings["ping_requested"].set()
                await ctx.session.send_ping()
            settings["ping_answered"].set()
        if ctx.method == "server/discover":
            settings["discover_started"].set()
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
        stateless_http=not settings.get("legacy", False), json_response=True,
        host="remote.example" if settings.get("tls") else "127.0.0.1",
    )
    requests = []

    async def recorded(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        oauth = settings.get("oauth")
        if oauth is not None:
            if oauth.get("redirect_to"):
                requests.append((scope, b""))
                return await Response(status_code=307, headers={
                    "Location": oauth["redirect_to"],
                })(scope, receive, send)
            if scope["path"] == "/.well-known/oauth-protected-resource/mcp":
                requests.append((scope, b""))
                document = {"resource": oauth.get("advertised_resource", oauth["resource"]),
                            "authorization_servers": [oauth.get("advertised_issuer", oauth["issuer"])],
                            "scopes_supported": ["read", "write"]}
                return await JSONResponse(document)(scope, receive, send)
            headers = dict(scope["headers"])
            if headers.get(b"authorization") != ("Bearer " + oauth["access_token"]).encode():
                requests.append((scope, b""))
                challenge = (f'Bearer resource_metadata="{oauth["metadata"]}", '
                             f'scope="{oauth.get("challenge_scope", "read")}"')
                return await Response(status_code=401, headers={
                    "WWW-Authenticate": challenge,
                })(scope, receive, send)
            if scope["method"] == "GET" and oauth.get("denied_authenticated_get"):
                requests.append((scope, b""))
                return await Response(status_code=oauth["denied_authenticated_get"])(scope, receive, send)
            if (settings.get("bootstrap_event_stream") and scope["method"] == "GET"
                    and headers.get(b"accept") == b"application/json"):
                async def held_event_stream():
                    settings["bootstrap_body_started"].set()
                    yield b": keep-alive\n\n"
                    await settings["release_bootstrap_body"].wait()
                try:
                    return await StreamingResponse(held_event_stream(), media_type="text/event-stream")(
                        scope, receive, send)
                finally:
                    requests.append((scope, b""))
        if settings.get("http_status"):
            body = bytearray()
            while True:
                message = await receive()
                body.extend(message.get("body", b""))
                if not message.get("more_body"):
                    break
            requests.append((scope, bytes(body)))
            status = settings["http_status"]
            headers = [(b"content-type", b"text/plain")]
            if status == 401:
                headers.append((b"www-authenticate", b'Bearer resource_metadata="https://issuer.example/metadata"'))
            else:
                headers.append((b"location", b"https://127.0.0.1:1/private"))
            await send({"type": "http.response.start", "status": status, "headers": headers})
            return await send({"type": "http.response.body", "body": b"remote rejected"})
        body = bytearray()
        if scope["method"] == "DELETE":
            requests.append((scope, b""))
            await asyncio.sleep(settings.get("delete_delay", 0))

        async def read():
            message = await receive()
            body.extend(message.get("body", b""))
            return message

        async def write(message):
            wire_mode = settings.get("resource_wire_mode")
            wire_method = settings.get("resource_wire_method", "resources/read")
            if wire_mode and ('"' + wire_method + '"').encode() in body:
                if message["type"] == "http.response.start":
                    return
                if message["type"] == "http.response.body":
                    async def adversarial_resource():
                        try:
                            if wire_mode == "gzip":
                                yield settings["compressed_resource_wire"]
                            elif wire_mode == "sse-many":
                                for _ in range(10):
                                    yield b":" + b"x" * 1024 + b"\n\n"
                                    settings["wire_comments_sent"] = settings.get("wire_comments_sent", 0) + 1
                                yield b"event: message\ndata: " + message["body"] + b"\n\n"
                            elif wire_mode == "sse-oversized":
                                yield b"event: message\ndata: " + b"x" * 8192 + b"\n\n"
                            else:
                                for _ in range(288):
                                    yield b"x" * (32 * 1024)
                                await settings["release_resource_wire"].wait()
                        finally:
                            settings["resource_wire_closed"].set()
                    headers = {"Content-Encoding": "gzip"} if wire_mode == "gzip" else {}
                    content_type = "text/event-stream" if wire_mode.startswith("sse-") else "application/json"
                    return await StreamingResponse(adversarial_resource(),
                        media_type=content_type, headers=headers)(scope, receive, send)
            if message["type"] == "http.response.start":
                settings.setdefault("responses", []).append(
                    (scope["method"], scope["path"], message["status"]))
            if settings.get("drop_tool_result") and b'"tools/call"' in body:
                if message["type"] == "http.response.start":
                    await send({"type": "http.response.start", "status": 200,
                                "headers": [(b"content-type", b"application/json"),
                                            (b"content-length", b"100000")]})
                    return
                if message["type"] == "http.response.body":
                    await send({"type": "http.response.body", "body": b"{", "more_body": True})
                    raise ConnectionResetError("Test peer lost the response after executing its tool")
            await send(message)
            if (message["type"] == "http.response.start" and scope["method"] == "GET"
                    and dict(message.get("headers", [])).get(b"content-type", b"").startswith(b"text/event-stream")):
                settings["standalone_ready"].set()
            if (message["type"] == "http.response.start" and body
                    and b'"initialize"' in body):
                await asyncio.sleep(settings.get("initialize_body_delay", 0))

        try:
            if (settings.get("legacy") and oauth is not None and scope["method"] == "GET"
                    and headers.get(b"accept") == b"application/json"):
                # A 2025-only peer has the SDK's handshake-era GET transport;
                # it does not select the 2026 handler from the request header.
                transport = StreamableHTTPServerTransport(
                    mcp_session_id=None, is_json_response_enabled=True)
                async with transport.connect():
                    try:
                        await transport.handle_request(scope, read, write)
                    finally:
                        await transport.terminate()
            else:
                await app(scope, read, write)
        finally:
            requests.append((scope, bytes(body)))
            if b'"tools/call"' in body and b'"app_mutate"' in body:
                settings["app_reply_recorded"].set()

    tls = settings.get("tls", False)
    certificate_host = settings.get("certificate_host", "remote.example") if tls else None
    async with serve_http(recorded, tmp_path, certificate_host=certificate_host) as peer:
        if tls:
            settings["certificate_file"] = peer.certificate_file
        yield HTTPMCPServer(peer.url + "/mcp", requests, peer.server, peer.task,
                            settings, mcp, peer.server_names, witness)
