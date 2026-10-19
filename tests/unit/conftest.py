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
    settings: dict
    mcp: MCPServer
    server_names: list
    witness: list

    async def stop(self):
        self.server.should_exit = True
        await asyncio.wait_for(self.task, 5)


@pytest_asyncio.fixture
async def mcp_http_server(request, tmp_path):
    settings = getattr(request, "param", {})
    settings["discover_started"] = asyncio.Event()
    settings["input_witness_file"] = tmp_path / "input-execution-witness"

    class TestServer(MCPServer):
        async def _handle_list_tools(self, ctx, params):
            await asyncio.sleep(settings.get("list_delay", 0))
            listed = [] if settings.get("empty_tools") else await self.list_tools()
            if settings.get("repeat_cursor"):
                return types.ListToolsResult(tools=listed, next_cursor="repeated")
            if settings.get("paginate"):
                return types.ListToolsResult(
                    tools=listed[1:] if params and params.cursor else listed[:1],
                    next_cursor=None if params and params.cursor else "page-2",
                )
            return types.ListToolsResult(tools=listed)

    mcp = TestServer("native-connection-test")
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
    tls = settings.get("tls", False)
    tls_options = {}
    if tls:
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        hostname = settings.get("certificate_host", "remote.example")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = tmp_path / "certificate.pem", tmp_path / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        tls_options = {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}
        settings["certificate_file"] = str(cert_path)
    server = uvicorn.Server(uvicorn.Config(recorded, log_level="error", **tls_options))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def ready():
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("test HTTP server exited before startup")
            await asyncio.sleep(0.01)

    try:
        await asyncio.wait_for(ready(), 5)
        server_names = []
        if tls:
            server.config.ssl.set_servername_callback(
                lambda _socket, name, _context: server_names.append(name))
        scheme = "https" if tls else "http"
        yield HTTPMCPServer(f"{scheme}://127.0.0.1:{port}/mcp", requests, server, task,
                            settings, mcp, server_names, witness)
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        sock.close()
