"""Unit tests for the non-blocking Docker/gateway changes (F397, F398).

F397: docker-py's blocking socket calls (from_env/ping, containers/images ops)
must run OFF the event loop so they can't freeze every agent on the host.

F398: the gateway's stdout must be drained for the process's whole life, not
just during startup, or the OS pipe fills (~64KB) and wedges the long-lived
gateway.
"""

from __future__ import annotations

import asyncio
import threading
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from requests.exceptions import ConnectionError as RequestsConnectionError, ReadTimeout

from kestrel_feature_mcp import manager as manager_module
from kestrel_feature_mcp.feature import MCPAgent

from kestrel_feature_mcp.gateway import DockerMCPGateway
from kestrel_feature_mcp.manager import DOCKER_CLIENT_TIMEOUT, DockerDaemonUnavailableError, MCPToolManager


# --- F397: connect off the event loop ---------------------------------------


@pytest.mark.asyncio
async def test_create_runs_connect_off_the_event_loop():
    """``MCPToolManager.create`` must build the Docker client in a worker
    thread — the blocking from_env()/ping() must not run on the loop."""
    main_thread = threading.current_thread()
    seen = {}

    def fake_from_env(**kwargs):
        seen["thread"] = threading.current_thread()
        client = MagicMock()
        return client

    with patch("kestrel_feature_mcp.manager.docker") as mock_docker:
        mock_docker.from_env.side_effect = fake_from_env
        manager = await MCPToolManager.create(owner_did="did:test:manager")

    assert manager.docker_client is not None
    # from_env ran in a worker thread (asyncio.to_thread), not the loop thread.
    assert seen["thread"] is not main_thread
    manager.docker_client.ping.assert_called_once()
    manager.docker_client.close.assert_not_called()
    # Client is built with an explicit socket-read timeout so a hung daemon
    # can't leave a worker thread blocked forever (F397).
    mock_docker.from_env.assert_called_once_with(timeout=DOCKER_CLIENT_TIMEOUT)


@pytest.mark.asyncio
async def test_create_raises_runtimeerror_on_docker_failure():
    class _DockerException(Exception):
        pass

    with patch("kestrel_feature_mcp.manager.docker") as mock_docker:
        mock_docker.errors.DockerException = _DockerException
        mock_docker.from_env.side_effect = _DockerException("no daemon")
        with pytest.raises(RuntimeError):
            await MCPToolManager.create(owner_did="did:test:manager")


@pytest.mark.asyncio
async def test_aclose_runs_off_the_event_loop():
    """``aclose`` closes the client in a worker thread (F397)."""
    main_thread = threading.current_thread()
    seen = {}

    def fake_close():
        seen["thread"] = threading.current_thread()

    client = MagicMock()
    client.close.side_effect = fake_close
    with patch("kestrel_feature_mcp.manager.docker"):
        manager = MCPToolManager(owner_did="did:test:manager", docker_client=client)
        await manager.aclose()

    assert seen["thread"] is not main_thread
    assert manager.docker_client is None


def test_close_closes_the_injected_client():
    """The synchronous close is the canonical operation behind aclose."""
    client = MagicMock()
    with patch("kestrel_feature_mcp.manager.docker"):
        manager = MCPToolManager(owner_did="did:test:manager", docker_client=client)
        result = manager.close()  # no await
    assert result is None
    client.close.assert_called_once()
    assert manager.docker_client is None


@pytest_asyncio.fixture
async def failing_docker_http(request, monkeypatch):
    """Real docker-py/Requests I/O; a loopback HTTP daemon fails only ping."""
    release_ping = threading.Event()
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append(self.path)
            if self.path == "/version":
                body = b'{"ApiVersion": "1.45"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/v1.45/_ping":
                if request.param == "timeout":
                    release_ping.wait(5)
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            else:
                self.send_error(404)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    monkeypatch.setenv("DOCKER_HOST", f"tcp://127.0.0.1:{server.server_port}")
    for name in ("DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                 "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setattr(manager_module, "DOCKER_CLIENT_TIMEOUT", 1)
    thread.start()
    try:
        yield observed
    finally:
        release_ping.set()
        await asyncio.to_thread(server.shutdown)
        await asyncio.to_thread(server.server_close)
        await asyncio.to_thread(thread.join, 5)
        assert not thread.is_alive()


@pytest.mark.parametrize("failing_docker_http,error_type", [
    ("disconnect", RequestsConnectionError), ("timeout", ReadTimeout),
], indirect=["failing_docker_http"])
async def test_real_docker_ping_transport_failure_is_a_typed_daemon_error(failing_docker_http, error_type):
    with pytest.raises(DockerDaemonUnavailableError) as caught:
        await MCPToolManager.create(owner_did="did:test:loopback-daemon")
    assert isinstance(caught.value.__cause__, error_type)
    assert failing_docker_http == ["/version", "/v1.45/_ping"]


@pytest.mark.parametrize("failing_docker_http", ["disconnect", "timeout"], indirect=True)
async def test_feature_survives_real_daemon_ping_transport_failure(failing_docker_http, caplog):
    feature = MCPAgent(SimpleNamespace(agent_id="did:test:loopback-daemon"))
    await feature.initialize()
    assert failing_docker_http == []
    assert not await feature._ensure_container_manager()
    assert feature.manager is None and feature.gateway_manager is None
    assert "Local Docker daemon unavailable" in caplog.text
    assert failing_docker_http == ["/version", "/v1.45/_ping"]


# --- F398: gateway stdout drained for the process's whole life --------------


class _FakeGatewayPopen:
    """Popen double that emits a ready line then a flood of log lines, then
    EOF. Records every line handed out so a test can prove the drainer kept
    reading after startup."""

    def __init__(self, cmd, **kw):
        self.returncode = 0
        self.stdout = self
        self.consumed = []
        lines = ["> Start streaming server on port 34567\n"]
        lines += [f"log line {i}\n" for i in range(2000)]
        self._it = iter(lines)
        self.total = len(lines)

    def readline(self):
        try:
            line = next(self._it)
        except StopIteration:
            return ""  # EOF
        self.consumed.append(line)
        return line

    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self):
        return 0

    def kill(self):
        pass


@pytest.mark.asyncio
async def test_gateway_stdout_drained_after_startup(monkeypatch):
    fakes = {}

    def _make(cmd, **kw):
        p = _FakeGatewayPopen(cmd, **kw)
        fakes["proc"] = p
        return p

    monkeypatch.setattr("kestrel_feature_mcp.gateway.subprocess.Popen", _make)
    monkeypatch.setattr(
        DockerMCPGateway, "check_docker_mcp_available", staticmethod(lambda: True)
    )

    async def _ready(self, timeout=10.0):
        return True

    monkeypatch.setattr(DockerMCPGateway, "_wait_port_listening", _ready)

    gw = DockerMCPGateway(port=34567)
    await gw.start(["x"])

    # startup returned on the ready line; the drainer must keep consuming the
    # remaining flood so the pipe is never left to fill and wedge the gateway.
    proc = fakes["proc"]
    for _ in range(500):
        if len(proc.consumed) >= proc.total:
            break
        await asyncio.sleep(0.005)

    assert len(proc.consumed) == proc.total  # every line drained post-startup

    await gw.stop()
    assert gw._stdout_thread is None  # drainer joined on stop
