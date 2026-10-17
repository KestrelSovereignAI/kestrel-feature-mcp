"""
Docker MCP Gateway Manager.

This module manages the Docker MCP Gateway process, which provides
a unified Streamable-HTTP endpoint for accessing any MCP server from
Docker's 311+ server catalog.

The gateway handles stdio->Streamable-HTTP conversion automatically, so we
can use any MCP server regardless of its native transport. MCP deprecated the
standalone HTTP+SSE transport (2025-03-26 spec) in favour of Streamable HTTP;
Only Streamable HTTP is supported by this host.

Usage:
    gateway = DockerMCPGateway()              # ephemeral port, streaming
    auth_token = await gateway.start(["fetch", "sqlite"])
    # Connect at gateway.endpoint_url (…/mcp) with the Bearer token
    await gateway.stop()
"""

import asyncio
import contextlib
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from collections import deque
from typing import List, Optional, Set

from .constants import (
    SSH_COMMAND_TIMEOUT_SHORT,
    SSH_COMMAND_TIMEOUT_DEFAULT,
    HTTP_TIMEOUT_SHORT,
)

logger = logging.getLogger(__name__)

# Gateway startup configuration.
# The gateway pulls the server image on first use, so a cold start can take far
# longer than a warm one — 30s timed out mid-pull for first-time servers (#12).
# Allow generous headroom; a genuinely hung gateway still fails, just later.
GATEWAY_STARTUP_TIMEOUT = 180.0  # seconds
GATEWAY_STARTUP_POLL_INTERVAL = 0.5  # seconds

# Bounded retention of the gateway's stdout for error/debug context. The
# background drainer keeps consuming the pipe for the process's whole life so
# it never fills and wedges the long-lived gateway (F398); only the most recent
# lines are kept in memory.
GATEWAY_LOG_HISTORY = 500


def _safe_put(q: "asyncio.Queue", item) -> None:
    """Best-effort ``put_nowait`` used from the stdout drainer via
    ``call_soon_threadsafe``; never raises back into the event loop."""
    with contextlib.suppress(Exception):
        q.put_nowait(item)


class DockerMCPGatewayError(Exception):
    """Error related to Docker MCP Gateway operations."""
    pass


class DockerMCPNotInstalledError(DockerMCPGatewayError):
    """Docker MCP Toolkit is not installed."""
    pass


class DockerMCPGateway:
    """
    Manages the Docker MCP Gateway process.

    The Docker MCP Gateway is a unified Streamable HTTP endpoint that can expose
    any MCP server from Docker's catalog. It handles the stdio->Streamable HTTP
    conversion automatically.

    Attributes:
        port: TCP port for the Streamable HTTP endpoint
        process: The gateway subprocess
        auth_token: Bearer token for authentication
        enabled_servers: Set of currently enabled server names
    """

    #: MCP deprecated the standalone HTTP+SSE transport (2025-03-26 spec) in
    #: favour of Streamable HTTP. We default to the gateway's ``streaming``
    #: transport. Legacy HTTP+SSE is no longer accepted.
    DEFAULT_TRANSPORT = "streaming"

    def __init__(
        self,
        port: int = 0,
        session_timeout: Optional[float] = None,
        transport: str = DEFAULT_TRANSPORT,
        long_lived: bool = True,
    ):
        """
        Initialize the gateway manager.

        Args:
            port: TCP port for the endpoint. ``0`` (default) selects a free
                  ephemeral port at start() time, which eliminates the
                  fixed-``:9000`` collision that blocked a second gateway (#12).
            session_timeout: Optional timeout in seconds after which gateway
                           auto-stops. None = no timeout (default).
                           Recommended: 300-900 for agent sessions.
            transport: Gateway transport — ``streaming`` (Streamable HTTP, the
                       current MCP standard). Other transports are refused.
            long_lived: Keep one container alive per server for the gateway's
                       lifetime (default True). Without it the gateway runs a
                       throwaway container per tool call, so stateful servers
                       (e.g. sequentialthinking's thoughtHistory) lose their
                       in-process state between calls. The containers are reaped
                       when the gateway stops.
        """
        if transport != self.DEFAULT_TRANSPORT:
            raise ValueError("MCP gateway requires the streaming (Streamable HTTP) transport")
        self.transport = transport
        self.long_lived = long_lived
        # Remember whether a fixed port was requested; 0 means "pick a free one
        # at bind time" so concurrent gateways never collide on a fixed port.
        self._requested_port = port
        self.port = port
        self.session_timeout = session_timeout
        self.process: Optional[subprocess.Popen] = None
        # Streamable HTTP authenticates via the MCP_GATEWAY_AUTH_TOKEN env var
        # (the gateway prints no Bearer line), so we mint the token up-front and
        # inject it into the gateway process and send it on every request.
        self.auth_token: Optional[str] = None
        self.enabled_servers: Set[str] = set()
        self._timeout_task: Optional[asyncio.Task] = None
        self._start_time: Optional[float] = None
        # Single owner of the gateway's stdout for the process's whole life
        # (F398). ``_stdout_thread`` does a blocking readline loop; every line
        # lands in the bounded ``_stdout_history`` deque, and — only during
        # startup — is also handed to the async startup loop via
        # ``_startup_queue`` (gated by ``_feed_startup_queue``).
        self._stdout_thread: Optional[threading.Thread] = None
        self._stdout_history: "deque[str]" = deque(maxlen=GATEWAY_LOG_HISTORY)
        self._startup_queue: Optional[asyncio.Queue] = None
        self._feed_startup_queue: bool = False

    @staticmethod
    def _find_free_port() -> int:
        """Reserve a free ephemeral TCP port (closed immediately; the gateway
        re-binds it microseconds later — a benign, standard race)."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    async def _wait_port_listening(self, timeout: float = 10.0) -> bool:
        """Poll until the gateway's TCP port accepts connections, so we never
        hand back a token before the endpoint can actually be dialed."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                fut = asyncio.open_connection("127.0.0.1", self.port)
                _, writer = await asyncio.wait_for(fut, timeout=1.0)
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return True
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.2)
        return False

    @staticmethod
    def check_docker_mcp_available() -> bool:
        """Check if Docker MCP Toolkit is installed and available."""
        try:
            result = subprocess.run(
                ["docker", "mcp", "--help"],
                capture_output=True,
                timeout=SSH_COMMAND_TIMEOUT_SHORT
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def get_docker_mcp_version() -> Optional[str]:
        """Get the Docker MCP Toolkit version."""
        try:
            result = subprocess.run(
                ["docker", "mcp", "version"],
                capture_output=True,
                text=True,
                timeout=SSH_COMMAND_TIMEOUT_SHORT
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    @staticmethod
    def _is_ready_line(line: str) -> bool:
        """Detect the streaming-transport readiness banner.

        The gateway prints e.g. ``> Start streaming server on port 9477`` once
        the Streamable HTTP endpoint is listening.
        """
        low = line.lower()
        return "streaming server" in low or "start streamable" in low

    async def start(self, servers: List[str]) -> str:
        """
        Start the Docker MCP Gateway with specified servers.

        Args:
            servers: List of server names to enable

        Returns:
            The bearer token for authentication

        Raises:
            DockerMCPNotInstalledError: If Docker MCP is not available
            DockerMCPGatewayError: If gateway fails to start
        """
        if not self.check_docker_mcp_available():
            raise DockerMCPNotInstalledError(
                "Docker MCP Toolkit is not installed. "
                "Please install Docker Desktop 29+ with MCP Toolkit enabled."
            )

        await self.stop()

        if not servers or any(not server or "," in server for server in servers):
            raise ValueError("MCP gateway needs a non-empty list of server names")
        # --servers is the gateway's authoritative per-process selection. The
        # old global `docker mcp server enable` command was removed by Docker.
        self.enabled_servers = set(servers)

        # Resolve the port at bind time: an explicit port is honoured, otherwise
        # pick a fresh ephemeral one so two gateways never fight over :9000 (#12).
        self.port = self._requested_port or self._find_free_port()

        servers_arg = ",".join(sorted(self.enabled_servers))
        cmd = [
            "docker", "mcp", "gateway", "run",
            f"--transport={self.transport}",
            f"--port={self.port}",
            "--host=127.0.0.1",
            f"--servers={servers_arg}",
        ]
        if self.long_lived:
            # Keep server containers alive across calls so stateful servers
            # retain in-process state (#12 follow-up); reaped on gateway stop.
            cmd.append("--long-lived")

        env = dict(os.environ)
        self.auth_token = secrets.token_hex(24)
        env["MCP_GATEWAY_AUTH_TOKEN"] = self.auth_token

        logger.info(f"Starting Docker MCP Gateway: {' '.join(cmd)}")

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )

        # Hand stdout to a single lifelong drainer thread (F398). It keeps the
        # pipe drained after startup so it never fills and wedges the long-lived
        # gateway, and it removes the per-poll ``to_thread(readline)`` that was
        # abandoned on every ``wait_for`` timeout (leaking threads / losing
        # lines). The startup loop below consumes from the queue it feeds.
        self._stdout_history.clear()
        self._startup_queue = asyncio.Queue()
        self._feed_startup_queue = True
        loop = asyncio.get_running_loop()
        self._stdout_thread = threading.Thread(
            target=self._drain_stdout,
            args=(self.process, loop, self._startup_queue),
            name="mcp-gateway-stdout-drain",
            daemon=True,
        )
        self._stdout_thread.start()

        start_time = time.monotonic()

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed >= GATEWAY_STARTUP_TIMEOUT:
                await self.stop()
                raise DockerMCPGatewayError(
                    f"Gateway startup timeout after {GATEWAY_STARTUP_TIMEOUT}s. "
                    f"Output:\n{self._recent_output(20)}"
                )

            try:
                line = await asyncio.wait_for(
                    self._startup_queue.get(),
                    timeout=GATEWAY_STARTUP_POLL_INTERVAL
                )
            except asyncio.TimeoutError:
                # No output this interval — surface a premature exit promptly
                # rather than waiting out the whole startup timeout.
                if self.process.poll() is not None:
                    raise DockerMCPGatewayError(
                        f"Gateway process exited with code "
                        f"{self.process.returncode}. "
                        f"Output:\n{self._recent_output()}"
                    )
                continue

            if line is None:
                # EOF sentinel: the drainer saw stdout close (process ended).
                raise DockerMCPGatewayError(
                    f"Gateway process exited with code {self.process.returncode}. "
                    f"Output:\n{self._recent_output()}"
                )

            logger.debug(f"Gateway: {line.rstrip()}")

            if self._is_ready_line(line):
                # Stop queueing before waiting for the port. The stdout drainer
                # remains active for the process lifetime, with bounded history.
                self._feed_startup_queue = False
                if not await self._wait_port_listening():
                    await self.stop()
                    raise DockerMCPGatewayError(
                        f"Gateway reported ready but port {self.port} never accepted connections"
                    )
                self._start_time = time.monotonic()
                logger.info("Gateway ready at %s", self.endpoint_url)
                if self.session_timeout:
                    self._start_timeout_task()
                return self.auth_token

    def _drain_stdout(self, proc, loop, startup_queue) -> None:
        """Single lifelong owner of the gateway's stdout (F398).

        Runs in a daemon thread doing a blocking readline loop. Every line is
        appended to the bounded ``_stdout_history`` deque; while
        ``_feed_startup_queue`` is set, each line is also delivered to the
        async startup loop via ``startup_queue``. After startup the pipe keeps
        being drained (into the bounded deque only) so it can never fill and
        wedge the long-lived gateway. On EOF a ``None`` sentinel is delivered so
        the startup loop can detect a premature process exit.
        """
        def _deliver(item):
            with contextlib.suppress(RuntimeError):
                # RuntimeError if the loop is already closed during teardown.
                loop.call_soon_threadsafe(_safe_put, startup_queue, item)

        try:
            stdout = proc.stdout
            while stdout is not None:
                line = stdout.readline()
                if not line:  # '' at EOF (process exited / pipe closed)
                    break
                self._stdout_history.append(line)
                if self._feed_startup_queue:
                    _deliver(line)
        except Exception as exc:  # noqa: BLE001 - drain thread has no caller
            logger.debug(f"Gateway stdout drain ended: {exc}")
        finally:
            _deliver(None)

    def _recent_output(self, limit: Optional[int] = None) -> str:
        """Join the most recent drained stdout lines for error context."""
        lines = list(self._stdout_history)
        if limit is not None:
            lines = lines[-limit:]
        return ''.join(lines)

    def _start_timeout_task(self):
        """Start a background task that stops the gateway after timeout."""
        async def timeout_handler():
            try:
                await asyncio.sleep(self.session_timeout)
                if self.is_running:
                    logger.warning(
                        f"Gateway session timeout ({self.session_timeout}s) - auto-stopping"
                    )
                    await self.stop()
            except asyncio.CancelledError:
                pass

        self._timeout_task = asyncio.create_task(timeout_handler())
        logger.debug(f"Session timeout set: {self.session_timeout}s")

    def _cancel_timeout_task(self):
        """Cancel the timeout task."""
        if self._timeout_task:
            self._timeout_task.cancel()
            self._timeout_task = None

    def reset_timeout(self):
        """Reset the session timeout (call on activity to keep alive)."""
        if self.session_timeout and self.is_running:
            self._cancel_timeout_task()
            self._start_time = time.monotonic()
            self._start_timeout_task()
            logger.debug("Session timeout reset")

    @property
    def time_remaining(self) -> Optional[float]:
        """Get remaining time before session timeout (None if no timeout)."""
        if not self.session_timeout or not self._start_time:
            return None
        elapsed = time.monotonic() - self._start_time
        remaining = self.session_timeout - elapsed
        return max(0, remaining)

    async def stop(self):
        """Stop the gateway process."""
        self._cancel_timeout_task()

        if self.process:
            logger.info("Stopping Docker MCP Gateway...")
            try:
                self.process.terminate()
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(self.process.wait),
                        timeout=HTTP_TIMEOUT_SHORT
                    )
                except asyncio.TimeoutError:
                    logger.warning("Gateway didn't terminate gracefully, killing...")
                    self.process.kill()
                    await asyncio.to_thread(self.process.wait)
            except Exception as e:
                logger.warning(f"Error stopping gateway: {e}")
            finally:
                # The process is dead, so stdout is at EOF and the drainer's
                # readline loop has ended (F398) — join it so no orphan thread
                # outlives the gateway.
                self._feed_startup_queue = False
                if self._stdout_thread is not None:
                    await asyncio.to_thread(self._stdout_thread.join, 2.0)
                    self._stdout_thread = None
                self._startup_queue = None
                self.process = None
                self.auth_token = None
                self._start_time = None
                logger.info("Gateway stopped")
        # enabled_servers tracks what THIS gateway process is serving; a stopped
        # gateway serves nothing. restart()/add_server()/remove_server() all
        # snapshot the desired list before calling stop(), so clearing here is
        # safe and keeps the set from accumulating stale servers across restarts.
        self.enabled_servers.clear()

    async def restart(self, servers: List[str] = None) -> str:
        """Restart the gateway with optionally different servers."""
        if servers is None:
            servers = list(self.enabled_servers)
        await self.stop()
        return await self.start(servers)

    async def add_server(self, server_name: str) -> str:
        """Add a server to the gateway (requires restart)."""
        servers = list(self.enabled_servers)
        servers.append(server_name)
        return await self.restart(servers)

    async def remove_server(self, server_name: str) -> str:
        """Remove a server from the gateway (requires restart)."""
        servers = list(self.enabled_servers)
        if server_name in servers:
            servers.remove(server_name)
        if not servers:
            await self.stop()
            raise DockerMCPGatewayError("Cannot remove last server, stopping gateway")
        return await self.restart(servers)

    @property
    def endpoint_url(self) -> str:
        """The gateway's Streamable HTTP endpoint."""
        return f"http://localhost:{self.port}/mcp"

    @property
    def is_running(self) -> bool:
        """Check if the gateway is running."""
        return self.process is not None and self.process.poll() is None


async def list_available_servers() -> List[str]:
    """List all available servers from Docker MCP catalog."""
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "mcp", "catalog", "show", "docker-mcp"],
            capture_output=True,
            text=True,
            timeout=SSH_COMMAND_TIMEOUT_DEFAULT
        )
        if result.returncode != 0:
            return []

        servers = []
        for line in result.stdout.split('\n'):
            match = re.search(r'\*\*([a-zA-Z0-9_-]+)\*\*', line)
            if match:
                servers.append(match.group(1))

        return servers
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


async def list_enabled_servers() -> List[str]:
    """List currently enabled servers in Docker MCP."""
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "mcp", "server", "ls"],
            capture_output=True,
            text=True,
            timeout=SSH_COMMAND_TIMEOUT_DEFAULT
        )
        if result.returncode != 0:
            return []

        servers = []
        in_table = False
        for line in result.stdout.split('\n'):
            if 'NAME' in line and 'DESCRIPTION' in line:
                in_table = True
                continue
            if in_table and line.strip() and not line.startswith('-'):
                parts = line.split()
                if parts:
                    servers.append(parts[0])

        return servers
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
