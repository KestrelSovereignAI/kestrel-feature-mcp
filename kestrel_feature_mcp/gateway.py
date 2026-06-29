"""
Docker MCP Gateway Manager.

This module manages the Docker MCP Gateway process, which provides
a unified Streamable-HTTP endpoint for accessing any MCP server from
Docker's 311+ server catalog.

The gateway handles stdio->Streamable-HTTP conversion automatically, so we
can use any MCP server regardless of its native transport. MCP deprecated the
standalone HTTP+SSE transport (2025-03-26 spec) in favour of Streamable HTTP;
``sse`` remains selectable only for legacy interop.

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
import time
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


class DockerMCPGatewayError(Exception):
    """Error related to Docker MCP Gateway operations."""
    pass


class DockerMCPNotInstalledError(DockerMCPGatewayError):
    """Docker MCP Toolkit is not installed."""
    pass


class DockerMCPGateway:
    """
    Manages the Docker MCP Gateway process.

    The Docker MCP Gateway is a unified SSE endpoint that can expose
    any MCP server from Docker's catalog. It handles the stdio->SSE
    conversion automatically.

    Attributes:
        port: TCP port for the SSE endpoint
        process: The gateway subprocess
        auth_token: Bearer token for authentication
        enabled_servers: Set of currently enabled server names
    """

    #: MCP deprecated the standalone HTTP+SSE transport (2025-03-26 spec) in
    #: favour of Streamable HTTP. We default to the gateway's ``streaming``
    #: transport; ``sse`` remains selectable only for legacy interop (#12).
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
                       current MCP standard, default) or ``sse`` (deprecated).
            long_lived: Keep one container alive per server for the gateway's
                       lifetime (default True). Without it the gateway runs a
                       throwaway container per tool call, so stateful servers
                       (e.g. sequentialthinking's thoughtHistory) lose their
                       in-process state between calls. The containers are reaped
                       when the gateway stops.
        """
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
        # inject it. Legacy sse parses the token from stdout instead.
        self.auth_token: Optional[str] = None
        self.enabled_servers: Set[str] = set()
        self._output_lines: List[str] = []
        self._timeout_task: Optional[asyncio.Task] = None
        self._start_time: Optional[float] = None

    @property
    def _is_streaming(self) -> bool:
        return self.transport != "sse"

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

    async def _enable_server(self, server_name: str) -> bool:
        """Enable a server in Docker MCP."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["docker", "mcp", "server", "enable", server_name],
                capture_output=True,
                text=True,
                timeout=SSH_COMMAND_TIMEOUT_DEFAULT
            )
            if result.returncode == 0:
                logger.info(f"Enabled MCP server: {server_name}")
                self.enabled_servers.add(server_name)
                return True
            else:
                logger.warning(f"Failed to enable {server_name}: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout enabling server {server_name}")
            return False

    async def _disable_server(self, server_name: str) -> bool:
        """Disable a server in Docker MCP."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["docker", "mcp", "server", "disable", server_name],
                capture_output=True,
                text=True,
                timeout=SSH_COMMAND_TIMEOUT_DEFAULT
            )
            if result.returncode == 0:
                logger.info(f"Disabled MCP server: {server_name}")
                self.enabled_servers.discard(server_name)
                return True
            else:
                logger.warning(f"Failed to disable {server_name}: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout disabling server {server_name}")
            return False

    def _parse_auth_token(self, line: str) -> Optional[str]:
        """Parse the auth token from gateway output (legacy sse transport)."""
        match = re.search(r'Authorization:\s*Bearer\s+([a-zA-Z0-9]+)', line)
        if match:
            return match.group(1)
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

        for server in servers:
            await self._enable_server(server)

        if not self.enabled_servers:
            raise DockerMCPGatewayError(
                f"Failed to enable any servers from: {servers}"
            )

        # Resolve the port at bind time: an explicit port is honoured, otherwise
        # pick a fresh ephemeral one so two gateways never fight over :9000 (#12).
        self.port = self._requested_port or self._find_free_port()

        servers_arg = ",".join(self.enabled_servers)
        cmd = [
            "docker", "mcp", "gateway", "run",
            f"--transport={self.transport}",
            f"--port={self.port}",
            f"--servers={servers_arg}",
        ]
        if self.long_lived:
            # Keep server containers alive across calls so stateful servers
            # retain in-process state (#12 follow-up); reaped on gateway stop.
            cmd.append("--long-lived")

        env = dict(os.environ)
        if self._is_streaming:
            # Streamable HTTP has no token line to parse — mint one and inject
            # it; the client sends it back as a Bearer header.
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

        start_time = time.monotonic()
        self._output_lines = []

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed >= GATEWAY_STARTUP_TIMEOUT:
                await self.stop()
                raise DockerMCPGatewayError(
                    f"Gateway startup timeout after {GATEWAY_STARTUP_TIMEOUT}s. "
                    f"Output:\n{''.join(self._output_lines[-20:])}"
                )

            if self.process.poll() is not None:
                remaining = self.process.stdout.read()
                if remaining:
                    self._output_lines.append(remaining)
                raise DockerMCPGatewayError(
                    f"Gateway process exited with code {self.process.returncode}. "
                    f"Output:\n{''.join(self._output_lines)}"
                )

            try:
                line = await asyncio.wait_for(
                    asyncio.to_thread(self.process.stdout.readline),
                    timeout=GATEWAY_STARTUP_POLL_INTERVAL
                )
                if not line:
                    continue
                self._output_lines.append(line)
                logger.debug(f"Gateway: {line.rstrip()}")

                if self._is_streaming:
                    # e.g. "> Start streaming server on port 9477"
                    if self._is_ready_line(line):
                        if not await self._wait_port_listening():
                            await self.stop()
                            raise DockerMCPGatewayError(
                                "Gateway reported ready but the streaming port "
                                f"{self.port} never accepted connections."
                            )
                        self._start_time = time.monotonic()
                        logger.info(
                            f"Gateway ready at {self.endpoint_url}"
                        )
                        if self.session_timeout:
                            self._start_timeout_task()
                        return self.auth_token
                    continue

                token = self._parse_auth_token(line)
                if token:
                    self.auth_token = token
                    self._start_time = time.monotonic()
                    logger.info(f"Gateway ready at {self.endpoint_url}")
                    if self.session_timeout:
                        self._start_timeout_task()
                    return token
                if "Start sse server" in line or "Gateway URL:" in line:
                    continue

            except asyncio.TimeoutError:
                continue

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
        """The MCP endpoint URL for the active transport.

        Streamable HTTP serves at ``/mcp``; legacy sse serves at ``/sse``.
        """
        path = "sse" if not self._is_streaming else "mcp"
        return f"http://localhost:{self.port}/{path}"

    @property
    def sse_url(self) -> str:
        """Deprecated alias for :attr:`endpoint_url` (kept for callers/tests)."""
        return self.endpoint_url

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
