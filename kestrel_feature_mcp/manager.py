"""
MCP Tool Manager - Manages MCP tools via Docker.

This module provides two modes of operation:

1. **Gateway Mode (Recommended)**: Uses Docker MCP Gateway for unified access
   to 311+ MCP servers with automatic stdio->Streamable HTTP conversion.

2. **Container Mode**: Direct container management for Streamable HTTP
   servers or custom test servers.

Gateway mode is recommended for production use as it provides access to
all MCP servers regardless of their native transport.
"""

import logging
import asyncio
import time
import hashlib
import json
from contextlib import ExitStack
from functools import wraps
from typing import Dict, Any, List, Optional

try:
    import docker
    from docker.models.containers import Container
    from docker.errors import NotFound, DockerException, APIError, ImageNotFound
except ImportError:
    docker = None  # type: ignore[assignment]
    Container = None  # type: ignore[assignment,misc]
    NotFound = None  # type: ignore[assignment,misc]
    DockerException = None  # type: ignore[assignment,misc]
    APIError = None  # type: ignore[assignment,misc]
    ImageNotFound = None  # type: ignore[assignment,misc]

from .connection import MCPConnection, MCP_CONNECTION_ERRORS
from .images import normalize_image_ref

from .constants import (
    SESSION_CONNECT_TIMEOUT_SHORT,
    SESSION_CONNECT_TIMEOUT_DEFAULT,
    CALL_TOOL_TIMEOUT,
    MCP_REMOVAL_ATTEMPTS,
    MCP_REMOVAL_RETRY_DELAY,
    MCP_CONTAINER_BIND_HOST,
)
from .gateway import DockerMCPGateway, DockerMCPGatewayError, DockerMCPNotInstalledError

logger = logging.getLogger(__name__)

# Container healthcheck configuration
HEALTHCHECK_INITIAL_DELAY = 0.5  # Initial delay before first check
HEALTHCHECK_MAX_DELAY = 4.0      # Maximum delay between retries
HEALTHCHECK_TIMEOUT = 30.0       # Total timeout for container to become ready
HEALTHCHECK_BACKOFF_FACTOR = 2.0 # Exponential backoff multiplier

# Explicit socket-read timeout for the Docker client (F397). ``asyncio.wait_for``
# alone only abandons the AWAIT — the worker thread stays blocked in the C-level
# socket read, so a hung daemon would leak executor threads until the pool is
# exhausted. A client-level timeout bounds each blocking read so the thread is
# actually reclaimed. Applies to every docker-py call; it is a per-read (not
# total) timeout, so a healthy streaming pull that keeps delivering bytes is
# unaffected. (docker-py defaults this to 60s implicitly; we set it explicitly
# and a little higher rather than rely on an undocumented default.)
DOCKER_CLIENT_TIMEOUT = 120

# Upper async bound on a single image pull, layered on top of the client-level
# read timeout: a total ceiling for the pull's await even if the daemon keeps
# trickling bytes forever (F397).
IMAGE_PULL_TIMEOUT = 600.0


MCP_OWNER_LABEL = "io.kestrel.mcp.agent-did"
MCP_IMAGE_LABEL = "io.kestrel.mcp.image"


def _require_owner_did(owner_did: str) -> str:
    if not isinstance(owner_did, str) or not owner_did.startswith("did:") or not owner_did[4:]:
        raise ValueError("An agent DID is required for MCP container ownership")
    return owner_did


def container_name_for_image(image_name: str, owner_did: str) -> str:
    """Stable resource identity shared by load, restore and manager startup."""
    identity = json.dumps([_require_owner_did(owner_did), normalize_image_ref(image_name)], separators=(",", ":"))
    return f"mcp-{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"


class ContainerOwnershipError(RuntimeError):
    """An existing Docker process does not belong to this agent/connection."""


def _serialize_container_lifecycle(operation):
    """One agent's resource mutations cannot replace each other's owners.

    Ordinary tool calls stay concurrent and hold no configuration lock while
    waiting on a server. These transitions perform only bounded setup/teardown.
    """
    @wraps(operation)
    async def serialized(self, *args, **kwargs):
        async with self._lifecycle_lock:
            return await operation(self, *args, **kwargs)
    return serialized


class MCPToolManager:
    """
    Manages MCP tools running in Docker containers.
    Handles container lifecycle and MCP connections.
    """

    def __init__(self, *, owner_did: str, docker_client):
        self._owner_did = _require_owner_did(owner_did)
        self.owned_containers: Dict[str, Dict[str, Any]] = {}
        self.docker_client = docker_client
        self._lifecycle_lock = asyncio.Lock()

    @property
    def owner_did(self) -> str:
        return self._owner_did

    @classmethod
    async def create(cls, *, owner_did: str) -> "MCPToolManager":
        """Build the manager with its Docker client connected OFF the loop.

        ``docker.from_env()`` and ``ping()`` block on the Docker daemon socket;
        this factory runs them in a worker thread (F397). The constructor
        accepts only an already-open client through dependency injection.
        """
        _require_owner_did(owner_did)
        if docker is None:
            raise ImportError(
                "docker package is required for MCPToolManager. "
                "Install it with: pip install kestrel-feature-mcp"
            )

        def _connect():
            with ExitStack() as pending:
                client = docker.from_env(timeout=DOCKER_CLIENT_TIMEOUT)
                pending.callback(client.close)
                client.ping()
                pending.pop_all()
                return client

        try:
            client = await asyncio.to_thread(_connect)
        except docker.errors.DockerException as e:
            logger.warning(f"Docker connection failed: {e}")
            raise RuntimeError(f"Docker not available for MCP tools: {e}")
        logger.info("MCPToolManager initialized with Docker connection")
        return cls(owner_did=owner_did, docker_client=client)

    def _assert_container_owner(self, container, *, image_name: str | None = None) -> None:
        labels = container.labels
        if not isinstance(labels, dict) or labels.get(MCP_OWNER_LABEL) != self.owner_did:
            raise ContainerOwnershipError("Refusing an MCP container without this agent's ownership label")
        if image_name is not None and labels.get(MCP_IMAGE_LABEL) != image_name:
            raise ContainerOwnershipError("Refusing an MCP container with a different connection image")

    async def _wait_for_container_ready(
        self,
        container_name: str,
        port: int = 8000,
        timeout: float = HEALTHCHECK_TIMEOUT
    ) -> bool:
        """Wait for a container to be ready using exponential backoff."""
        start_time = time.monotonic()
        delay = HEALTHCHECK_INITIAL_DELAY
        attempt = 0

        while True:
            attempt += 1
            elapsed = time.monotonic() - start_time

            if elapsed >= timeout:
                raise TimeoutError(
                    f"Container {container_name} did not become ready within {timeout}s"
                )

            try:
                container = await asyncio.to_thread(
                    self.docker_client.containers.get, container_name
                )
                await asyncio.to_thread(container.reload)

                if container.status == 'exited':
                    logs_raw = await asyncio.to_thread(container.logs, tail=50)
                    logs = logs_raw.decode('utf-8', errors='replace')
                    raise RuntimeError(
                        f"Container {container_name} exited unexpectedly. Logs:\n{logs}"
                    )

                if container.status != 'running':
                    logger.debug(
                        f"Container {container_name} status: {container.status}, "
                        f"waiting... (attempt {attempt})"
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * HEALTHCHECK_BACKOFF_FACTOR, HEALTHCHECK_MAX_DELAY)
                    continue

                ports = container.ports
                port_key = f'{port}/tcp'

                if not ports or port_key not in ports or not ports[port_key]:
                    logger.debug(
                        f"Container {container_name} port {port} not mapped yet "
                        f"(attempt {attempt})"
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * HEALTHCHECK_BACKOFF_FACTOR, HEALTHCHECK_MAX_DELAY)
                    continue

                host_port = int(ports[port_key][0]['HostPort'])

                if await self._check_port_ready(MCP_CONTAINER_BIND_HOST, host_port):
                    if await self._check_mcp_ready(MCP_CONTAINER_BIND_HOST, host_port):
                        logger.info(
                            f"Container {container_name} ready after {attempt} attempts "
                            f"({elapsed:.1f}s)"
                        )
                        return True

                logger.debug(
                    f"Container {container_name} port {host_port} not ready yet "
                    f"(attempt {attempt})"
                )

            except NotFound:
                raise RuntimeError(f"Container {container_name} not found")
            except (TimeoutError, RuntimeError):
                raise
            except docker.errors.DockerException as e:
                logger.debug(f"Health check attempt {attempt} failed (Docker error): {e}")

            await asyncio.sleep(delay)
            delay = min(delay * HEALTHCHECK_BACKOFF_FACTOR, HEALTHCHECK_MAX_DELAY)

    async def _check_port_ready(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a TCP port is accepting connections."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
            return False

    async def _check_mcp_ready(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check readiness through the same native client used for tool calls."""
        connection = MCPConnection(
            f"http://{host}:{port}/mcp", connect_timeout=timeout,
            call_timeout=timeout, close_timeout=timeout
        )
        ready = True
        try:
            try:
                await connection.connect()
            finally:
                await connection.close()
        except* MCP_CONNECTION_ERRORS:
            ready = False
        return ready

    @_serialize_container_lifecycle
    async def start_tool_container(self, image_name: str, container_name: str = None, command: List[str] = None, environment: Dict[str, str] = None, volumes: Dict[str, Dict[str, str]] = None) -> str:
        """Starts a Docker container for an MCP tool. Returns the container name."""
        image_name = normalize_image_ref(image_name)
        if not container_name:
            container_name = container_name_for_image(image_name, self.owner_did)
        # Retire the old transport before Docker restarts/replaces its process.
        # A failed healthcheck must not leave an earlier connection published.
        await self._drop_connection(container_name)

        try:
            try:
                container = await asyncio.to_thread(
                    self.docker_client.containers.get, container_name
                )
                self._assert_container_owner(container, image_name=image_name)
                self._retain_container(container_name, container)
                if container.status == 'running':
                    logger.info(f"Container {container_name} exists and running. Restarting for clean state...")
                    await asyncio.to_thread(container.restart)
                    await self._wait_for_container_ready(container_name, port=8000)
                    await asyncio.to_thread(container.reload)
                    return container_name
                else:
                    logger.info(f"Container {container_name} exists but not running (status={container.status}). Removing and recreating...")
                    await self._remove_container(container_name, container)
                    self.owned_containers.pop(container_name, None)
            except NotFound:
                self.owned_containers.pop(container_name, None)

            try:
                await asyncio.to_thread(self.docker_client.images.get, image_name)
            except NotFound:
                logger.info(f"Pulling image {image_name}...")
                # Bound the pull: a large image or a hung daemon socket must not
                # tie up a worker thread indefinitely (F397).
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(
                            self.docker_client.images.pull, image_name
                        ),
                        timeout=IMAGE_PULL_TIMEOUT,
                    )
                except asyncio.TimeoutError as e:
                    raise RuntimeError(
                        f"Timed out pulling image {image_name} after "
                        f"{IMAGE_PULL_TIMEOUT}s"
                    ) from e

            env = environment or {}
            env.setdefault("PORT", "8000")

            logger.info(f"Starting container {container_name} from {image_name}...")
            container = await asyncio.to_thread(
                lambda: self.docker_client.containers.create(
                    image_name,
                    command=command,
                    name=container_name,
                    detach=True,
                    ports={'8000/tcp': (MCP_CONTAINER_BIND_HOST, None)},
                    environment=env,
                    volumes=volumes or {},
                    labels={MCP_OWNER_LABEL: self.owner_did, MCP_IMAGE_LABEL: image_name},
                )
            )

            self._retain_container(container_name, container)
            await asyncio.to_thread(container.start)
            await self._wait_for_container_ready(container_name, port=8000)
            await asyncio.to_thread(container.reload)
            return container_name

        except TimeoutError as e:
            logger.error(f"Container {container_name} startup timeout: {e}")
            try:
                container = await asyncio.to_thread(
                    self.docker_client.containers.get, container_name
                )
                logs_raw = await asyncio.to_thread(container.logs, tail=50)
                logs = logs_raw.decode('utf-8', errors='replace')
                logger.error(f"Container logs:\n{logs}")
            except docker.errors.DockerException as log_err:
                logger.debug(f"Could not retrieve container logs (Docker error): {log_err}")
            except Exception as log_err:
                logger.debug(f"Could not retrieve container logs: {log_err}", exc_info=True)
            raise
        except docker.errors.ImageNotFound as e:
            logger.error(f"Docker image not found: {image_name}")
            raise
        except docker.errors.APIError as e:
            logger.error(f"Docker API error starting container: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to start tool container {image_name}: {e}", exc_info=True)
            raise

    def _retain_container(self, name: str, container):
        """Keep resource custody independently of transport publication.

        A None catalog is unpublished; an empty list is a discovered server
        with no tools. Both states still own the container and its cleanup.
        """
        record = self.owned_containers.setdefault(
            name, {"container": container, "connection": None, "tools": None},
        )
        record["container"] = container
        return record

    async def _drop_connection(self, container_name: str) -> None:
        """Retire a transport while retaining its container for unload/retry."""
        info = self.owned_containers.get(container_name)
        if info is not None:
            info["tools"] = None
            connection = info["connection"]
            if connection is not None:
                await connection.close()
            info["connection"] = None

    @_serialize_container_lifecycle
    async def connect_to_tool(self, container_name: str):
        """Connect to a running container with native Streamable HTTP."""
        await self._drop_connection(container_name)
        container = await asyncio.to_thread(self.docker_client.containers.get, container_name)
        await asyncio.to_thread(container.reload)
        self._assert_container_owner(container)
        ports = container.ports
        if not ports or not ports.get("8000/tcp"):
            raise ValueError(f"Container {container_name} does not expose port 8000")
        host_port = ports["8000/tcp"][0]["HostPort"]
        record = self._retain_container(container_name, container)
        connection = MCPConnection(
            f"http://{MCP_CONTAINER_BIND_HOST}:{host_port}/mcp",
            connect_timeout=SESSION_CONNECT_TIMEOUT_SHORT,
            call_timeout=CALL_TOOL_TIMEOUT,
        )
        record["connection"] = connection
        tools = await connection.connect()
        record["tools"] = tools
        logger.info("Connected to %s; found %s tools", container_name, len(tools))
        return tools

    async def _remove_container(self, name: str, container) -> None:
        """Remove a container and require its name to become reusable."""
        try:
            await asyncio.to_thread(container.remove, force=True)
        except NotFound:
            return
        for attempt in range(MCP_REMOVAL_ATTEMPTS):
            try:
                await asyncio.to_thread(self.docker_client.containers.get, name)
            except NotFound:
                return
            if attempt + 1 < MCP_REMOVAL_ATTEMPTS:
                await asyncio.sleep(MCP_REMOVAL_RETRY_DELAY)
        raise TimeoutError(f"MCP container {name!r} is still registered after removal")

    @_serialize_container_lifecycle
    async def stop_tool(self, container_name: str) -> bool:
        """Stops a tool, closes connection, and stops container.

        Returns True when this manager retires an owned container record,
        including one whose connection never finished. Returns False when
        this manager owns no container under that name."""
        if container_name in self.owned_containers:
            tool_info = self.owned_containers[container_name]

            tool_info["tools"] = None
            container = tool_info["container"]
            try:
                connection = tool_info["connection"]
                if connection is not None:
                    await connection.close()
            finally:
                # Reclaim the process even if connection exit failed. Retain
                # bookkeeping on failure so a later unload can rejoin cleanup.
                try:
                    await asyncio.to_thread(container.stop)
                except NotFound:
                    pass
                finally:
                    await self._remove_container(container_name, container)

            del self.owned_containers[container_name]
            logger.info(f"Stopped tool {container_name}")
            return True

        logger.info(f"stop_tool: no active container named {container_name}")
        return False

    async def call_tool(self, container_name: str, tool_name: str, arguments: dict = None):
        """Calls a tool on a specific container."""
        info = self.owned_containers.get(container_name)
        if info is None or info["connection"] is None or info["tools"] is None:
            raise ValueError(f"Tool {container_name} not connected")

        connection = info["connection"]
        return await connection.call_tool(tool_name, arguments or {})

    def get_all_tools(self):
        """Returns a list of all available tools across all containers."""
        all_tools = []
        for c_name, info in self.owned_containers.items():
            if info["tools"] is None:
                continue
            for tool in info["tools"]:
                all_tools.append({
                    "container": c_name,
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                    "protocol_version": info["connection"].protocol_version,
                })
        return all_tools

    def close(self):
        """Close the Docker client to release threads (synchronous).

        Kept synchronous for back-compat with existing direct callers. Event-
        loop callers should prefer :meth:`aclose`, which runs the (blocking)
        client close off the loop (F397).
        """
        if self.docker_client:
            try:
                self.docker_client.close()
            except docker.errors.DockerException as e:
                logger.warning(f"Docker error closing client: {e}")
            except Exception as e:
                logger.warning(f"Error closing Docker client: {e}", exc_info=True)
            self.docker_client = None

    async def aclose(self):
        """Close the Docker client OFF the event loop (F397)."""
        await asyncio.to_thread(self.close)


class MCPGatewayManager:
    """
    Manages MCP tools via Docker MCP Gateway.

    This is the recommended way to access MCP servers as it provides:
    - Access to 311+ servers from Docker's catalog
    - Automatic stdio->Streamable-HTTP conversion
    - Single unified connection point
    - Bearer token authentication
    """

    def __init__(self, port: int = 0, transport: str = DockerMCPGateway.DEFAULT_TRANSPORT,
                 long_lived: bool = True):
        self.gateway = DockerMCPGateway(port=port, transport=transport, long_lived=long_lived)
        self.connection: MCPConnection | None = None
        self.tools: Dict[str, Any] = {}

    async def start(self, servers: List[str] = None):
        """Start and publish only a gateway with a working native connection."""
        if servers is None:
            servers = ["fetch"]
        published = False
        try:
            auth_token = await self.gateway.start(servers)
            tools = await self._connect(auth_token)
            published = True
            return tools
        finally:
            if not published:
                await self.stop()

    async def _disconnect(self):
        connection = self.connection
        self.tools = {}
        if connection is not None:
            await connection.close()
        self.connection = None

    async def _connect(self, auth_token: str):
        await self._disconnect()
        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
        connection = MCPConnection(
            self.gateway.endpoint_url, headers=headers,
            connect_timeout=SESSION_CONNECT_TIMEOUT_DEFAULT,
            call_timeout=CALL_TOOL_TIMEOUT,
        )
        try:
            tools = await connection.connect()
        except TimeoutError as error:
            raise DockerMCPGatewayError("Timeout connecting to gateway or discovering its tools") from error
        self.connection = connection
        self.tools = {tool.name: tool for tool in tools}
        return tools

    async def stop(self):
        """Join the client owner before stopping the gateway process."""
        try:
            await self._disconnect()
        finally:
            await self.gateway.stop()

    async def enable_server(self, server_name: str):
        await self._disconnect()
        auth_token = await self.gateway.add_server(server_name)
        return await self._connect(auth_token)

    async def disable_server(self, server_name: str):
        await self._disconnect()
        auth_token = await self.gateway.remove_server(server_name)
        return await self._connect(auth_token)

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any] = None):
        """Call a tool through the gateway."""
        if self.connection is None:
            raise RuntimeError("Not connected to gateway")

        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}. Available: {list(self.tools.keys())}")

        return await self.connection.call_tool(tool_name, arguments or {})

    def get_all_tools(self) -> List[Dict[str, Any]]:
        """Get all available tools."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "protocol_version": self.connection.protocol_version if self.connection else None,
            }
            for tool in self.tools.values()
        ]

    @property
    def is_connected(self) -> bool:
        """Check if connected to the gateway."""
        return (self.connection is not None
                and self.connection.is_connected and self.gateway.is_running)
