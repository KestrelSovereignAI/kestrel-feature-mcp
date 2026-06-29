"""
MCP Tool Manager - Manages MCP tools via Docker.

This module provides two modes of operation:

1. **Gateway Mode (Recommended)**: Uses Docker MCP Gateway for unified access
   to 311+ MCP servers with automatic stdio->SSE conversion.

2. **Container Mode (Legacy)**: Direct container management for SSE-native
   servers or custom test servers.

Gateway mode is recommended for production use as it provides access to
all MCP servers regardless of their native transport.
"""

import logging
import asyncio
import aiohttp
import time
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

try:
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
except ImportError:
    sse_client = None  # type: ignore[assignment]
    ClientSession = None  # type: ignore[assignment,misc]

from .constants import (
    SESSION_CONNECT_TIMEOUT_SHORT,
    SESSION_CONNECT_TIMEOUT_DEFAULT,
    MCP_MAX_CONNECTION_ATTEMPTS,
    MCP_CONNECTION_RETRY_DELAY,
)
from .gateway import DockerMCPGateway, DockerMCPGatewayError, DockerMCPNotInstalledError

logger = logging.getLogger(__name__)

# Container healthcheck configuration
HEALTHCHECK_INITIAL_DELAY = 0.5  # Initial delay before first check
HEALTHCHECK_MAX_DELAY = 4.0      # Maximum delay between retries
HEALTHCHECK_TIMEOUT = 30.0       # Total timeout for container to become ready
HEALTHCHECK_BACKOFF_FACTOR = 2.0 # Exponential backoff multiplier

class MCPToolManager:
    """
    Manages MCP tools running in Docker containers.
    Handles container lifecycle and SSE connections.
    """

    def __init__(self):
        if docker is None:
            raise ImportError(
                "docker package is required for MCPToolManager. "
                "Install it with: pip install kestrel-feature-mcp"
            )
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            self.active_tools: Dict[str, Dict[str, Any]] = {}
            logger.info("MCPToolManager initialized with Docker connection")
        except docker.errors.DockerException as e:
            logger.warning(f"Docker connection failed: {e}")
            raise RuntimeError(f"Docker not available for MCP tools: {e}")
        except Exception as e:
            logger.error(f"Unexpected error initializing Docker: {e}", exc_info=True)
            raise RuntimeError(f"Docker not available for MCP tools: {e}")

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
                container = self.docker_client.containers.get(container_name)
                container.reload()

                if container.status == 'exited':
                    logs = container.logs(tail=50).decode('utf-8', errors='replace')
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

                if await self._check_port_ready('localhost', host_port):
                    if await self._check_sse_ready('localhost', host_port):
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
            except Exception as e:
                logger.debug(f"Health check attempt {attempt} failed: {e}", exc_info=True)

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

    async def _check_sse_ready(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if the SSE endpoint is ready by making an HTTP request."""
        url = f"http://{host}:{port}/sse"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    return resp.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
        except Exception as e:
            logger.debug(f"Unexpected error checking SSE readiness: {e}", exc_info=True)
            return False

    async def start_tool_container(self, image_name: str, container_name: str = None, command: List[str] = None, environment: Dict[str, str] = None, volumes: Dict[str, Dict[str, str]] = None) -> str:
        """Starts a Docker container for an MCP tool. Returns the container name."""
        if not container_name:
            container_name = f"mcp-{image_name.replace('/', '-').replace(':', '-')}"

        try:
            try:
                container = self.docker_client.containers.get(container_name)
                if container.status == 'running':
                    logger.info(f"Container {container_name} exists and running. Restarting for clean state...")
                    container.restart()
                    await self._wait_for_container_ready(container_name, port=8000)
                    container.reload()
                    return container_name
                else:
                    logger.info(f"Container {container_name} exists but not running (status={container.status}). Removing and recreating...")
                    try:
                        container.remove(force=True)
                    except docker.errors.APIError as e:
                        logger.warning(f"Error removing stale container: {e}")
                    except Exception as e:
                        logger.warning(f"Unexpected error removing stale container: {e}", exc_info=True)
            except NotFound:
                pass

            try:
                self.docker_client.images.get(image_name)
            except NotFound:
                logger.info(f"Pulling image {image_name}...")
                self.docker_client.images.pull(image_name)

            env = environment or {}
            env.setdefault("PORT", "8000")

            logger.info(f"Starting container {container_name} from {image_name}...")
            container = self.docker_client.containers.run(
                image_name,
                command=command,
                name=container_name,
                detach=True,
                ports={'8000/tcp': None},
                environment=env,
                volumes=volumes or {}
            )

            await self._wait_for_container_ready(container_name, port=8000)
            container.reload()
            return container_name

        except TimeoutError as e:
            logger.error(f"Container {container_name} startup timeout: {e}")
            try:
                container = self.docker_client.containers.get(container_name)
                logs = container.logs(tail=50).decode('utf-8', errors='replace')
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

    async def _run_session_loop(self, url: str, session_future: asyncio.Future):
        """Background task to run the MCP session loop."""
        try:
            async with sse_client(url) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    session_future.set_result(session)
                    await asyncio.Future()
        except asyncio.CancelledError:
            logger.info(f"Session loop for {url} cancelled.")
            raise
        except ExceptionGroup as eg:
            for exc in eg.exceptions:
                logger.error(f"Sub-exception in session loop for {url}: {type(exc).__name__}: {exc}")
            if not session_future.done():
                session_future.set_exception(eg)
            raise
        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error in session loop for {url}: {e}")
            if not session_future.done():
                session_future.set_exception(e)
            raise
        except Exception as e:
            logger.error(f"Error in session loop for {url}: {e}", exc_info=True)
            if not session_future.done():
                session_future.set_exception(e)
            raise

    async def _drop_stale_session(self, container_name: str) -> None:
        """Cancel and forget a cached SSE session WITHOUT stopping the container.

        Used before a reconnect: the container has just been restarted for a
        clean state, so its cached session task is bound to the dead process.
        Unlike ``stop_tool`` this leaves the (restarted, running) container in
        place — we only release the stale connection so a fresh one can bind.
        """
        info = self.active_tools.pop(container_name, None)
        if not info:
            return
        task = info.get("task")
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    f"Error cancelling stale session task for {container_name}: {e}"
                )

    async def connect_to_tool(self, container_name: str):
        """Connects to a running MCP tool container via SSE."""
        if container_name in self.active_tools:
            # The caller (load_tool) restarts an already-running container for a
            # clean state BEFORE reconnecting, so the cached SSE session here is
            # now stale (bound to the pre-restart process). Tear it down and
            # reconnect fresh below — the old bare `return` (None) made load_tool
            # crash on `[t.name for t in tools]`, and returning the cached tools
            # would report success over a dead session whose call_tool fails.
            logger.info(
                f"Reconnecting to {container_name}: dropping stale session"
            )
            await self._drop_stale_session(container_name)

        try:
            container = self.docker_client.containers.get(container_name)
            container.reload()
            ports = container.ports
            logger.info(f"Container {container_name} ports after reload: {ports}")

            if not ports or '8000/tcp' not in ports or not ports['8000/tcp']:
                raise ValueError(f"Container {container_name} does not expose port 8000")

            host_port = ports['8000/tcp'][0]['HostPort']
            url = f"http://localhost:{host_port}/sse"

            logger.info(f"Connecting to MCP tool at {url}...")

            session_future = asyncio.Future()
            task = asyncio.create_task(self._run_session_loop(url, session_future))

            try:
                session = await asyncio.wait_for(session_future, timeout=SESSION_CONNECT_TIMEOUT_SHORT)

                result = await session.list_tools()
                tools = result.tools

                self.active_tools[container_name] = {
                    "container": container,
                    "session": session,
                    "task": task,
                    "tools": tools
                }

                logger.info(f"Connected to {container_name}. Found {len(tools)} tools.")
                return tools

            except asyncio.TimeoutError as e:
                logger.error(f"Timeout connecting to tool {container_name}: {e}")
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                raise
            except Exception as e:
                logger.error(f"Failed to connect to tool {container_name}: {e}", exc_info=True)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                raise

        except docker.errors.NotFound as e:
            logger.error(f"Container {container_name} not found: {e}")
            raise
        except docker.errors.APIError as e:
            logger.error(f"Docker API error connecting to {container_name}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to tool {container_name}: {e}", exc_info=True)
            raise

    async def stop_tool(self, container_name: str) -> bool:
        """Stops a tool, closes connection, and stops container.

        Returns ``True`` if a loaded container by that name was actually
        stopped, ``False`` if nothing was loaded under that name (a no-op).
        Lets callers report an honest no-op instead of a phantom success
        (#9, finding #4)."""
        if container_name in self.active_tools:
            tool_info = self.active_tools[container_name]

            if "task" in tool_info:
                task = tool_info["task"]
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.error(f"Error stopping session task for {container_name}: {e}", exc_info=True)

            container = tool_info["container"]
            try:
                container.stop()
                container.remove(force=True)
                for _ in range(MCP_MAX_CONNECTION_ATTEMPTS):
                    try:
                        self.docker_client.containers.get(container_name)
                        await asyncio.sleep(MCP_CONNECTION_RETRY_DELAY)
                    except NotFound:
                        break
            except NotFound:
                pass
            except docker.errors.APIError as e:
                logger.warning(f"Docker API error stopping container {container_name}: {e}")
            except Exception as e:
                logger.warning(f"Error stopping container {container_name}: {e}", exc_info=True)

            del self.active_tools[container_name]
            logger.info(f"Stopped tool {container_name}")
            return True

        logger.info(f"stop_tool: no active container named {container_name}")
        return False

    async def call_tool(self, container_name: str, tool_name: str, arguments: dict = None):
        """Calls a tool on a specific container."""
        if container_name not in self.active_tools:
            raise ValueError(f"Tool {container_name} not connected")

        session = self.active_tools[container_name]["session"]
        result = await session.call_tool(tool_name, arguments or {})
        return result

    def get_all_tools(self):
        """Returns a list of all available tools across all containers."""
        all_tools = []
        for c_name, info in self.active_tools.items():
            for tool in info["tools"]:
                all_tools.append({
                    "container": c_name,
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema
                })
        return all_tools

    def close(self):
        """Close the Docker client to release threads."""
        if self.docker_client:
            try:
                self.docker_client.close()
            except docker.errors.DockerException as e:
                logger.warning(f"Docker error closing client: {e}")
            except Exception as e:
                logger.warning(f"Error closing Docker client: {e}", exc_info=True)
            self.docker_client = None


class MCPGatewayManager:
    """
    Manages MCP tools via Docker MCP Gateway.

    This is the recommended way to access MCP servers as it provides:
    - Access to 311+ servers from Docker's catalog
    - Automatic stdio->SSE conversion
    - Single unified connection point
    - Bearer token authentication
    """

    def __init__(self, port: int = 9000):
        self.gateway = DockerMCPGateway(port=port)
        self.session: Optional[ClientSession] = None
        self.tools: Dict[str, Any] = {}
        self._session_task: Optional[asyncio.Task] = None

    async def start(self, servers: List[str] = None):
        """Start the gateway and connect via SSE."""
        if servers is None:
            servers = ["fetch"]

        auth_token = await self.gateway.start(servers)
        return await self._connect_sse(auth_token)

    async def _connect_sse(self, auth_token: str):
        """Connect to the gateway via SSE with authentication."""
        url = self.gateway.sse_url

        logger.info(f"Connecting to gateway at {url}...")

        session_future = asyncio.Future()

        async def session_loop():
            try:
                headers = {"Authorization": f"Bearer {auth_token}"}
                async with aiohttp.ClientSession(headers=headers) as http_session:
                    async with sse_client(url, headers=headers) as (read_stream, write_stream):
                        async with ClientSession(read_stream, write_stream) as session:
                            await session.initialize()
                            session_future.set_result(session)
                            await asyncio.Future()
            except asyncio.CancelledError:
                logger.info("Gateway session cancelled")
                raise
            except aiohttp.ClientError as e:
                logger.error(f"Gateway session HTTP error: {e}")
                if not session_future.done():
                    session_future.set_exception(e)
                raise
            except Exception as e:
                logger.error(f"Gateway session error: {e}", exc_info=True)
                if not session_future.done():
                    session_future.set_exception(e)
                raise

        self._session_task = asyncio.create_task(session_loop())

        try:
            self.session = await asyncio.wait_for(session_future, timeout=SESSION_CONNECT_TIMEOUT_DEFAULT)

            result = await self.session.list_tools()
            for tool in result.tools:
                self.tools[tool.name] = tool

            logger.info(f"Connected to gateway with {len(self.tools)} tools")
            return list(self.tools.values())

        except asyncio.TimeoutError:
            if self._session_task:
                self._session_task.cancel()
                try:
                    await self._session_task
                except asyncio.CancelledError:
                    pass
            raise DockerMCPGatewayError("Timeout connecting to gateway")
        except (aiohttp.ClientError, DockerMCPGatewayError) as e:
            if self._session_task:
                self._session_task.cancel()
                try:
                    await self._session_task
                except asyncio.CancelledError:
                    pass
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to gateway: {e}", exc_info=True)
            if self._session_task:
                self._session_task.cancel()
                try:
                    await self._session_task
                except asyncio.CancelledError:
                    pass
            raise

    async def stop(self):
        """Stop the gateway and disconnect."""
        if self._session_task:
            self._session_task.cancel()
            try:
                await self._session_task
            except asyncio.CancelledError:
                pass
            self._session_task = None

        self.session = None
        self.tools = {}
        await self.gateway.stop()

    async def enable_server(self, server_name: str):
        """Enable a server and reconnect."""
        auth_token = await self.gateway.add_server(server_name)

        if self._session_task:
            self._session_task.cancel()
            try:
                await self._session_task
            except asyncio.CancelledError:
                pass

        self.session = None
        self.tools = {}
        return await self._connect_sse(auth_token)

    async def disable_server(self, server_name: str):
        """Disable a server and reconnect."""
        auth_token = await self.gateway.remove_server(server_name)

        if self._session_task:
            self._session_task.cancel()
            try:
                await self._session_task
            except asyncio.CancelledError:
                pass

        self.session = None
        self.tools = {}
        return await self._connect_sse(auth_token)

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any] = None):
        """Call a tool through the gateway."""
        if not self.session:
            raise RuntimeError("Not connected to gateway")

        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}. Available: {list(self.tools.keys())}")

        result = await self.session.call_tool(tool_name, arguments or {})
        return result

    def get_all_tools(self) -> List[Dict[str, Any]]:
        """Get all available tools."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.inputSchema
            }
            for tool in self.tools.values()
        ]

    @property
    def is_connected(self) -> bool:
        """Check if connected to the gateway."""
        return self.session is not None and self.gateway.is_running
