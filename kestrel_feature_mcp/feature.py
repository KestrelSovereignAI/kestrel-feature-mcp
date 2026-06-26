"""
MCP Feature Agent - Manages Model Context Protocol (MCP) tools.

This feature provides two modes of operation:

1. **Gateway Mode (Recommended)**: Uses Docker MCP Gateway for unified access
   to 311+ MCP servers. Commands: !mcp-gateway-start, !mcp-gateway-stop

2. **Container Mode (Legacy)**: Direct container management for custom servers.
   Commands: !mcp-load, !mcp-unload

Gateway mode is recommended as it provides access to all servers regardless
of their native transport protocol.
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from kestrel_sdk.features.base import Feature, tool
from kestrel_sdk.tools.base import ToolCategory
from kestrel_sdk.tools.result import ToolResult
from .registry import (
    get_registry,
    MCPRegistry,
    check_docker_mcp_available,
    search_docker_catalog,
    list_enabled_docker_servers,
    format_docker_catalog_summary,
)

# Lazy import to avoid loading MCP/anyio at module import time
# This prevents pytest from hanging due to anyio event loop issues
if TYPE_CHECKING:
    from .manager import MCPToolManager, MCPGatewayManager

logger = logging.getLogger(__name__)


def _extract_mcp_result(result) -> tuple[str, bool]:
    """Pull display text + error flag from an MCP ``CallToolResult``.

    MCP signals tool-level failures by returning a normal result with
    ``isError=True`` rather than raising, so the caller must branch on the
    flag to keep the ToolResult status envelope honest (a failed MCP tool must
    not be recorded as a successful dispatch).
    """
    if hasattr(result, "content") and result.content:
        first = result.content[0]
        text = first.text if hasattr(first, "text") else str(first)
    else:
        text = str(result)
    return text, bool(getattr(result, "isError", False))

class MCPAgent(Feature):
    """
    A Feature Agent that manages Model Context Protocol (MCP) tools.
    It encapsulates the complexity of Docker container management and tool discovery,
    providing a high-level interface for the main KestrelAgent.
    """

    @property
    def tool_description(self) -> str:
        return (
            "Manage Model Context Protocol (MCP) servers - load MCP tools from Docker images, "
            "list available tools, call tools on running servers, and unload servers"
        )

    async def initialize(self):
        try:
            # Lazy import to avoid loading MCP/anyio at module import time
            from .manager import MCPToolManager, MCPGatewayManager
            self.manager = MCPToolManager()
            self.gateway_manager: Optional["MCPGatewayManager"] = None
            logger.info("MCPAgent initialized.")
        except RuntimeError as e:
            # Docker not available - expected in some environments
            logger.warning(f"MCPAgent initialization failed (likely Docker unavailable): {e}")
            logger.info("MCPAgent disabled - Docker tools will not be available")
            self.manager = None
            self.gateway_manager = None
        except Exception as e:
            logger.warning(f"Unexpected error initializing MCPAgent: {e}", exc_info=True)
            logger.info("MCPAgent disabled - Docker tools will not be available")
            self.manager = None
            self.gateway_manager = None

    @tool(
        name="mcp_load_server",
        description="Load an MCP server from a Docker image.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-load"
    )
    async def load_tool(self, image_name: str, args: List[str] = None) -> ToolResult:
        """
        Loads an MCP tool from a Docker image.
        Returns a success message with the container name and available tools.
        """
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        try:
            container_name = await self.manager.start_tool_container(image_name, command=args)
            tools = await self.manager.connect_to_tool(container_name)
            tool_names = [t.name for t in tools]
            return ToolResult.ok(
                f"Loaded {image_name} as {container_name}. Tools: {', '.join(tool_names)}",
                data={"container": container_name, "image": image_name, "tools": tool_names},
            )
        except (TimeoutError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to load tool {image_name}: {e}")
            return ToolResult.failed(f"Failed to load MCP tool: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error loading tool {image_name}: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to load MCP tool: {str(e)}")

    @tool(
        name="mcp_list_servers",
        description="List all running MCP servers and their tools.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-list"
    )
    async def list_tools(self) -> ToolResult:
        """
        Lists all currently loaded MCP tools.
        """
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        tools = self.manager.get_all_tools()
        if not tools:
            return ToolResult.ok("No MCP tools loaded.", data={"tools": []})

        response = "Available MCP Tools:\n"
        for t in tools:
            response += f"- [{t['container']}] {t['name']}: {t['description']}\n"
        return ToolResult.ok(response, data={"tools": tools})

    @tool(
        name="mcp_unload_server",
        description="Unload (stop) an MCP server.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-unload"
    )
    async def unload_tool(self, container_name: str) -> ToolResult:
        """
        Unloads (stops) an MCP tool.
        """
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        try:
            await self.manager.stop_tool(container_name)
            return ToolResult.ok(f"Unloaded {container_name}", data={"container": container_name})
        except ValueError as e:
            logger.error(f"Tool not found: {container_name}")
            return ToolResult.failed(f"Failed to unload tool: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to unload tool {container_name}: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to unload tool: {str(e)}")

    @tool(
        name="mcp_call_tool",
        description="Call a tool on a specific MCP server.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-call"
    )
    async def call_tool(self, container_name: str, tool_name: str, args: Dict[str, Any]) -> ToolResult:
        """
        Calls a specific tool on a loaded container.
        """
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        try:
            result = await self.manager.call_tool(container_name, tool_name, args)
            text, is_error = _extract_mcp_result(result)
            if is_error:
                return ToolResult.failed(
                    f"Tool '{tool_name}' reported an error:\n{text}",
                    data={"container": container_name, "tool": tool_name},
                )
            return ToolResult.ok(
                f"Result:\n{text}",
                data={"container": container_name, "tool": tool_name},
            )
        except ValueError as e:
            logger.error(f"Tool not found or invalid arguments: {e}")
            return ToolResult.failed(f"Tool execution failed: {str(e)}")
        except Exception as e:
            logger.error(f"Tool execution failed: {e}", exc_info=True)
            return ToolResult.failed(f"Tool execution failed: {str(e)}")

    @tool(
        name="mcp_search",
        description="Search available MCP servers by capability, name, or category.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-search"
    )
    async def search_servers(self, query: str) -> ToolResult:
        """
        Search the MCP server catalog for servers matching a query.

        Args:
            query: Search term - matches against name, description, tools, and categories

        Returns:
            List of matching MCP servers with their details.
        """
        registry = get_registry()
        matches = registry.search(query)

        if not matches:
            return ToolResult.ok(
                f"No MCP servers found matching '{query}'.\n\nTip: Use `!mcp-catalog` to see all available servers.",
                data={"query": query, "matches": []},
            )

        lines = [f"**MCP servers matching '{query}':**\n"]
        for server in matches:
            type_marker = "builtin" if server.is_builtin else "docker"
            private_marker = " [private]" if server.private else ""
            tools_preview = ", ".join(server.tools[:3])
            if len(server.tools) > 3:
                tools_preview += f" (+{len(server.tools) - 3} more)"

            lines.append(f"[{type_marker}] **{server.name}**{private_marker}")
            lines.append(f"   {server.description}")
            lines.append(f"   Tools: {tools_preview}")
            if not server.is_builtin:
                lines.append(f"   Load: `!mcp-load {server.image}`")
            lines.append("")

        return ToolResult.ok(
            "\n".join(lines),
            data={"query": query, "matches": [s.name for s in matches]},
        )

    @tool(
        name="mcp_catalog",
        description="List all available MCP servers in the catalog.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-catalog"
    )
    async def show_catalog(self) -> ToolResult:
        """
        Display the full MCP server catalog.

        Returns:
            Formatted list of all available MCP servers.
        """
        registry = get_registry()
        return ToolResult.ok(
            registry.format_catalog(),
            data={"servers": [s.name for s in registry.list_all()]},
        )

    @tool(
        name="mcp_server_info",
        description="Get detailed information about a specific MCP server.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-info"
    )
    async def server_info(self, server_name: str) -> ToolResult:
        """
        Get detailed information about a specific MCP server.

        Args:
            server_name: Name of the server (e.g., "postgres", "fetch")

        Returns:
            Detailed server information including tools and requirements.
        """
        registry = get_registry()
        server = registry.get(server_name)

        if not server:
            similar = registry.search(server_name)
            if similar:
                suggestions = ", ".join(s.name for s in similar[:3])
                return ToolResult.failed(
                    f"Server '{server_name}' not found. Did you mean: {suggestions}?"
                )
            return ToolResult.failed(
                f"Server '{server_name}' not found. Use `!mcp-catalog` to see available servers."
            )

        return ToolResult.ok(
            registry.format_server_info(server),
            data={"server": server.name},
        )

    # =========================================================================
    # Gateway Mode Commands (Recommended)
    # =========================================================================

    @tool(
        name="mcp_gateway_start",
        description="Start Docker MCP Gateway with specified servers. Access 311+ MCP servers.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-start"
    )
    async def gateway_start(self, servers: str = "fetch") -> ToolResult:
        """
        Start the Docker MCP Gateway with specified servers.

        The gateway provides unified access to 311+ MCP servers from Docker's catalog
        with automatic stdio->SSE conversion.

        Args:
            servers: Comma-separated list of server names (e.g., "fetch,sqlite")

        Returns:
            Status message with available tools.
        """
        if not check_docker_mcp_available():
            return ToolResult.failed(
                "Docker MCP Toolkit not installed.\n\n"
                "Please install Docker Desktop 29+ with MCP Toolkit enabled.\n"
                "See: https://docs.docker.com/desktop/extensions/mcp/"
            )

        try:
            from .manager import MCPGatewayManager
            from .gateway import DockerMCPGatewayError, DockerMCPNotInstalledError

            if self.gateway_manager and self.gateway_manager.is_connected:
                await self.gateway_manager.stop()

            server_list = [s.strip() for s in servers.split(",")]

            self.gateway_manager = MCPGatewayManager()
            tools = await self.gateway_manager.start(server_list)

            tool_names = [t.name for t in tools]
            return ToolResult.ok(
                f"Gateway started with {len(tool_names)} tools\n\n"
                f"**Enabled servers:** {', '.join(server_list)}\n"
                f"**Tools:** {', '.join(tool_names[:10])}"
                + (f" (+{len(tool_names) - 10} more)" if len(tool_names) > 10 else "")
                + "\n\nUse `!mcp-gateway-call <tool> <args>` to call tools.",
                data={"servers": server_list, "tools": tool_names},
            )

        except (DockerMCPGatewayError, DockerMCPNotInstalledError) as e:
            logger.error(f"Gateway error: {e}")
            return ToolResult.failed(f"Failed to start gateway: {str(e)}")
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout starting gateway: {e}")
            return ToolResult.failed("Failed to start gateway: Connection timeout")
        except Exception as e:
            logger.error(f"Unexpected error starting gateway: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to start gateway: {str(e)}")

    @tool(
        name="mcp_gateway_stop",
        description="Stop the Docker MCP Gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-stop"
    )
    async def gateway_stop(self) -> ToolResult:
        """Stop the Docker MCP Gateway."""
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.ok("Gateway is not running.")

        try:
            await self.gateway_manager.stop()
            self.gateway_manager = None
            return ToolResult.ok("Gateway stopped.")
        except asyncio.CancelledError:
            logger.info("Gateway stop cancelled")
            return ToolResult.failed("Gateway stop cancelled")
        except Exception as e:
            logger.error(f"Failed to stop gateway: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to stop gateway: {str(e)}")

    @tool(
        name="mcp_gateway_call",
        description="Call a tool through the Docker MCP Gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-call"
    )
    async def gateway_call(self, tool_name: str, arguments: Dict[str, Any] = None) -> ToolResult:
        """
        Call a tool through the gateway.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments as JSON object
        """
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.failed("Gateway not running. Use `!mcp-gateway-start` first.")

        try:
            result = await self.gateway_manager.call_tool(tool_name, arguments or {})
            text, is_error = _extract_mcp_result(result)
            if is_error:
                return ToolResult.failed(
                    f"**{tool_name}** reported an error:\n\n{text}",
                    data={"tool": tool_name},
                )
            return ToolResult.ok(
                f"**{tool_name}** result:\n\n{text}",
                data={"tool": tool_name},
            )

        except (ValueError, RuntimeError) as e:
            logger.error(f"Gateway tool call failed: {e}")
            return ToolResult.failed(f"Tool call failed: {str(e)}")
        except Exception as e:
            logger.error(f"Gateway tool call failed: {e}", exc_info=True)
            return ToolResult.failed(f"Tool call failed: {str(e)}")

    @tool(
        name="mcp_gateway_tools",
        description="List tools available through the Docker MCP Gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-tools"
    )
    async def gateway_tools(self) -> ToolResult:
        """List all tools available through the gateway."""
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.failed("Gateway not running. Use `!mcp-gateway-start` first.")

        tools = self.gateway_manager.get_all_tools()
        if not tools:
            return ToolResult.ok("No tools available.", data={"tools": []})

        lines = [f"**Gateway Tools ({len(tools)} available):**\n"]
        for t in tools:
            desc = t.get('description', 'No description')[:80]
            lines.append(f"- **{t['name']}**: {desc}")

        return ToolResult.ok(
            "\n".join(lines),
            data={"tools": [t['name'] for t in tools]},
        )

    @tool(
        name="mcp_gateway_enable",
        description="Enable an additional server in the gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-enable"
    )
    async def gateway_enable(self, server_name: str) -> ToolResult:
        """
        Enable an additional server in the gateway.

        Args:
            server_name: Name of the server to enable
        """
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.failed("Gateway not running. Use `!mcp-gateway-start` first.")

        try:
            tools = await self.gateway_manager.enable_server(server_name)
            tool_names = [t.name for t in tools]
            return ToolResult.ok(
                f"Enabled {server_name}\n\n"
                f"**Total tools:** {len(tool_names)}",
                data={"server": server_name, "tools": tool_names},
            )
        except (ValueError, RuntimeError) as e:
            logger.error(f"Failed to enable server: {e}")
            return ToolResult.failed(f"Failed to enable {server_name}: {str(e)}")
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout enabling server: {e}")
            return ToolResult.failed(f"Failed to enable {server_name}: Connection timeout")
        except Exception as e:
            logger.error(f"Unexpected error enabling server: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to enable {server_name}: {str(e)}")

    @tool(
        name="mcp_docker_catalog",
        description="Search Docker's MCP catalog (311+ servers).",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-docker-catalog"
    )
    async def docker_catalog_search(self, query: str = None) -> ToolResult:
        """
        Search or list servers from Docker's MCP catalog.

        Args:
            query: Optional search term (leave empty to see summary)
        """
        if not check_docker_mcp_available():
            return ToolResult.failed(
                "Docker MCP Toolkit not installed.\n\n"
                "Please install Docker Desktop 29+ with MCP Toolkit enabled."
            )

        if not query:
            summary = format_docker_catalog_summary()
            enabled = await list_enabled_docker_servers()
            enabled_str = ", ".join(enabled) if enabled else "none"
            return ToolResult.ok(
                f"{summary}\n\n**Currently enabled:** {enabled_str}",
                data={"enabled": enabled},
            )

        results = await search_docker_catalog(query)
        if not results:
            return ToolResult.ok(
                f"No servers found matching '{query}'.",
                data={"query": query, "results": []},
            )

        lines = [f"**Docker MCP servers matching '{query}':**\n"]
        for s in results[:15]:
            desc = s.get('description', 'No description')[:100]
            lines.append(f"- **{s['name']}**: {desc}")

        if len(results) > 15:
            lines.append(f"\n... and {len(results) - 15} more")

        lines.append("\n\nUse `!mcp-gateway-start <server>` to start with a specific server.")
        return ToolResult.ok(
            "\n".join(lines),
            data={"query": query, "results": [s['name'] for s in results]},
        )

    async def shutdown(self):
        """Stops all active tools, gateway, and closes the Docker client."""
        if self.gateway_manager and self.gateway_manager.is_connected:
            try:
                await self.gateway_manager.stop()
            except asyncio.CancelledError:
                logger.info("Gateway stop cancelled during shutdown")
            except Exception as e:
                logger.warning(f"Error stopping gateway: {e}", exc_info=True)
            self.gateway_manager = None

        if self.manager is None:
            return

        active_containers = list(self.manager.active_tools.keys())
        for container in active_containers:
            await self.manager.stop_tool(container)

        self.manager.close()
