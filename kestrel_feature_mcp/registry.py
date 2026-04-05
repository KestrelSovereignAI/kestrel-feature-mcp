"""
MCP Server Registry - Discoverable catalog of available MCP servers.

This registry provides:
1. Integration with Docker MCP Catalog (311+ servers)
2. Local catalog.toml for Kestrel-specific metadata and private servers
3. Server metadata including tools, categories, and requirements
4. Search/discovery by capability or category
5. Support for public (Docker Hub) and private (gcr.io) registries

The registry combines Docker's MCP catalog with our local catalog.toml,
where the local catalog provides Kestrel-specific categorization and
private server definitions.
"""

import asyncio
import logging
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any

from .constants import (
    SSH_COMMAND_TIMEOUT_SHORT,
    SSH_COMMAND_TIMEOUT_DEFAULT,
)

logger = logging.getLogger(__name__)


class ServerType(Enum):
    """Type of MCP server."""
    DOCKER = "docker"
    BUILTIN = "builtin"


class TransportType(Enum):
    """MCP transport protocol."""
    SSE = "sse"
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"


class ServerCategory(Enum):
    """Categories for MCP servers."""
    DATABASE = "database"
    FILESYSTEM = "filesystem"
    WEB = "web"
    DEVTOOLS = "devtools"
    SEARCH = "search"
    STORAGE = "storage"
    HEALTHCARE = "healthcare"
    AI = "ai"
    UTILITY = "utility"


@dataclass
class MCPServerEntry:
    """An entry in the MCP server registry."""
    name: str
    description: str
    tools: List[str] = field(default_factory=list)
    categories: List[ServerCategory] = field(default_factory=list)
    server_type: ServerType = ServerType.DOCKER
    transport: TransportType = TransportType.SSE
    image: Optional[str] = None
    env_required: List[str] = field(default_factory=list)
    env_optional: List[str] = field(default_factory=list)
    port: int = 8000
    private: bool = False
    registry: Optional[str] = None
    wrapper_image: Optional[str] = None

    @property
    def is_builtin(self) -> bool:
        return self.server_type == ServerType.BUILTIN

    @property
    def full_image(self) -> Optional[str]:
        if self.image is None:
            return None
        if self.private and self.registry:
            return f"{self.registry}/{self.image}"
        return self.image

    def matches_query(self, query: str) -> bool:
        query_lower = query.lower()
        if query_lower in self.name.lower():
            return True
        if query_lower in self.description.lower():
            return True
        for tool in self.tools:
            if query_lower in tool.lower():
                return True
        for cat in self.categories:
            if query_lower in cat.value.lower():
                return True
        return False

    @property
    def requires_wrapper(self) -> bool:
        return self.transport == TransportType.STDIO and not self.is_builtin

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tools": self.tools,
            "categories": [c.value for c in self.categories],
            "server_type": self.server_type.value,
            "transport": self.transport.value,
            "image": self.full_image,
            "env_required": self.env_required,
            "env_optional": self.env_optional,
            "port": self.port,
            "private": self.private,
            "builtin": self.is_builtin,
            "requires_wrapper": self.requires_wrapper,
        }


class MCPRegistry:
    """Registry of available MCP servers."""

    def __init__(self, catalog_path: Optional[Path] = None):
        self.servers: Dict[str, MCPServerEntry] = {}
        self._catalog_path = catalog_path or Path(__file__).parent / "catalog.toml"
        self._load_catalog()

    def _load_catalog(self):
        if not self._catalog_path.exists():
            logger.warning(f"MCP catalog not found at {self._catalog_path}")
            return

        try:
            with open(self._catalog_path, "rb") as f:
                catalog = tomllib.load(f)

            for name, data in catalog.get("servers", {}).items():
                entry = self._parse_server_entry(name, data)
                self.servers[name] = entry
                logger.debug(f"Loaded MCP server: {name}")

            logger.info(f"Loaded {len(self.servers)} MCP servers from catalog")

        except (OSError, IOError) as e:
            logger.error(f"Failed to read MCP catalog file: {e}")
        except tomllib.TOMLDecodeError as e:
            logger.error(f"Failed to parse MCP catalog TOML: {e}")
        except Exception as e:
            logger.error(f"Failed to load MCP catalog: {e}", exc_info=True)

    def _parse_server_entry(self, name: str, data: Dict[str, Any]) -> MCPServerEntry:
        categories = []
        for cat_name in data.get("categories", []):
            try:
                categories.append(ServerCategory(cat_name))
            except ValueError:
                logger.warning(f"Unknown category '{cat_name}' for server {name}")

        server_type_str = data.get("type", "docker")
        try:
            server_type = ServerType(server_type_str)
        except ValueError:
            logger.warning(f"Unknown server type '{server_type_str}' for {name}, defaulting to docker")
            server_type = ServerType.DOCKER

        transport_str = data.get("transport", "sse")
        try:
            transport = TransportType(transport_str)
        except ValueError:
            logger.warning(f"Unknown transport '{transport_str}' for {name}, defaulting to sse")
            transport = TransportType.SSE

        return MCPServerEntry(
            name=name,
            description=data.get("description", ""),
            tools=data.get("tools", []),
            categories=categories,
            server_type=server_type,
            transport=transport,
            image=data.get("image"),
            env_required=data.get("env_required", []),
            env_optional=data.get("env_optional", []),
            port=data.get("port", 8000),
            private=data.get("private", False),
            registry=data.get("registry"),
            wrapper_image=data.get("wrapper_image"),
        )

    def get(self, name: str) -> Optional[MCPServerEntry]:
        return self.servers.get(name)

    def list_all(self) -> List[MCPServerEntry]:
        return list(self.servers.values())

    def list_by_category(self, category: ServerCategory) -> List[MCPServerEntry]:
        return [s for s in self.servers.values() if category in s.categories]

    def list_docker(self) -> List[MCPServerEntry]:
        return [s for s in self.servers.values() if s.server_type == ServerType.DOCKER]

    def list_builtin(self) -> List[MCPServerEntry]:
        return [s for s in self.servers.values() if s.server_type == ServerType.BUILTIN]

    def list_sse_ready(self) -> List[MCPServerEntry]:
        return [s for s in self.servers.values()
                if s.transport == TransportType.SSE and not s.is_builtin]

    def list_requires_wrapper(self) -> List[MCPServerEntry]:
        return [s for s in self.servers.values() if s.requires_wrapper]

    def search(self, query: str) -> List[MCPServerEntry]:
        return [s for s in self.servers.values() if s.matches_query(query)]

    def find_by_tool(self, tool_name: str) -> List[MCPServerEntry]:
        tool_lower = tool_name.lower()
        return [
            s for s in self.servers.values()
            if any(tool_lower in t.lower() for t in s.tools)
        ]

    def get_required_env(self, name: str) -> List[str]:
        server = self.get(name)
        return server.env_required if server else []

    def format_server_info(self, server: MCPServerEntry) -> str:
        lines = [
            f"**{server.name}**",
            f"  {server.description}",
            f"  Type: {'Built-in' if server.is_builtin else 'Docker'}",
        ]
        if server.image:
            lines.append(f"  Image: {server.full_image}")
        if server.tools:
            lines.append(f"  Tools: {', '.join(server.tools)}")
        if server.categories:
            lines.append(f"  Categories: {', '.join(c.value for c in server.categories)}")
        if server.env_required:
            lines.append(f"  Required env: {', '.join(server.env_required)}")
        return "\n".join(lines)

    def format_catalog(self) -> str:
        if not self.servers:
            return "No MCP servers registered."

        lines = ["**Available MCP Servers:**\n"]

        builtin = self.list_builtin()
        docker_servers = self.list_docker()

        if builtin:
            lines.append("*Built-in (no Docker required):*")
            for s in builtin:
                lines.append(f"  - {s.name}: {s.description}")
            lines.append("")

        if docker_servers:
            lines.append("*Docker-based:*")
            for s in docker_servers:
                private_marker = " [private]" if s.private else ""
                lines.append(f"  - {s.name}{private_marker}: {s.description}")

        return "\n".join(lines)


# Singleton instance
_registry: Optional[MCPRegistry] = None


def get_registry() -> MCPRegistry:
    """Get the global MCP registry instance."""
    global _registry
    if _registry is None:
        _registry = MCPRegistry()
    return _registry


# =============================================================================
# Docker MCP Catalog Integration
# =============================================================================

def check_docker_mcp_available() -> bool:
    """Check if Docker MCP Toolkit is installed."""
    try:
        result = subprocess.run(
            ["docker", "mcp", "--help"],
            capture_output=True,
            timeout=SSH_COMMAND_TIMEOUT_SHORT
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    except Exception as e:
        logger.debug(f"Unexpected error checking Docker MCP availability: {e}", exc_info=True)
        return False


async def list_docker_catalog_servers() -> List[Dict[str, str]]:
    """List all servers from Docker MCP catalog."""
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "mcp", "catalog", "show", "docker-mcp"],
            capture_output=True,
            text=True,
            timeout=SSH_COMMAND_TIMEOUT_DEFAULT
        )
        if result.returncode != 0:
            logger.warning(f"Failed to list Docker MCP catalog: {result.stderr}")
            return []

        servers = []
        current_name = None
        current_desc_lines = []

        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_output = ansi_escape.sub('', result.stdout)

        for line in clean_output.split('\n'):
            stripped = line.strip()

            if not stripped or stripped.startswith('\u2500') or 'servers available' in stripped.lower():
                continue
            if stripped == 'MCP Server Directory':
                continue

            original_indent = len(line) - len(line.lstrip())

            if stripped and original_indent <= 3 and not stripped.startswith('\u2022'):
                if current_name:
                    servers.append({
                        'name': current_name,
                        'description': ' '.join(current_desc_lines).strip()[:200]
                    })
                current_name = stripped
                current_desc_lines = []
            elif current_name and stripped:
                current_desc_lines.append(stripped)

        if current_name:
            servers.append({
                'name': current_name,
                'description': ' '.join(current_desc_lines).strip()[:200]
            })

        return servers

    except subprocess.TimeoutExpired as e:
        logger.warning(f"Timeout listing Docker MCP catalog: {e}")
        return []
    except FileNotFoundError as e:
        logger.warning(f"Docker command not found: {e}")
        return []
    except OSError as e:
        logger.warning(f"OS error listing Docker MCP catalog: {e}")
        return []
    except Exception as e:
        logger.warning(f"Unexpected error listing Docker MCP catalog: {e}", exc_info=True)
        return []


async def list_enabled_docker_servers() -> List[str]:
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

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    except Exception as e:
        logger.debug(f"Unexpected error listing enabled Docker servers: {e}", exc_info=True)
        return []


async def search_docker_catalog(query: str) -> List[Dict[str, str]]:
    """Search the Docker MCP catalog for servers matching a query."""
    all_servers = await list_docker_catalog_servers()
    query_lower = query.lower()

    return [
        s for s in all_servers
        if query_lower in s['name'].lower() or query_lower in s.get('description', '').lower()
    ]


def format_docker_catalog_summary() -> str:
    """Format a summary of Docker MCP catalog status."""
    if not check_docker_mcp_available():
        return "Docker MCP Toolkit not installed. Install Docker Desktop 29+ with MCP Toolkit."

    try:
        result = subprocess.run(
            ["docker", "mcp", "catalog", "show", "docker-mcp"],
            capture_output=True,
            text=True,
            timeout=SSH_COMMAND_TIMEOUT_DEFAULT
        )

        if result.returncode != 0:
            return "Docker MCP catalog unavailable."

        server_count = len(re.findall(r'\*\*[a-zA-Z0-9_-]+\*\*', result.stdout))

        enabled_result = subprocess.run(
            ["docker", "mcp", "server", "ls"],
            capture_output=True,
            text=True,
            timeout=SSH_COMMAND_TIMEOUT_DEFAULT
        )

        enabled_count = 0
        if enabled_result.returncode == 0:
            lines = [l for l in enabled_result.stdout.split('\n')
                     if l.strip() and not l.startswith('-') and 'NAME' not in l and 'enabled' not in l.lower()]
            enabled_count = len(lines)

        return f"Docker MCP: {server_count} servers available, {enabled_count} enabled"

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning(f"Error getting Docker MCP summary: {e}")
        return "Docker MCP status unknown"
    except Exception as e:
        logger.warning(f"Unexpected error getting Docker MCP summary: {e}", exc_info=True)
        return "Docker MCP status unknown"
