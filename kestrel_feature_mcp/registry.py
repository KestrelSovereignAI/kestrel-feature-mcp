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
import os
import subprocess
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, ValidationError

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
    transport: TransportType = TransportType.STREAMABLE_HTTP
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
        with self._catalog_path.open("rb") as stream:
            catalog = tomllib.load(stream)
        entries = {
            name: self._parse_server_entry(name, data)
            for name, data in catalog.get("servers", {}).items()
        }
        self.servers = entries
        logger.info("Loaded %s MCP servers from catalog", len(entries))

    def _parse_server_entry(self, name: str, data: Dict[str, Any]) -> MCPServerEntry:
        try:
            categories = [ServerCategory(value) for value in data.get("categories", [])]
            server_type = ServerType(data.get("type", "docker"))
            transport = TransportType(data.get("transport", "streamable_http"))
        except ValueError as error:
            raise ValueError(f"Invalid MCP catalog entry {name!r}: {error}") from error

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

    def list_http_ready(self) -> List[MCPServerEntry]:
        return [s for s in self.servers.values()
                if s.transport == TransportType.STREAMABLE_HTTP and not s.is_builtin]

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


class DockerCatalogError(RuntimeError):
    """The Docker catalog could not be read or validated."""


class _DockerCatalogServer(BaseModel):
    name: str = Field(min_length=1)
    description: str = ""


class _DockerCatalogSnapshot(BaseModel):
    server: _DockerCatalogServer


class _DockerCatalogEntry(BaseModel):
    snapshot: _DockerCatalogSnapshot


class _DockerCatalog(BaseModel):
    servers: list[_DockerCatalogEntry]


async def list_docker_catalog_servers() -> List[Dict[str, str]]:
    """Read Docker's OCI catalog through its structured CLI, or fail clearly.

    This is discovery metadata, not evidence that a server is configured or
    running in any gateway/profile. Pulling a missing catalog only caches its
    metadata; it does not enable servers or modify profiles.
    """
    reference = os.environ.get("KESTREL_MCP_DOCKER_CATALOG", "mcp/docker-mcp-catalog")
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "mcp", "catalog", "show", reference,
             "--format", "json", "--pull", "missing"],
            capture_output=True,
            text=True,
            timeout=SSH_COMMAND_TIMEOUT_DEFAULT,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise DockerCatalogError(f"Could not read Docker MCP catalog {reference}: {error}") from error
    if result.returncode != 0:
        raise DockerCatalogError(
            f"Could not read Docker MCP catalog {reference}: {result.stderr.strip()}"
        )
    try:
        catalog = _DockerCatalog.model_validate_json(result.stdout)
    except ValidationError as error:
        raise DockerCatalogError(f"Invalid Docker MCP catalog {reference}: {error}") from error
    return [entry.snapshot.server.model_dump() for entry in catalog.servers]


async def search_docker_catalog(query: str) -> List[Dict[str, str]]:
    """Search an available catalog; unreadable metadata is never an empty match."""
    all_servers = await list_docker_catalog_servers()
    query_lower = query.lower()
    return [
        server for server in all_servers
        if query_lower in server["name"].lower()
        or query_lower in server["description"].lower()
    ]
