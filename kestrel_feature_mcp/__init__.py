"""
Kestrel Feature: MCP (Model Context Protocol)

Native remote MCP connections with OAuth and Apps, official MCP Registry
discovery, Docker MCP Gateway and direct container management.

Install: pip install kestrel-feature-mcp
"""

from .feature import MCPAgent
from .registry import (
    MCPRegistry,
    MCPServerEntry,
    ServerType,
    TransportType,
    ServerCategory,
    get_registry,
    check_docker_mcp_available,
)

__all__ = [
    "MCPAgent",
    "MCPRegistry",
    "MCPServerEntry",
    "ServerType",
    "TransportType",
    "ServerCategory",
    "get_registry",
    "check_docker_mcp_available",
]
