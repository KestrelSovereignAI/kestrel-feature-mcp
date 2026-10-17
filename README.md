# kestrel-feature-mcp

Model Context Protocol (MCP) server management and tool bridging for Kestrel Sovereign. Provides unified access to 311+ MCP servers via Docker MCP Toolkit, direct container management for custom servers, and a searchable catalog of available tools.

## Installation

```bash
uv pip install kestrel-feature-mcp
```

## Dependencies

- `kestrel-sovereign-sdk`
- `docker>=7.1.0`
- `mcp>=1.26.0`
- `trio>=0.32.0`
- `aiohttp>=3.13.3`

## Usage

Once installed, the `MCPAgent` feature is automatically discovered by kestrel-sovereign via the `kestrel_sovereign.features` entry point.

### Commands

- `!mcp-gateway-start <servers>` — Start Docker MCP Gateway
- `!mcp-gateway-stop` — Stop gateway
- `!mcp-gateway-call <tool> <args>` — Call tool through gateway
- `!mcp-load <image>` — Load MCP server from Docker image
- `!mcp-list` — List running MCP servers
- `!mcp-search <query>` — Search MCP catalog
- `!mcp-catalog` — List all available servers

## Configuration

| Variable | Description |
|----------|-------------|
| `DOCKER_HOST` | Docker daemon socket (optional, defaults to local) |

## Development

```bash
uv pip install kestrel-sovereign-sdk && uv pip install -e ".[test]"
uv run pytest
```

## Native MCP protocol

Version 0.5 uses the official MCP 2.x `Client` with protocol `2026-07-28` over
Streamable HTTP. Container servers must expose native MCP at `/mcp`; the
standalone HTTP+SSE transport and gateway `transport="sse"` selection have been
removed. Gateway loading requires a gateway that supports the same native
revision. Docker MCP Gateway 0.44.1, its newest published release when checked,
rejects this revision. Gateway rollout remains blocked on the scope decision in
[Kestrel #3683](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3683).
Tool discovery follows pagination and fails on repeated cursors. Connection and
call deadlines also apply while discovering tools; cancelled startup joins its
transport owner before returning.

Upgrade the MCP feature before upgrading a host with the Phoenix 20/Pydantic AI
2 dependency set. Feature 0.4's `mcp<2` requirement cannot resolve with that set.
The host dependency lock must be regenerated and verified as part of the same
rollout (Kestrel Sovereign epic #3679).
