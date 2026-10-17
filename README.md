# kestrel-feature-mcp

Model Context Protocol (MCP) server management and tool bridging for Kestrel Sovereign. Provides unified access to 311+ MCP servers via Docker MCP Toolkit, direct container management for custom servers, and a searchable catalog of available tools.

## Installation

```bash
uv pip install kestrel-feature-mcp
```

## Dependencies

- `kestrel-sovereign-sdk`
- `docker>=7.1.0`
- `mcp>=2.3,<3`
- `httpx2>=2.10`

## Usage

Once installed, the `MCPAgent` feature is automatically discovered by kestrel-sovereign via the `kestrel_sovereign.features` entry point.

### Commands

- `!mcp-gateway-start <servers>` — Start Docker MCP Gateway
- `!mcp-gateway-stop` — Stop gateway
- `!mcp-gateway-call <tool> <args>` — Call tool through gateway
- `!mcp-load <image>` — Load MCP server from Docker image
- `!mcp-unload <container>` — Unload a container and remove its saved connection
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

Version 0.5 uses the official MCP 2.x `Client` over Streamable HTTP. Its standard
version negotiation selects `2026-07-28` with modern servers and a mutually
supported published revision with other servers. Tool listings expose the
selected `protocol_version`. Container servers must expose MCP at `/mcp`; the
standalone HTTP+SSE transport and gateway `transport="sse"` selection have been
removed. Docker MCP Gateway 0.44.1 negotiates `2025-11-25`; its lack of the
newer revision is tracked in
[Kestrel #3683](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3683).
Features requiring newer capabilities must check the negotiated connection.
Gateway server lists describe requested configuration; observed tools do not
prove readiness of every requested server.
Tool discovery follows pagination and fails on repeated cursors. Negotiation
uses the connection deadline, then discovery uses the whole-call deadline.
Cancelled startup joins its transport owner before returning. Shutdown has its
own graceful deadline (`KESTREL_MCP_CLOSE_TIMEOUT`, default 15 seconds), including
session termination and partially completed SDK entry. Forced cleanup gets one
further budget of the same length. The owner timer survives caller cancellation;
failures propagate and any unfinished owner is retained for a cleanup retry.

Upgrade the MCP feature before upgrading a host with the Phoenix 20/Pydantic AI
2 dependency set. Feature 0.4's `mcp<2` requirement cannot resolve with that set.
The host dependency lock must be regenerated and verified as part of the same
rollout (Kestrel Sovereign epic #3679).

Container identities bind the agent DID and image. New managers require
`owner_did`; they reuse a process only when its ownership and image labels
match. Each agent can reload or unload its own server independently. Saved
container entries using the former global identifiers require explicit removal
with `!mcp-unload <old-identifier>` and reconnection with `!mcp-load <image>`.
An already absent container can report a no-op after clearing its saved entry.
Shut down the old feature before upgrading to release the processes it owns.

Docker catalog discovery uses the current OCI catalog JSON API. Set `KESTREL_MCP_DOCKER_CATALOG` to select a catalog reference (default `mcp/docker-mcp-catalog`). Missing metadata is pulled into Docker's cache; unreadable catalogs return an error. Catalog counts describe available definitions, while gateway status reports this process's requested configuration and observed tools.
