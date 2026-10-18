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
- `requests>=2.34.2`
- `anyio>=4.7,<5`
- `pydantic>=2.12,<3`

## Usage

Once installed, the `MCPAgent` feature is automatically discovered by kestrel-sovereign via the `kestrel_sovereign.features` entry point.

### Commands

- `!mcp-gateway-start <servers>` — Start Docker MCP Gateway
- `!mcp-gateway-stop` — Stop gateway
- `!mcp-load <image>` — Load MCP server from Docker image
- `!mcp-unload <container>` — Unload a container and remove its saved connection
- `!mcp-list` — List running MCP servers
- `!mcp-search <query>` — Search MCP catalog
- `!mcp-catalog` — List all available servers

## Calling tools

Discovered server tools are mounted in the host's dynamic registry. Invoke the
advertised handle through Kestrel's governed tool dispatch; its exact owner and
handle determine permissions, approvals and audit records. The generic
`mcp_call_tool` / `mcp_gateway_call` tools and their command aliases have been
removed: allowing a generic dispatcher could otherwise bypass a DENY on its
target. A host without the dynamic registry cannot mount MCP tools.

Each handle is bound to the connection that advertised its schema. Reloading or
withdrawing that connection invalidates its old handles, including a call still
waiting for approval. A fresh handle and approval are required after reload.

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

Container identities bind the agent DID and image, with Docker's implicit
`:latest` tag made explicit by the same planner used for routing and unload.
Catalog names resolve to their container image through the load route. New managers require
`owner_did`; they reuse a process only when its ownership and image labels
match. Each agent can reload or unload its own server independently. MCP
container ports bind only to host loopback. Listings retain failed containers'
identifiers so they can be unloaded even when no tools were published. Saved
container entries using the former global identifiers require explicit removal
with `!mcp-unload <old-identifier>` and reconnection with `!mcp-load <image>`.
The current unload result does not distinguish saved-configuration removal
from live-process removal; outcome reporting is tracked in
[#26](https://github.com/KestrelSovereignAI/kestrel-feature-mcp/issues/26).
Shut down the old feature before upgrading to release the processes it owns.
Hosts expose their agent DID through `agent_id`. Missing required Python
dependencies, invalid identities and unexpected initialization failures stop
startup. An unavailable local Docker daemon disables local Docker operations;
it is handled separately from an invalid installation. This includes Docker SDK
errors and its Requests transport failures during connection or ping. Other
implementation errors still fail startup. Saved container connections retain
their container mode when restored, even if the Docker catalog changes. Server
selectors and image references reject surrounding whitespace before routing.

Container creation is recorded before Docker starts the process, so a rejected
command still leaves an identifiable resource that unload can reclaim. Resource
configuration transitions are serialized per container; a slow load does not
block another container's unload. Model-facing handles use the image reference,
while resource ownership keeps the full DID-bound identifier. Ordinary MCP tool calls
remain concurrent and hold no configuration lock.

Docker catalog discovery uses the current OCI catalog JSON API. Set `KESTREL_MCP_DOCKER_CATALOG` to select a catalog reference (default `mcp/docker-mcp-catalog`). Missing metadata is pulled into Docker's cache; unreadable catalogs return an error. Catalog counts describe available definitions, while gateway status reports this process's requested configuration and observed tools.

The installation CI matrix also runs the production connection through the
official [MCP conformance harness](https://github.com/modelcontextprotocol/conformance),
pinned to `0.2.0-alpha.12` with an npm integrity lock. It runs `tools_call` and
`request-metadata` explicitly at `2026-07-28`, with no expected-failure baseline.
These checks cover native tool exchange, wire schemas, per-request metadata and
version negotiation retry. Optional client capabilities that Kestrel does not
advertise are reported as skipped by the official scenario. The OAuth, input
request and extension scenarios remain outside this initial CI profile; passing
these two scenarios does not establish full client conformance (epic #3679 A7).

To run the same profile locally with Python test dependencies and Node 24+:

```bash
npm ci --prefix tests/conformance --ignore-scripts --no-audit --no-fund
for scenario in tools_call request-metadata; do
  tests/conformance/node_modules/.bin/conformance client \
    --command '.venv/bin/python tests/conformance/client.py' \
    --scenario "$scenario" --spec-version 2026-07-28 --timeout 60000 \
    --output-dir "tests/conformance/results/$scenario" || exit $?
done
```

Update the pinned harness and lock together, rerun both scenarios, and review
new required scenarios as the remaining host capabilities land.
