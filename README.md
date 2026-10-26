# kestrel-feature-mcp

Model Context Protocol (MCP) server management and tool bridging for Kestrel Sovereign. Discover servers in the official MCP Registry, Docker's catalog, or the bundled local catalog. Connect to public HTTPS endpoints, Docker MCP gateways and custom container servers through the native MCP client.

## Installation

```bash
uv pip install kestrel-feature-mcp
```

## Dependencies

- `kestrel-sovereign-sdk[httpx2]` (version constraints are declared in [pyproject.toml](https://github.com/KestrelSovereignAI/kestrel-feature-mcp/blob/main/pyproject.toml))
- `docker>=7.1.0`
- `mcp>=2.3,<3`
- `requests>=2.34.2`
- `anyio>=4.7,<5`
- `pydantic>=2.12,<3`
- `jsonschema>=4.26,<5`

## Usage

Once installed, the `MCPAgent` feature is automatically discovered by kestrel-sovereign via the `kestrel_sovereign.features` entry point.

### Commands

- `!mcp-gateway-start <servers>` — Start Docker MCP Gateway
- `!mcp-gateway-stop` — Stop gateway
- `!mcp-load <HTTPS-URL|catalog-name|image>` — Connect a remote endpoint or load a Docker server
- `!mcp-unload <connection|HTTPS-URL|container>` — Disconnect a server and remove its saved connection
- `!mcp-list` — List running MCP servers
- `!mcp-search <query>` — Search official registry server names
- `!mcp-catalog` — List one page of the official registry
- `!mcp-info <name>` — Inspect an official namespaced server and version
- `!mcp-docker-catalog <query>` — Search Docker's catalog

## Remote HTTPS servers

Use the normal load/list/unload commands for an unauthenticated public server:

```text
!mcp-load https://learn.microsoft.com/api/mcp
!mcp-list
!mcp-unload https://learn.microsoft.com/api/mcp
```

Remote mode never probes the Docker daemon. Docker connects lazily on the first
container operation. HTTPS endpoints use the SDK's public-address validation
and DNS-pinned native transport, including certificate/hostname verification;
redirects and environment proxy routing are refused. URL credentials, fragments,
non-public addresses and mixed public/private DNS answers are rejected. Container
command arguments are invalid for a remote endpoint.

Load results include the canonical endpoint, DID-bound connection identifier,
negotiated `protocol_version`, mounted count and `persistent` status. Unload
accepts that identifier or the canonical endpoint returned by load. Enabled
connections are restored from the host's agent-scoped enablement store.
Restore reads existing remote rows without rewriting them and rechecks saved
state before tools become callable. Hosts without that capability explicitly
report that connections last for the session.
Saved state is read back before persistence or removal is reported. A host
that silently ignores an enablement write fails explicitly. Storage errors
fail the operation; a failed remote load withdraws handles and closes its transport. Reload, unload and shutdown invalidate old bound callers.
If setup fails after confirmed persistence, its error reports that enablement
remains saved and will restore after restart; unload it to disable that state.
New catalogs become callable only after persistence is confirmed. Unload
invalidates the catalog before waiting on storage removal.
Configuration changes for one remote connection are serialized without locking
ordinary calls or unrelated connections.

Feature shutdown refuses new connection starts and joins admitted Docker starts
before reporting that resources are released. Docker configuration changes are
serialized per feature; remote connections keep their separate connection gates.
If container removal fails, the feature retains its resource record and Docker
client for cleanup retry. Re-enabling the same feature instance completes that
cleanup before allowing a fresh manager and restoring saved connections.
Across connection modes, a host that supports enablement persistence must
confirm the saved state and configuration by readback before publication.
Gateway start also confirms that its complete saved server set matches the
requested replacement. If publication fails after that acknowledgement, the
error discloses the retained enablement and, for gateway start, the replaced
server set. Unload the saved connection to disable restoration.

This release supports `auth="none"` only. It does not accept token headers or
start OAuth registration/consent when a server challenges for authentication.
Saved authentication modes or fields it cannot implement are refused. Vendor
OAuth, encrypted grants and refresh after restart remain part of
[Kestrel #3679](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3679),
including the native SDK gate in
[#3690](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3690).
Connecting to a public documentation server is not the three-vendor OAuth
acceptance experiment. Remote write scopes remain gated on
[#596](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/596).

## Calling tools

Discovered server tools are mounted in the host's dynamic registry. Invoke the
advertised handle through Kestrel's governed tool dispatch; its exact owner and
handle determine permissions, approvals and audit records. The generic
`mcp_call_tool` / `mcp_gateway_call` tools and their command aliases have been
removed: allowing a generic dispatcher could otherwise bypass a DENY on its
target. A host without the dynamic registry cannot mount MCP tools.

Tool listings retain the official SDK's standard Tool fields, including
`_meta.ui`, annotations, icons and output schemas, across remote, gateway and
container discovery. Server metadata is untrusted data and does not grant
permissions. Retaining Apps metadata does not advertise an Apps renderer;
sandboxed rendering and governed app calls remain in
[Kestrel #3679](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3679).

Each handle is bound to the connection that advertised its schema. Reloading or
withdrawing that connection invalidates its old handles, including a call still
waiting for approval. A fresh handle and approval are required after reload.

## Configuration

| Variable | Description |
|----------|-------------|
| `DOCKER_HOST` | Docker daemon socket (optional, defaults to local) |
| `KESTREL_MCP_REGISTRY_URL` | HTTPS Registry API base, default `https://registry.modelcontextprotocol.io/v0.1` |
| `KESTREL_MCP_REGISTRY_TIMEOUT` | Request deadline including decoding and schema validation, in seconds; default `30` |
| `KESTREL_MCP_REGISTRY_MAX_BYTES` | Maximum response body size, default `2097152` bytes |
| `KESTREL_MCP_REGISTRY_PROBLEM_CHARS` | Maximum characters per diagnostic field, default `256` |
| `KESTREL_MCP_REGISTRY_PROBLEMS_PER_RECORD` | Maximum diagnostic details per rejected record, default `4` |
| `KESTREL_MCP_REGISTRY_TEXT_CHARS` | Maximum characters per tool confirmation or error, default `8192` |

### Discovery sources

`mcp_search`, `mcp_catalog` and `mcp_server_info` default to `source="official"`.
Select `source="local"` explicitly to search or inspect bundled entries by
capability/category. Docker discovery retains the separate `mcp_docker_catalog`
tool. A local entry never overrides an official entry with the same name, and
an official registry error never becomes a successful local result.

Official catalog and search requests return one page, with `limit` from 1 to 100
(default 20). Omit `limit` and `cursor` for the local source; explicit values
are refused there. Search and catalog list latest versions only; detail lookup
can request a known exact version. Pass the exact `result.metadata.nextCursor` back as `cursor` for
the next page. Detail lookup accepts the namespaced server name and an exact
`version`, or `latest`; results retain the actual version, remote endpoint
templates, package definitions and registry metadata. Search results are
discovery metadata: they do not install packages, connect to remote endpoints or
send credentials. SSE definitions remain visible with an unsupported-transport
label. These discovery tools work without Docker.

Registry HTTPS requests use the SDK's canonical URL policy and pinned transport,
with native TLS verification, no redirects and no proxy-environment routing.
Private registry addresses, malformed page envelopes, failed pagination and
HTTP errors fail explicitly. Individual records that violate the published
schema are rejected with visible diagnostics and a `partial` result; the exact
next cursor remains available. `result` retains the unmodified response,
including rejected records, and `rejected_records` identifies their indices,
names and schema problems. Only conforming records are displayed as catalog
entries. A rejected detail lookup is inspectable with its schema problems;
`RegistryRecord.require_valid()` refuses it. Publisher text is quoted and
control characters are escaped in the human-readable rendering. The request
deadline and byte limit also apply to custom registry bases.

Schema diagnostics are bounded to 256 characters per path, detail or rejected
name, with four problems per rejected record plus an explicit omitted-count
summary. Every rejected index remains excluded from conforming results even
when diagnostics are omitted. Model-facing confirmation and error text each
have an 8192-character budget; complete record blocks and escaped cursor lines are omitted with a visible
notice rather than cutting an opaque cursor into a different value. The full
response and exact cursor remain in `data.result`. The next cursor has display
priority over record blocks so a normal pagination token remains available when
the record display budget is exhausted. Configure these bounds with
`KESTREL_MCP_REGISTRY_PROBLEM_CHARS`, `KESTREL_MCP_REGISTRY_PROBLEMS_PER_RECORD`
and `KESTREL_MCP_REGISTRY_TEXT_CHARS`. These limits apply to the official source.

Validation follows JSON Schema 2020-12 without a format checker: `uri` and
`date-time` formats are annotations, not additional validity assertions. Strict
JSON syntax, schema types, required fields, enumerations and other assertions
are enforced. Discovery does not establish that an advertised endpoint works.

The bundled `registry_openapi_2025_12_01.json` is an unmodified JSON conversion of
the official [Registry API contract](https://github.com/modelcontextprotocol/registry/blob/11b7b0e274d518b6f449c5ee3518a6151d9848b9/docs/reference/api/openapi.yaml),
commit `11b7b0e274d518b6f449c5ee3518a6151d9848b9`. Its upstream YAML SHA-256 is
`3ed9ca429754087f2c7de81aa845c1cab3286c33941ac48482f923bbd6f1442d`;
the converted JSON SHA-256 is
`69a092a20321d6616d0e83933b1de39916bd0fa87975d7931ef3b92f825c7edc`.
The upstream license is included alongside it as `registry_contract_LICENSE.txt`.
This Registry API/schema revision is independent of the MCP wire revision.

`tests/fixtures/official_registry_rejected_repository.json` was captured from
the official registry on 2026-10-17 for `ai.agentrapay/agentra` version `1.0.0`.
Its `repository: {}` violates the published required-field contract. The
fixture proves visible rejection and continued pagination; the schema is not
relaxed to accept it.

## Development

The [manual vendor OAuth acceptance spike](tests/oauth_acceptance/README.md)
drives initial consent with the native SDK and a published Kestrel client
identity. It has separate discovery and authorization modes and keeps tokens
in memory. It does not enable production OAuth connections or establish refresh
after restart.

```bash
uv pip install -e ".[test]"
uv run pytest
```

## Native MCP protocol

The feature uses the official MCP 2.x `Client` over Streamable HTTP. Its standard
version negotiation selects `2026-07-28` with modern servers and a mutually
supported published revision with other servers. Tool listings expose the
selected `protocol_version`. Container servers must expose MCP at `/mcp`; the
standalone HTTP+SSE transport and gateway `transport="sse"` selection have been
removed. Docker MCP Gateway 0.44.1 negotiates `2025-11-25`; its lack of the
newer revision is tracked in
[Kestrel #3683](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3683).
Features requiring newer capabilities must check the negotiated connection.
Gateway server lists describe requested configuration; observed tools do not
prove readiness of every requested server. A call that loses its response or
times out has an unconfirmed execution outcome, because the server may have
already produced effects. Its tool error carries `data.execution_outcome="unknown"`.
The connection does not replay that call. A retry needs policy approval and an
explicit idempotency or safe-repeat guarantee; an error is not evidence that
nothing executed. Standard pre-execution JSON-RPC rejections retain their
original error. Caller cancellation remains cancellation.
Operator-input continuations are not implemented yet. The native client's
automatic input loop is disabled; an input-required response produces an
unknown-outcome error without another tool request. Managed container and gateway
HTTP connections also ignore environment proxies, including for gateway bearer
headers.
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
Hosts expose their agent DID through `agent_id`; invalid identities fail startup.
The first container operation acquires the Docker client off the event loop.
An unavailable local daemon disables that operation and leaves remote mode
available. Missing Docker dependencies and programming errors propagate at
that first container use, independently of typed daemon connection failures. Saved container connections retain
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

## MCP Apps components (0.8.0)

The MCP Apps host is under development in #3679. Version 0.8.0 ships the native
tool contracts, bounded resources, governed App execution and standalone sandbox
service described below. These components do not yet
advertise Apps support: authenticated view routes, initial result associations
and the chat renderer still need to be composed and accepted together.
MCP tool loading requires the governed registration API provided by Core 0.55.0
or newer. An unsupported host is refused before connecting or saving enablement.
When a server rejects a call with `HeaderMismatch`, Kestrel retires the original
catalog. Reload the connection to discover and admit the new contract before
calling again. The [transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#client-behavior)
recommends refreshing and retrying; Kestrel requires that recovery to pass through
fresh host admission instead of resending under the previous approval.

The package includes a standalone public sandbox service. Run it on a separate
origin that receives no host identity cookies, behind your normal HTTPS ingress:

```bash
kestrel-mcp-apps-sandbox --config /absolute/path/to/sandbox.json
```

This command requires Node.js 22 or newer. Set `KESTREL_MCP_APPS_NODE` to an
explicit executable when Node is not on `PATH`. The launcher starts the built
service without importing the agent feature or passing host credentials,
`HOME`, cloud configuration or `NODE_OPTIONS` into that process. It verifies
the packaged asset hashes before listening and refuses credentials on its
public HTTP routes.

Supply the deployment configuration explicitly. For example, for local
development with the host console on port 8000:

```json
{
  "listen": {"host": "127.0.0.1", "port": 8090},
  "sandbox": {
    "hostOrigin": "http://127.0.0.1:8000",
    "maxMessageBytes": 8388608,
    "maxHtmlBytes": 1048576,
    "policy": {}
  }
}
```

The operator's `policy` bounds resource-requested `connectDomains`,
`resourceDomains`, `baseUriDomains` and device `permissions`. Empty grants deny
those capabilities. Nested network-frame grants are unsupported and refused.
Only exact configured origins can be granted. HTTP limits are configurable
through the deployment's `httpLimits` object: `maxHeaderBytes`,
`requestTimeoutMs`, `headersTimeoutMs` and `keepAliveTimeoutMs`.

The source of the bundled assets is `web/`, its npm lock and the unchanged
official SDK packages. Regenerate the checked-in bundles and original license
notices together; CI checks a clean rebuild byte for byte:

```bash
npm ci --prefix web --no-audit --no-fund
npm run build --prefix web
npm run build --prefix web -- --check
npm run test:node --prefix web
npm exec --prefix web -- playwright install --with-deps chromium
npm test --prefix web
```

The browser checks use the actual built standalone service, the official App
and AppBridge, and an opaque View inside the separate-origin proxy. They cover
native initialization, teardown, source/origin checks and effective browser
policies. They do not establish complete host acceptance or vendor OAuth consent.
