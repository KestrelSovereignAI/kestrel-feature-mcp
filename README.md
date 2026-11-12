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
- `Authlib>=1.9.4,<2`
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

## Native Docker Gateway profiles

Gateway mode requires Docker MCP CLI 0.44.1 or later with native profiles and a
POSIX host. `KESTREL_MCP_DOCKER_CATALOG` selects the OCI catalog used for both
discovery and execution (default `mcp/docker-mcp-catalog`). Server names are exact
catalog names; patterns and separators are refused before replacing a gateway.

Each gateway owns a unique native profile and a private Docker CLI configuration.
Native server names retain their configuration-template and OAuth identity.
`KESTREL_MCP_DOCKER_PROFILE` selects an existing native profile whose selected
server settings, secret bindings and tool allowlists should be retained. The
native `default` profile supplies settings when present; a new installation
without one has no saved server settings. An explicitly named missing profile
fails before replacing a working gateway.
The source profile must retain the same native server snapshot as the selected
catalog before settings can be transferred. Rebuild the native source profile
after changing the catalog definition, including its command or environment.

The process exposes concrete server tools rather than Docker's generic execution
and configuration tools, so every mounted call reaches Kestrel's shared permission
rail. The operator's configuration is read without being rewritten, and implicit
and explicit Docker TLS certificate paths retain their original lookup.

Shutdown joins the original CLI process group and checks native daemon-container
inventory before releasing its profile and private configuration. Docker labels
containers by catalog name, without a per-profile ownership receipt. Remaining
containers therefore produce an explicit unconfirmed retirement, including when
another gateway uses the same server. Kestrel retains reconciliation state and
never deletes containers it cannot attribute. Retirement can be retried after
physical absence is confirmed. Failed inspection, profile operations and
unacknowledged creation also retain their original cleanup state.

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

The generic load command accepts `auth="none"` only. OAuth connections use the
authenticated Console flow below; commands never accept token headers or
start consent implicitly. Saved authentication modes or fields that are not
supported are refused. Connecting to a public documentation server is not the
three-vendor OAuth acceptance experiment in
[Kestrel #3679](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3679).
Remote write scopes remain gated on
[#596](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/596).

## Optional OAuth connectors (0.14)

OAuth is disabled by default and requires the [supported host contract](#runtime-requirements). Configure the
Console's public HTTPS origin in Core with
`KESTREL_MCP_OAUTH_CONSOLE_ORIGIN=https://console.example.com`. That origin must
serve the native callback page and `/js` assets. Core owns the client metadata,
callback routing, authentication, CSRF and finite connection authority; the
feature owns encrypted grants and the original native MCP connections.

Enable the feature's OAuth settings before opening **MCP connectors**:

```json
{"oauth": {"enabled": true}}
```

Enter the HTTPS MCP server URL and the requested scopes, then choose
**Authorize connector**. Consent opens in the same tab. Return to Console and
choose **Connect** after authorization completes. This profile uses a public
Client ID Metadata Document, PKCE S256 and issuer-bound responses; it requires
the provider to accept that client identity. Providers requiring a registered
client or a different profile are refused. Three-vendor acceptance remains an
explicit release gate, not a claim established by synthetic integration tests.

The SDK discovers the protected resource and authorization server and performs
the single authorization-code exchange. Authlib performs explicit, single-attempt
refresh. Tokens are encrypted with the SDK's agent key; provision the normal
Kestrel data key before authorization and preserve it across restarts. Tokens
never enter browser storage or enablement records. Status reads do not load the
key or decrypt credentials. A saved connection restarts dormant: the same
principal must explicitly connect it under fresh Core authority. Changing the
client identity requires new consent before using the old grant.

**Refresh credentials** refreshes and reconnects under the current principal.
Recent resource-rejection labels survive connection cleanup without keeping a
connection open. These diagnostics last for the current feature runtime;
`oauth.max_status_entries` bounds their retained count (default 256). They apply
only to the saved grant revision that the resource refused.
Unknown exchange or refresh outcomes remain visible and are never automatically
replayed; explicitly acknowledge an uncertain outcome before starting replacement
consent. **Disconnect locally** withdraws tools, deletes local tokens and removes
the saved connection. It does not revoke the grant at the provider. The generic
unload command refuses an OAuth connection so it cannot bypass the original
principal's authority. Authorization alone grants no tool permission: calls still
pass through Core's permission, approval, policy and audit boundary.

Apps, OAuth and operator input share one feature configuration generation. Omitted settings are
preserved, all enabled domains are validated before replacement, and existing
connections or pending authorizations must be retired before changing settings.

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
permissions. Apps negotiation is enabled only when the optional authenticated
host and separate sandbox described below are configured.

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

Official server-name searches require at least three Unicode characters after
trimming surrounding whitespace. The original query is sent unchanged. Use
`mcp_catalog` to list servers without a search, or `source="local"` for shorter
bundled capability/category queries.

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

Production custody uses one encrypted credential slot per
agent, principal, and connection. It records authorization and exchange intent
before token HTTP, requires commit acknowledgment and readback before use, and
retains unknown exchange/refresh outcomes without replay. Status and restart
metadata reads neither load encryption keys nor decrypt credentials. Local
revocation leaves a tombstone and does not claim vendor revocation.

Its table is `mcp_oauth_credential_slots`. The earlier `mcp_oauth_grants`
foundation was used only by isolated tests and is not read or migrated. Scope
and issuer changes replace the same slot under its current revision; they
cannot create parallel live grants. The native HTTP and Console browser tests exercise
Core controllers, independent TLS authorization/resource peers, governed tool
dispatch, refresh, dormant restart and local disconnect. They establish neither
real-vendor compatibility nor the remaining full permission acceptance gate.

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
State-only multi round-trip requests require the [supported host contract](#runtime-requirements) so faults
after execution begins remain unconfirmed across model, named and direct tool
dispatch. Hosts must declare `supports_unconfirmed_tool_outcomes` exactly true;
unsupported hosts are refused before connection acquisition or Apps/OAuth
enablement. They use the SDK's public one-round session APIs. Each round keeps the original tool/arguments or resource URI, echoes only
the latest opaque state, and checks the original connection, caller and any
live App View. OAuth rounds check the original principal and lease; the native
HTTP credential boundary refuses expired credentials without starting a refresh.
Initial foreground credential admission remains separate. The one call deadline
includes every round and backoff. A lost response, later rejection or authority
loss never establishes that earlier rounds were effect-free.

`KESTREL_MCP_STATE_ONLY_MAX_ROUNDS` defaults to 10 continuations (up to 11
requests); zero disables them. `KESTREL_MCP_STATE_ONLY_BACKOFF_INITIAL` and
`KESTREL_MCP_STATE_ONLY_BACKOFF_MAX` default to 0.05 and 0.25 seconds, with capped
exponential pacing. Low-level calls without an original host authority check
do not continue. The SDK's automatic input loop stays disabled. Nonempty input
requests require the governed input host described below; without it they are
refused without fulfillment. MCP SDK 2.3 rejects an empty `inputRequests` map
without `requestState`; that response fails without retry, rather than bypassing
the native validator. This is a documented SDK limitation, not full conformance.
See the [MRTR specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)
and [public SDK manual loop](https://py.sdk.modelcontextprotocol.io/handlers/multi-round-trip/).
Managed container and gateway HTTP connections also ignore environment proxies,
including for gateway bearer headers.
Tool discovery follows pagination and fails on repeated cursors. Negotiation
uses the connection deadline, then discovery uses the whole-call deadline.
Cancelled startup waits on its original transport owner within the shutdown
budget. A later caller cancellation or outer timeout retains the original
startup deadline in its explicit cause/group evidence. Shutdown has its
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
pinned to `0.2.0-alpha.12` with an npm integrity lock. The canonical
[`profile.json`](tests/conformance/profile.json) selects `tools_call`,
`request-metadata`, `http-standard-headers`, `http-custom-headers`,
`http-invalid-tool-headers`, and
`json-schema-ref-no-deref` at `2026-07-28`, with no expected-failure baseline.
These checks exercise native tool exchange, request metadata, version negotiation,
standard headers on tool calls and resource reads, custom header value encoding,
rejection of malformed header declarations while retaining valid tools, and refusal
to fetch external JSON Schema references. Optional client capabilities
and unexercised request methods are reported as skipped by the official scenarios.
OAuth, input requests, and extension scenarios remain outside this profile.
Passing these six scenarios does not establish full client
conformance (epic #3679 A7).

To run the same profile locally with Python test dependencies and Node 24+:

```bash
npm ci --prefix tests/conformance --ignore-scripts --no-audit --no-fund
version=$(.venv/bin/python -c 'from tests.conformance.client import load_profile; print(load_profile()["protocol_version"])') || exit $?
scenarios=$(.venv/bin/python -c 'from tests.conformance.client import load_profile; print(" ".join(load_profile()["scenarios"]))') || exit $?
for scenario in $scenarios; do
  tests/conformance/node_modules/.bin/conformance client \
    --command '.venv/bin/python tests/conformance/client.py' \
    --scenario "$scenario" --spec-version "$version" --timeout 60000 \
    --output-dir "tests/conformance/results/$scenario" || exit $?
done
```

Update the pinned harness and lock together, rerun the profile, and review
new required scenarios as the remaining host capabilities land.

## Optional operator input (0.16)

Governed tool calls can pause for standard MCP form elicitation, including calls
from an open MCP App. Input is disabled by default. It requires Core's durable,
authenticated `mcp-input` host, introduced in the Core 0.65 delivery; earlier
hosts refuse explicit enablement. Configure it before loading connections:

```json
{"inputs": {"enabled": true}}
```

For saved agent configuration, use the registered package key:

```toml
[features.mcp.config.inputs]
enabled = true

[features.mcp.config.inputs.host]
max_pending = 64
max_payload_bytes = 1048576
max_request_bytes = 65536
retention_seconds = 900.0
operation_seconds = 30.0
```

An input card identifies the requesting server and permits review, modification,
decline and cancellation. Server text is rendered as text. Form values are
validated against the original schema, including its formats. Answers, original
arguments and native request state stay out of conversation parts and browser
storage. Core encrypts the checkpoint and answers under the agent's data key;
preserve that key across restarts. `retention_seconds` is the response deadline,
not a promise that encrypted reconciliation records are deleted at that time.

The original turn returns control without awaiting the person. Submitting an
answer creates a fresh governed dispatch under the authenticated principal,
original chat, current connection contract, tool permissions and approvals.
A durable compare-and-swap consumes each waiting revision before network I/O.
The native SDK request keeps the exact original arguments and opaque
`requestState`, supplies standard `inputResponses`, and receives a fresh RPC
identifier. Reloading a card reads saved state, including subsequent form rounds;
it does not repeat the original operation. A matching reconnected server can
resume its checkpoint after a host restart if the remote state remains valid.

App continuations retain the exact original physical View through private HTTP
delivery. A closed, replaced or lost View cannot be adopted after restart.
Completed private native results reach that View through AppBridge; an initial
tool's completed App publication uses Core's audited part renderer. Another
initial App call is refused while that View's input remains pending.

Signal-driven and other unattended work receives an audited `no_approver`
decline. URL-mode elicitation receives an audited standard decline, with no
navigation. Legacy inline requests have no restartable checkpoint and are also
declined. Resources and prompts do not acquire a tool's interactive authority;
this delivery provides durable forms for governed tool calls. Unknown or
already-consumed continuations remain fenced against replay, including when
native execution completed but result storage or delivery failed.

Durable MCP Tasks remains a separate capability and is not advertised yet.
Its implementation uses the official SDK's public extension interface and the
published Tasks schema, while MCP stays on the published official Python SDK.
There is no MCP SDK fork or private protocol translation layer.

## Optional MCP Apps host

The optional host composes native AppBridge rendering, Core-authenticated View
routes, governed App tool calls and bounded private result retention. It requires
the [supported host contract](#runtime-requirements) and a separate credential-free sandbox origin. Apps are
disabled by default. Configure the feature before loading MCP connections:

```json
{
  "apps": {
    "enabled": true,
    "host": {
      "host_origin": "https://console.example.com",
      "sandbox_url": "https://apps-sandbox.example.net/proxy",
      "connection_policies": {}
    }
  }
}
```

The public `host_origin` is explicit, including behind a TLS proxy. Run the
sandbox service with the same `hostOrigin`; its policy and the feature's
per-connection policy must both allow any requested network or device grants.
Empty policies deny those grants. Invalid configuration is rejected before
replacing the current host. Unload connections before changing configuration.

Saved connections restore in the native `on_agent_ready` phase, after initial
registration or soft re-enable commits. Maintenance boot does not restore
outbound connections. Core reports ready-hook failures and keeps the committed
feature enabled; failed connections remain unavailable. At initial boot,
agent cognition may begin while saved connections are still restoring.

Only the enabled complete host advertises the official Apps extension, across
remote, container and gateway connections. The parent renderer receives the
original chat's locator, fetches its native resource and result through Core,
and gives them to the opaque App iframe. App calls use the original governed
tool bindings and required audit. Leaving a chat, removing its rendered part,
retiring a connection or shutting down the feature closes its physical Views.
Reopening reads the retained result without replaying the initial tool.
Choose **Open App** to allocate a View and **Close App** to release it. Replaying
conversation history creates no Views or resource reads until an App is opened,
so a long conversation does not automatically exhaust its View budget.

Configuration and connection admission share the feature's lifecycle gates.
A start from an earlier configuration generation is refused. Cleanup attempts
every original resource and propagates failures and cancellation; settled
maintenance failures are reported without poisoning later re-enable attempts.
An unfinished close retains its original owner and is retried before re-enable.

## Runtime requirements

Version 0.8.0 introduced the native components described below; 0.9.0 added
completed post-tool policy, 0.10.0 added private initial result associations,
and 0.10.1 added ownership through physical HTTP delivery.
Version 0.16 requires Core 0.64.4 or newer and SDK 0.52.1 or newer for native
Apps, OAuth and durable tool outcome contracts. The test profile uses the same
minimums. `uv sync --locked --extra test` resolves the host and the feature's
runtime dependencies from the public package index.
Initial publication and result associations are detailed below.
An unsupported host is refused before connecting or saving enablement.
The host must declare `supports_durable_tool_effects` as exactly `True`.
Every App tool call carries an `operation_id` for its original intent: a
redelivery retains that ID, while a new user action receives a fresh ID.
The host records durable admission before dispatch. An unconfirmed outcome
requires reconciliation; neither a reconnect nor a repeated delivery may
silently dispatch the same effect again.
When a server rejects a call with `HeaderMismatch`, Kestrel retires the original
catalog. Reload the connection to discover and admit the new contract before
calling again. The [transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#client-behavior)
recommends refreshing and retrying; Kestrel requires that recovery to pass through
fresh host admission instead of resending under the previous approval.
The App execution component preserves known native refusals before an effect
starts, including withdrawal of the original OAuth grant. After native
admission, a missing complete governed result is unconfirmed. Consumers must
not turn that uncertainty into an automatic retry.
Construct the App executor with its actual host, for example
`AppExecutor(host=agent, max_pending_calls=configured_limit)`. The host must
declare `supports_deferred_tool_results` as exactly `True`. App results use the SDK's deferred delivery contract: completed,
allowing post-tool policy on the unchanged public result is required before
private native output can be delivered. Denial, ASK/stop, replacement,
redaction and incomplete hooks withhold it, even if the public values did not
change. Required structured audit must still complete before delivery.
Withdrawing a View before native admission raises `ResourceConflict`; withdrawal
after admission raises `ResourceOutcomeUnknown`. An awaiting caller's own
cancellation remains cancellation. Closing a View joins its owned calls and
required audit finalization; it cannot undo effects already accepted remotely.

Initial publication requires the supported host contracts
`supports_audited_deferred_tool_results` and `supports_tool_publication_context`,
both exactly `True`. Pass a synchronous `initial_publisher` to `AppExecutor`;
the callback receives the original tool, actual chat destination, native result
and arguments only after the policy and audit boundary. Headless or expired
chat collectors do not create a result association. Publication failures preserve the completed
tool result and emit a UI failure notice without suggesting tool replay.

`AppPublications` is an in-process composition component. Construct it with the
actual `host`, `agent_id` and configured limits; use its `executor` when building
the wrappers retained by Core's registration callback. It owns the executor and
publisher together, so no construction trampoline or separate publisher is needed.
The host supplies the original publisher identity and independently authenticates every reader of that
original principal, agent and chat. A serialized part carries only a random
locator and session metadata; possession grants no read or execution authority.
The `publication_owner(context)` callback returns an immutable, comparable
principal snapshot, or `None` when there is no authorized interactive publisher.
`require_reader(owner, context)` must independently authenticate the current
reader, check that original principal and exact agent/chat, then return `None` or
raise. Expected denials may use `ResourceError` or `PermissionError`; locator
failures have one non-disclosing error. A failed View authority check refuses
that operation, preserving its original cause and no-replay outcome after admission.
An unauthorized reader does not revoke the legitimate owner's View or sibling
calls. Source withdrawal, expiry and explicit close own permanent revocation.
Cancellation and process control retain their existing semantics. Callbacks must
be ordinary synchronous functions or bound methods; returned awaitables and
generators are refused. The monotonic clock also permits synchronous builtins.

Configure `max_publications`, `max_views`, `max_publications_per_owner`,
`max_views_per_owner`, `max_payload_bytes`, `max_pending_calls` and
`retention_seconds`. The two owner limits count across that principal's chats;
setting them below the feature totals reserves capacity for other principals.
Payload limits count the native result and arguments as UTF-8 JSON before retained
copies are made. Reopening a View reads a copy of the stored native
result without invoking the tool again. Registration replacement or withdrawal
revokes associated Views synchronously; the host must then await `drain_retired()`
before closing the original connection, and `close()` before feature teardown.
`drain_retired()` also expires idle results and stale original connections or
registrations before joining their Views, reclaiming both result and View capacity.
Source predicates are checked only for their own records during publication or
read. A failing predicate fences its original batch; a drain attempts every
source and joins all revoked work before raising a failure. If checks and joins
both fail, an explicit exception group preserves every original failure,
including control errors and cancellation; the drain never reports success.
On unplanned connection loss, retire the owner and drain promptly so stale
results and Views do not keep holding capacity. Retire or replace a fenced
owner to release its retained wrapper and binding references.

From 0.10.1, physical HTTP response children use
`AppView.borrow_delivery()` through their actual transport send, checking the
yielded guard before and after delivery. `cancel_delivery()` cancels an original
child at most once; View retirement joins it alongside approvals and calls.
Cancellation authority ends with each borrow. Retirement joins the borrow's
settlement, not unrelated later work on the host's task. A task cannot close its
own borrowed View; its external lifetime owner must close it.
`AppExecutor.supports_owned_delivery is True` identifies this host contract;
`AppView.is_closed` is lifecycle state and grants no access.
On a privacy or other host policy transition, `withdraw_publications()` erases
private associations and fences every View synchronously; then drain retired
work. This leaves the original tool registrations available for new policy-bound
results and never reopens an old private result. Withdrawal does not cancel an
initial chat tool that has already run: the host's `publication_owner` must
compare the original turn's privacy-policy epoch with the current epoch after
the required audit. It must refuse a staged result from a previous epoch, even
if the host has since returned to the same privacy mode. A fresh caller or a
current mode check alone cannot renew that original turn's publication rights.
Each registration needs fresh tool wrappers, so a result staged before an audit
await cannot be reassociated with a replacement registration of the same object.
No Apps capability is advertised until those host integrations are present.

The package includes a standalone public sandbox service. Run it on a separate
origin that receives no host identity cookies, behind your normal HTTPS ingress:

```bash
kestrel-mcp-apps-sandbox --config /absolute/path/to/sandbox.json
```

This command requires Node.js 22 or newer. Set `KESTREL_MCP_APPS_NODE` to an
explicit executable when Node is not on `PATH`. Relative configuration and
executable paths resolve from the caller's working directory. The launcher
starts the built service without importing the agent feature or passing host credentials,
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

For a standalone container, build from the repository root with Docker BuildKit:

```bash
docker build -f docker/Dockerfile.apps-sandbox -t kestrel-mcp-apps-sandbox .
docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --mount type=bind,source=/absolute/path/to/sandbox.json,target=/etc/kestrel-mcp-apps/sandbox.json,readonly \
  --publish 127.0.0.1:8090:8090 kestrel-mcp-apps-sandbox
```

Set `listen.host` to `0.0.0.0` in the container's JSON configuration and publish
its configured listener port. The image follows
maintained Node LTS, runs as a non-root user and includes the hash-verified
sandbox assets, their manifest and the project license. Its build context excludes source, Git
metadata and host configuration. Mount no host identity files or credentials,
and expose the service through a separate HTTPS origin. Startup refuses
corrupted assets.

The source of the bundled assets is `web/`, its npm lock and the unchanged
official SDK packages. Regenerate the checked-in bundles and original license
notices together.

The build also identifies dependencies embedded inside the official SDK's
distribution through its source maps. It requires their original notices from
the hashed [notice inventory](web/licenses/README.md), and refuses unknown
embedded versions or altered notice files. These attribution records do not
constrain the runtime dependency resolver.

CI checks a clean rebuild byte for byte:

```bash
npm ci --prefix web --no-audit --no-fund
npm run build --prefix web
npm run build --prefix web -- --check
npm run test:node --prefix web
npm exec --prefix web -- playwright install --with-deps chromium
npm test --prefix web
```

The browser checks use the actual built standalone service, the official App
and AppBridge, and an opaque View inside the separate-origin proxy. The Python
browser lane also drives the actual Core chat renderer and authenticated HTTP
controller, a native MCP peer and SQLite audit. ALLOW, ASK and DENY campaigns
check external effects and every successful or refused dispatch row against the
original agent, tool and chat. ASK approves one call, refuses replay of that
approval and denies a fresh call. The checks also cover model-only tool refusal,
navigation, reopening and DOM retirement.

The `apps-native-browser` CI job and local runner use an explicitly owned
container built from the immutable official Playwright image declared in
`tests/browser/runtime.json`. The runner retains the original immutable Docker
ID before startup, joins the entire namespace, and verifies its removal on
success, failure or interruption. The container has no host mounts, Docker
socket, external network or host PID namespace. A normal GitHub job container
exposes its host Docker socket and is unsuitable for this boundary.

Node/Playwright normally close through their original stdin and browser
lifetime; a stalled shutdown is a test failure. Docker retires every child,
including detached descendants or a child created during shutdown. Run locally
with Docker running and the test extra installed:

```bash
uv run --locked --extra test --python 3.14 python tests/browser/run_native.py --output /absolute/temporary/browser-results
```

The output contains the source inventory, build log, JUnit results and original
container receipt. `--cleanup` reconciles that same receipt; CI invokes it in an
`always()` step as well as the runner's normal `finally` cleanup. Native Docker
tests exercise the same owner on original failure, late forks and normal exit.
These checks establish component integration; full Bootstrap, the actual
approval dialog, deployed-host acceptance and real vendor OAuth consent remain
separate acceptance work.
