# Vendor OAuth acceptance spike

This checkout provides the manual Phase 0 experiment for
[Kestrel #3679](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3679).
It uses the official MCP SDK's `OAuthClientProvider` and the feature's existing
`MCPConnection`. The SDK owns discovery, PKCE, authorization-code exchange and
protocol negotiation. Public HTTP auth hooks enforce the selected client,
issuer, resource, callback and scope boundaries without changing requests or
overriding private SDK methods.

This tool measures **initial authorization and MCP discovery**. Production
remote connections still support `auth="none"`. The console connect flow,
agent-scoped encrypted grants, governed tool dispatch, refresh after restart
and write-scope acceptance remain separate epic requirements. The native SDK
restart-state issue remains
[#3690](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3690).

## Run in an isolated environment

From this worktree, create a separate environment rather than syncing an
active host environment:

Run on the same computer as the browser: its loopback callback terminates
there. A remote console needs a separately designed HTTPS callback and client
metadata identity; this native profile does not establish that design.

```bash
mcp_probe_dir="$(mktemp -d)"
env -u VIRTUAL_ENV uv venv --python 3.13 "$mcp_probe_dir/venv"
env -u VIRTUAL_ENV uv pip install --python "$mcp_probe_dir/venv/bin/python" -e '.[test]' uvicorn
```

Inspect `vendors.json` before selecting a vendor. It declares the exact MCP
`server_url`, OAuth `resource` identifier, issuer, metadata URLs and selected
scopes. The resource can be a parent of the MCP endpoint; the SDK's own
resource-hierarchy check validates that selection. All entries use the
public Kestrel client document at
<https://agents.kestrelsovereign.com/oauth/kestrel-local-client.json> and its
published IPv4 loopback callback on port 44721. The public document must match
that client ID, callback, native application type and public-client auth method.

Discovery is the default. It fetches the public client document and drives
the native resource challenge and metadata flow. It stops before opening an
authorization page, registering a client or exchanging tokens:

```bash
env -u VIRTUAL_ENV PYTHON_DOTENV_DISABLED=1 KESTREL_SKIP_DOTENV=1 \
  "$mcp_probe_dir/venv/bin/python" -m tests.oauth_acceptance.client \
  --config tests/oauth_acceptance/vendors.json --vendor notion \
  --output "$mcp_probe_dir/notion-discovery.json"
```

After the worktree review, run initial authorization explicitly. The tool
owns the exact callback listener before opening the normal browser. Complete
the vendor's login and consent for the intended account or test workspace:

```bash
env -u VIRTUAL_ENV PYTHON_DOTENV_DISABLED=1 KESTREL_SKIP_DOTENV=1 \
  "$mcp_probe_dir/venv/bin/python" -m tests.oauth_acceptance.client \
  --config tests/oauth_acceptance/vendors.json --vendor notion --mode authorize \
  --output "$mcp_probe_dir/notion-authorization.json"
```

An occupied callback port fails without selecting a different redirect. The
receiver accepts one matching state and issuer, rejects duplicate parameters
and callbacks, and ignores unknown response parameters as required by
[RFC 6749 §4.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2).
This profile requires advertised authorization-response issuer support and
validates `iss` on success and denial according to
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207).
It compares the issuer strings from resource and authorization metadata
directly, before URL parsing can normalize their spelling.

The native HTTP transports validate and pin public addresses, verify TLS,
refuse HTTP redirects and ignore environment proxies. Authorization opens in
the user's browser, where the vendor can perform its normal login redirects.
No default client registration, borrowed product identity, token header input
or scope expansion substitutes for the selected grant.

Tokens stay in memory. Results contain public client/resource/issuer bindings,
the fetched client-document hash, scopes, negotiated protocol and tool count.
They contain no access token, refresh token, authorization code, PKCE verifier,
state, account content or tool descriptions. An existing output file is refused
before requests or consent so a previous success cannot be silently reused.
A failed attempt records `stage="failed"` rather than claiming that no grant
was issued. A vendor authorization remains
in that account's connected-app settings until the account owner revokes it.

`authorization_ready` means discovery reached a valid native request; it does
not mean the vendor accepted the client or granted access.
`authorized_and_discovered` requires a real token exchange and successful
canonical MCP discovery/listing. The tool performs zero `tools/call` requests;
it does not establish governed dispatch, full feature initialization or
restart acceptance.

## Observations to distinguish

With MCP SDK 2.3.0 on 2026-10-25:

- Notion reaches the native authorization boundary using Kestrel's public CIMD
  document and PKCE S256. Real consent and token/tool acceptance are still
  separate measurements.
- Linear advertises CIMD, but its `/mcp` and `/mcp/readonly` challenges request
  `read write`. SDK 2.3.0 replaces the selected `read` scope with that challenge.
  The guard refuses before browser or token I/O. This is the client scope-policy
  gap in [#3836](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/3836),
  not evidence of a vendor allowlist. Expanding the grant to get a green result
  would invalidate the selected read-only experiment.
- GitHub's metadata supports S256 but does not advertise CIMD. This CIMD-only
  profile reports that its own registered client is required. That is distinct
  from proving GitHub rejects self-hosted clients.

Vendor references: [Notion client guide](https://developers.notion.com/guides/mcp/build-mcp-client),
[Linear MCP](https://linear.app/docs/mcp),
[GitHub host integration](https://github.com/github/github-mcp-server/blob/main/docs/host-integration.md).
Keep the three-vendor acceptance item open until the real account flows and
their limitations are recorded. Remote write scopes remain gated on
[#596](https://github.com/KestrelSovereignAI/kestrel-sovereign/issues/596).

## Automated evidence

The unit suite runs the actual native OAuth client against separate HTTPS
resource and authorization servers with real certificates and PKCE checking,
then exercises the same production MCP connection and loopback callback.
It checks disclosure before result shapes: a scope or identity refusal must
produce no browser/token request, and an overgranted token must never reach
the resource. A corrupted public SDK request is stopped before the independent
token server receives its credential header. These are local protocol tests,
with no real account or vendor-acceptance claim.

```bash
env -u VIRTUAL_ENV "$mcp_probe_dir/venv/bin/python" -m pytest tests/unit -q
```
