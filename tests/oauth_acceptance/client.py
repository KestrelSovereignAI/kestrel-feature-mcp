"""Manual Phase 0 client: native initial OAuth, then canonical MCP discovery.

This is not the console authentication service or persistent grant storage.
Run as a module from this checkout; tokens stay in this short-lived process.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import AsyncExitStack
from importlib.metadata import version
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

import httpx2
from kestrel_sdk.security.outbound import assert_safe_url, pinned_httpx2_async_transport
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import OAuthClientMetadata
from mcp_types.version import LATEST_PROTOCOL_VERSION

from kestrel_feature_mcp.connection import MCPConnection
from .callback import CallbackRejected, LoopbackCallback
from .policy import GrantPolicy, GrantRejected, GrantSelection, GuardedAuth, MemoryGrant


class AuthorizationReady(Exception):
    """Discovery mode stops before opening authorization or receiving credentials."""


class RefuseUnselectedOrigin(httpx2.AsyncBaseTransport):
    async def handle_async_request(self, request):
        raise GrantRejected("No transport is available for an unselected origin")


async def open_authorization(url: str):
    """Own and join the launcher; the user's browser retains its normal lifetime."""
    child = await asyncio.create_subprocess_exec(
        sys.executable, "-c",
        "import sys,webbrowser;sys.exit(0 if webbrowser.open(sys.argv[1],new=1) else 1)",
        url, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with asyncio.timeout(20):
            result = await child.wait()
    except (TimeoutError, asyncio.CancelledError):
        if child.returncode is None:
            try:
                child.terminate()
            except ProcessLookupError:
                pass
        try:
            async with asyncio.timeout(2):
                await child.wait()
        except TimeoutError:
            child.kill()
            await child.wait()
        raise
    if result != 0:
        raise GrantRejected("The browser launcher could not open the authorization page")


async def client_metadata(selection: GrantSelection, *, timeout: float):
    endpoint = await assert_safe_url(selection.client_id, allowed_schemes=("https",))
    async with httpx2.AsyncClient(
        transport=pinned_httpx2_async_transport(endpoint), trust_env=False,
        follow_redirects=False, timeout=timeout,
    ) as client:
        response = await client.get(endpoint.url)
        if (response.status_code != 200
                or response.headers.get("Content-Type", "").split(";", 1)[0] != "application/json"):
            raise GrantRejected("The public CIMD document did not return 200 application/json")
        body = await response.aread()
        if len(body) > 65536:
            raise GrantRejected("The CIMD document exceeded the acceptance response budget")
        document = json.loads(body)
    metadata = OAuthClientMetadata.model_validate(document)
    if (document.get("client_id") != selection.client_id
            or [str(uri) for uri in metadata.redirect_uris or []] != [selection.redirect_uri]
            or metadata.token_endpoint_auth_method != "none"
            or document.get("application_type") != "native"
            or "authorization_code" not in (metadata.grant_types or [])
            or "refresh_token" not in (metadata.grant_types or [])
            or any(key in document for key in ("client_secret", "jwks", "jwks_uri"))):
        raise GrantRejected("The published identity does not describe this exact native client")
    return (metadata.model_copy(update={"scope": " ".join(sorted(selection.scopes))}),
            hashlib.sha256(body).hexdigest())


async def run(selection: GrantSelection, *, mode: str, browser_timeout: float,
              network_timeout: float, connect_timeout: float, call_timeout: float,
              close_timeout: float, browser_opener=open_authorization):
    if mode not in {"discover", "authorize"}:
        raise GrantRejected("Select discovery or initial authorization explicitly")
    if any(not 0 < value < float("inf") for value in (
            browser_timeout, network_timeout, connect_timeout, call_timeout, close_timeout)):
        raise GrantRejected("Every acceptance timeout must be finite and positive")
    callback_candidate = LoopbackCallback(
        selection.redirect_uri, selection.issuer, timeout=browser_timeout,
    )
    metadata, identity_sha256 = await client_metadata(selection, timeout=network_timeout)
    policy = GrantPolicy(selection)
    storage = MemoryGrant(policy)
    public = {"client_id": selection.client_id, "server_url": selection.server_url,
              "resource": selection.resource,
              "issuer": selection.issuer, "selected_scopes": sorted(selection.scopes),
              "mcp_sdk_version": version("mcp"), "client_document_sha256": identity_sha256,
              "persistent_tokens": False,
              "restart_refresh_verified": False, "tool_calls": 0}
    async with AsyncExitStack() as resources:
        callback = None
        if mode == "authorize":
            callback = await resources.enter_async_context(callback_candidate)

        async def redirect(url):
            state = policy.redirect(url)
            if mode == "discover":
                raise AuthorizationReady()
            assert callback is not None
            callback.arm(state)
            await browser_opener(url)

        async def receive_callback():
            if callback is None:
                raise GrantRejected("Discovery mode cannot receive an authorization code")
            return await callback.result()

        provider = OAuthClientProvider(
            server_url=selection.server_url, client_metadata=metadata, storage=storage,
            redirect_handler=redirect, callback_handler=receive_callback,
            client_metadata_url=selection.client_id,
        )
        auth = GuardedAuth(provider, policy)
        mounts = {}
        server = None
        for url in (selection.server_url, selection.issuer):
            parsed = urlsplit(url)
            origin = parsed.scheme + "://" + parsed.netloc
            if origin not in mounts:
                approved = await assert_safe_url(url, allowed_schemes=("https",))
                mounts[origin] = pinned_httpx2_async_transport(approved)
                if url == selection.server_url:
                    server = approved
        assert server is not None
        # The SDK's original auth generator drives every discovery/exchange
        # request through the role guard and origin-pinned native transports.
        async with httpx2.AsyncClient(
            transport=RefuseUnselectedOrigin(), mounts=mounts, auth=auth,
            follow_redirects=False, trust_env=False, timeout=network_timeout,
        ) as client:
            try:
                response = await client.get(selection.server_url, headers={
                    "Accept": "application/json", "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION,
                })
            except AuthorizationReady:
                return {**public, "stage": "authorization_ready", "grant_obtained": False,
                        "scope": "Native discovery and request validation only; no vendor consent"}
            if response.status_code not in {200, 405}:
                raise GrantRejected("The resource rejected the completed initial authorization")
        tokens = await storage.get_tokens()
        if tokens is None:
            raise GrantRejected("No native OAuth token exchange completed")
        # Reuse the feature's sole protocol implementation and lifecycle owner.
        # The same public auth guard/provider retains the in-memory grant.
        connection = MCPConnection(
            server, auth=auth, connect_timeout=connect_timeout,
            call_timeout=call_timeout, close_timeout=close_timeout,
        )
        try:
            tools = await connection.connect()
            return {**public, "stage": "authorized_and_discovered", "grant_obtained": True,
                    "granted_scopes": sorted((tokens.scope or "").split()),
                    "protocol_version": connection.protocol_version, "tools": len(tools),
                    "scope": "Real initial OAuth and canonical MCP discovery; no governed tool dispatch or restart proof"}
        finally:
            await connection.close()


def load_selection(config: dict, vendor: str):
    timeout_names = ("browser_timeout", "network_timeout", "connect_timeout", "call_timeout", "close_timeout")
    if set(config) != {"client_id", "redirect_uri", "vendors"} | set(timeout_names):
        raise GrantRejected("Acceptance configuration contains unsupported or missing fields")
    if not isinstance(config["vendors"], dict) or vendor not in config["vendors"]:
        raise GrantRejected("The selected vendor is missing from the acceptance configuration")
    raw = config["vendors"][vendor]
    required = {"server_url", "resource", "issuer", "protected_metadata", "authorization_metadata", "scopes"}
    if (set(raw) != required or not isinstance(raw["scopes"], list)
            or any(not isinstance(scope, str) for scope in raw["scopes"])):
        raise GrantRejected("Vendor configuration contains unsupported grant fields")
    selected = GrantSelection(
        **{key: raw[key] for key in required - {"scopes"}},
        scopes=frozenset(raw["scopes"]), client_id=config["client_id"],
        redirect_uri=config["redirect_uri"],
    )
    if any(type(config[name]) not in {int, float} for name in timeout_names):
        raise GrantRejected("Acceptance timeouts must be numbers")
    timeouts = {name: float(config[name]) for name in timeout_names}
    return selected, timeouts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--vendor", required=True)
    parser.add_argument("--mode", choices=["discover", "authorize"], default="discover")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # This isolated CLI emits structured results. SDK exception messages can
    # contain response bodies or state; never print them or request URLs.
    logging.disable(logging.CRITICAL)

    def failure(kind, error, traceback):
        detail = str(error) if isinstance(error, (GrantRejected, CallbackRejected)) else "Native operation failed; credential and response details withheld"
        json.dump({"stage": "failed", "error_type": kind.__name__, "detail": detail}, sys.stderr)
        sys.stderr.write("\n")

    sys.excepthook = failure
    # Reserve the report before config/network/consent work. A failed attempt
    # records no success, even if the vendor already issued a grant.
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        result = {"stage": "failed", "acceptance_verified": False}
        try:
            selected, timeouts = load_selection(json.loads(args.config.read_text()), args.vendor)
            result = asyncio.run(run(selected, mode=args.mode, **timeouts))
        finally:
            json.dump(result, output, indent=2)
            output.write("\n")
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
