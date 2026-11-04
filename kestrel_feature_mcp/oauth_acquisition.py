"""Durable intent behind the official SDK's acquisition-only TokenStorage."""

from __future__ import annotations

from dataclasses import replace
import time

from mcp.client.auth.utils import create_client_info_from_metadata_url

from .oauth_grants import OAuthGrantBinding, OAuthGrantTokens
from .oauth_policy import GrantRejected, positive_seconds


class IntentTokenStorage:
    """Never give the interactive provider a saved or refreshable credential.

    Core's current phase checker is supplied explicitly, including by the
    fresh callback request. The original operation owns these claim secrets;
    another task cannot reconstruct them from durable slot metadata.
    """

    def __init__(self, policy, store, *, agent_did, principal_id, connection_id, check):
        self.policy, self.store = policy, store
        self.agent_did, self.principal_id, self.connection_id = agent_did, principal_id, connection_id
        self.check = check
        self.claim = None
        self.snapshot = None

    async def get_client_info(self):
        identity = self.policy.identity
        return create_client_info_from_metadata_url(identity.client_id, [identity.redirect_uri])

    async def set_client_info(self, client):
        selected = self.policy.selection
        if (client.client_id != selected.client_id or client.issuer != selected.issuer
                or client.client_secret is not None or client.token_endpoint_auth_method != 'none'
                or [str(uri) for uri in client.redirect_uris or []] != [selected.redirect_uri]):
            raise GrantRejected('The SDK attempted to replace the approved public client identity')

    async def get_tokens(self):
        return None

    async def authorize(self, *, expected, acknowledge_unknown=False):
        selected = self.policy.selection
        requested = self.policy.requested_scopes
        if requested is None or self.claim is not None:
            raise GrantRejected('Authorization intent requires one original approved redirect')
        binding = OAuthGrantBinding(self.agent_did, self.principal_id, self.connection_id,
            selected.server_url, selected.resource, selected.issuer, selected.client_id,
            selected.redirect_uri, requested, selected.protected_metadata, selected.authorization_metadata)
        self.check()
        self.claim = await self.store.begin_authorization(binding, expected=expected,
            acknowledge_unknown=acknowledge_unknown)
        self.check()
        return self.claim.binding

    async def begin_exchange(self):
        if self.claim is None:
            raise GrantRejected('OAuth exchange has no original durable authorization intent')
        self.check()
        self.claim = await self.store.begin_exchange(self.claim)
        self.check()

    async def reject_exchange(self):
        if self.claim is None or self.claim.state != 'exchanging':
            raise GrantRejected('OAuth rejection requires its original exchange intent')
        self.check()
        await self.store.reject_exchange(self.claim)
        self.check()

    async def set_tokens(self, tokens):
        requested = self.policy.requested_scopes
        granted = requested if tokens.scope is None else frozenset(tokens.scope.split())
        if (self.claim is None or self.claim.state != 'exchanging' or requested is None
                or not granted or not granted <= requested or tokens.token_type != 'Bearer'
                or (tokens.expires_in is not None
                    and (type(tokens.expires_in) is not int or tokens.expires_in < 0))):
            raise GrantRejected('OAuth token receipt changed its original approved grant')
        expires_at = None if tokens.expires_in is None else time.time() + tokens.expires_in
        receipt = OAuthGrantTokens(tokens.access_token, tokens.refresh_token, expires_at, granted)
        self.check()
        snapshot = await self.store.complete_authorization(self.claim, receipt)
        self.check()
        # Status/operation ownership retains metadata only. Credential use later
        # requires a fresh Core lease and a revalidated store payload read.
        self.snapshot = replace(snapshot, tokens=None)
        self.policy.grant_ready = True


class AuthorizationOperation:
    """One retained native SDK task, with fresh authority per host phase."""

    def __init__(self, handle, store, *, agent_did, principal_id, connection_id,
                 server_url, scopes, identity, budgets, check, expected,
                 acknowledge_unknown, close_seconds):
        import asyncio
        from .oauth_policy import BootstrapPolicy

        self.handle, self.identity, self.budgets = handle, identity, dict(budgets)
        self.server_url = server_url
        self.expected, self.acknowledge_unknown = expected, acknowledge_unknown
        self.close_seconds = positive_seconds(close_seconds)
        self._phase_check = check
        self._withdrawn = False
        self._cancel_requested = False
        self._task = None
        self._transport = None
        self._identity_transport = None
        self._ready = asyncio.get_running_loop().create_future()
        self._callback = asyncio.get_running_loop().create_future()
        self.policy = BootstrapPolicy(server_url, identity, scopes,
            on_exchange=self._begin_exchange, on_rejection=self.storage_rejection, response_max_bytes=budgets['response_max_bytes'])
        self.storage = IntentTokenStorage(self.policy, store, agent_did=agent_did,
            principal_id=principal_id, connection_id=connection_id, check=self._check)

    def _check(self):
        if self._withdrawn:
            raise GrantRejected('The original OAuth authorization was withdrawn')
        self._phase_check()

    async def storage_rejection(self):
        await self.storage.reject_exchange()

    async def _begin_exchange(self):
        await self.storage.begin_exchange()

    async def _redirect(self, url):
        state = self.policy.redirect(url)
        binding = await self.storage.authorize(expected=self.expected,
            acknowledge_unknown=self.acknowledge_unknown)
        self._check()
        self._ready.set_result({'handle': self.handle, 'authorization_url': url,
            'state': state, 'issuer': binding.issuer, 'resource': binding.resource,
            'scopes': sorted(binding.scopes)})

    async def _receive_callback(self):
        result = await self._callback
        self._check()
        return result

    async def _run(self):
        import httpx2
        from mcp.client.auth import OAuthClientProvider
        from mcp.shared.auth import OAuthClientMetadata
        from mcp_types.version import LATEST_PROTOCOL_VERSION
        from .http_limits import IDENTITY_ACCEPT_ENCODING
        from .oauth_http import BudgetedTransport, GuardedAuth, OriginPinnedTransport, fetch_client_document

        from .oauth_policy import _origin
        self._check()
        origin = _origin(self.identity.client_id)
        self._identity_transport = BudgetedTransport(OriginPinnedTransport(lambda: {origin}),
            self.budgets['response_max_bytes'], self.budgets['network_seconds'])
        document = await fetch_client_document(self.identity, self.budgets['client_document'],
            transport=self._identity_transport, timeout=self.budgets['network_seconds'])
        self._check()
        metadata = OAuthClientMetadata(**{key: value for key, value in document.items() if key != 'client_id'})
        provider = OAuthClientProvider(server_url=self.server_url, client_metadata=metadata,
            storage=self.storage, redirect_handler=self._redirect,
            callback_handler=self._receive_callback, client_metadata_url=self.identity.client_id)
        self._transport = BudgetedTransport(OriginPinnedTransport(lambda: self.policy.approved_origins),
            self.budgets['response_max_bytes'], self.budgets['network_seconds'])
        async with httpx2.AsyncClient(transport=self._transport, auth=GuardedAuth(provider, self.policy),
                headers={'Accept-Encoding': IDENTITY_ACCEPT_ENCODING}, trust_env=False,
                follow_redirects=False, timeout=self.budgets['network_seconds']) as client:
            async with client.stream('GET', self.server_url, headers={
                    'Accept': 'application/json', 'MCP-Protocol-Version': LATEST_PROTOCOL_VERSION}) as response:
                # Acquisition ends at headers, never waiting on a resource SSE
                # stream and never using this provider for an MCP operation.
                if response.status_code in {401, 403}:
                    raise GrantRejected('The resource rejected the completed OAuth authorization')
        self._check()
        if self.storage.snapshot is None:
            raise GrantRejected('The native OAuth exchange did not commit a grant')
        return self.storage.snapshot

    async def start(self):
        import asyncio
        import contextvars

        if self._task is not None:
            raise GrantRejected('The original OAuth operation was already started')
        self._check()
        self._task = asyncio.create_task(self._run(), context=contextvars.Context())
        done, _ = await asyncio.wait({self._ready, self._task}, return_when=asyncio.FIRST_COMPLETED)
        if self._task in done:
            self._task.result()
            raise GrantRejected('OAuth acquisition ended without a consent request')
        self._check()
        return self._ready.result()

    async def complete(self, callback, check):
        import asyncio
        from mcp.client.auth.oauth2 import AuthorizationCodeResult

        check()
        if self._task is None or self._callback.done() or self._withdrawn:
            raise GrantRejected('The original OAuth operation cannot accept another callback')
        if callback.get('error') is not None:
            raise GrantRejected('The authorization server denied this OAuth request')
        self._phase_check = check
        self._callback.set_result(AuthorizationCodeResult(code=callback.get('code'),
            state=callback.get('state'), iss=callback.get('iss')))
        result = await asyncio.shield(self._task)
        self._check()
        return result

    def withdraw(self):
        self._withdrawn = True
        if self._task is not None and not self._task.done() and not self._cancel_requested:
            self._cancel_requested = True
            self._task.cancel()

    async def retire(self):
        import asyncio

        self.withdraw()
        if self._task is not None:
            done, _ = await asyncio.wait({self._task}, timeout=self.close_seconds)
            if not done:
                raise TimeoutError('The original OAuth acquisition worker has not physically closed')
            if not self._task.cancelled():
                self._task.exception()  # Observe failure; closure is acknowledged below.
        if self._identity_transport is not None:
            await self._identity_transport.aclose()
        if self._transport is not None:
            # Reenter the original transport after a failed close observation;
            # never replace a retained physical owner with a new cleanup task.
            await self._transport.aclose()
