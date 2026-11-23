"""One explicit OAuth refresh through Authlib and durable native custody."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from functools import partial
import time

from authlib.integrations.httpx_client import AsyncOAuth2Client
from kestrel_sdk.resources import ResourceConflict
from mcp.shared.auth import OAuthToken
from pydantic import ValidationError

from ._lifecycle import join_maintenance, run_cleanup_steps
from .http_limits import IDENTITY_ACCEPT_ENCODING
from .oauth_grants import OAuthGrantRejected, OAuthGrantTokens
from .oauth_http import BudgetedTransport, OriginPinnedTransport
from .oauth_policy import GrantRejected, GrantSelection, RefreshPolicy, _origin, positive_seconds


class OAuthRefresher:
    """One retained attempt; an unknown result never starts another token POST.

    The caller owns Core's credential operation and per-connection admission
    lock. No lock is held across a resource request or authentication yield.
    This object remains owned until its original transport closes.
    """

    def __init__(self, store, budgets, *, close_seconds, remaining_seconds=None):
        self.store, self.budgets = store, dict(budgets)
        self._started = False
        self._transport = None
        self._claim = None
        self.close_seconds = positive_seconds(close_seconds)
        self._done = asyncio.Event()
        self._owner = None
        self._retiring = False
        self._remaining_seconds = remaining_seconds

    async def run(self, snapshot, check):
        if self._started or self._retiring:
            raise GrantRejected('The original OAuth refresh attempt cannot be replayed')
        self._started = True
        self._owner = asyncio.current_task()
        try:
            return await self._run(snapshot, check)
        finally:
            self._done.set()

    async def _run(self, snapshot, check):
        check()
        original = await self.store.read_tokens(snapshot)
        check()
        binding, tokens = original.binding, original.tokens
        if tokens.refresh_token is None:
            raise GrantRejected('This grant requires new authorization; it has no refresh token')
        selected = GrantSelection.for_binding(binding, scopes=tokens.scopes)

        async def begin_exchange():
            check()
            if self._remaining_seconds is None:
                self._claim = await self.store.begin_refresh(original)
                check()
                return
            exchange_budget = self.budgets['network_seconds'] + self.close_seconds
            if self._remaining_seconds() <= exchange_budget:
                raise ResourceConflict('MCP Task refresh has insufficient time for its token exchange')

            async def claim():
                self._claim = await self.store.begin_refresh(original)

            try:
                await self._join_custody(claim)
                check()
                if self._remaining_seconds() <= exchange_budget:
                    raise ResourceConflict('MCP Task refresh expired before sending its token exchange')
            except BaseException as error:
                if self._claim is not None:
                    # Authlib is still inside the request hook. No transport
                    # owns this POST, even if the original Task was withdrawn.
                    abandon = partial(self.store.abandon_refresh, self._claim)
                    await run_cleanup_steps([(True, partial(self._join_custody, abandon))], failure=error)
                raise

        async def rejected(code, definite):
            if self._remaining_seconds is None:
                check()
                await self.store.reject_refresh(self._claim)
            elif definite:
                disposition = self.store.reject_refresh if code == 'invalid_grant' else self.store.abandon_refresh
                await self._join_custody(partial(disposition, self._claim))
            check()

        policy = RefreshPolicy(selected, on_exchange=begin_exchange, on_rejection=rejected,
            response_max_bytes=self.budgets['response_max_bytes'])
        origins = {_origin(binding.server_url, allow_query=True), _origin(binding.issuer)}
        self._transport = BudgetedTransport(OriginPinnedTransport(lambda: origins),
            self.budgets['response_max_bytes'], self.budgets['network_seconds'])
        saved = {'access_token': tokens.access_token, 'refresh_token': tokens.refresh_token,
            'token_type': 'Bearer', 'scope': ' '.join(sorted(tokens.scopes)),
            'expires_at': tokens.expires_at}
        # No constructor token_endpoint: Authlib cannot silently refresh while
        # performing discovery or a resource request. Its public hooks inspect
        # the fully formed native request, after public-client authentication.
        async with AsyncOAuth2Client(client_id=binding.client_id, token_endpoint_auth_method='none',
                token=saved, transport=self._transport, follow_redirects=False, trust_env=False,
                timeout=self.budgets['network_seconds'], headers={'Accept-Encoding': IDENTITY_ACCEPT_ENCODING},
                event_hooks={'request': [policy.request], 'response': [policy.response]}) as client:
            for url in (binding.protected_metadata, binding.authorization_metadata):
                check()
                await client.get(url, auth=None)
                check()
            try:
                refreshed = await client.refresh_token(policy.token_endpoint,
                    refresh_token=tokens.refresh_token, scope=saved['scope'], resource=binding.resource)
                receipt = OAuthToken.model_validate(refreshed)
                granted = tokens.scopes if receipt.scope is None else frozenset(receipt.scope.split())
                if (not granted or not granted <= tokens.scopes
                        or (receipt.expires_in is not None and receipt.expires_in < 0)):
                    raise GrantRejected('OAuth refresh changed its original approved grant')
                expiry = None if receipt.expires_in is None else time.time() + receipt.expires_in
                fresh = OAuthGrantTokens(receipt.access_token, receipt.refresh_token, expiry, granted)
            except (ValidationError, OverflowError, OAuthGrantRejected):
                raise GrantRejected('The OAuth refresh receipt is invalid') from None
            try:
                if self._remaining_seconds is None:
                    check()
                    snapshot = await self.store.finish_refresh(self._claim, fresh)
                else:
                    # Only finish the original receipt. The caller must recheck
                    # Task authority before it can use the resulting grant.
                    snapshot = await self._join_custody(partial(self.store.finish_refresh, self._claim, fresh))
            except OAuthGrantRejected:
                raise GrantRejected('The OAuth refresh receipt cannot be retained') from None
            check()
        return replace(snapshot, tokens=None)

    @staticmethod
    async def _join_custody(write):
        task = asyncio.create_task(write(), name='mcp-oauth-refresh-custody')
        await join_maintenance(task, 'MCP OAuth refresh custody')
        return task.result()

    async def retire(self):
        self._retiring = True
        if self._started and not self._done.is_set():
            if asyncio.current_task() is self._owner:
                raise GrantRejected('An active OAuth refresh cannot join its own caller')
            # Closing is an observer of the original foreground frame. A join
            # timeout never cancels that caller or manufactures another attempt.
            await asyncio.wait_for(self._done.wait(), self.close_seconds)
        if self._transport is not None:
            await self._transport.aclose()
