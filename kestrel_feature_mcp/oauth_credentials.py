"""Per-dispatch native MCP credentials delegated by the original Core lease."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import time

import httpx2

from .oauth_policy import GrantRejected, ResourceGrantRejected, positive_seconds, resource_lane
from .oauth_refresh import OAuthRefresher


class OAuthConnectionCredential:
    """Grant metadata is attribution; only the original Core lease authorizes use."""

    def __init__(self, store, snapshot, lease, budgets, *, close_seconds, withdraw):
        binding = snapshot.binding
        if (binding.agent_did != lease.agent_id or binding.principal_id != lease.principal_id
                or binding.connection_id != lease.connection_id or binding.slot_id != lease.slot_id
                or snapshot.state != 'active'):
            raise GrantRejected('OAuth credential and original Core lease have different bindings')
        self.store, self.snapshot, self.lease = store, replace(snapshot, tokens=None), lease
        self.budgets, self.close_seconds = dict(budgets), positive_seconds(close_seconds)
        self._withdraw = withdraw
        self._withdrawn = False
        self._refresh = None
        self._admission = asyncio.Lock()

    @property
    def principal_id(self):
        return self.lease.principal_id

    @property
    def slot_id(self):
        return self.lease.slot_id

    def withdraw(self, reason):
        if not self._withdrawn:
            self._withdrawn = True
            self.lease.revoke()
            self._withdraw(reason)

    def _open(self):
        if self._withdrawn:
            raise GrantRejected('The original OAuth connection was withdrawn; request not sent')

    async def _payload(self, check):
        self._open()
        check()
        payload = await self.store.read_tokens(self.snapshot)
        check()
        self._open()
        return payload.tokens

    async def admit(self):
        # A foreign principal must not withdraw another principal's connection.
        self.lease.require_principal()
        async with self._admission:
            self.lease.require_principal()
            admitted = False
            try:
                payload = await self._payload(self.lease.require_principal)
                if payload.is_expired(time.time()):
                    async with self.lease.credential_operation() as check:
                        self._refresh = OAuthRefresher(self.store, self.budgets, close_seconds=self.close_seconds)
                        snapshot = await self._refresh.run(self.snapshot, check)
                        await self._refresh.retire()
                        self._refresh = None
                        self.snapshot = snapshot
                self.lease.require_principal()
                self._open()
                admitted = True
            finally:
                if not admitted:
                    self.withdraw('reauthorization_required')

    async def dispatch_token(self, lane):
        check = self.lease.require_principal if lane == 'principal' else self.lease.require_background
        # Admission happens before entering the SDK. Wire checks never refresh,
        # and hold no lock across an authentication yield or resource response.
        check()
        admitted = False
        try:
            payload = await self._payload(check)
            if payload.is_expired(time.time()):
                raise GrantRejected('OAuth credentials expired before dispatch; request not sent')
            admitted = True
            return payload.access_token
        finally:
            if not admitted:
                self.withdraw('reauthorization_required')

    def bearer_auth(self):
        return GrantBearerAuth(self)

    async def retire(self):
        self.withdraw('revoked')
        if self._refresh is not None:
            await self._refresh.retire()
            self._refresh = None


class GrantBearerAuth(httpx2.Auth):
    """One native request and response, with no consent, refresh or replay."""

    requires_request_body = True

    def __init__(self, credential):
        self.credential = credential

    async def async_auth_flow(self, request):
        selected = self.credential.snapshot.binding
        lane = await resource_lane(request, selected.server_url)
        if request.headers.get('Authorization'):
            raise GrantRejected('OAuth resource credentials must come from the original grant owner')
        token = await self.credential.dispatch_token(lane)
        request.headers['Authorization'] = 'Bearer ' + token
        response = yield request
        if response.is_redirect or response.status_code in {401, 403}:
            self.credential.withdraw('resource_rejected')
            raise ResourceGrantRejected('The resource rejected this authorization; do not replay the request')
