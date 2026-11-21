"""Per-dispatch native MCP credentials delegated by the original Core lease."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import time

import httpx2

from mcp_types import JSONRPCNotification, JSONRPCRequest

from ._lifecycle import run_cleanup_steps
from .oauth_grants import OAuthGrantChanged, OAuthRefreshPending
from .oauth_policy import GrantRejected, ResourceGrantRejected, positive_seconds, resource_envelope, resource_lane
from .tasks_protocol import CancelTaskRequest, GetTaskRequest, UpdateTaskRequest
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
        self.withdrawal_reason = None
        self.retired = False
        self._refresh = None
        self._admission = asyncio.Lock()

    @property
    def principal_id(self):
        return self.lease.principal_id

    @property
    def slot_id(self):
        return self.lease.slot_id

    @property
    def authorization_identity(self):
        identity = self.snapshot.authorization_identity
        if identity is None:
            raise GrantRejected('Legacy OAuth credentials need fresh foreground admission')
        return identity

    def withdraw(self, reason):
        if not self._withdrawn:
            self._withdrawn = True
            self.withdrawal_reason = reason
            self.lease.revoke()
            self._withdraw(reason)

    def _open(self):
        if self._withdrawn:
            raise GrantRejected('The original OAuth connection was withdrawn; request not sent')

    async def _payload(self, check):
        self._open()
        check()
        current = await self._current_grant(check)
        if current.state == 'refreshing':
            raise OAuthRefreshPending('The original OAuth refresh outcome is still pending')
        payload = await self.store.read_tokens(current)
        check()
        self._open()
        self.snapshot = replace(payload, tokens=None)
        return payload.tokens

    async def _current_grant(self, check):
        check()
        current = await self.store.read(self.snapshot.binding)
        check()
        if (current is None or current.state not in {'active', 'refreshing'}
                or current.authorization_identity != self.snapshot.authorization_identity):
            raise OAuthGrantChanged('The original OAuth authorization changed')
        return current

    async def _retain_after_conflict(self, check):
        try:
            await self._current_grant(check)
        except OAuthGrantChanged:
            return False
        return True

    async def _retire_refresh(self):
        if self._refresh is not None:
            await self._refresh.retire()
            self._refresh = None

    async def admit(self, *, force_refresh=False):
        # A foreign principal must not withdraw another principal's connection.
        self.lease.require_principal()
        async with self._admission:
            self.lease.require_principal()
            admitted = False
            try:
                if self.snapshot.generation is None:
                    async with self.lease.credential_operation() as check:
                        snapshot = await self.store.admit_legacy(self.snapshot, check)
                        self.snapshot = replace(snapshot, tokens=None)
                payload = await self._payload(self.lease.require_principal)
                if force_refresh or payload.is_expired(time.time()):
                    async with self.lease.credential_operation() as check:
                        if self._refresh is not None:
                            raise GrantRejected('The original OAuth refresh still needs retirement')
                        self._refresh = OAuthRefresher(self.store, self.budgets, close_seconds=self.close_seconds)
                        try:
                            snapshot = await self._refresh.run(self.snapshot, check)
                        except BaseException as error:
                            await run_cleanup_steps([(True, self._retire_refresh)], failure=error)
                            raise
                        await self._retire_refresh()
                        self.snapshot = snapshot
                self.lease.require_principal()
                self._open()
                admitted = True
            except OAuthGrantChanged:
                admitted = await self._retain_after_conflict(self.lease.require_principal)
                raise
            finally:
                if not admitted:
                    self.withdraw('reauthorization_required')

    async def dispatch_token(self, lane):
        check = self.lease.require_principal if lane == 'principal' else self.lease.require_background
        # Admission happens before entering the SDK. Wire checks never refresh,
        # and hold no lock across an authentication yield or resource response.
        check()
        # Wait for an already owned foreground refresh before reading its new
        # revision. The lock is released before the auth flow yields any MCP
        # request, so a native ping reply cannot deadlock a resource request.
        async with self._admission:
            check()
            admitted = False
            try:
                payload = await self._payload(check)
                if payload.is_expired(time.time()):
                    raise GrantRejected('OAuth credentials expired before dispatch; request not sent')
                admitted = True
                return payload.access_token
            except OAuthGrantChanged:
                admitted = await self._retain_after_conflict(check)
                raise
            finally:
                if not admitted:
                    self.withdraw('reauthorization_required')

    def bearer_auth(self):
        return GrantBearerAuth(self)

    async def retire(self):
        self.withdraw('revoked')
        await self._retire_refresh()
        self.retired = True


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


class TaskOperationAuth(httpx2.Auth):
    """Authorize one exact native Task request on a dedicated connection."""

    requires_request_body = True

    def __init__(self, server_url, request, *, read_access_token, check_current):
        if type(request) not in {GetTaskRequest, UpdateTaskRequest, CancelTaskRequest}:
            raise TypeError('MCP Task credentials require a typed original request')
        self._server_url = server_url
        self._read_access_token = read_access_token
        self._check_current = check_current
        self._request = request.model_copy(deep=True)
        original = self._request
        self._method = original.method
        self._params = json.dumps(
            original.params.model_dump(mode='json', by_alias=True, exclude_none=True),
            sort_keys=True, allow_nan=False)
        self._spent = False
        self._armed = False
        self._rejected = False

    @property
    def request(self):
        return self._request.model_copy(deep=True)

    @property
    def resource_rejected(self) -> bool:
        return self._rejected

    def sync_auth_flow(self, request):
        raise GrantRejected('MCP Task operations require the asynchronous transport')

    def require_resource(self) -> None:
        """Retain a definite HTTP refusal across native SDK transport teardown."""
        if self._rejected:
            raise ResourceGrantRejected('The resource refused this MCP Task operation')

    def arm(self):
        self._check_current()
        self.require_resource()
        if self._armed or self._spent:
            raise GrantRejected('The original MCP Task operation already owns its one request')
        self._armed = True

    def _authorize(self, envelope):
        if envelope is None or isinstance(envelope, JSONRPCNotification):
            return
        if isinstance(envelope, JSONRPCRequest):
            if (not self._armed and not self._spent
                    and envelope.method in {'server/discover', 'initialize', 'tools/list'}):
                return
            params = {key: value for key, value in (envelope.params or {}).items() if key != '_meta'}
            if (self._armed and envelope.method == self._method
                    and json.dumps(params, sort_keys=True, allow_nan=False) == self._params):
                # Spend the permit before any credential or transport await.
                self._armed, self._spent = False, True
                return
        raise GrantRejected('This MCP connection may only send its original Task request')

    async def async_auth_flow(self, request):
        self._check_current()
        self.require_resource()
        if request.headers.get('Authorization'):
            raise GrantRejected('MCP Task credentials must come from the original operation owner')
        envelope = await resource_envelope(request, self._server_url)
        self._check_current()
        self.require_resource()
        self._authorize(envelope)
        token = await self._read_access_token()
        self._check_current()
        self.require_resource()
        request.headers['Authorization'] = 'Bearer ' + token
        response = yield request
        if response.is_redirect or response.status_code in {401, 403}:
            self._rejected = True
        self._check_current()
        self.require_resource()
