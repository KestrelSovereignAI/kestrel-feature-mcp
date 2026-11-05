"""Native OAuth host operations sharing the feature's original MCP owners."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial

from kestrel_sdk.operator import OperatorAuthorizationError
from kestrel_sdk.resources import ResourceConflict
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._lifecycle import run_cleanup_steps
from .connection import connection_lifecycle
from .oauth_acquisition import AuthorizationOperation
from .oauth_credentials import OAuthConnectionCredential
from .oauth_grants import OAuthGrantStore
from .oauth_policy import ClientIdentity, GrantRejected
from .remote import remote_name_for_url, remote_owner


class OAuthSettings(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, allow_inf_nan=False)
    enabled: bool = False
    close_seconds: float = Field(default=10.0, gt=0, le=60)
    maintenance_seconds: float = Field(default=1.0, gt=0, le=60)
    max_connections: int = Field(default=64, gt=0, le=1024)
    max_status_entries: int = Field(default=256, gt=0, le=10000)
    max_connections_per_principal: int = Field(default=8, gt=0, le=128)

    @model_validator(mode='after')
    def bounded_principal(self):
        if self.max_connections_per_principal > self.max_connections:
            raise ValueError('OAuth principal connection quota exceeds the feature quota')
        return self


@dataclass
class _AuthorizationOwner:
    operation: AuthorizationOperation
    retirement: asyncio.Lock = field(default_factory=asyncio.Lock)


class OAuthRuntime:
    """Stored identifiers describe grants; only Core's live context authorizes use."""

    def __init__(self, feature, host, settings):
        self.feature, self.host, self.settings = feature, host, settings
        self._operations = {}
        self._credentials = {}
        self._resource_rejections = OrderedDict()
        self._connections = {}
        self._accepting = True

    @property
    def has_owners(self):
        return bool(self._operations or self._credentials)

    def _require_open(self):
        self.feature._require_open()
        if not self._accepting:
            raise GrantRejected('The original OAuth runtime is closing')

    def _store(self, identity):
        return OAuthGrantStore(self.host.database, self.feature._connection_owner_did(),
            max_token_bytes=identity['max_token_bytes'])

    def _identity_store(self, context):
        identity = self.host.client_identity(context)
        return identity, self._store(identity)

    def _name(self, server_url, principal_id):
        return remote_name_for_url(server_url, self.feature._connection_owner_did(), principal_id=principal_id)

    async def begin(self, context, check, value, identity, *, authorization_handle):
        self._require_open()
        check()
        if authorization_handle in self._operations:
            raise GrantRejected('The original OAuth handle is already owned')
        document = identity['client_document']
        store = self._store(identity)
        name = self._name(value['server_url'], context.principal_id)
        operation = AuthorizationOperation(authorization_handle, store,
            agent_did=self.feature._connection_owner_did(), principal_id=context.principal_id,
            connection_id=name, server_url=value['server_url'], scopes=frozenset(value['scopes']),
            identity=ClientIdentity(document['client_id'], document['redirect_uris'][0]),
            budgets=identity, check=check, expected=None,
            acknowledge_unknown=value['acknowledge_unknown'], close_seconds=self.settings.close_seconds)
        # Register the original handle before any awaited metadata or network work.
        self._operations[authorization_handle] = _AuthorizationOwner(operation)
        operation.expected = await store.read_slot(context.principal_id, name)
        check()
        return await operation.start()

    async def complete(self, handle, context, check, value):
        owner = self._operations.get(handle)
        if owner is None:
            raise GrantRejected('The original OAuth authorization is unavailable')
        operation = owner.operation
        if operation.storage.principal_id != context.principal_id:
            raise GrantRejected('The original OAuth principal is required')
        try:
            snapshot = await operation.complete(value, check)
        except BaseException as error:
            await run_cleanup_steps([(True, partial(self.retire_authorization, handle))], failure=error)
            raise
        await self.retire_authorization(handle)
        check()
        return self._status(snapshot, self.host.client_identity(context))

    async def cancel(self, handle, check):
        owner = self._operations.get(handle)
        if owner is None:
            return
        async with owner.retirement:
            await owner.operation.cancel(check)
            if self._operations.get(handle) is owner:
                del self._operations[handle]

    async def retire_authorization(self, handle):
        owner = self._operations.get(handle)
        if owner is None:
            return
        async with owner.retirement:
            if self._operations.get(handle) is not owner:
                return
            await owner.operation.retire()
            del self._operations[handle]

    @staticmethod
    def _identity_matches(binding, identity):
        document = identity['client_document']
        return (binding.client_id == document['client_id']
            and [binding.redirect_uri] == document['redirect_uris'])

    def _status(self, snapshot, identity):
        binding = snapshot.binding
        credential = self._credentials.get(binding.connection_id)
        record = self.feature._remote_connections.get(binding.connection_id)
        connected = (snapshot.state == 'active' and credential is not None
            and credential.snapshot.revision == snapshot.revision and credential.snapshot.binding == binding
            and credential.withdrawal_reason is None and record is not None
            and record.credential is credential and record.tools is not None and record.connection.is_connected)
        state = {'active': 'authorized', 'exchanging': 'outcome_unknown', 'refreshing': 'refresh_unknown',
            'revoked': 'revoked', 'authorizing': 'reauthorization_required'}[snapshot.state]
        if snapshot.state == 'authorizing' and any(
                owner.operation.storage.claim is not None
                and owner.operation.storage.claim.revision == snapshot.revision
                and not owner.operation._withdrawn for owner in self._operations.values()):
            state = 'authorizing'
        if snapshot.state == 'revoked' and snapshot.reason in {'abandoned', 'exchange_rejected', 'refresh_rejected'}:
            state = 'reauthorization_required'
        if (snapshot.state == 'active'
                and self._resource_rejections.get(binding.connection_id) == snapshot.revision):
            state = 'resource_rejected'
        if connected:
            state = 'connected'
        if not self._identity_matches(binding, identity):
            state, connected = 'reauthorization_required', False
        return {'connection_id': binding.connection_id, 'server_url': binding.server_url,
            'issuer': binding.issuer, 'resource': binding.resource, 'scopes': sorted(binding.scopes),
            'state': state, 'connected': bool(connected)}

    async def list(self, context):
        identity, store = self._identity_store(context)
        return [self._status(snapshot, identity) for snapshot in await store.list_principal(context.principal_id)]

    async def _snapshot(self, store, context, name, check):
        check()
        snapshot = await store.read_slot(context.principal_id, name)
        check()
        if snapshot is None:
            raise GrantRejected('The original OAuth connection is unavailable')
        return snapshot

    async def _retire_connection(self, name, credential):
        """Retire an original physical record inside its admitted OAuth operation."""
        async with connection_lifecycle(self.feature._remote_lifecycle, name):
            record = self.feature._remote_connections.get(name)
            steps = [(True, credential.retire)]
            if record is not None and record.credential is credential:
                self.feature._unmount_tools(remote_owner(name))
                steps.insert(0, (True, partial(self.feature._retire_remote, name)))
            await run_cleanup_steps(steps)
            # Metadata remains in durable custody. The process retains only
            # original owners whose complete physical close is unacknowledged.
            if self._credentials.get(name) is credential:
                del self._credentials[name]

    async def _retire_idle_connection(self, name, credential):
        """Join foreground admission before a background or close retirement."""
        async with connection_lifecycle(self._connections, name):
            await self._retire_connection(name, credential)

    async def connect(self, context, check, name, *, refresh=False):
        self._require_open()
        identity, store = self._identity_store(context)
        # Resolve this principal's slot before touching any process-local owner.
        snapshot = await self._snapshot(store, context, name, check)
        if not self._identity_matches(snapshot.binding, identity):
            raise GrantRejected('The OAuth client identity changed; new authorization is required')
        if snapshot.state != 'active':
            raise GrantRejected('This OAuth grant requires new authorization or explicit local disconnect')
        if self.settings.close_seconds >= identity['lease_seconds']:
            raise GrantRejected('OAuth close budget must be shorter than its host lease')
        async with connection_lifecycle(self._connections, name):
            check()
            previous = self._credentials.get(name)
            if previous is not None:
                await self._retire_connection(name, previous)
                check()
            others = [credential for key, credential in self._credentials.items() if key != name]
            if (len(others) >= self.settings.max_connections
                    or sum(credential.principal_id == context.principal_id for credential in others)
                    >= self.settings.max_connections_per_principal):
                raise ResourceConflict('Disconnect an owned OAuth connection before opening another')
            lease = self.host.issue_lease(context, connection_id=name, slot_id=snapshot.binding.slot_id)
            def withdraw(reason):
                record = self.feature._remote_connections.get(name)
                if record is not None and record.credential is credential:
                    self.feature._unmount_tools(remote_owner(name))
                    if reason == 'resource_rejected':
                        self._resource_rejections[name] = credential.snapshot.revision
                        self._resource_rejections.move_to_end(name)
                        while len(self._resource_rejections) > self.settings.max_status_entries:
                            self._resource_rejections.popitem(last=False)

            credential = OAuthConnectionCredential(store, snapshot, lease, identity,
                close_seconds=self.settings.close_seconds,
                withdraw=withdraw)
            self._credentials[name] = credential
            self._resource_rejections.pop(name, None)
            ready = False
            try:
                await credential.admit(force_refresh=refresh)
                check()
                await self.feature._load_remote_connection(snapshot.binding.server_url, None, credential=credential)
                check()
                ready = True
                return self._status(credential.snapshot, identity)
            finally:
                if not ready:
                    await self._retire_connection(name, credential)

    async def disconnect(self, context, check, name):
        _, store = self._identity_store(context)
        snapshot = await self._snapshot(store, context, name, check)
        async with connection_lifecycle(self._connections, name):
            credential = self._credentials.get(name)
            if credential is not None:
                credential.withdraw('revoked')
            self.feature._unmount_tools(remote_owner(name))
            async def forget():
                check()
                await store.revoke_local(snapshot)
                check()
                await self.feature._forget_server(name)
                check()
                if await self.feature._read_server_delta(name) is not None:
                    raise GrantRejected('OAuth enablement removal was not acknowledged')
                check()
                self._resource_rejections.pop(name, None)
            steps = [(True, forget)]
            if credential is not None:
                steps.append((True, partial(self._retire_connection, name, credential)))
            await run_cleanup_steps(steps)
            return {'local_tokens_deleted': True, 'remote_revocation': 'not_attempted'}

    def withdraw_authorizations(self):
        for owner in tuple(self._operations.values()):
            owner.operation.withdraw()
        for credential in tuple(self._credentials.values()):
            credential.withdraw('reauthorization_required')

    async def close_authorizations(self):
        self._accepting = False
        self.withdraw_authorizations()
        steps = [(True, partial(self.retire_authorization, handle)) for handle in tuple(self._operations)]
        steps.extend((True, partial(self._retire_idle_connection, name, credential))
            for name, credential in tuple(self._credentials.items()))
        await run_cleanup_steps(steps)
        self._credentials.clear()
        self._resource_rejections.clear()

    async def maintain(self):
        steps = [(True, self.host.maintain)]
        for name, credential in tuple(self._credentials.items()):
            if credential.withdrawal_reason is None:
                try:
                    credential.lease.require_background()
                except OperatorAuthorizationError:
                    credential.withdraw('reauthorization_required')
                else:
                    if datetime.now(UTC) + timedelta(seconds=self.settings.close_seconds) >= credential.lease.expires_at:
                        credential.withdraw('reauthorization_required')
            if credential.withdrawal_reason is not None and (
                    not credential.retired or name in self.feature._remote_connections):
                steps.append((True, partial(self._retire_idle_connection, name, credential)))
        await run_cleanup_steps(steps)
