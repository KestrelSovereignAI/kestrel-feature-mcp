"""Native OAuth host operations sharing the feature's original MCP owners."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
import time

from kestrel_sdk.operator import OperatorAuthorizationError
from kestrel_sdk.resources import ResourceConflict
from kestrel_sdk.security.outbound import assert_safe_url
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._lifecycle import run_cleanup_steps
from .connection import connection_lifecycle
from .connector_catalog import ConnectorPreset
from .oauth_acquisition import AuthorizationOperation
from .oauth_credentials import OAuthConnectionCredential
from .oauth_grants import OAuthGrantRejected, OAuthGrantStore, OAuthRefreshPending
from .oauth_policy import ClientIdentity, GrantRejected, TaskObservationBlocked
from .oauth_refresh import OAuthRefresher
from .remote import remote_name_for_url, remote_owner
from .tool_contract import MCPToolContractSnapshot


class OAuthSettings(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, allow_inf_nan=False)
    enabled: bool = False
    close_seconds: float = Field(default=10.0, gt=0, le=60)
    maintenance_seconds: float = Field(default=1.0, gt=0, le=60)
    max_connections: int = Field(default=64, gt=0, le=1024)
    max_status_entries: int = Field(default=256, gt=0, le=10000)
    max_connections_per_principal: int = Field(default=8, gt=0, le=128)
    connector_presets: list[ConnectorPreset] = Field(default_factory=list, max_length=32)

    @model_validator(mode='after')
    def bounded_principal(self):
        if self.max_connections_per_principal > self.max_connections:
            raise ValueError('OAuth principal connection quota exceeds the feature quota')
        if len({(preset.name, preset.url) for preset in self.connector_presets}) != len(self.connector_presets):
            raise ValueError('Connector preset names and endpoints must form unique pairs')
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

    async def task_grant_binding(self, lease, check, *, pace):
        """Open the grant selected by authenticated Task custody."""
        self._require_open()
        check()
        locator, policy = lease.authorization, lease.policy
        contract = MCPToolContractSnapshot(lease.contract)
        connection, original_url, _ = contract.connection
        store = self._store(policy.model_dump(mode='json'))

        async def require_current_grant():
            self._require_open()
            check()
            try:
                current = await store.read_slot(locator.principal_digest, locator.connection_name)
            except OAuthGrantRejected:
                raise TaskObservationBlocked('credential_unavailable',
                    'The original MCP Task OAuth authorization is invalid') from None
            check()
            if current is None or current.generation is None:
                raise TaskObservationBlocked('credential_unavailable', 'The original MCP Task OAuth authorization is unavailable')
            if (current.binding.slot_id != locator.slot_id
                    or current.authorization_identity != lease.authorization_id):
                raise TaskObservationBlocked('authorization_changed', 'The original MCP Task OAuth authorization changed')
            if current.state == 'refreshing':
                raise OAuthRefreshPending('The original MCP Task refresh outcome is still pending')
            if current.state != 'active':
                reason = 'authorization_revoked' if current.state == 'revoked' else 'credential_unavailable'
                raise TaskObservationBlocked(reason, 'The original MCP Task OAuth authorization is unavailable')
            return current

        async def read_original_tokens(snapshot):
            try:
                payload = await store.read_tokens(snapshot)
            except OAuthGrantRejected:
                raise TaskObservationBlocked('credential_unavailable',
                    'The original MCP Task OAuth tokens are invalid') from None
            check()
            return payload.tokens

        snapshot = await require_current_grant()
        binding = snapshot.binding
        if (binding.server_url != original_url or connection != locator.connection_name
                or self._name(binding.server_url, locator.principal_digest) != connection
                or remote_owner(connection) != locator.owner or binding.client_id != policy.client_id
                or binding.redirect_uri != policy.redirect_uri):
            raise TaskObservationBlocked('authorization_changed', 'The original MCP Task OAuth resource identity changed')

        original = await read_original_tokens(snapshot)
        needs_refresh = original.is_expired(time.time())
        if needs_refresh and lease.remaining_seconds() <= 3 * policy.network_seconds + self.settings.close_seconds:
            raise ResourceConflict('MCP Task refresh has insufficient time for discovery and exchange')
        if pace:
            await lease.pace()
        if needs_refresh:
            refresh = OAuthRefresher(store, policy.model_dump(mode='json'),
                close_seconds=self.settings.close_seconds, remaining_seconds=lease.remaining_seconds)
            try:
                await refresh.run(snapshot, check)
            except GrantRejected as error:
                await refresh.retire()
                try:
                    await require_current_grant()
                except (TaskObservationBlocked, OAuthRefreshPending) as current:
                    raise current from error
                raise TaskObservationBlocked('credential_unavailable', 'The original MCP Task refresh failed') from error
            except BaseException as error:
                await run_cleanup_steps([(True, refresh.retire)], failure=error)
                raise
            await refresh.retire()
            check()

        async def read_access_token():
            tokens = await read_original_tokens(await require_current_grant())
            if tokens.is_expired(time.time()):
                raise GrantRejected('The original MCP Task access token has expired')
            return tokens.access_token

        endpoint = await assert_safe_url(binding.server_url, allowed_schemes=('https',))
        check()
        if endpoint.url != binding.server_url:
            raise GrantRejected('The original MCP Task OAuth resource URL changed')
        return endpoint, contract, read_access_token, require_current_grant

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
