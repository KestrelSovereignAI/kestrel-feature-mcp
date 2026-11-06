"""Encrypted OAuth grant custody; authorization and HTTP belong to the host.

The host must independently authorize the current principal before using this
store. A binding or a database row is attribution, never execution authority.
Refresh claims are durable before HTTP: a stranded claim is an unknown remote
outcome and cannot be retried or taken over automatically.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import hashlib
import hmac
import json
import math
import secrets
import sys
from urllib.parse import urlsplit
import uuid

from kestrel_sdk.security.aead import AEADCipher
from kestrel_sdk.security.encryption import get_agent_key
from kestrel_sdk.storage.database import DatabaseBackend
from kestrel_sdk.resources import ResourceConflict

from .connection import require_owner_did


class OAuthGrantRejected(ValueError):
    """Non-secret binding or token validation failure."""


class OAuthGrantChanged(ResourceConflict):
    """The exact grant revision is no longer current; do not replay HTTP."""


def _record(value, expected):
    if type(value) is not expected:
        raise OAuthGrantRejected("OAuth grant record type is invalid")


def _text(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise OAuthGrantRejected("OAuth grant fields require nonempty control-free strings")


def _scopes(value):
    if (not isinstance(value, frozenset) or not value
            or any(not isinstance(s, str) or not s or any(
                ord(c) < 33 or ord(c) > 126 or c in {'"', '\\'} for c in s) for s in value)):
        raise OAuthGrantRejected("OAuth scopes require an explicit immutable scope set")


def _https(value):
    _text(value)
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        raise OAuthGrantRejected("Malformed OAuth grant URL") from None
    if (parsed.scheme != 'https' or not parsed.hostname
            or parsed.password is not None or parsed.fragment or parsed.username is not None):
        raise OAuthGrantRejected("OAuth grant URLs require HTTPS without credentials or fragments")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


@dataclass(frozen=True)
class OAuthGrantBinding:
    agent_did: str
    principal_id: str
    connection_id: str
    server_url: str
    resource: str
    issuer: str
    client_id: str
    redirect_uri: str
    scopes: frozenset[str]
    protected_metadata: str
    authorization_metadata: str

    def __post_init__(self):
        require_owner_did(self.agent_did)
        for name in ('principal_id', 'connection_id', 'client_id', 'redirect_uri'):
            _text(getattr(self, name))
        for name in ('server_url', 'resource', 'issuer', 'protected_metadata', 'authorization_metadata'):
            _https(getattr(self, name))
        if urlsplit(self.issuer).query:
            raise OAuthGrantRejected("OAuth issuer must not contain a query")
        _scopes(self.scopes)

    @property
    def slot_id(self):
        return _slot_id(self.agent_did, self.principal_id, self.connection_id)

    @property
    def identifier(self):
        return hashlib.sha256(self.canonical_json()).hexdigest()

    def canonical_json(self):
        fields = asdict(self)
        fields['scopes'] = sorted(self.scopes)
        return _json(fields)


@dataclass(frozen=True)
class OAuthGrantTokens:
    access_token: str = field(repr=False)
    refresh_token: str | None = field(repr=False)
    expires_at: float | None
    scopes: frozenset[str]

    def __post_init__(self):
        _text(self.access_token)
        if self.refresh_token is not None:
            _text(self.refresh_token)
        if self.expires_at is not None and (
                type(self.expires_at) not in (int, float) or self.expires_at < 0
                or self.expires_at > sys.float_info.max or not math.isfinite(self.expires_at)):
            raise OAuthGrantRejected("OAuth expiry must be an absolute finite timestamp")
        _scopes(self.scopes)

    def is_expired(self, now: float) -> bool:
        """Compare the persisted absolute receipt expiry, without rebasing it."""
        return self.expires_at is not None and self.expires_at <= now


@dataclass(frozen=True)
class OAuthGrantSnapshot:
    binding: OAuthGrantBinding
    revision: str
    state: str
    tokens: OAuthGrantTokens | None = field(default=None, repr=False)
    reason: str | None = None


@dataclass(frozen=True)
class OAuthAuthorizationClaim:
    """Original acquisition capability; never reconstructed from stored metadata."""
    binding: OAuthGrantBinding
    revision: str
    state: str
    secret: str = field(repr=False)


@dataclass(frozen=True)
class OAuthRefreshClaim:
    """Caller-held completion capability; never reconstructed by a reader."""
    binding: OAuthGrantBinding
    revision: str
    secret: str = field(repr=False)
    tokens: OAuthGrantTokens = field(repr=False)

    @property
    def state(self):
        return 'refreshing'


def _slot_id(agent_did, principal_id, connection_id):
    require_owner_did(agent_did)
    _text(principal_id)
    _text(connection_id)
    return hashlib.sha256(_json(['kestrel-mcp-oauth-slot-v1', agent_did, principal_id, connection_id])).hexdigest()


def _native_database(database):
    if not isinstance(database, DatabaseBackend):
        raise OAuthGrantRejected('OAuth custody requires a native database backend')


def _require_top_level(database):
    if database.owns_open_transaction is not False:
        raise OAuthGrantRejected('OAuth custody requires a known top-level transaction boundary')


async def initialize_grant_schema(database):
    """Initialize native metadata custody without a key or credential budget."""
    _native_database(database)
    _require_top_level(database)
    options = {}
    if database.backend_type == 'sqlite':
        supported = getattr(database, 'transaction_options', None)
        if not isinstance(supported, frozenset) or 'immediate' not in supported:
            raise OAuthGrantRejected('OAuth schema creation requires native SQLite immediate transactions')
        options['immediate'] = True
    elif database.backend_type != 'postgres':
        raise OAuthGrantRejected('OAuth custody requires SQLite or PostgreSQL')
    async with database.transaction(**options):
        if database.backend_type == 'postgres':
            # Serialize first DDL across native owners, including a table
            # that does not exist yet. This is transaction-scoped custody.
            key = int.from_bytes(hashlib.sha256(b'mcp_oauth_credential_slots').digest()[:8], 'big') & ((1 << 63) - 1)
            await database.fetch_val('SELECT pg_advisory_xact_lock(?)', (key,))
        await database.execute('''CREATE TABLE IF NOT EXISTS mcp_oauth_credential_slots (
            agent_did TEXT NOT NULL, principal_id TEXT NOT NULL, slot_id TEXT NOT NULL,
            binding_id TEXT NOT NULL, binding TEXT NOT NULL,
            revision TEXT NOT NULL, state TEXT NOT NULL,
            ciphertext TEXT, claim_hash TEXT, reason TEXT,
            PRIMARY KEY (agent_did, slot_id),
            CHECK (state IN ('authorizing', 'exchanging', 'active', 'refreshing', 'revoked')),
            CHECK ((state IN ('active', 'refreshing') AND ciphertext IS NOT NULL)
                OR (state NOT IN ('active', 'refreshing') AND ciphertext IS NULL)),
            CHECK ((state IN ('authorizing', 'exchanging', 'refreshing') AND claim_hash IS NOT NULL)
                OR (state IN ('active', 'revoked') AND claim_hash IS NULL)),
            CHECK ((state = 'revoked' AND reason IS NOT NULL AND reason IN ('local', 'abandoned', 'exchange_rejected', 'refresh_rejected'))
                OR (state != 'revoked' AND reason IS NULL))
        )''')
        await database.execute('CREATE INDEX IF NOT EXISTS idx_mcp_oauth_principal '
            'ON mcp_oauth_credential_slots (agent_did, principal_id, slot_id)')


class OAuthGrantStore:
    """One durable CAS per agent/principal/connection; no background authority.

    Metadata reads never load the encryption key or decrypt tokens. Callers
    authorize every use through Core before asking for credential payloads.
    A stranded exchanging/refreshing claim is an unknown remote outcome.
    """

    def __init__(self, database: DatabaseBackend, agent_did: str, *, max_token_bytes: int):
        self.agent_did = require_owner_did(agent_did)
        if type(max_token_bytes) is not int or max_token_bytes < 1:
            raise OAuthGrantRejected('OAuth token budget must be a positive integer')
        _native_database(database)
        self._db, self._max_token_bytes = database, max_token_bytes

    async def initialize(self):
        await initialize_grant_schema(self._db)

    def _require_top_level(self):
        _require_top_level(self._db)

    def _binding(self, binding):
        _record(binding, OAuthGrantBinding)
        if binding.agent_did != self.agent_did:
            raise OAuthGrantRejected('OAuth grant belongs to another agent')
        return binding.slot_id

    @staticmethod
    def _binding_json(binding):
        return binding.canonical_json().decode()

    def _aad(self, binding, revision, state, claim_hash):
        return _json(['kestrel-mcp-oauth-credential-v2', self._binding(binding),
                      binding.identifier, revision, state, claim_hash])

    def _cipher(self):
        # Deliberately lazy: restore/status and revocation need no key access.
        return AEADCipher(get_agent_key(self.agent_did, 'service-keys'))

    def _encode(self, binding, revision, state, tokens, claim_hash):
        _record(tokens, OAuthGrantTokens)
        if not tokens.scopes <= binding.scopes:
            raise OAuthGrantRejected('OAuth token exceeded approved scopes')
        payload = asdict(tokens)
        payload['scopes'] = sorted(tokens.scopes)
        raw = _json(payload)
        if len(raw) > self._max_token_bytes:
            raise OAuthGrantRejected('OAuth token exceeded its storage budget')
        return self._cipher().encrypt(raw, aad=self._aad(binding, revision, state, claim_hash)).decode('ascii')

    async def _read_slot(self, slot_id, *, secret=None, decrypt=False):
        self._require_top_level()
        payload_column = 'ciphertext' if decrypt else 'NULL'
        row = await self._db.fetch_one('SELECT principal_id, binding_id, binding, revision, state, claim_hash, reason, '
            'LENGTH(ciphertext), ' + payload_column + ' FROM mcp_oauth_credential_slots '
            'WHERE agent_did = ? AND slot_id = ?', (self.agent_did, slot_id))
        if row is None:
            return None
        principal_id, binding_id, encoded, revision, state, claim_hash, reason, size, ciphertext = row
        if not isinstance(encoded, str) or len(encoded) > 65_536:
            raise OAuthGrantRejected('OAuth binding metadata is invalid')
        try:
            value = json.loads(encoded)
        except json.JSONDecodeError:
            raise OAuthGrantRejected('OAuth binding metadata is invalid') from None
        if (not isinstance(value, dict) or set(value) != set(OAuthGrantBinding.__dataclass_fields__)
                or not isinstance(value['scopes'], list)
                or any(not isinstance(scope, str) for scope in value['scopes'])
                or value['scopes'] != sorted(set(value['scopes']))):
            raise OAuthGrantRejected('OAuth binding metadata is invalid')
        value['scopes'] = frozenset(value['scopes'])
        binding = OAuthGrantBinding(**value)
        if (principal_id != binding.principal_id or self._binding(binding) != slot_id or binding.identifier != binding_id
                or self._binding_json(binding) != encoded):
            raise OAuthGrantRejected('OAuth binding metadata integrity failed')
        _text(revision)
        if state not in {'authorizing', 'exchanging', 'active', 'refreshing', 'revoked'}:
            raise OAuthGrantRejected('OAuth credential state is invalid')
        if ((state in {'authorizing', 'exchanging', 'refreshing'}) != (isinstance(claim_hash, str) and len(claim_hash) == 64)
                or (state not in {'authorizing', 'exchanging', 'refreshing'} and claim_hash is not None)
                or ((state in {'active', 'refreshing'}) != (type(size) is int and size > 0))
                or (state not in {'active', 'refreshing'} and size is not None)
                or (state == 'revoked' and reason not in {'local', 'abandoned', 'exchange_rejected', 'refresh_rejected'})
                or (state != 'revoked' and reason is not None)):
            raise OAuthGrantRejected('OAuth credential custody record is invalid')
        if secret is not None and (claim_hash is None or not hmac.compare_digest(
                claim_hash, hashlib.sha256(secret.encode()).hexdigest())):
            raise OAuthGrantChanged('OAuth original claim is no longer current')
        tokens = None
        if decrypt and state in {'active', 'refreshing'}:
            if state == 'refreshing' and secret is None:
                raise OAuthGrantRejected('OAuth refreshing credentials require their original claim')
            if size > 6 + 4 * ((self._max_token_bytes + 29 + 2) // 3):
                raise OAuthGrantRejected('OAuth stored token exceeded its storage budget')
            raw = self._cipher().decrypt(ciphertext.encode('ascii'), aad=self._aad(binding, revision, state, claim_hash))
            payload = json.loads(raw)
            tokens = OAuthGrantTokens(payload['access_token'], payload['refresh_token'],
                                      payload['expires_at'], frozenset(payload['scopes']))
            if not tokens.scopes <= binding.scopes:
                raise OAuthGrantRejected('OAuth stored token exceeded approved scopes')
        return OAuthGrantSnapshot(binding, revision, state, tokens, reason)

    async def read_slot(self, principal_id, connection_id):
        """Read canonical non-secret metadata, never credential payloads."""
        return await self._read_slot(_slot_id(self.agent_did, principal_id, connection_id))

    async def list_principal(self, principal_id):
        """Enumerate this principal's metadata, including grants never connected."""
        _text(principal_id)
        self._require_top_level()
        rows = await self._db.fetch_all('SELECT slot_id FROM mcp_oauth_credential_slots '
            'WHERE agent_did = ? AND principal_id = ? ORDER BY slot_id', (self.agent_did, principal_id))
        snapshots = []
        for row in rows:
            snapshot = await self._read_slot(row[0])
            if snapshot is not None:
                if snapshot.binding.principal_id != principal_id:
                    raise OAuthGrantRejected('OAuth principal metadata integrity failed')
                snapshots.append(snapshot)
        return snapshots

    async def read(self, binding):
        actual = await self._read_slot(self._binding(binding))
        return actual if actual is None or actual.binding == binding else None

    async def read_tokens(self, snapshot):
        _record(snapshot, OAuthGrantSnapshot)
        if snapshot.state != 'active':
            raise OAuthGrantRejected('OAuth credentials require an active snapshot')
        current = await self.read(snapshot.binding)
        if current is None or current.revision != snapshot.revision or current.state != 'active':
            raise OAuthGrantChanged('OAuth active credential revision changed')
        actual = await self._read_slot(self._binding(snapshot.binding), decrypt=True)
        if actual is None or actual.binding != snapshot.binding or actual.revision != snapshot.revision or actual.state != 'active':
            raise OAuthGrantChanged('OAuth active credential revision changed')
        return actual

    def _expected(self, expected, binding):
        if type(expected) not in {OAuthGrantSnapshot, OAuthAuthorizationClaim, OAuthRefreshClaim}:
            raise OAuthGrantRejected('OAuth grant record type is invalid')
        if self._binding(expected.binding) != self._binding(binding):
            raise OAuthGrantRejected('OAuth replacement changed its credential slot')

    @staticmethod
    def _secret(claim):
        if type(claim.secret) is not str or len(claim.secret) != 43:
            raise OAuthGrantRejected('OAuth operation requires its original claim secret')
        return claim.secret

    async def _replace(self, binding, tokens, state, expected, *, claim_secret=None, expected_secret=None, reason=None):
        self._require_top_level()
        slot_id, revision = self._binding(binding), uuid.uuid4().hex
        if expected is not None:
            self._expected(expected, binding)
        claim_hash = hashlib.sha256(claim_secret.encode()).hexdigest() if claim_secret is not None else None
        ciphertext = self._encode(binding, revision, state, tokens, claim_hash) if state in {'active', 'refreshing'} else None
        fields = (binding.principal_id, binding.identifier, self._binding_json(binding), revision, state, ciphertext, claim_hash, reason)
        async with self._db.transaction():
            if expected is None:
                affected = await self._db.execute('''INSERT INTO mcp_oauth_credential_slots
                    (principal_id, binding_id, binding, revision, state, ciphertext, claim_hash, reason, agent_did, slot_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (agent_did, slot_id) DO NOTHING''',
                    fields + (self.agent_did, slot_id))
            else:
                predicate = '' if expected_secret is None else ' AND claim_hash = ?'
                parameters = fields + (self.agent_did, slot_id, expected.binding.identifier, expected.revision, expected.state)
                if expected_secret is not None:
                    parameters += (hashlib.sha256(expected_secret.encode()).hexdigest(),)
                affected = await self._db.execute('''UPDATE mcp_oauth_credential_slots
                    SET principal_id = ?, binding_id = ?, binding = ?, revision = ?, state = ?, ciphertext = ?, claim_hash = ?, reason = ?
                    WHERE agent_did = ? AND slot_id = ? AND binding_id = ? AND revision = ? AND state = ?''' + predicate, parameters)
        if affected != 1:
            raise OAuthGrantChanged('OAuth grant changed before durable custody committed')
        actual = await self._read_slot(slot_id)
        if actual is None or actual.binding != binding or actual.revision != revision or actual.state != state:
            raise OAuthGrantChanged('OAuth grant changed before durable custody was acknowledged')
        actual = await self._read_slot(slot_id, secret=claim_secret, decrypt=tokens is not None)
        if actual is None or actual.binding != binding or actual.revision != revision or actual.state != state:
            raise OAuthGrantChanged('OAuth grant changed before durable custody was acknowledged')
        return actual

    async def begin_authorization(self, binding, *, expected=None, acknowledge_unknown=False):
        self._require_top_level()
        self._binding(binding)
        if type(acknowledge_unknown) is not bool:
            raise OAuthGrantRejected('OAuth unknown-outcome acknowledgment must be explicit')
        if expected is not None:
            _record(expected, OAuthGrantSnapshot)
            self._expected(expected, binding)
            if expected.state in {'active', 'refreshing'}:
                raise OAuthGrantRejected('Disconnect the original OAuth grant before authorization')
            if expected.state == 'exchanging' and not acknowledge_unknown:
                raise OAuthGrantRejected('OAuth exchange outcome is unknown; explicit acknowledgment is required')
        secret = secrets.token_urlsafe(32)
        actual = await self._replace(binding, None, 'authorizing', expected, claim_secret=secret)
        return OAuthAuthorizationClaim(actual.binding, actual.revision, actual.state, secret)

    async def _authorization(self, claim, state):
        _record(claim, OAuthAuthorizationClaim)
        self._secret(claim)
        if claim.state != state:
            raise OAuthGrantRejected('OAuth acquisition requires its original phase claim')
        actual = await self._read_slot(self._binding(claim.binding), secret=claim.secret)
        if actual is None or actual.binding != claim.binding or actual.revision != claim.revision or actual.state != state:
            raise OAuthGrantChanged('OAuth acquisition claim is no longer current')
        return actual

    async def begin_exchange(self, claim):
        current = await self._authorization(claim, 'authorizing')
        actual = await self._replace(claim.binding, None, 'exchanging', current,
                                     claim_secret=claim.secret, expected_secret=claim.secret)
        return OAuthAuthorizationClaim(actual.binding, actual.revision, actual.state, claim.secret)

    async def complete_authorization(self, claim, tokens):
        _record(tokens, OAuthGrantTokens)
        current = await self._authorization(claim, 'exchanging')
        return await self._replace(claim.binding, tokens, 'active', current, expected_secret=claim.secret)

    async def abandon_authorization(self, claim):
        current = await self._authorization(claim, 'authorizing')
        return await self._replace(claim.binding, None, 'revoked', current, expected_secret=claim.secret, reason='abandoned')

    async def reject_exchange(self, claim):
        current = await self._authorization(claim, 'exchanging')
        return await self._replace(claim.binding, None, 'revoked', current, expected_secret=claim.secret, reason='exchange_rejected')

    async def begin_refresh(self, snapshot):
        _record(snapshot, OAuthGrantSnapshot)
        if snapshot.state != 'active':
            raise OAuthGrantRejected('OAuth grant cannot begin another refresh')
        original = await self.read_tokens(snapshot)
        if original.tokens.refresh_token is None:
            raise OAuthGrantRejected('OAuth grant has no refresh token')
        secret = secrets.token_urlsafe(32)
        actual = await self._replace(original.binding, original.tokens, 'refreshing', original, claim_secret=secret)
        return OAuthRefreshClaim(actual.binding, actual.revision, secret, actual.tokens)

    async def _refresh(self, claim):
        _record(claim, OAuthRefreshClaim)
        self._secret(claim)
        actual = await self._read_slot(self._binding(claim.binding), secret=claim.secret, decrypt=True)
        if actual is None or actual.binding != claim.binding or actual.state != 'refreshing' or actual.revision != claim.revision:
            raise OAuthGrantChanged('OAuth refresh claim is no longer current')
        return actual

    async def finish_refresh(self, claim, tokens):
        _record(tokens, OAuthGrantTokens)
        original = await self._refresh(claim)
        if not tokens.scopes <= original.tokens.scopes:
            raise OAuthGrantRejected('OAuth refresh expanded its original token scopes')
        if tokens.refresh_token is None:
            tokens = replace(tokens, refresh_token=original.tokens.refresh_token)
        return await self._replace(claim.binding, tokens, 'active', original, expected_secret=claim.secret)

    async def reject_refresh(self, claim):
        original = await self._refresh(claim)
        return await self._replace(claim.binding, None, 'revoked', original,
                                   expected_secret=claim.secret, reason='refresh_rejected')

    async def revoke_local(self, snapshot):
        self._expected(snapshot, snapshot.binding if type(snapshot) in {OAuthGrantSnapshot, OAuthAuthorizationClaim, OAuthRefreshClaim} else None)
        if snapshot.state == 'revoked':
            actual = await self.read(snapshot.binding)
            if actual != snapshot:
                raise OAuthGrantChanged('OAuth revocation tombstone is no longer current')
            return actual
        return await self._replace(snapshot.binding, None, 'revoked', snapshot, reason='local')
