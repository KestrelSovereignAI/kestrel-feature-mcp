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

from .connection import require_owner_did


class OAuthGrantRejected(ValueError):
    """Non-secret binding or token validation failure."""


class OAuthGrantChanged(RuntimeError):
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

    def __post_init__(self):
        require_owner_did(self.agent_did)
        for name in ('principal_id', 'connection_id', 'client_id', 'redirect_uri'):
            _text(getattr(self, name))
        for name in ('server_url', 'resource', 'issuer'):
            _https(getattr(self, name))
        if urlsplit(self.issuer).query:
            raise OAuthGrantRejected("OAuth issuer must not contain a query")
        _scopes(self.scopes)

    @property
    def identifier(self):
        fields = asdict(self)
        fields['scopes'] = sorted(self.scopes)
        return hashlib.sha256(_json(fields)).hexdigest()


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


@dataclass(frozen=True)
class OAuthGrantSnapshot:
    binding: OAuthGrantBinding
    revision: str
    state: str
    tokens: OAuthGrantTokens | None = field(repr=False)


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


class OAuthGrantStore:
    """Agent-scoped CAS on the host's canonical database and encryption key.

    A transaction ACK plus exact readback is required before a credential is
    exposed. There is no refresh lease expiry: another process cannot know
    whether a crashed claimant already rotated the remote refresh token.
    Local revocation leaves a tombstone so stale refresh completion cannot
    resurrect the grant. This does not claim authorization-server revocation.
    """

    def __init__(self, database: DatabaseBackend, agent_did: str, *, max_token_bytes: int):
        self.agent_did = require_owner_did(agent_did)
        if type(max_token_bytes) is not int or max_token_bytes < 1:
            raise OAuthGrantRejected("OAuth token budget must be a positive integer")
        if not isinstance(database, DatabaseBackend):
            raise OAuthGrantRejected("OAuth custody requires a native database backend")
        self._db = database
        self._cipher = AEADCipher(get_agent_key(agent_did, 'service-keys'))
        self._max_token_bytes = max_token_bytes

    async def initialize(self):
        self._require_top_level()
        async with self._db.transaction():
            await self._db.execute('''CREATE TABLE IF NOT EXISTS mcp_oauth_grants (
                agent_did TEXT NOT NULL, grant_id TEXT NOT NULL,
                revision TEXT NOT NULL, state TEXT NOT NULL,
                ciphertext TEXT, claim_hash TEXT,
                PRIMARY KEY (agent_did, grant_id),
                CHECK (state IN ('active', 'refreshing', 'revoked')),
                CHECK ((state = 'revoked' AND ciphertext IS NULL)
                    OR (state != 'revoked' AND ciphertext IS NOT NULL)),
                CHECK ((state = 'refreshing' AND claim_hash IS NOT NULL)
                    OR (state != 'refreshing' AND claim_hash IS NULL))
            )''')

    def _require_top_level(self):
        if self._db.owns_open_transaction is not False:
            raise OAuthGrantRejected("OAuth custody requires a known top-level transaction boundary")

    def _binding(self, binding):
        _record(binding, OAuthGrantBinding)
        if binding.agent_did != self.agent_did:
            raise OAuthGrantRejected("OAuth grant belongs to another agent")
        return binding.identifier

    def _aad(self, binding, revision, state, claim_hash):
        return _json(['kestrel-mcp-oauth-grant-v1', self._binding(binding), revision, state, claim_hash])

    def _encode(self, binding, revision, state, tokens, claim_hash):
        _record(tokens, OAuthGrantTokens)
        if not tokens.scopes <= binding.scopes:
            raise OAuthGrantRejected("OAuth token exceeded approved scopes")
        payload = asdict(tokens)
        payload['scopes'] = sorted(tokens.scopes)
        raw = _json(payload)
        if len(raw) > self._max_token_bytes:
            raise OAuthGrantRejected("OAuth token exceeded its storage budget")
        return self._cipher.encrypt(raw, aad=self._aad(binding, revision, state, claim_hash)).decode('ascii')

    async def read(self, binding: OAuthGrantBinding) -> OAuthGrantSnapshot | None:
        return await self._read(binding)

    async def _read(self, binding, *, secret=None):
        grant_id = self._binding(binding)
        self._require_top_level()
        row = await self._db.fetch_one(
            'SELECT revision, state, ciphertext, claim_hash FROM mcp_oauth_grants WHERE agent_did = ? AND grant_id = ?',
            (self.agent_did, grant_id))
        if row is None:
            return None
        revision, state, ciphertext, claim_hash = row
        if state == 'revoked' and ciphertext is None:
            return OAuthGrantSnapshot(binding, revision, state, None)
        if state not in {'active', 'refreshing'} or not isinstance(ciphertext, str):
            raise OAuthGrantRejected("OAuth grant custody record is invalid")
        if ((state == 'refreshing' and not isinstance(claim_hash, str))
                or (state == 'active' and claim_hash is not None)):
            raise OAuthGrantRejected("OAuth refresh custody record is invalid")
        if secret is not None and (state != 'refreshing' or not hmac.compare_digest(
                claim_hash, hashlib.sha256(secret.encode()).hexdigest())):
            raise OAuthGrantChanged("OAuth refresh claim is no longer current")
        # The encoded AEAD envelope has fixed overhead and base64 expansion.
        if len(ciphertext) > 6 + 4 * ((self._max_token_bytes + 29 + 2) // 3):
            raise OAuthGrantRejected("OAuth stored token exceeded its storage budget")
        raw = self._cipher.decrypt(ciphertext.encode('ascii'), aad=self._aad(binding, revision, state, claim_hash))
        payload = json.loads(raw)
        tokens = OAuthGrantTokens(payload['access_token'], payload['refresh_token'],
                                  payload['expires_at'], frozenset(payload['scopes']))
        if not tokens.scopes <= binding.scopes:
            raise OAuthGrantRejected("OAuth stored token exceeded approved scopes")
        return OAuthGrantSnapshot(binding, revision, state, tokens if state == 'active' or secret is not None else None)

    async def _replace(self, binding, tokens, state, expected, *, claim_secret=None, expected_secret=None):
        self._require_top_level()
        grant_id, revision = self._binding(binding), uuid.uuid4().hex
        claim_hash = hashlib.sha256(claim_secret.encode()).hexdigest() if claim_secret is not None else None
        ciphertext = None if state == 'revoked' else self._encode(binding, revision, state, tokens, claim_hash)
        async with self._db.transaction():
            if expected is None:
                affected = await self._db.execute('''INSERT INTO mcp_oauth_grants
                    (agent_did, grant_id, revision, state, ciphertext, claim_hash) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (agent_did, grant_id) DO NOTHING''',
                    (self.agent_did, grant_id, revision, state, ciphertext, claim_hash))
            else:
                predicate = '' if expected_secret is None else ' AND claim_hash = ?'
                parameters = (revision, state, ciphertext, claim_hash, self.agent_did, grant_id, expected.revision, expected.state)
                if expected_secret is not None:
                    parameters += (hashlib.sha256(expected_secret.encode()).hexdigest(),)
                affected = await self._db.execute('''UPDATE mcp_oauth_grants
                    SET revision = ?, state = ?, ciphertext = ?, claim_hash = ?
                    WHERE agent_did = ? AND grant_id = ? AND revision = ? AND state = ?''' + predicate,
                    parameters)
        if affected != 1:
            raise OAuthGrantChanged("OAuth grant changed before durable custody committed")
        actual = await self._read(binding, secret=claim_secret)
        if actual is None or actual.revision != revision or actual.state != state:
            raise OAuthGrantChanged("OAuth grant changed before durable custody was acknowledged")
        return actual

    async def install(self, binding, tokens, *, expected: OAuthGrantSnapshot | None = None):
        """Store a separately authorized initial/replacement grant, never an upsert."""
        if expected is not None:
            _record(expected, OAuthGrantSnapshot)
        if expected is not None and expected.binding != binding:
            raise OAuthGrantRejected("OAuth replacement changed its frozen binding")
        return await self._replace(binding, tokens, 'active', expected)

    async def begin_refresh(self, snapshot: OAuthGrantSnapshot):
        if type(snapshot) is not OAuthGrantSnapshot or snapshot.state != 'active':
            raise OAuthGrantRejected("OAuth grant cannot begin another refresh")
        original = await self.read(snapshot.binding)
        if original is None or original.state != 'active' or original.revision != snapshot.revision:
            raise OAuthGrantChanged("OAuth grant changed before refresh admission")
        if original.tokens.refresh_token is None:
            raise OAuthGrantRejected("OAuth grant has no refresh token")
        secret = secrets.token_urlsafe(32)
        actual = await self._replace(original.binding, original.tokens, 'refreshing', original, claim_secret=secret)
        return OAuthRefreshClaim(actual.binding, actual.revision, secret, actual.tokens)

    async def finish_refresh(self, claim: OAuthRefreshClaim, tokens: OAuthGrantTokens):
        if type(claim) is not OAuthRefreshClaim:
            raise OAuthGrantRejected("OAuth refresh requires its original durable claim")
        if type(claim.secret) is not str or len(claim.secret) != 43:
            raise OAuthGrantRejected("OAuth refresh requires its original claim secret")
        _record(tokens, OAuthGrantTokens)
        original = await self._read(claim.binding, secret=claim.secret)
        if original is None or original.state != 'refreshing' or original.revision != claim.revision:
            raise OAuthGrantChanged("OAuth refresh claim is no longer current")
        if not tokens.scopes <= original.tokens.scopes:
            raise OAuthGrantRejected("OAuth refresh expanded its original token scopes")
        if tokens.refresh_token is None:
            tokens = replace(tokens, refresh_token=original.tokens.refresh_token)
        return await self._replace(claim.binding, tokens, 'active', original, expected_secret=claim.secret)

    async def revoke_local(self, snapshot: OAuthGrantSnapshot):
        if snapshot.state == 'revoked':
            actual = await self.read(snapshot.binding)
            if actual != snapshot:
                raise OAuthGrantChanged("OAuth revocation tombstone is no longer current")
            return actual
        return await self._replace(snapshot.binding, None, 'revoked', snapshot)
