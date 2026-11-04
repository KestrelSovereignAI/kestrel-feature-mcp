"""Encrypted OAuth grant custody; authorization and HTTP belong to the host.

The host must independently authorize the current principal before using this
store. A binding or a database row is attribution, never execution authority.
Refresh claims are durable before HTTP: a stranded claim is an unknown remote
outcome and cannot be retried or taken over automatically.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
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
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
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
                type(self.expires_at) not in (int, float) or not math.isfinite(self.expires_at)
                or self.expires_at < 0):
            raise OAuthGrantRejected("OAuth expiry must be an absolute finite timestamp")
        _scopes(self.scopes)


@dataclass(frozen=True)
class OAuthGrantSnapshot:
    binding: OAuthGrantBinding
    revision: str
    state: str
    tokens: OAuthGrantTokens | None = field(repr=False)


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
        self._db = database
        self._cipher = AEADCipher(get_agent_key(agent_did, 'service-keys'))
        self._max_token_bytes = max_token_bytes

    async def initialize(self):
        async with self._db.transaction():
            await self._db.execute('''CREATE TABLE IF NOT EXISTS mcp_oauth_grants (
                agent_did TEXT NOT NULL, grant_id TEXT NOT NULL,
                revision TEXT NOT NULL, state TEXT NOT NULL,
                ciphertext TEXT,
                PRIMARY KEY (agent_did, grant_id),
                CHECK (state IN ('active', 'refreshing', 'revoked')),
                CHECK ((state = 'revoked' AND ciphertext IS NULL)
                    OR (state != 'revoked' AND ciphertext IS NOT NULL))
            )''')

    def _binding(self, binding):
        if binding.agent_did != self.agent_did:
            raise OAuthGrantRejected("OAuth grant belongs to another agent")
        return binding.identifier

    def _aad(self, binding, revision, state):
        return _json(['kestrel-mcp-oauth-grant-v1', self._binding(binding), revision, state])

    def _encode(self, binding, revision, state, tokens):
        if not tokens.scopes <= binding.scopes:
            raise OAuthGrantRejected("OAuth token exceeded approved scopes")
        payload = asdict(tokens)
        payload['scopes'] = sorted(tokens.scopes)
        raw = _json(payload)
        if len(raw) > self._max_token_bytes:
            raise OAuthGrantRejected("OAuth token exceeded its storage budget")
        return self._cipher.encrypt(raw, aad=self._aad(binding, revision, state)).decode('ascii')

    async def read(self, binding: OAuthGrantBinding) -> OAuthGrantSnapshot | None:
        grant_id = self._binding(binding)
        row = await self._db.fetch_one(
            'SELECT revision, state, ciphertext FROM mcp_oauth_grants WHERE agent_did = ? AND grant_id = ?',
            (self.agent_did, grant_id))
        if row is None:
            return None
        revision, state, ciphertext = row
        if state == 'revoked' and ciphertext is None:
            return OAuthGrantSnapshot(binding, revision, state, None)
        if state not in {'active', 'refreshing'} or not isinstance(ciphertext, str):
            raise OAuthGrantRejected("OAuth grant custody record is invalid")
        # The encoded AEAD envelope has fixed overhead and base64 expansion.
        if len(ciphertext) > 6 + 4 * ((self._max_token_bytes + 29 + 2) // 3):
            raise OAuthGrantRejected("OAuth stored token exceeded its storage budget")
        raw = self._cipher.decrypt(ciphertext.encode('ascii'), aad=self._aad(binding, revision, state))
        payload = json.loads(raw)
        tokens = OAuthGrantTokens(payload['access_token'], payload['refresh_token'],
                                  payload['expires_at'], frozenset(payload['scopes']))
        if not tokens.scopes <= binding.scopes:
            raise OAuthGrantRejected("OAuth stored token exceeded approved scopes")
        return OAuthGrantSnapshot(binding, revision, state, tokens)

    async def _replace(self, binding, tokens, state, expected):
        grant_id, revision = self._binding(binding), uuid.uuid4().hex
        ciphertext = None if state == 'revoked' else self._encode(binding, revision, state, tokens)
        async with self._db.transaction():
            if expected is None:
                affected = await self._db.execute('''INSERT INTO mcp_oauth_grants
                    (agent_did, grant_id, revision, state, ciphertext) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (agent_did, grant_id) DO NOTHING''',
                    (self.agent_did, grant_id, revision, state, ciphertext))
            else:
                affected = await self._db.execute('''UPDATE mcp_oauth_grants
                    SET revision = ?, state = ?, ciphertext = ?
                    WHERE agent_did = ? AND grant_id = ? AND revision = ? AND state = ?''',
                    (revision, state, ciphertext, self.agent_did, grant_id, expected.revision, expected.state))
        if affected != 1:
            raise OAuthGrantChanged("OAuth grant changed before durable custody committed")
        actual = await self.read(binding)
        if actual is None or actual.revision != revision or actual.state != state:
            raise OAuthGrantChanged("OAuth grant changed before durable custody was acknowledged")
        return actual

    async def install(self, binding, tokens, *, expected: OAuthGrantSnapshot | None = None):
        """Store a separately authorized initial/replacement grant, never an upsert."""
        if expected is not None and expected.binding != binding:
            raise OAuthGrantRejected("OAuth replacement changed its frozen binding")
        return await self._replace(binding, tokens, 'active', expected)

    async def begin_refresh(self, snapshot: OAuthGrantSnapshot):
        if snapshot.state != 'active' or snapshot.tokens is None or snapshot.tokens.refresh_token is None:
            raise OAuthGrantRejected("OAuth grant cannot begin another refresh")
        return await self._replace(snapshot.binding, snapshot.tokens, 'refreshing', snapshot)

    async def finish_refresh(self, claim: OAuthGrantSnapshot, tokens: OAuthGrantTokens):
        if claim.state != 'refreshing' or claim.tokens is None:
            raise OAuthGrantRejected("OAuth refresh requires its original durable claim")
        if not tokens.scopes <= claim.tokens.scopes:
            raise OAuthGrantRejected("OAuth refresh expanded its original token scopes")
        return await self._replace(claim.binding, tokens, 'active', claim)

    async def revoke_local(self, snapshot: OAuthGrantSnapshot):
        return await self._replace(snapshot.binding, None, 'revoked', snapshot)
