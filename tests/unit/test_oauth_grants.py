"""Real encrypted SQL grant custody, independent owners, and stale completion."""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import replace
import hashlib
import os
from urllib.parse import urlsplit
import uuid

import pytest

from kestrel_sdk.security.exceptions import DecryptionError
from kestrel_sdk.storage.database import TransactionError
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_feature_mcp.oauth_grants import (
    OAuthGrantBinding, OAuthGrantChanged, OAuthGrantRejected,
    OAuthGrantStore, OAuthGrantTokens, OAuthRefreshClaim, OAuthAuthorizationClaim,
)


async def install_grant(store, binding, tokens, *, expected=None):
    claim = await store.begin_authorization(binding, expected=expected)
    exchange = await store.begin_exchange(claim)
    return await store.complete_authorization(exchange, tokens)


async def read_payload(store, binding):
    snapshot = await store.read(binding)
    return (await store.read_tokens(snapshot)) if snapshot is not None and snapshot.state == 'active' else snapshot


@pytest.fixture
def binding():
    return OAuthGrantBinding('did:test:oauth-owner', 'operator-one', 'connection-one',
        'https://remote.example/mcp', 'https://remote.example/mcp',
        'https://issuer.example', 'vendor-registered-client',
        'https://host.example/oauth/callback', frozenset({'read', 'write'}),
        'https://remote.example/.well-known/oauth-protected-resource/mcp',
        'https://issuer.example/.well-known/oauth-authorization-server')


@pytest.fixture
def tokens():
    return OAuthGrantTokens('synthetic-access-secret', 'synthetic-refresh-secret',
                           1_700_000_000, frozenset({'read'}))


@pytest.fixture(params=['sqlite', 'postgres'])
async def owners(tmp_path, binding, owned_oauth_key, request):
    async with AsyncExitStack() as cleanup:
        databases = []
        if request.param == 'sqlite':
            for _ in range(2):
                db = SQLiteBackend(str(tmp_path / 'grants.db'))
                await db.connect()
                cleanup.push_async_callback(db.close)
                databases.append(db)
        else:
            if os.environ.get('GITHUB_ACTIONS') != 'true':
                pytest.skip('Native PostgreSQL grant tests run only in the dedicated CI service')
            dsn = os.environ.get('TEST_POSTGRES_URL')
            if not dsn:
                if os.environ.get('KESTREL_REQUIRE_POSTGRES_TESTS') == '1':
                    pytest.fail('The native PostgreSQL grant lane requires TEST_POSTGRES_URL')
                pytest.skip('The dedicated native PostgreSQL grant lane provides TEST_POSTGRES_URL')
            parsed = urlsplit(dsn)
            if parsed.hostname not in {'localhost', '127.0.0.1'} or parsed.path != '/kestrel_mcp_oauth_test':
                pytest.fail('Native grant tests require their dedicated local CI database')
            import asyncpg
            from kestrel_sovereign.storage.db.postgres import PostgresBackend

            admin = await asyncpg.connect(dsn)
            cleanup.push_async_callback(admin.close)
            schema = 'mcp_grants_' + uuid.uuid4().hex
            await admin.execute('CREATE SCHEMA "' + schema + '"')
            cleanup.push_async_callback(admin.execute, 'DROP SCHEMA "' + schema + '" CASCADE')
            for _ in range(2):
                pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2,
                    server_settings={'search_path': schema})
                cleanup.push_async_callback(pool.close)
                db = PostgresBackend.from_pool(pool)
                cleanup.push_async_callback(db.close)
                databases.append(db)
        stores = [OAuthGrantStore(db, binding.agent_did, max_token_bytes=4096) for db in databases]
        for store in stores:
            await store.initialize()
        yield databases, stores


@pytest.mark.asyncio
async def test_outer_transaction_never_publishes_an_uncommitted_refresh(owners, binding, tokens):
    databases, (first, second) = owners
    installed = await install_grant(first, binding, tokens)
    async with databases[0].transaction():
        with pytest.raises(OAuthGrantRejected, match='top-level'):
            await first.begin_refresh(installed)
        with pytest.raises(OAuthGrantRejected, match='top-level'):
            await read_payload(first, binding)
    assert await read_payload(second, binding) == installed


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['install', 'begin', 'finish', 'revoke'])
async def test_every_grant_write_refuses_before_changing_an_outer_transaction(
        owners, binding, tokens, operation):
    databases, (first, second) = owners
    original = await install_grant(first, binding, tokens)
    target = binding
    claim = None
    if operation == 'install':
        target = replace(binding, client_id='another-approved-client')
    elif operation == 'finish':
        claim = await first.begin_refresh(original)
    before = await read_payload(second, target)
    async with databases[0].transaction():
        with pytest.raises(OAuthGrantRejected, match='top-level'):
            if operation == 'install':
                await install_grant(first, target, tokens)
            elif operation == 'begin':
                await first.begin_refresh(original)
            elif operation == 'finish':
                await first.finish_refresh(claim, tokens)
            else:
                await first.revoke_local(original)
    assert await read_payload(second, target) == before, 'Refused OAuth write changed durable grant custody'


@pytest.mark.asyncio
async def test_unknown_native_custody_is_refused_before_sql(owners, binding, tokens, monkeypatch):
    databases, (store, _) = owners
    monkeypatch.setattr(type(databases[0]), 'owns_open_transaction', property(lambda self: None))
    with pytest.raises(OAuthGrantRejected, match='top-level'):
        await install_grant(store, binding, tokens)
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_credential_slots') == 0


@pytest.mark.asyncio
async def test_encrypted_grant_survives_independent_store_restart(owners, binding, tokens):
    databases, (first, second) = owners
    installed = await install_grant(first, binding, tokens)
    restored = await read_payload(second, binding)
    assert restored == installed and restored.tokens.expires_at == 1_700_000_000
    row = await databases[0].fetch_one('SELECT ciphertext FROM mcp_oauth_credential_slots')
    assert row[0].startswith('KSAv2:')
    assert tokens.access_token not in row[0] and tokens.refresh_token not in row[0]
    assert tokens.access_token not in repr(restored) and tokens.refresh_token not in repr(tokens)


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value', [
    ('principal_id', 'operator-two'), ('connection_id', 'connection-two'),
    ('server_url', 'https://remote.example/other'), ('resource', 'https://remote.example'),
    ('issuer', 'https://other-issuer.example'), ('client_id', 'other-client'),
    ('redirect_uri', 'https://host.example/other'), ('scopes', frozenset({'read'})),
])
async def test_every_frozen_binding_field_isolated(owners, binding, tokens, field, value):
    databases, (store, _) = owners
    await install_grant(store, binding, tokens)
    other = replace(binding, **{field: value})
    assert await read_payload(store, other) is None
    # Even a ciphertext copied to the other binding cannot decrypt there.
    if other.slot_id == binding.slot_id:
        await databases[0].execute('UPDATE mcp_oauth_credential_slots SET principal_id = ?, binding_id = ?, binding = ?',
            (other.principal_id, other.identifier, store._binding_json(other)))
    else:
        await databases[0].execute('INSERT INTO mcp_oauth_credential_slots '
            '(agent_did, principal_id, slot_id, binding_id, binding, revision, state, ciphertext) '
            'SELECT agent_did, ?, ?, ?, ?, revision, state, ciphertext FROM mcp_oauth_credential_slots',
            (other.principal_id, other.slot_id, other.identifier, store._binding_json(other)))
    with pytest.raises(DecryptionError):
        await read_payload(store, other)


@pytest.mark.asyncio
async def test_other_agent_is_rejected_before_storage(owners, binding, tokens):
    _, (store, _) = owners
    other = replace(binding, agent_did='did:test:other')
    with pytest.raises(OAuthGrantRejected, match='another agent'):
        await install_grant(store, other, tokens)
    with pytest.raises(OAuthGrantRejected, match='another agent'):
        await read_payload(store, other)


@pytest.mark.asyncio
async def test_only_one_independent_refresh_claim_can_commit(owners, binding, tokens):
    _, (first, second) = owners
    installed = await install_grant(first, binding, tokens)
    results = await asyncio.gather(first.begin_refresh(installed),
                                   second.begin_refresh(installed), return_exceptions=True)
    claims = [result for result in results if not isinstance(result, BaseException)]
    assert len(claims) == 1
    assert sum(isinstance(result, OAuthGrantChanged) for result in results) == 1
    claim = claims[0]
    assert claim.state == 'refreshing'
    restored = await read_payload(second, binding)
    assert restored.revision == claim.revision and restored.state == claim.state
    assert restored.tokens is None
    with pytest.raises(OAuthGrantRejected, match='another refresh'):
        await second.begin_refresh(restored)
    with pytest.raises(OAuthGrantRejected, match='record type'):
        await second.finish_refresh(restored, tokens)
    rotated = replace(tokens, access_token='next-access', refresh_token='rotated-refresh',
                      expires_at=1_900_000_000)
    complete = await first.finish_refresh(claim, rotated)
    assert complete.state == 'active' and complete.tokens == rotated
    with pytest.raises(OAuthGrantChanged):
        await second.finish_refresh(claim, rotated)
    next_claim = await second.begin_refresh(complete)
    with pytest.raises(OAuthGrantChanged):
        await first.begin_refresh(installed)
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(claim, rotated)
    assert (await read_payload(first, binding)).revision == next_claim.revision


@pytest.mark.asyncio
async def test_revision_cas_rejects_refresh_completed_between_read_and_update(
        owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await install_grant(first, binding, tokens)
    entered, release = asyncio.Event(), asyncio.Event()
    execute = databases[0].execute

    async def pause_before_real_update(query, parameters=None):
        if query.lstrip().startswith('UPDATE mcp_oauth_credential_slots'):
            entered.set()
            await release.wait()
        return await execute(query, parameters)

    monkeypatch.setattr(databases[0], 'execute', pause_before_real_update)
    pending = asyncio.create_task(first.begin_refresh(installed))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        current_claim = await second.begin_refresh(installed)
        rotated = replace(tokens, access_token='race-next-access',
                          refresh_token='race-rotated-refresh')
        completed = await second.finish_refresh(current_claim, rotated)
        release.set()
        with pytest.raises(OAuthGrantChanged, match='changed before durable custody'):
            await pending
        assert await read_payload(second, binding) == completed
    finally:
        release.set()
        await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_local_revocation_cannot_be_undone_by_stale_refresh_or_insert(owners, binding, tokens):
    _, (first, second) = owners
    installed = await install_grant(first, binding, tokens)
    claim = await first.begin_refresh(installed)
    revoked = await second.revoke_local(claim)
    assert revoked.state == 'revoked' and revoked.tokens is None
    assert await second.revoke_local(revoked) == revoked
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(claim, replace(tokens, refresh_token='rotated'))
    with pytest.raises(OAuthGrantChanged):
        await install_grant(first, binding, tokens)
    # Replacement requires the current tombstone and a separately authorized
    # host call; possessing this revision alone confers no operator authority.
    new = await install_grant(first, binding, tokens, expected=revoked)
    assert new.state == 'active' and new.revision != installed.revision


@pytest.mark.asyncio
async def test_scope_expansion_refused_before_initial_or_rotated_storage(owners, binding, tokens):
    databases, (store, _) = owners
    with pytest.raises(OAuthGrantRejected, match='approved scopes'):
        await install_grant(store, binding, replace(tokens, scopes=frozenset({'admin'})))
    unknown = await store.read(binding)
    assert unknown.state == 'exchanging' and unknown.tokens is None
    tombstone = await store.revoke_local(unknown)
    claim = await store.begin_refresh(await install_grant(store, binding, tokens, expected=tombstone))
    with pytest.raises(OAuthGrantRejected, match='original token scopes'):
        await store.finish_refresh(claim, replace(tokens, scopes=frozenset({'read', 'write'})))
    assert (await read_payload(store, binding)).revision == claim.revision


@pytest.mark.asyncio
async def test_claim_secret_is_not_stored_and_scope_metadata_is_not_authority(owners, binding, tokens):
    databases, (first, second) = owners
    claim = await first.begin_refresh(await install_grant(first, binding, tokens))
    row = await databases[0].fetch_one('SELECT claim_hash, ciphertext FROM mcp_oauth_credential_slots')
    assert row[0] == hashlib.sha256(claim.secret.encode()).hexdigest()
    assert claim.secret not in row[1] and claim.secret not in repr(claim)
    with pytest.raises(OAuthGrantChanged):
        await second.finish_refresh(replace(claim, secret='x' * 43), tokens)
    expanded = replace(tokens, scopes=binding.scopes)
    with pytest.raises(OAuthGrantRejected, match='original token scopes'):
        await first.finish_refresh(replace(claim, tokens=expanded), expanded)
    finished = await first.finish_refresh(claim, replace(tokens, refresh_token=None))
    assert finished.tokens.refresh_token == tokens.refresh_token


@pytest.mark.asyncio
async def test_begin_refresh_uses_committed_tokens_instead_of_snapshot_metadata(owners, binding, tokens):
    _, (store, _) = owners
    snapshot = await install_grant(store, binding, tokens)
    forged = replace(snapshot, tokens=replace(tokens, refresh_token='forged-refresh', scopes=binding.scopes))
    claim = await store.begin_refresh(forged)
    assert claim.tokens == tokens


@pytest.mark.asyncio
@pytest.mark.parametrize('secret', [None, 1, b'x' * 43, 'short'])
async def test_malformed_claim_secret_is_rejected_without_disclosure(owners, binding, tokens, secret):
    _, (store, _) = owners
    claim = await store.begin_refresh(await install_grant(store, binding, tokens))
    with pytest.raises(OAuthGrantRejected, match='original claim secret'):
        await store.finish_refresh(replace(claim, secret=secret), tokens)


@pytest.mark.asyncio
async def test_lost_commit_ack_retains_real_refresh_claim_without_retry(owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await install_grant(first, binding, tokens)
    transaction = databases[0].transaction

    @asynccontextmanager
    async def lose_ack():
        async with transaction():
            yield
        raise TransactionError('Synthetic loss of the real committed ACK')

    monkeypatch.setattr(databases[0], 'transaction', lose_ack)
    with pytest.raises(TransactionError, match='committed ACK'):
        await first.begin_refresh(installed)
    retained = await read_payload(second, binding)
    assert retained.state == 'refreshing' and retained.revision != installed.revision
    with pytest.raises(OAuthGrantRejected, match='another refresh'):
        await second.begin_refresh(retained)


@pytest.mark.asyncio
async def test_revocation_between_commit_and_readback_refuses_publication(owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await install_grant(first, binding, tokens)
    transaction = databases[0].transaction

    @asynccontextmanager
    async def revoke_after_commit():
        async with transaction():
            yield
        committed = await read_payload(second, binding)
        assert committed.state == 'refreshing'
        await second.revoke_local(committed)

    monkeypatch.setattr(databases[0], 'transaction', revoke_after_commit)
    with pytest.raises(OAuthGrantChanged, match='acknowledged'):
        await first.begin_refresh(installed)
    retained = await read_payload(second, binding)
    assert retained.state == 'revoked' and retained.tokens is None


@pytest.mark.asyncio
@pytest.mark.parametrize('column,value', [('revision', 'swapped-revision'), ('state', 'refreshing')])
async def test_custody_state_and_revision_authenticated(owners, binding, tokens, column, value):
    databases, (store, _) = owners
    await install_grant(store, binding, tokens)
    assert column in {'revision', 'state'}
    if column == 'state':
        secret = 'x' * 43
        snapshot = await store.read(binding)
        await databases[0].execute('UPDATE mcp_oauth_credential_slots SET state = ?, claim_hash = ?',
                                  (value, hashlib.sha256(secret.encode()).hexdigest()))
        with pytest.raises(DecryptionError):
            await store.finish_refresh(OAuthRefreshClaim(binding, snapshot.revision, secret, tokens), tokens)
    else:
        await databases[0].execute('UPDATE mcp_oauth_credential_slots SET revision = ?', (value,))
        with pytest.raises(DecryptionError):
            await read_payload(store, binding)


@pytest.mark.asyncio
async def test_token_budget_refuses_write_and_oversized_stored_ciphertext(owners, binding, tokens):
    databases, (store, _) = owners
    with pytest.raises(OAuthGrantRejected, match='storage budget'):
        await install_grant(store, binding, replace(tokens, access_token='x' * 5000))
    unknown = await store.read(binding)
    assert unknown.state == 'exchanging' and unknown.tokens is None
    tombstone = await store.revoke_local(unknown)
    await install_grant(store, binding, tokens, expected=tombstone)
    await databases[0].execute('UPDATE mcp_oauth_credential_slots SET ciphertext = ?', ('x' * 6000,))
    with pytest.raises(OAuthGrantRejected, match='storage budget'):
        await read_payload(store, binding)


@pytest.mark.parametrize('expiry', [True, -1, float('nan'), float('inf'), '3600', 10**400])
def test_expiry_is_absolute_finite_and_never_coerced(tokens, expiry):
    with pytest.raises(OAuthGrantRejected, match='absolute finite timestamp'):
        replace(tokens, expires_at=expiry)


@pytest.mark.parametrize('field,value', [('resource', 'https://@remote.example/mcp'),
    ('issuer', 'https://issuer.example?changed=true')])
def test_malformed_frozen_urls_are_refused(binding, field, value):
    with pytest.raises(OAuthGrantRejected):
        replace(binding, **{field: value})


@pytest.mark.asyncio
async def test_explicit_replacement_fences_the_original_inflight_refresh(owners, binding, tokens):
    _, (first, second) = owners
    claim = await first.begin_refresh(await install_grant(first, binding, tokens))
    current = await read_payload(second, binding)
    replacement = replace(tokens, access_token='newly-approved-access',
                          refresh_token='newly-approved-refresh')
    with pytest.raises(OAuthGrantRejected, match='Disconnect'):
        await install_grant(second, binding, replacement, expected=current)
    revoked = await second.revoke_local(current)
    installed = await install_grant(second, binding, replacement, expected=revoked)
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(claim, tokens)
    assert await read_payload(first, binding) == installed


class UnvalidatedTokens(OAuthGrantTokens):
    def __post_init__(self):
        pass


class UnvalidatedBinding(OAuthGrantBinding):
    def __post_init__(self):
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['install_tokens', 'finish_tokens', 'binding', 'expected'])
async def test_invalid_grant_record_is_refused_without_sql_change(owners, binding, tokens, operation):
    databases, (store, _) = owners
    invalid = UnvalidatedTokens(tokens.access_token, tokens.refresh_token, -1, tokens.scopes)
    claim = None
    if operation == 'install_tokens':
        claim = await store.begin_exchange(await store.begin_authorization(binding))
    if operation == 'finish_tokens':
        claim = await store.begin_refresh(await install_grant(store, binding, tokens))
    before = await databases[1].fetch_all('SELECT revision, state, ciphertext FROM mcp_oauth_credential_slots')
    with pytest.raises(OAuthGrantRejected, match='record type'):
        if operation == 'install_tokens':
            await store.complete_authorization(claim, invalid)
        elif operation == 'finish_tokens':
            await store.finish_refresh(claim, invalid)
        elif operation == 'binding':
            fields = {name: getattr(binding, name) for name in binding.__dataclass_fields__}
            await install_grant(store, UnvalidatedBinding(**fields), tokens)
        else:
            await install_grant(store, binding, tokens, expected=object())
    assert await databases[1].fetch_all('SELECT revision, state, ciphertext FROM mcp_oauth_credential_slots') == before


def test_grant_store_requires_the_native_database_contract(binding, owned_oauth_key):
    with pytest.raises(OAuthGrantRejected, match='native database'):
        OAuthGrantStore(object(), binding.agent_did, max_token_bytes=4096)


@pytest.mark.asyncio
async def test_authorization_intent_and_exchange_are_distinct_one_use_durable_claims(owners, binding, tokens):
    databases, (first, second) = owners
    authorizing = await first.begin_authorization(binding)
    assert type(authorizing) is OAuthAuthorizationClaim
    assert authorizing.state == 'authorizing' and authorizing.secret not in repr(authorizing)
    restored = await second.read(binding)
    assert restored.state == 'authorizing' and restored.tokens is None
    row = await databases[0].fetch_one('SELECT claim_hash, ciphertext FROM mcp_oauth_credential_slots')
    assert row == (hashlib.sha256(authorizing.secret.encode()).hexdigest(), None)
    with pytest.raises(OAuthGrantRejected, match='phase claim'):
        await first.complete_authorization(authorizing, tokens)
    with pytest.raises(OAuthGrantRejected, match='record type'):
        await second.begin_exchange(restored)
    exchanging = await first.begin_exchange(authorizing)
    assert exchanging.state == 'exchanging' and exchanging.revision != authorizing.revision
    assert (await second.read(binding)).state == 'exchanging'
    with pytest.raises(OAuthGrantChanged):
        await first.begin_exchange(authorizing)
    active = await first.complete_authorization(exchanging, tokens)
    assert active.state == 'active' and active.tokens == tokens
    assert (await second.read(binding)).tokens is None
    assert (await second.read_tokens(await second.read(binding))).tokens == tokens
    with pytest.raises(OAuthGrantChanged):
        await first.complete_authorization(exchanging, tokens)


@pytest.mark.asyncio
async def test_slot_replacement_cannot_create_parallel_grants_for_new_scope_or_issuer(owners, binding, tokens):
    databases, (first, second) = owners
    original = await first.begin_authorization(binding)
    replacement = replace(binding, issuer='https://other-issuer.example',
        authorization_metadata='https://other-issuer.example/.well-known/oauth-authorization-server',
        scopes=frozenset({'read'}))
    assert replacement.slot_id == binding.slot_id and replacement.identifier != binding.identifier
    assert await second.read(replacement) is None
    with pytest.raises(OAuthGrantChanged):
        await second.begin_authorization(replacement)
    current = await second.read_slot(binding.principal_id, binding.connection_id)
    latest = await second.begin_authorization(replacement, expected=current)
    assert await first.read(binding) is None
    assert (await first.read_slot(binding.principal_id, binding.connection_id)).binding == replacement
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_credential_slots') == 1
    with pytest.raises(OAuthGrantChanged):
        await first.begin_exchange(original)
    active = await second.complete_authorization(await second.begin_exchange(latest), tokens)
    with pytest.raises(OAuthGrantRejected, match='Disconnect'):
        await first.begin_authorization(binding, expected=await second.read(replacement))
    assert (await second.read_tokens(await second.read(replacement))).tokens == active.tokens


@pytest.mark.asyncio
async def test_unknown_exchange_requires_explicit_current_revision_and_acknowledgment(owners, binding, tokens):
    databases, (first, second) = owners
    claim = await first.begin_exchange(await first.begin_authorization(binding))
    current = await second.read(binding)
    with pytest.raises(OAuthGrantRejected, match='unknown'):
        await second.begin_authorization(binding, expected=current)
    with pytest.raises(OAuthGrantChanged):
        await second.begin_authorization(binding, acknowledge_unknown=True)
    next_claim = await second.begin_authorization(binding, expected=current, acknowledge_unknown=True)
    assert next_claim.state == 'authorizing'
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_credential_slots') == 1
    with pytest.raises(OAuthGrantChanged):
        await first.complete_authorization(claim, tokens)


@pytest.mark.asyncio
async def test_metadata_restart_and_local_revocation_never_load_key_or_decrypt(owners, binding, tokens, monkeypatch):
    from kestrel_feature_mcp import oauth_grants
    databases, (first, _) = owners
    installed = await install_grant(first, binding, tokens)
    def forbidden_key(*args, **kwargs):
        pytest.fail('Metadata/restore/revocation accessed credential key material')
    monkeypatch.setattr(oauth_grants, 'get_agent_key', forbidden_key)
    restarted = OAuthGrantStore(databases[1], binding.agent_did, max_token_bytes=4096)
    await restarted.initialize()
    metadata = await restarted.read(binding)
    assert metadata.revision == installed.revision and metadata.tokens is None
    assert await restarted.read_slot(binding.principal_id, binding.connection_id) == metadata
    revoked = await restarted.revoke_local(metadata)
    assert revoked.state == 'revoked' and revoked.reason == 'local' and revoked.tokens is None
    assert await restarted.read(binding) == revoked


@pytest.mark.asyncio
@pytest.mark.parametrize('phase,method,reason', [
    ('authorizing', 'abandon_authorization', 'abandoned'),
    ('exchanging', 'reject_exchange', 'exchange_rejected'),
    ('refreshing', 'reject_refresh', 'refresh_rejected'),
])
async def test_definitive_rejection_tombstones_only_original_phase_claim(owners, binding, tokens, phase, method, reason):
    _, (first, second) = owners
    claim = await first.begin_authorization(binding)
    if phase != 'authorizing':
        claim = await first.begin_exchange(claim)
    if phase == 'refreshing':
        claim = await first.begin_refresh(await first.complete_authorization(claim, tokens))
    revoked = await getattr(first, method)(claim)
    assert revoked.reason == reason and revoked.tokens is None and revoked.state == 'revoked'
    assert await second.read(binding) == revoked
    with pytest.raises(OAuthGrantChanged):
        await getattr(first, method)(claim)


@pytest.mark.asyncio
async def test_lost_exchange_commit_ack_never_restores_an_authorizing_claim(owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    claim = await first.begin_authorization(binding)
    transaction = databases[0].transaction
    @asynccontextmanager
    async def lose_ack():
        async with transaction():
            yield
        raise TransactionError('Synthetic loss of the real exchange commit ACK')
    monkeypatch.setattr(databases[0], 'transaction', lose_ack)
    with pytest.raises(TransactionError, match='exchange commit ACK'):
        await first.begin_exchange(claim)
    retained = await second.read(binding)
    assert retained.state == 'exchanging' and retained.tokens is None
    with pytest.raises(OAuthGrantChanged):
        await second.begin_exchange(claim)
    with pytest.raises(OAuthGrantRejected, match='unknown'):
        await second.begin_authorization(binding, expected=retained)


@pytest.mark.asyncio
async def test_first_schema_creation_is_serialized_across_independent_native_owners(owners):
    databases, stores = owners
    await databases[0].execute('DROP TABLE mcp_oauth_credential_slots')
    await asyncio.gather(*(store.initialize() for store in stores))
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_credential_slots') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('column', ['binding', 'binding_id', 'slot_id'])
async def test_canonical_metadata_tampering_is_rejected_without_key_access(owners, binding, tokens, monkeypatch, column):
    from kestrel_feature_mcp import oauth_grants
    databases, (store, _) = owners
    await install_grant(store, binding, tokens)
    def forbidden_key(*args, **kwargs):
        pytest.fail('Corrupted metadata reached credential decryption')
    monkeypatch.setattr(oauth_grants, 'get_agent_key', forbidden_key)
    values = {'binding': binding.canonical_json().decode().replace('operator-one', 'operator-two'),
              'binding_id': '0' * 64, 'slot_id': '0' * 64}
    assert column in values
    await databases[0].execute('UPDATE mcp_oauth_credential_slots SET ' + column + ' = ?', (values[column],))
    if column == 'slot_id':
        assert await store.read(binding) is None
        with pytest.raises(OAuthGrantRejected, match='integrity'):
            await store._read_slot(values[column])
    else:
        with pytest.raises(OAuthGrantRejected, match='integrity'):
            await store.read(binding)


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['initialize', 'authorize', 'exchange', 'complete', 'abandon', 'reject-exchange', 'reject-refresh'])
async def test_every_acquisition_transition_refuses_an_outer_transaction(owners, binding, tokens, operation):
    databases, (first, second) = owners
    claim = await first.begin_authorization(binding)
    if operation in {'complete', 'reject-exchange', 'reject-refresh'}:
        claim = await first.begin_exchange(claim)
    if operation == 'reject-refresh':
        claim = await first.begin_refresh(await first.complete_authorization(claim, tokens))
    before = await second.read(binding)
    async with databases[0].transaction():
        with pytest.raises(OAuthGrantRejected, match='top-level'):
            if operation == 'initialize':
                await first.initialize()
            elif operation == 'authorize':
                await first.begin_authorization(binding, expected=before)
            elif operation == 'exchange':
                await first.begin_exchange(claim)
            elif operation == 'complete':
                await first.complete_authorization(claim, tokens)
            elif operation == 'abandon':
                await first.abandon_authorization(claim)
            elif operation == 'reject-exchange':
                await first.reject_exchange(claim)
            else:
                await first.reject_refresh(claim)
    assert await second.read(binding) == before


@pytest.mark.asyncio
@pytest.mark.parametrize('owners', ['sqlite'], indirect=True)
async def test_sqlite_schema_creation_refuses_missing_native_writer_capability(owners, monkeypatch):
    databases, (store, _) = owners
    assert databases[0].backend_type == 'sqlite'
    monkeypatch.setattr(type(databases[0]), 'transaction_options', property(lambda self: frozenset()))
    with pytest.raises(OAuthGrantRejected, match='native SQLite immediate'):
        await store.initialize()
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_credential_slots') == 0


@pytest.mark.parametrize('expiry,now,expected', [(None, 1000, False),
    (1000.5, 1000.49, False), (1000.5, 1000.5, True), (1000.5, 1001, True)])
def test_token_expiry_uses_the_persisted_absolute_timestamp(expiry, now, expected):
    token = OAuthGrantTokens('owned-access', None, expiry, frozenset({'read'}))
    assert token.is_expired(now) is expected


@pytest.mark.asyncio
async def test_principal_listing_uses_metadata_only_and_includes_unconnected_grants(owners, binding, tokens, monkeypatch):
    _, (store, _) = owners
    active = await install_grant(store, binding, tokens)
    pending_binding = replace(binding, connection_id='not-yet-connected')
    await store.begin_authorization(pending_binding)
    foreign = replace(binding, principal_id='another-operator')
    await install_grant(store, foreign, tokens)
    def forbidden_key():
        raise AssertionError('Metadata listing must not access credential keys')
    monkeypatch.setattr(store, '_cipher', forbidden_key)
    rows = await store.list_principal(binding.principal_id)
    assert {row.binding.connection_id for row in rows} == {binding.connection_id, pending_binding.connection_id}
    assert {row.state for row in rows} == {'active', 'authorizing'}
    assert all(row.tokens is None for row in rows)
    assert await store.list_principal('no-grants') == []
    assert (await store.read(binding)).revision == active.revision


@pytest.mark.asyncio
async def test_principal_index_cannot_relabel_another_principals_grant(owners, binding, tokens):
    databases, (store, _) = owners
    await install_grant(store, binding, tokens)
    await databases[0].execute('UPDATE mcp_oauth_credential_slots SET principal_id = ?', ('other-operator',))
    with pytest.raises(OAuthGrantRejected, match='integrity'):
        await store.list_principal('other-operator')
    with pytest.raises(OAuthGrantRejected, match='integrity'):
        await store.read(binding)


@pytest.mark.asyncio
async def test_schema_bootstrap_needs_neither_credential_budget_nor_encryption_key(owners, binding, monkeypatch):
    from kestrel_feature_mcp.oauth_grants import initialize_grant_schema
    import kestrel_feature_mcp.oauth_grants as module
    databases, _ = owners
    await databases[0].execute('DROP TABLE mcp_oauth_credential_slots')
    def forbidden_key(*args):
        raise AssertionError('Schema bootstrap must not read a credential key')
    monkeypatch.setattr(module, 'get_agent_key', forbidden_key)
    await initialize_grant_schema(databases[0])
    assert await databases[1].fetch_val('SELECT COUNT(*) FROM mcp_oauth_credential_slots') == 0
