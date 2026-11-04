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
    OAuthGrantStore, OAuthGrantTokens,
)


@pytest.fixture
def binding():
    return OAuthGrantBinding('did:test:oauth-owner', 'operator-one', 'connection-one',
        'https://remote.example/mcp', 'https://remote.example/mcp',
        'https://issuer.example', 'vendor-registered-client',
        'https://host.example/oauth/callback', frozenset({'read', 'write'}))


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
    installed = await first.install(binding, tokens)
    async with databases[0].transaction():
        with pytest.raises(OAuthGrantRejected, match='top-level'):
            await first.begin_refresh(installed)
        with pytest.raises(OAuthGrantRejected, match='top-level'):
            await first.read(binding)
    assert await second.read(binding) == installed


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['install', 'begin', 'finish', 'revoke'])
async def test_every_grant_write_refuses_before_changing_an_outer_transaction(
        owners, binding, tokens, operation):
    databases, (first, second) = owners
    original = await first.install(binding, tokens)
    target = binding
    claim = None
    if operation == 'install':
        target = replace(binding, client_id='another-approved-client')
    elif operation == 'finish':
        claim = await first.begin_refresh(original)
    before = await second.read(target)
    async with databases[0].transaction():
        with pytest.raises(OAuthGrantRejected, match='top-level'):
            if operation == 'install':
                await first.install(target, tokens)
            elif operation == 'begin':
                await first.begin_refresh(original)
            elif operation == 'finish':
                await first.finish_refresh(claim, tokens)
            else:
                await first.revoke_local(original)
    assert await second.read(target) == before, 'Refused OAuth write changed durable grant custody'


@pytest.mark.asyncio
async def test_unknown_native_custody_is_refused_before_sql(owners, binding, tokens, monkeypatch):
    databases, (store, _) = owners
    monkeypatch.setattr(type(databases[0]), 'owns_open_transaction', property(lambda self: None))
    with pytest.raises(OAuthGrantRejected, match='top-level'):
        await store.install(binding, tokens)
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_grants') == 0


@pytest.mark.asyncio
async def test_encrypted_grant_survives_independent_store_restart(owners, binding, tokens):
    databases, (first, second) = owners
    installed = await first.install(binding, tokens)
    restored = await second.read(binding)
    assert restored == installed and restored.tokens.expires_at == 1_700_000_000
    row = await databases[0].fetch_one('SELECT ciphertext FROM mcp_oauth_grants')
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
    await store.install(binding, tokens)
    other = replace(binding, **{field: value})
    assert await store.read(other) is None
    # Even a ciphertext copied to the other binding cannot decrypt there.
    await databases[0].execute('INSERT INTO mcp_oauth_grants '
        '(agent_did, grant_id, revision, state, ciphertext) '
        'SELECT agent_did, ?, revision, state, ciphertext FROM mcp_oauth_grants',
        (other.identifier,))
    with pytest.raises(DecryptionError):
        await store.read(other)


@pytest.mark.asyncio
async def test_other_agent_is_rejected_before_storage(owners, binding, tokens):
    _, (store, _) = owners
    other = replace(binding, agent_did='did:test:other')
    with pytest.raises(OAuthGrantRejected, match='another agent'):
        await store.install(other, tokens)
    with pytest.raises(OAuthGrantRejected, match='another agent'):
        await store.read(other)


@pytest.mark.asyncio
async def test_only_one_independent_refresh_claim_can_commit(owners, binding, tokens):
    _, (first, second) = owners
    installed = await first.install(binding, tokens)
    results = await asyncio.gather(first.begin_refresh(installed),
                                   second.begin_refresh(installed), return_exceptions=True)
    claims = [result for result in results if not isinstance(result, BaseException)]
    assert len(claims) == 1
    assert sum(isinstance(result, OAuthGrantChanged) for result in results) == 1
    claim = claims[0]
    assert claim.state == 'refreshing'
    restored = await second.read(binding)
    assert restored.revision == claim.revision and restored.state == claim.state
    assert restored.tokens is None
    with pytest.raises(OAuthGrantRejected, match='another refresh'):
        await second.begin_refresh(restored)
    with pytest.raises(OAuthGrantRejected, match='original durable claim'):
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
    assert (await first.read(binding)).revision == next_claim.revision


@pytest.mark.asyncio
async def test_revision_cas_rejects_refresh_completed_between_read_and_update(
        owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await first.install(binding, tokens)
    entered, release = asyncio.Event(), asyncio.Event()
    execute = databases[0].execute

    async def pause_before_real_update(query, parameters=None):
        if query.lstrip().startswith('UPDATE mcp_oauth_grants'):
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
        assert await second.read(binding) == completed
    finally:
        release.set()
        await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_local_revocation_cannot_be_undone_by_stale_refresh_or_insert(owners, binding, tokens):
    _, (first, second) = owners
    installed = await first.install(binding, tokens)
    claim = await first.begin_refresh(installed)
    revoked = await second.revoke_local(claim)
    assert revoked.state == 'revoked' and revoked.tokens is None
    assert await second.revoke_local(revoked) == revoked
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(claim, replace(tokens, refresh_token='rotated'))
    with pytest.raises(OAuthGrantChanged):
        await first.install(binding, tokens)
    # Replacement requires the current tombstone and a separately authorized
    # host call; possessing this revision alone confers no operator authority.
    new = await first.install(binding, tokens, expected=revoked)
    assert new.state == 'active' and new.revision != installed.revision


@pytest.mark.asyncio
async def test_scope_expansion_refused_before_initial_or_rotated_storage(owners, binding, tokens):
    databases, (store, _) = owners
    with pytest.raises(OAuthGrantRejected, match='approved scopes'):
        await store.install(binding, replace(tokens, scopes=frozenset({'admin'})))
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_grants') == 0
    claim = await store.begin_refresh(await store.install(binding, tokens))
    with pytest.raises(OAuthGrantRejected, match='original token scopes'):
        await store.finish_refresh(claim, replace(tokens, scopes=frozenset({'read', 'write'})))
    assert (await store.read(binding)).revision == claim.revision


@pytest.mark.asyncio
async def test_claim_secret_is_not_stored_and_scope_metadata_is_not_authority(owners, binding, tokens):
    databases, (first, second) = owners
    claim = await first.begin_refresh(await first.install(binding, tokens))
    row = await databases[0].fetch_one('SELECT claim_hash, ciphertext FROM mcp_oauth_grants')
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
    snapshot = await store.install(binding, tokens)
    forged = replace(snapshot, tokens=replace(tokens, refresh_token='forged-refresh', scopes=binding.scopes))
    claim = await store.begin_refresh(forged)
    assert claim.tokens == tokens


@pytest.mark.asyncio
@pytest.mark.parametrize('secret', [None, 1, b'x' * 43, 'short'])
async def test_malformed_claim_secret_is_rejected_without_disclosure(owners, binding, tokens, secret):
    _, (store, _) = owners
    claim = await store.begin_refresh(await store.install(binding, tokens))
    with pytest.raises(OAuthGrantRejected, match='original claim secret'):
        await store.finish_refresh(replace(claim, secret=secret), tokens)


@pytest.mark.asyncio
async def test_lost_commit_ack_retains_real_refresh_claim_without_retry(owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await first.install(binding, tokens)
    transaction = databases[0].transaction

    @asynccontextmanager
    async def lose_ack():
        async with transaction():
            yield
        raise TransactionError('Synthetic loss of the real committed ACK')

    monkeypatch.setattr(databases[0], 'transaction', lose_ack)
    with pytest.raises(TransactionError, match='committed ACK'):
        await first.begin_refresh(installed)
    retained = await second.read(binding)
    assert retained.state == 'refreshing' and retained.revision != installed.revision
    with pytest.raises(OAuthGrantRejected, match='another refresh'):
        await second.begin_refresh(retained)


@pytest.mark.asyncio
async def test_revocation_between_commit_and_readback_refuses_publication(owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await first.install(binding, tokens)
    transaction = databases[0].transaction

    @asynccontextmanager
    async def revoke_after_commit():
        async with transaction():
            yield
        committed = await second.read(binding)
        assert committed.state == 'refreshing'
        await second.revoke_local(committed)

    monkeypatch.setattr(databases[0], 'transaction', revoke_after_commit)
    with pytest.raises(OAuthGrantChanged, match='acknowledged'):
        await first.begin_refresh(installed)
    retained = await second.read(binding)
    assert retained.state == 'revoked' and retained.tokens is None


@pytest.mark.asyncio
@pytest.mark.parametrize('column,value', [('revision', 'swapped-revision'), ('state', 'refreshing')])
async def test_custody_state_and_revision_authenticated(owners, binding, tokens, column, value):
    databases, (store, _) = owners
    await store.install(binding, tokens)
    assert column in {'revision', 'state'}
    if column == 'state':
        await databases[0].execute('UPDATE mcp_oauth_grants SET state = ?, claim_hash = ?', (value, 'altered-claim-hash'))
    else:
        await databases[0].execute('UPDATE mcp_oauth_grants SET revision = ?', (value,))
    with pytest.raises(DecryptionError):
        await store.read(binding)


@pytest.mark.asyncio
async def test_token_budget_refuses_write_and_oversized_stored_ciphertext(owners, binding, tokens):
    databases, (store, _) = owners
    with pytest.raises(OAuthGrantRejected, match='storage budget'):
        await store.install(binding, replace(tokens, access_token='x' * 5000))
    await store.install(binding, tokens)
    await databases[0].execute('UPDATE mcp_oauth_grants SET ciphertext = ?', ('x' * 6000,))
    with pytest.raises(OAuthGrantRejected, match='storage budget'):
        await store.read(binding)


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
    claim = await first.begin_refresh(await first.install(binding, tokens))
    current = await second.read(binding)
    replacement = replace(tokens, access_token='newly-approved-access',
                          refresh_token='newly-approved-refresh')
    installed = await second.install(binding, replacement, expected=current)
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(claim, tokens)
    assert await first.read(binding) == installed


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
    if operation == 'finish_tokens':
        claim = await store.begin_refresh(await store.install(binding, tokens))
    before = await databases[1].fetch_all('SELECT revision, state, ciphertext FROM mcp_oauth_grants')
    with pytest.raises(OAuthGrantRejected, match='record type'):
        if operation == 'install_tokens':
            await store.install(binding, invalid)
        elif operation == 'finish_tokens':
            await store.finish_refresh(claim, invalid)
        elif operation == 'binding':
            fields = {name: getattr(binding, name) for name in binding.__dataclass_fields__}
            await store.install(UnvalidatedBinding(**fields), tokens)
        else:
            await store.install(binding, tokens, expected=object())
    assert await databases[1].fetch_all('SELECT revision, state, ciphertext FROM mcp_oauth_grants') == before


def test_grant_store_requires_the_native_database_contract(binding, owned_oauth_key):
    with pytest.raises(OAuthGrantRejected, match='native database'):
        OAuthGrantStore(object(), binding.agent_did, max_token_bytes=4096)
