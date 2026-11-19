"""Authorization generations survive refresh, never reauthorization or tampering."""

from dataclasses import replace
import asyncio
import hashlib
import json
import re

import pytest

from kestrel_sdk.security.exceptions import DecryptionError
from kestrel_sdk.storage.database import TransactionError
from kestrel_feature_mcp.oauth_grants import (
    OAuthGrantChanged, OAuthGrantRejected, OAuthAuthorizationClaim,
)
from tests.unit.test_oauth_grants import (
    binding as binding, owners as owners, tokens as tokens, install_grant,
)


def generation(snapshot):
    value = getattr(snapshot, 'generation', None)
    assert type(value) is str and re.fullmatch('[0-9a-f]{64}', value), \
        'Every new authorization needs its own 256-bit generation'
    return value


@pytest.mark.asyncio
async def test_generation_is_minted_once_per_authorization_and_carried_through_refresh(owners, binding, tokens):
    _, (first, second) = owners
    claim = await first.begin_authorization(binding)
    original = generation(claim)
    exchange = await first.begin_exchange(claim)
    assert generation(exchange) == original
    active = await first.complete_authorization(exchange, tokens)
    assert generation(active) == original
    refresh = await second.begin_refresh(active)
    assert generation(refresh) == original
    renewed = await second.finish_refresh(refresh, replace(tokens, access_token='rotated-access'))
    assert generation(renewed) == original and renewed.revision != active.revision
    revoked = await first.revoke_local(renewed)
    assert generation(revoked) == original
    replacement = await install_grant(second, binding, tokens, expected=revoked)
    assert generation(replacement) != original


@pytest.mark.asyncio
async def test_authorization_identity_is_key_free_stable_metadata_and_not_a_refresh_revision(owners, binding, tokens, monkeypatch):
    _, (first, second) = owners
    active = await install_grant(first, binding, tokens)
    original = generation(active)
    expected = hashlib.sha256(json.dumps([
        'kestrel-mcp-oauth-authorization-v1', binding.slot_id, binding.identifier, original,
    ], sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    def forbidden_key():
        raise AssertionError('Metadata reads must never open credential keys')
    monkeypatch.setattr(second, '_cipher', forbidden_key)
    metadata = await second.read(binding)
    assert metadata.authorization_identity == expected
    assert metadata.tokens is None
    refreshed = await first.finish_refresh(await first.begin_refresh(active), tokens)
    assert refreshed.authorization_identity == expected
    assert (await second.read_slot(binding.principal_id, binding.connection_id)).authorization_identity == expected


@pytest.mark.asyncio
async def test_generation_is_authenticated_with_the_token_ciphertext(owners, binding, tokens):
    databases, (store, _) = owners
    active = await install_grant(store, binding, tokens)
    assert generation(active) != 'a' * 64
    await databases[0].execute('UPDATE mcp_oauth_credential_slots SET generation = ?', ('a' * 64,))
    changed = await store.read(binding)
    assert changed.generation == 'a' * 64
    with pytest.raises(DecryptionError):
        await store.read_tokens(changed)


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid', ['', 'short', 'A' * 64, 'g' * 64], ids=['empty', 'short', 'upper', 'nonhex'])
async def test_malformed_generation_metadata_refuses_before_key_access(owners, binding, tokens, invalid, monkeypatch):
    databases, (store, _) = owners
    await install_grant(store, binding, tokens)
    await databases[0].execute('UPDATE mcp_oauth_credential_slots SET generation=?', (invalid,))
    def forbidden_key():
        raise AssertionError('Malformed generation metadata must not open a key')
    monkeypatch.setattr(store, '_cipher', forbidden_key)
    with pytest.raises(OAuthGrantRejected, match='generation'):
        await store.read(binding)


@pytest.mark.asyncio
async def test_oversize_token_ciphertext_is_refused_before_opening_a_key(owners, binding, tokens, monkeypatch):
    databases, (store, _) = owners
    active = await install_grant(store, binding, tokens)
    await databases[0].execute('UPDATE mcp_oauth_credential_slots SET ciphertext=?', ('x' * 6000,))
    def forbidden_key():
        raise AssertionError('Oversize ciphertext must not open a key')
    monkeypatch.setattr(store, '_cipher', forbidden_key)
    with pytest.raises(OAuthGrantRejected, match='storage budget'):
        await store.read_tokens(active)


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['read', 'revoke'])
async def test_a_forged_generation_cannot_use_the_same_binding_and_revision(owners, binding, tokens, operation):
    databases, (first, second) = owners
    active = await install_grant(first, binding, tokens)
    assert generation(active) != 'b' * 64
    forged = replace(active, generation='b' * 64)
    before = await databases[0].fetch_all('SELECT revision,state,ciphertext,generation FROM mcp_oauth_credential_slots')
    with pytest.raises(OAuthGrantChanged):
        if operation == 'read':
            await first.read_tokens(forged)
        else:
            await first.revoke_local(forged)
    assert await databases[0].fetch_all('SELECT revision,state,ciphertext,generation FROM mcp_oauth_credential_slots') == before
    assert (await second.read_tokens(active)).tokens == tokens


async def install_legacy_active(store, active):
    """Recreate the released v2 ciphertext, using only the fixture's owned key."""
    payload = (await store.read_tokens(active)).tokens
    encoded = json.dumps({
        'access_token': payload.access_token, 'refresh_token': payload.refresh_token,
        'expires_at': payload.expires_at, 'scopes': sorted(payload.scopes),
    }, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    aad = json.dumps(['kestrel-mcp-oauth-credential-v2', active.binding.slot_id,
        active.binding.identifier, active.revision, 'active', None],
        sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    ciphertext = store._cipher().encrypt(encoded, aad=aad).decode('ascii')
    await store._db.execute('UPDATE mcp_oauth_credential_slots SET generation=NULL,ciphertext=? '
        'WHERE agent_did=? AND slot_id=?', (ciphertext, active.binding.agent_did, active.binding.slot_id))
    return await store.read(active.binding)


@pytest.fixture
async def legacy(owners, binding, tokens):
    databases, (first, _) = owners
    original = await install_legacy_active(first, await install_grant(first, binding, tokens))
    # Remove exactly the two pieces the released v2 store did not have.
    await databases[0].execute('DROP TABLE mcp_oauth_store_schema')
    await databases[0].execute('ALTER TABLE mcp_oauth_credential_slots DROP COLUMN generation')
    return original


@pytest.mark.asyncio
async def test_legacy_schema_and_status_upgrade_without_opening_a_key(owners, binding, legacy, monkeypatch):
    databases, (first, second) = owners
    def forbidden_key():
        raise AssertionError('Schema and metadata migration must remain key-free')
    monkeypatch.setattr(first, '_cipher', forbidden_key)
    monkeypatch.setattr(second, '_cipher', forbidden_key)
    await first.initialize()
    await second.initialize()
    status = await second.read(binding)
    assert status == legacy and status.generation is None and status.authorization_identity is None
    assert await databases[0].fetch_all('SELECT component,revision FROM mcp_oauth_store_schema') == [('credentials', 3)]
    with pytest.raises(OAuthGrantRejected, match='foreground'):
        await second.read_tokens(status)


@pytest.mark.asyncio
async def test_explicit_foreground_admission_reseals_a_legacy_active_grant_once(owners, binding, tokens, legacy):
    databases, (first, second) = owners
    await first.initialize()
    checks = []
    upgraded = await first.admit_legacy(legacy, lambda: checks.append('live-principal'))
    assert generation(upgraded) and len(checks) >= 3
    assert upgraded.revision != legacy.revision and upgraded.tokens == tokens
    assert (await second.read_tokens(upgraded)).tokens == tokens
    assert (await second.read(binding)).generation == upgraded.generation
    with pytest.raises(OAuthGrantChanged):
        await second.admit_legacy(legacy, lambda: None)
    assert await databases[0].fetch_val('SELECT generation FROM mcp_oauth_credential_slots') == upgraded.generation


@pytest.mark.asyncio
@pytest.mark.parametrize('boundary', [1, 2, 3])
async def test_legacy_admission_checks_authority_before_key_or_write(owners, binding, legacy, monkeypatch, boundary):
    databases, (first, _) = owners
    await first.initialize()
    before = await databases[0].fetch_all('SELECT revision,state,generation,ciphertext FROM mcp_oauth_credential_slots')
    checks = []
    def refused():
        checks.append('check')
        if len(checks) == boundary:
            raise PermissionError('Original foreground authority ended')
    def forbidden_key():
        raise AssertionError('Refused admission must not open a key')
    monkeypatch.setattr(first, '_cipher', forbidden_key)
    with pytest.raises(PermissionError, match='foreground authority'):
        await first.admit_legacy(legacy, refused)
    assert await databases[0].fetch_all('SELECT revision,state,generation,ciphertext FROM mcp_oauth_credential_slots') == before


@pytest.mark.asyncio
async def test_concurrent_legacy_admissions_have_one_durable_generation_winner(owners, binding, legacy):
    _, (first, second) = owners
    await first.initialize()
    results = await asyncio.gather(first.admit_legacy(legacy, lambda: None),
        second.admit_legacy(legacy, lambda: None), return_exceptions=True)
    accepted = [value for value in results if not isinstance(value, BaseException)]
    refused = [value for value in results if isinstance(value, BaseException)]
    assert len(accepted) == len(refused) == 1
    assert isinstance(refused[0], OAuthGrantChanged)
    assert generation(accepted[0]) == (await second.read(binding)).generation


@pytest.mark.asyncio
async def test_unknown_credential_schema_refuses_before_key_access(owners, monkeypatch):
    databases, (first, _) = owners
    await databases[0].execute("UPDATE mcp_oauth_store_schema SET revision=999 WHERE component='credentials'")
    def forbidden_key():
        raise AssertionError('An unknown credential schema must not open a key')
    monkeypatch.setattr(first, '_cipher', forbidden_key)
    with pytest.raises(TransactionError, match='schema revision'):
        await first.initialize()


@pytest.mark.asyncio
@pytest.mark.parametrize('state', ['authorizing', 'exchanging', 'refreshing', 'revoked'])
async def test_legacy_unknown_or_inactive_states_never_resume_or_decrypt(owners, binding, legacy, state, monkeypatch):
    databases, (first, _) = owners
    await first.initialize()
    await databases[0].execute('UPDATE mcp_oauth_credential_slots SET state=?,claim_hash=?,reason=?,ciphertext='
        + ('ciphertext' if state == 'refreshing' else 'NULL'),
        (state, None if state == 'revoked' else 'a'*64, 'local' if state == 'revoked' else None))
    status = await first.read(binding)
    def forbidden_key():
        raise AssertionError('Inactive legacy grants must never decrypt')
    monkeypatch.setattr(first, '_cipher', forbidden_key)
    with pytest.raises(OAuthGrantRejected, match='active legacy'):
        await first.admit_legacy(status, lambda: None)
    assert await first.read(binding) == status


@pytest.mark.asyncio
async def test_a_retained_legacy_authorization_claim_cannot_resume_exchange(owners, binding, legacy):
    databases, (first, _) = owners
    await first.initialize()
    secret = 'x' * 43
    await databases[0].execute("UPDATE mcp_oauth_credential_slots SET state='authorizing',"
        'ciphertext=NULL,claim_hash=?', (hashlib.sha256(secret.encode()).hexdigest(),))
    claim = OAuthAuthorizationClaim(binding, legacy.revision, 'authorizing', secret, None)
    with pytest.raises(OAuthGrantRejected, match='generation'):
        await first.begin_exchange(claim)
    assert (await first.read(binding)).state == 'authorizing'


@pytest.mark.asyncio
async def test_forged_refresh_generation_is_checked_before_opening_tokens(owners, binding, tokens, monkeypatch):
    _, (first, _) = owners
    active = await install_grant(first, binding, tokens)
    claim = await first.begin_refresh(active)
    forged = replace(claim, generation='f' * 64)
    assert claim.generation != forged.generation
    def forbidden_key():
        raise AssertionError('A different authorization generation must not open tokens')
    monkeypatch.setattr(first, '_cipher', forbidden_key)
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(forged, tokens)
