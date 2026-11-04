"""Actual independent AS/resource TLS with two fresh clients per grant."""
import asyncio
import json
import os
from pathlib import Path
import sys
import time

import pytest

from tests.unit.test_oauth_acceptance_http import oauth_peers  # noqa: F401
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_feature_mcp.oauth_grants import OAuthGrantBinding, OAuthGrantStore, OAuthGrantTokens
from tests.unit.test_oauth_grants import install_grant


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True)
@pytest.mark.parametrize('oauth_peers', [
    {'refresh': True, 'refresh_rotate': True},
    {'refresh': True, 'refresh_rotate': False},
], indirect=True)
async def test_public_authlib_refresh_survives_two_fresh_processes(oauth_peers, tmp_path, owned_oauth_key):
    peers = oauth_peers
    selection = peers.selection
    path = tmp_path / 'synthetic-grant.db'
    expired = {'access_token': 'fixture-expired-access', 'refresh_token': 'native-fixture-refresh',
        'token_type': 'Bearer', 'expires_in': 3600, 'expires_at': int(time.time()) - 300,
        'scope': 'read'}
    binding = OAuthGrantBinding('did:test:refresh-owner', 'fixture-operator', 'fixture-connection',
        selection.server_url, selection.resource, selection.issuer, selection.client_id,
        selection.redirect_uri, selection.scopes, selection.protected_metadata, selection.authorization_metadata)
    db = SQLiteBackend(str(path))
    await db.connect()
    try:
        store = OAuthGrantStore(db, binding.agent_did, max_token_bytes=4096)
        await store.initialize()
        await install_grant(store, binding, OAuthGrantTokens(expired['access_token'], expired['refresh_token'],
            expired['expires_at'], frozenset({'read'})))
    finally:
        await db.close()
    config = dict(server_url=selection.server_url, resource=selection.resource, issuer=selection.issuer,
        protected_metadata=selection.protected_metadata,
        authorization_metadata=selection.authorization_metadata,
        client_id=selection.client_id,
        redirect_uri=selection.redirect_uri,
        certificate=os.environ['SSL_CERT_FILE'], grant_file=str(path), owned_root=str(tmp_path),
        expected_refresh_token='native-fixture-rotated' if peers.options['refresh_rotate'] else 'native-fixture-refresh')
    results = []
    for phase in ('expired', 'fresh'):
        child = await asyncio.create_subprocess_exec(sys.executable, '-I', '-B',
            str(Path(__file__).resolve().parents[1] / 'oauth_acceptance/refresh_child.py'),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(
                child.communicate(json.dumps(dict(config, phase=phase)).encode()), 15)
        except TimeoutError:
            child.kill()
            await child.wait()
            raise
        assert child.returncode == 0, stderr.decode()
        results.append(json.loads(stdout))
    assert [r['expired_on_restore'] for r in results] == [True, False]
    assert [r['refresh_performed'] for r in results] == [True, False]
    assert all(r['absolute_expiry_preserved'] for r in results)
    assert all(r['encrypted_grant_restored'] for r in results)
    for file in (path, path.with_name(path.name + '-wal')):
        if file.exists():
            stored = file.read_bytes()
            for secret in (b'fixture-expired-access', b'native-fixture-refresh',
                           b'native-fixture-access', b'native-fixture-rotated'):
                assert secret not in stored
    assert peers.requests.count(('POST', '/token')) == 1
    assert ('GET', '/authorize') not in peers.requests and not peers.browser_requests
    assert peers.resource.witness == []
    assert {name for name in peers.issuer.server_names} == {'issuer.example'}
    assert {name for name in peers.resource.server_names} == {'remote.example'}
    messages = [json.loads(body) for _, body in peers.resource.requests if body]
    assert [m['method'] for m in messages].count('server/discover') == 2
    assert [m['method'] for m in messages].count('tools/list') == 2
    assert not any(m.get('method') == 'tools/call' for m in messages)


@pytest.mark.asyncio
async def test_refresh_child_import_does_not_read_stdin_or_start_a_grant():
    script = Path(__file__).resolve().parents[1] / 'oauth_acceptance/refresh_child.py'
    child = await asyncio.create_subprocess_exec(sys.executable, '-I', '-B', '-c',
        "import runpy,sys;runpy.run_path(sys.argv[1],run_name='owned_import_probe')", str(script),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(child.communicate(b''), 15)
    except TimeoutError:
        child.kill()
        await child.wait()
        raise
    assert child.returncode == 0, stderr.decode()
    assert stdout == b''
