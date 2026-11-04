"""Actual independent AS/resource TLS with two fresh clients per grant."""
import asyncio
import json
import os
from pathlib import Path
import sys
import time

import pytest

from tests.unit.test_oauth_acceptance_http import oauth_peers  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True)
@pytest.mark.parametrize('oauth_peers', [
    {'refresh': True, 'refresh_rotate': True},
    {'refresh': True, 'refresh_rotate': False},
], indirect=True)
async def test_public_authlib_refresh_survives_two_fresh_processes(oauth_peers, tmp_path):
    peers = oauth_peers
    selection = peers.selection
    path = tmp_path / 'synthetic-grant.json'
    expired = {'access_token': 'fixture-expired-access', 'refresh_token': 'native-fixture-refresh',
        'token_type': 'Bearer', 'expires_in': 3600, 'expires_at': int(time.time()) - 300,
        'scope': 'read'}
    path.write_text(json.dumps(expired))
    config = dict(server_url=selection.server_url, resource=selection.resource, issuer=selection.issuer,
        protected_metadata=selection.protected_metadata,
        authorization_metadata=selection.authorization_metadata,
        client_id=selection.client_id,
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
    assert peers.requests.count(('POST', '/token')) == 1
    assert ('GET', '/authorize') not in peers.requests and not peers.browser_requests
    assert peers.resource.witness == []
    assert {name for name in peers.issuer.server_names} == {'issuer.example'}
    assert {name for name in peers.resource.server_names} == {'remote.example'}
    messages = [json.loads(body) for _, body in peers.resource.requests if body]
    assert [m['method'] for m in messages].count('server/discover') == 2
    assert [m['method'] for m in messages].count('tools/list') == 2
    assert not any(m.get('method') == 'tools/call' for m in messages)
