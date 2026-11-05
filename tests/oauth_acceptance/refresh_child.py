"""Synthetic-only subprocess for the owned OAuth HTTPS feasibility test."""
import asyncio
import json
import logging
import os
from pathlib import Path
import socket
import sys
import time
from urllib.parse import urlsplit

import httpcore2
import httpx2
from kestrel_sdk.security.outbound import assert_safe_url, pinned_httpx2_async_transport
from kestrel_feature_mcp.connection import MCPConnection
from kestrel_feature_mcp.oauth_grants import OAuthGrantBinding, OAuthGrantStore
from kestrel_feature_mcp.oauth_refresh import OAuthRefresher
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend


async def with_store(config, store, binding):
    resource = config['resource']
    server_url = config['server_url']
    issuer = config['issuer']
    authorities = {(urlsplit(url).hostname, urlsplit(url).port) for url in (server_url, issuer)}
    assert {name for name, _ in authorities} == {'remote.example', 'issuer.example'}
    ports = {port for _, port in authorities}
    original_dial = httpcore2.AnyIOBackend.connect_tcp

    def resolve(host, port, *, type, proto):
        assert (host, port) in authorities
        return [(socket.AF_INET, type, proto, '', ('8.8.8.8', port))]

    async def dial(backend, host, port, **kwargs):
        assert host == '8.8.8.8' and port in ports
        return await original_dial(backend, '127.0.0.1', port, **kwargs)

    socket.getaddrinfo = resolve
    httpcore2.AnyIOBackend.connect_tcp = dial
    os.environ['SSL_CERT_FILE'] = config['certificate']
    os.environ.pop('SSL_CERT_DIR', None)
    metadata = await store.read(binding)
    snapshot = await store.read_tokens(metadata)
    assert snapshot is not None and snapshot.state == 'active'
    token = snapshot.tokens
    saved = dict(access_token=token.access_token, refresh_token=token.refresh_token,
        token_type='Bearer', expires_at=token.expires_at, expires_in=3600,
        scope=' '.join(sorted(token.scopes)))
    assert saved['access_token'] in {'fixture-expired-access', 'native-fixture-access'}
    assert saved['refresh_token'] in {'native-fixture-refresh', 'native-fixture-rotated'}
    if config['phase'] == 'fresh':
        assert saved['refresh_token'] == config['expected_refresh_token']
    expiry = saved['expires_at']
    expired = token.is_expired(time.time())
    preserved_expiry = token.expires_at == expiry
    assert preserved_expiry
    assert expired is (config['phase'] == 'expired')
    if expired:
        owner = OAuthRefresher(store, {'network_seconds': 5, 'response_max_bytes': 65536}, close_seconds=5)
        try:
            refreshed = await owner.run(metadata, lambda: None)
            current = await store.read_tokens(refreshed)
            assert current.tokens.access_token == 'native-fixture-access'
            assert current.tokens.scopes == frozenset({'read'})
            assert current.tokens.expires_at > time.time()
            assert current.tokens.refresh_token == config['expected_refresh_token']
            saved = dict(access_token=current.tokens.access_token)
        finally:
            await owner.retire()
    resource_endpoint = await assert_safe_url(server_url, allowed_schemes=('https',))
    connection = MCPConnection(resource_endpoint,
        headers={'Authorization': 'Bearer ' + saved['access_token']},
        connect_timeout=5, call_timeout=5, close_timeout=5)
    try:
        tools = await connection.connect()
        assert len(tools) == 2 and connection.protocol_version == '2026-07-28'
        return dict(phase=config['phase'], expired_on_restore=expired,
            refresh_performed=expired, absolute_expiry_preserved=preserved_expiry,
            encrypted_grant_restored=True,
            tools=len(tools), protocol=connection.protocol_version)
    finally:
        await connection.close()


async def main(config):
    path = Path(config['grant_file'])
    assert path.is_relative_to(Path(config['owned_root']))
    binding = OAuthGrantBinding('did:test:refresh-owner', 'fixture-operator', 'fixture-connection',
        config['server_url'], config['resource'], config['issuer'], config['client_id'],
        config['redirect_uri'], frozenset({'read'}), config['protected_metadata'], config['authorization_metadata'])
    database = SQLiteBackend(str(path))
    await database.connect()
    try:
        store = OAuthGrantStore(database, binding.agent_did, max_token_bytes=4096)
        await store.initialize()
        return await with_store(config, store, binding)
    finally:
        await database.close()


if __name__ == '__main__':
    logging.disable(logging.CRITICAL)
    print(json.dumps(asyncio.run(main(json.loads(sys.stdin.read())))))
