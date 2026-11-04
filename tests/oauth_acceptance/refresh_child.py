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
from authlib.integrations.httpx_client import AsyncOAuth2Client
from kestrel_sdk.security.outbound import assert_safe_url, pinned_httpx2_async_transport
from kestrel_feature_mcp.connection import MCPConnection


async def main(config):
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
    path = Path(config['grant_file'])
    assert path.is_relative_to(Path(config['owned_root']))
    saved = json.loads(path.read_text())
    assert saved['access_token'] in {'fixture-expired-access', 'native-fixture-access'}
    assert saved['refresh_token'] in {'native-fixture-refresh', 'native-fixture-rotated'}
    expiry = saved['expires_at']
    # Discovery uses separate pinned origins with no credentials. The returned
    # issuer and token endpoint must match the independently configured grant.
    documents = []
    for url in (config['protected_metadata'], config['authorization_metadata']):
        endpoint = await assert_safe_url(url, allowed_schemes=('https',))
        async with httpx2.AsyncClient(transport=pinned_httpx2_async_transport(endpoint),
            trust_env=False, follow_redirects=False, timeout=5) as client:
            response = await client.get(url)
            assert response.status_code == 200
            documents.append(response.json())
    protected, authorization = documents
    assert protected['resource'] == resource and protected['authorization_servers'] == [issuer]
    assert authorization['issuer'] == issuer
    endpoint_url = authorization['token_endpoint']
    assert endpoint_url == issuer + '/token'
    endpoint = await assert_safe_url(endpoint_url, allowed_schemes=('https',))
    async with AsyncOAuth2Client(client_id=config['client_id'],
        token_endpoint_auth_method='none', token=saved, scope='read',
        transport=pinned_httpx2_async_transport(endpoint), trust_env=False,
        follow_redirects=False, timeout=5) as client:
        expired = client.token.is_expired(leeway=0)
        preserved_expiry = client.token['expires_at'] == expiry
        assert preserved_expiry
        assert expired is (config['phase'] == 'expired')
        if expired:
            refreshed = await client.refresh_token(endpoint_url,
                refresh_token=saved['refresh_token'], scope='read', resource=resource)
            assert refreshed['access_token'] == 'native-fixture-access'
            assert frozenset(refreshed['scope'].split()) == frozenset({'read'})
            assert refreshed['expires_at'] > time.time()
            assert refreshed['refresh_token'] == config['expected_refresh_token']
            saved = dict(refreshed)
            path.write_text(json.dumps(saved))
    resource_endpoint = await assert_safe_url(server_url, allowed_schemes=('https',))
    connection = MCPConnection(resource_endpoint,
        headers={'Authorization': 'Bearer ' + saved['access_token']},
        connect_timeout=5, call_timeout=5, close_timeout=5)
    try:
        tools = await connection.connect()
        assert len(tools) == 2 and connection.protocol_version == '2026-07-28'
        return dict(phase=config['phase'], expired_on_restore=expired,
            refresh_performed=expired, absolute_expiry_preserved=preserved_expiry,
            tools=len(tools), protocol=connection.protocol_version)
    finally:
        await connection.close()


logging.disable(logging.CRITICAL)
print(json.dumps(asyncio.run(main(json.loads(sys.stdin.read())))))
