import test from 'node:test';
import assert from 'node:assert/strict';
import { createSandboxService } from '../src/sandbox-service.js';
import { validateSandboxConfig } from '../src/sandbox-config.js';

const config = () => ({ hostOrigin: 'https://host.example', maxMessageBytes: 8 * 1024 * 1024,
    maxHtmlBytes: 1024 * 1024, policy: {} });

async function withService(operation) {
    const initial = config();
    const server = createSandboxService({ config: initial, entryJavascript: 'export const owned = true;', thirdPartyNotices: 'Owned test assets' });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try { await operation('http://127.0.0.1:' + server.address().port, initial); }
    finally {
        server.closeAllConnections();
        await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
}

test('public sandbox config is snapshotted and allows only the configured host', async () => {
    await withService(async (origin, initial) => {
        initial.policy.connectDomains = ['https://attacker.example'];
        initial.hostOrigin = 'https://attacker.example';
        const response = await fetch(origin + '/config', { headers: { Origin: 'https://host.example' } });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), config());
        assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://host.example');
        assert.equal(response.headers.get('Access-Control-Allow-Credentials'), null);
        const denied = await fetch(origin + '/config', { headers: { Origin: 'https://attacker.example' } });
        assert.equal(denied.status, 403);
        assert.equal(denied.headers.get('Access-Control-Allow-Origin'), null);
    });
});

test('sandbox documents restrict framing and never set identity state', async () => {
    await withService(async origin => {
        for (const path of ['/proxy', '/sandbox-entry.js', '/config', '/health', '/THIRD_PARTY_NOTICES.txt']) {
            const response = await fetch(origin + path);
            assert.equal(response.status, 200);
            assert.equal(response.headers.get('Set-Cookie'), null);
            assert.equal(response.headers.get('Cache-Control'), 'no-store');
            assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer');
            assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
            assert.equal(response.headers.get('Origin-Agent-Cluster'), '?1');
            assert.match(response.headers.get('Content-Security-Policy'), /frame-ancestors https:\/\/host.example/);
            assert.match(response.headers.get('Content-Security-Policy'), /frame-src 'none'/);
            assert.doesNotMatch(response.headers.get('Content-Security-Policy'), /(?:default|script|connect)-src|base-uri/);
            assert.equal(response.headers.get('Permissions-Policy'), 'camera=(), microphone=(), geolocation=(), clipboard-write=()');
        }
        const response = await fetch(origin + '/proxy');
        const html = await response.text();
        assert.match(html, /type="application\/json" id="sandbox-config"/);
        assert.match(html, /src="\/sandbox-entry.js"/);
        assert.doesNotMatch(html, /allow-same-origin/);
    });
});

test('credentials are refused on every route rather than creating a sandbox auth lane', async () => {
    await withService(async origin => {
        for (const path of ['/proxy', '/sandbox-entry.js', '/config', '/health', '/THIRD_PARTY_NOTICES.txt']) {
            for (const headers of [{ Cookie: 'operator=secret' }, { Authorization: 'Bearer secret' }, { 'X-API-Key': 'secret' }]) {
                const response = await fetch(origin + path, { headers });
                assert.equal(response.status, 400);
                assert.equal(response.headers.get('Set-Cookie'), null);
                assert.doesNotMatch(await response.text(), /secret/);
            }
        }
    });
});

test('only the fixed read-only resources are served', async () => {
    await withService(async origin => {
        assert.equal((await fetch(origin + '/proxy', { method: 'POST', body: 'untrusted' })).status, 405);
        for (const path of ['/config?token=secret', '/.env', '/api/agent/invoke', '/other']) {
            assert.equal((await fetch(origin + path)).status, 404);
        }
        const response = await fetch(origin + '/proxy', { method: 'HEAD' });
        assert.equal(response.status, 200);
        assert.equal(await response.text(), '');
    });
});

for (const changes of [
    { hostOrigin: 'https://host.example/' }, { hostOrigin: 'data:text/html,hi' },
    { maxMessageBytes: 0 }, { maxHtmlBytes: 1.5 }, { unexpected: true },
    { policy: { permissions: ['unrecognized'] } }, { policy: { frameDomains: ['https://frames.example'] } },
]) {
    test('invalid sandbox configuration fails before creating a listener: ' + JSON.stringify(changes), () => {
        assert.throws(() => validateSandboxConfig({ ...config(), ...changes }), TypeError);
    });
}


test('HTTP limits are configurable and malformed limits fail before listening', () => {
    const server = createSandboxService({ config: config(), entryJavascript: 'export {};', thirdPartyNotices: 'Owned test assets',
        httpLimits: { requestTimeoutMs: 1234, headersTimeoutMs: 2345, keepAliveTimeoutMs: 3456 } });
    assert.equal(server.requestTimeout, 1234);
    assert.equal(server.headersTimeout, 2345);
    assert.equal(server.keepAliveTimeout, 3456);
    for (const httpLimits of [null, [], { requestTimeoutMs: 0 }, { unexpected: 10 }]) {
        assert.throws(() => createSandboxService({ config: config(), entryJavascript: 'export {};', thirdPartyNotices: 'Owned test assets', httpLimits }), TypeError);
    }
    assert.throws(() => createSandboxService({ config: config(), entryJavascript: '' }), TypeError);
});
