import { test, expect } from '@playwright/test';
import { createServer } from 'node:http';
import { build } from 'esbuild';

const servers = [];
let hostOrigin, sandboxOrigin, hostBundle, appBundle;

async function listen() {
    const server = createServer((request, response) => {
        const path = new URL(request.url, 'http://localhost').pathname;
        response.setHeader('Cache-Control', 'no-store');
        if (path === '/host.js') {
            response.setHeader('Content-Type', 'text/javascript');
            return response.end(hostBundle);
        }
        if (path === '/app.js') {
            response.setHeader('Content-Type', 'text/javascript');
            return response.end(appBundle);
        }
        response.setHeader('Content-Type', 'text/html');
        if (path === '/peer.html' || path === '/app-peer.html') {
            return response.end(`<!doctype html><script>
                window.incoming = [];
                addEventListener('message', event => incoming.push(event.data));
            </script>${path === '/app-peer.html' ? '<script type="module" src="/app.js"></script>' : ''}`);
        }
        response.end('<!doctype html><body>Owned MCP transport test</body>');
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    servers.push(server);
    return 'http://127.0.0.1:' + server.address().port;
}

test.beforeAll(async () => {
    const resolveDir = process.cwd();
    const host = await build({
        stdin: {
            contents: `export { OriginBoundTransport } from './src/origin-transport.js';
                       export { AppBridge } from '@modelcontextprotocol/ext-apps/app-bridge';`,
            resolveDir,
        },
        bundle: true, format: 'esm', platform: 'browser', write: false,
    });
    hostBundle = host.outputFiles[0].contents;
    const app = await build({
        stdin: {
            contents: `import { App } from '@modelcontextprotocol/ext-apps';
                const app = new App({ name: 'Native Apps peer', version: '1.0.0' }, {});
                await app.connect(); window.nativeAppConnected = true;`,
            resolveDir,
        },
        bundle: true, format: 'esm', platform: 'browser', write: false,
    });
    appBundle = app.outputFiles[0].contents;
    hostOrigin = await listen();
    sandboxOrigin = await listen();
});

test.afterAll(async () => {
    for (const server of servers) {
        server.closeAllConnections();
        await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
});

async function openTransport(page, limit = 64 * 1024) {
    await page.goto(hostOrigin);
    await page.evaluate(async ({ origin, limit }) => {
        const { OriginBoundTransport } = await import('/host.js');
        window.accepted = [];
        window.errors = [];
        window.arrived = [];
        addEventListener('message', event => window.arrived.push(event.data?.id));
        const iframe = document.createElement('iframe');
        iframe.id = 'sandbox';
        document.body.append(iframe);
        window.transport = new OriginBoundTransport({
            targetWindow: iframe.contentWindow, origin, maxMessageBytes: limit,
        });
        window.transport.onmessage = message => window.accepted.push(message);
        window.transport.onerror = error => window.errors.push(error.name);
        await window.transport.start();
        const loaded = new Promise(resolve => iframe.addEventListener('load', resolve, { once: true }));
        iframe.src = origin + '/peer.html';
        await loaded;
    }, { origin: sandboxOrigin, limit });
    return page.frame({ url: sandboxOrigin + '/peer.html' });
}

test('only the bound window and exact origin can deliver MCP messages', async ({ page }) => {
    const peer = await openTransport(page);
    await peer.evaluate(origin => parent.postMessage({ jsonrpc: '2.0', method: 'ping', id: 1 }, origin), hostOrigin);
    await expect.poll(() => page.evaluate(() => window.accepted.map(m => m.id))).toEqual([1]);
    await page.evaluate(async origin => {
        const rogue = document.createElement('iframe');
        rogue.id = 'rogue';
        const loaded = new Promise(resolve => rogue.addEventListener('load', resolve, { once: true }));
        rogue.src = origin + '/peer.html';
        document.body.append(rogue);
        await loaded;
    }, sandboxOrigin);
    const rogue = page.frames().find(frame => frame !== peer && frame.url() === sandboxOrigin + '/peer.html');
    await rogue.evaluate(origin => parent.postMessage({ jsonrpc: '2.0', method: 'ping', id: 2 }, origin), hostOrigin);
    await expect.poll(() => page.evaluate(() => window.arrived.includes(2))).toBe(true);
    expect(await page.evaluate(() => window.accepted.map(m => m.id))).toEqual([1]);

    // A WindowProxy survives navigation; an origin check must survive it too.
    await peer.goto(hostOrigin + '/peer.html');
    await peer.evaluate(origin => parent.postMessage({ jsonrpc: '2.0', method: 'ping', id: 3 }, origin), hostOrigin);
    await expect.poll(() => page.evaluate(() => window.arrived.includes(3))).toBe(true);
    expect(await page.evaluate(() => window.accepted.map(m => m.id))).toEqual([1]);
});

test('outgoing messages use the exact target origin after navigation', async ({ page }) => {
    const peer = await openTransport(page);
    await page.evaluate(() => window.transport.send({ jsonrpc: '2.0', id: 4, result: {} }));
    await expect.poll(() => peer.evaluate(() => window.incoming.map(m => m.id))).toContain(4);
    await peer.goto(hostOrigin + '/peer.html');
    await page.evaluate(async origin => {
        await window.transport.send({ jsonrpc: '2.0', id: 5, result: {} });
        // Same-sender, same-window FIFO barrier: the preceding message would
        // be visible before this one if send used a wildcard target origin.
        document.querySelector('#sandbox').contentWindow.postMessage({ barrier: true }, origin);
    }, hostOrigin);
    await expect.poll(() => peer.evaluate(() => window.incoming.some(m => m.barrier))).toBe(true);
    expect(await peer.evaluate(() => window.incoming.some(m => m.id === 5))).toBe(false);
});

test('invalid JSON and oversized UTF-8 payloads never reach protocol handlers', async ({ page }) => {
    const peer = await openTransport(page, 256);
    await peer.evaluate(origin => {
        const messages = [
            { jsonrpc: '2.0', id: 10, method: 42 },
            { jsonrpc: '2.0', id: 11, method: 'ping', params: { text: '字'.repeat(80) } },
            { jsonrpc: '2.0', id: 12, method: 'ping', params: { value: NaN } },
            { jsonrpc: '2.0', id: 13, method: 'ping', params: { value: 1n } },
        ];
        const cycle = { jsonrpc: '2.0', id: 14, method: 'ping' };
        cycle.params = { cycle };
        messages.push(cycle);
        for (const message of messages) parent.postMessage(message, origin);
    }, hostOrigin);
    await expect.poll(() => page.evaluate(() => window.arrived.includes(14))).toBe(true);
    expect(await page.evaluate(() => window.errors.length)).toBe(5);
    expect(await page.evaluate(() => window.accepted)).toEqual([]);
});

test('closing removes the listener and cannot revive the old transport', async ({ page }) => {
    const peer = await openTransport(page);
    await page.evaluate(async () => {
        window.closedCount = 0;
        window.transport.onclose = () => { window.closedCount += 1; };
        await window.transport.close();
        await window.transport.close();
    });
    await peer.evaluate(origin => parent.postMessage({ jsonrpc: '2.0', method: 'ping', id: 20 }, origin), hostOrigin);
    await expect.poll(() => page.evaluate(() => window.arrived.includes(20))).toBe(true);
    expect(await page.evaluate(() => window.accepted)).toEqual([]);
    expect(await page.evaluate(() => window.closedCount)).toBe(1);
    await expect(page.evaluate(() => window.transport.start())).rejects.toThrow('cannot be restarted');
    await expect(page.evaluate(() => window.transport.send({ jsonrpc: '2.0', id: 21, result: {} })))
        .rejects.toThrow('not active');
});

test('sandbox origin and byte limits are validated before transport startup', async ({ page }) => {
    await page.goto(hostOrigin);
    const result = await page.evaluate(async sandbox => {
        const { OriginBoundTransport } = await import('/host.js');
        const refused = options => {
            try {
                new OriginBoundTransport({ targetWindow: window, ...options });
                return null;
            } catch (error) {
                return error.name;
            }
        };
        return {
            sameOrigin: refused({ origin: location.origin, maxMessageBytes: 256 }),
            path: refused({ origin: sandbox + '/path', maxMessageBytes: 256 }),
            limits: [0, -1, NaN, Infinity, 1.5].map(limit => refused({
                origin: sandbox, maxMessageBytes: limit,
            })),
        };
    }, sandboxOrigin);
    expect(result).toEqual({
        sameOrigin: 'TypeError', path: 'TypeError', limits: Array(5).fill('TypeError'),
    });
});

test('the current official App and AppBridge complete their native handshake', async ({ page }) => {
    await page.goto(hostOrigin);
    await page.evaluate(async origin => {
        const { OriginBoundTransport, AppBridge } = await import('/host.js');
        const iframe = document.createElement('iframe');
        document.body.append(iframe);
        const bridge = new AppBridge(null, { name: 'Kestrel transport proof', version: '1.0.0' }, {});
        bridge.oninitialized = () => { window.nativeBridgeReady = true; };
        window.bridge = bridge;
        await bridge.connect(new OriginBoundTransport({
            targetWindow: iframe.contentWindow, origin, maxMessageBytes: 64 * 1024,
        }));
        iframe.src = origin + '/app-peer.html';
    }, sandboxOrigin);
    await expect.poll(() => page.evaluate(() => window.nativeBridgeReady)).toBe(true);
    const peer = page.frame({ url: sandboxOrigin + '/app-peer.html' });
    await expect.poll(() => peer.evaluate(() => window.nativeAppConnected)).toBe(true);
    await page.evaluate(() => window.bridge.close());
});
