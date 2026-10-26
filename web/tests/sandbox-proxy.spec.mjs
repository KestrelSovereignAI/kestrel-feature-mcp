import { test, expect } from '@playwright/test';
import { createServer } from 'node:http';
import { build } from 'esbuild';
import { readFileSync } from 'node:fs';

const servers = [];
let hostOrigin, sandboxOrigin, hostBundle, proxyBundle, appBundle;
let networkRequests = [];
let operatorPolicy;
// Original geometric glyph authored for these tests; repository Apache-2.0 license.
const testFont = readFileSync(new URL('./fixtures/view-test-font.ttf', import.meta.url));

async function listen() {
    const server = createServer((request, response) => {
        const path = new URL(request.url, 'http://localhost').pathname;
        response.setHeader('Cache-Control', 'no-store');
        response.setHeader('Referrer-Policy', 'no-referrer');
        if (path.endsWith('.js')) {
            response.setHeader('Content-Type', 'text/javascript');
            return response.end(path === '/host.js' ? hostBundle : proxyBundle);
        }
        if (path === '/view-test-font.ttf') {
            networkRequests.push(request.url);
            response.setHeader('Content-Type', 'font/ttf');
            response.setHeader('Access-Control-Allow-Origin', '*');
            return response.end(testFont);
        }
        if (path === '/early-navigation') {
            networkRequests.push(request.url);
            response.setHeader('Content-Type', 'text/html');
            return response.end('<!doctype html><body>Foreign resource</body>');
        }
        if (path === '/network-probe') {
            networkRequests.push(request.url);
            response.setHeader('Access-Control-Allow-Origin', '*');
            return response.end('owned network probe');
        }
        response.setHeader('Content-Type', 'text/html');
        if (path === '/proxy') {
            return response.end(`<!doctype html><body><script type="module">
                import { startSandboxProxy } from '/proxy.js';
                window.proxyErrors = [];
                window.proxyListeners = new Set(); window.proxyRemoveCalls = 0;
                const add = window.addEventListener.bind(window), remove = window.removeEventListener.bind(window);
                window.addEventListener = (type, listener, options) => {
                    if (type === 'message') proxyListeners.add(listener);
                    return add(type, listener, options);
                };
                window.removeEventListener = (type, listener, options) => {
                    if (type === 'message') { proxyListeners.delete(listener); proxyRemoveCalls += 1; }
                    return remove(type, listener, options);
                };
                window.resourceNotifications = 0; window.viewLoads = 0;
                document.addEventListener('load', event => {
                    if (event.target.tagName === 'IFRAME') viewLoads += 1;
                }, true);
                window.disposeProxy = startSandboxProxy({
                    hostOrigin: ${JSON.stringify(hostOrigin)}, maxMessageBytes: 2 * 1024 * 1024,
                    maxHtmlBytes: 1024 * 1024, policy: ${JSON.stringify(operatorPolicy)},
                    onerror: error => proxyErrors.push(error.message),
                });
                add('message', event => {
                    if (event.data?.method === 'ui/notifications/sandbox-resource-ready') resourceNotifications += 1;
                });
            </script>`);
        }
        response.end('<!doctype html><body>Owned double-iframe test</body>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    servers.push(server);
    return 'http://127.0.0.1:' + server.address().port;
}

test.beforeAll(async () => {
    const resolveDir = process.cwd();
    const bundle = async contents => (await build({ stdin: { contents, resolveDir },
        bundle: true, platform: 'browser', format: 'esm', minify: true, write: false })).outputFiles[0].text;
    hostBundle = await bundle(`export { OriginBoundTransport } from './src/origin-transport.js';
        export { approveSandboxPolicy } from './src/sandbox-proxy.js';
        export { AppBridge } from '@modelcontextprotocol/ext-apps/app-bridge';`);
    proxyBundle = await bundle(`export { startSandboxProxy } from './src/sandbox-proxy.js';`);
    appBundle = await bundle(`import { App } from '@modelcontextprotocol/ext-apps';
        window.received = [];
        const app = new App({ name: 'Owned opaque View', version: '1.0.0' }, {});
        app.ontoolinput = params => received.push({ input: params });
        app.ontoolresult = params => received.push({ result: params });
        app.onteardown = async () => { received.push({ teardown: true }); return {}; };
        await app.connect(); window.nativeConnected = true;`);
    expect(Buffer.byteLength(appBundle)).toBeLessThan(1024 * 1024);
    hostOrigin = await listen();
    sandboxOrigin = await listen();
});

test.beforeEach(async ({ page }) => {
    networkRequests = [];
    const diagnostics = [];
    page.on('pageerror', error => diagnostics.push(error.message));
    page.on('console', message => {
        if (message.type() === 'error') diagnostics.push(message.text());
    });
    page.diagnostics = diagnostics;
});
test.afterEach(async ({ page }, info) => {
    if (info.status !== info.expectedStatus) {
        await info.attach('browser-diagnostics', { body: JSON.stringify({
            errors: page.diagnostics,
            frames: await Promise.all(page.frames().map(async frame => ({
                url: frame.url(), state: await frame.evaluate(() => ({
                    title: document.title, body: document.body?.innerText.slice(0, 300),
                    scripts: document.scripts.length, received: window.received,
                })).catch(error => ({ error: error.message })),
            }))),
        }, null, 2), contentType: 'application/json' });
    }
});
test.afterAll(async () => {
    for (const server of servers) {
        server.closeAllConnections();
        await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
});

async function mount(page, { html = '<script type="module">' + appBundle + '</script>', csp,
    sandbox = 'allow-scripts', permissions, policy = { connectDomains: [hostOrigin] }, outerAllow = '' } = {}) {
    operatorPolicy = policy;
    await page.goto(hostOrigin);
    await page.evaluate(async ({ origin, html, csp, sandbox, permissions, outerAllow }) => {
        const { OriginBoundTransport, AppBridge } = await import('/host.js');
        const proxy = document.createElement('iframe');
        proxy.id = 'proxy';
        proxy.setAttribute('sandbox', 'allow-scripts allow-same-origin');
        proxy.setAttribute('allow', outerAllow);
        document.body.append(proxy);
        window.messages = [];
        window.hostErrors = [];
        addEventListener('message', event => messages.push(event.data));
        window.bridge = new AppBridge(null, { name: 'Owned proxy host', version: '1.0.0' }, {});
        bridge.onerror = error => hostErrors.push(error.message);
        bridge.onsandboxready = () => bridge.sendSandboxResourceReady({
            html, ...(csp === undefined ? {} : { csp }),
            ...(permissions === undefined ? {} : { permissions }), sandbox,
        });
        bridge.oninitialized = () => { window.initialized = true; };
        await bridge.connect(new OriginBoundTransport({
            targetWindow: proxy.contentWindow, origin, maxMessageBytes: 2 * 1024 * 1024,
        }));
        proxy.src = origin + '/proxy';
    }, { origin: sandboxOrigin, html, csp, sandbox, permissions, outerAllow });
    await expect.poll(() => page.frames().some(frame => frame.url() === sandboxOrigin + '/proxy')).toBe(true);
    return page.frame({ url: sandboxOrigin + '/proxy' });
}

test('native App and AppBridge initialize through the mandatory proxy and opaque View', async ({ page }) => {
    const proxy = await mount(page);
    await expect.poll(() => proxy.childFrames().length).toBe(1);
    expect(await proxy.locator('iframe').getAttribute('sandbox')).toBe('allow-scripts');
    const view = proxy.childFrames()[0];
    expect(await view.evaluate(() => self.origin)).toBe('null');
    await expect.poll(async () => ({
        initialized: await page.evaluate(() => window.initialized),
        hostErrors: await page.evaluate(() => window.hostErrors),
        proxyErrors: await proxy.evaluate(() => window.proxyErrors),
    })).toEqual({ initialized: true, hostErrors: [], proxyErrors: [] });
    await expect.poll(() => view.evaluate(() => window.nativeConnected)).toBe(true);
    expect(await proxy.locator('iframe').getAttribute('sandbox')).toBe('allow-scripts');
    expect(await view.evaluate(() => self.origin)).toBe('null');
    expect(await view.evaluate(() => {
        try { return parent.document.body.textContent; } catch (error) { return error.name; }
    })).toBe('SecurityError');
    await page.evaluate(async () => {
        await bridge.sendToolInput({ arguments: { city: 'Chicago' } });
        await bridge.sendToolResult({ content: [{ type: 'text', text: 'Completed original call' }] });
    });
    await expect.poll(() => view.evaluate(() => window.received)).toEqual([
        { input: { arguments: { city: 'Chicago' } } },
        { result: { content: [{ type: 'text', text: 'Completed original call' }] } },
    ]);
    await page.evaluate(() => bridge.teardownResource({}));
    await expect.poll(() => view.evaluate(() => window.received.some(item => item.teardown))).toBe(true);
    await page.evaluate(() => bridge.close());
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual([]);
});

test('CSP denies undeclared and unapproved network domains in the actual View', async ({ page }) => {
    const html = `<script>window.probeFinished = false;
        Promise.all(${JSON.stringify([hostOrigin + '/network-probe?undeclared', sandboxOrigin + '/network-probe?unapproved'])}
            .map(url => fetch(url).then(() => 'escaped', () => 'denied')))
        .then(results => window.probeResult = results).finally(() => window.probeFinished = true);</script>`;
    const proxy = await mount(page, { html, csp: { connectDomains: [sandboxOrigin] } });
    await expect.poll(() => proxy.childFrames().length).toBe(1);
    const view = proxy.childFrames()[0];
    await expect.poll(() => view.evaluate(() => window.probeFinished)).toBe(true);
    expect(await view.evaluate(() => window.probeResult)).toEqual(['denied', 'denied']);
    expect(networkRequests).toEqual([]);
    expect(await proxy.locator('iframe').getAttribute('srcdoc')).toContain("connect-src 'none'");
});

test('a declared operator-approved domain can be used without widening other CSP directives', async ({ page }) => {
    const html = `<script>window.probeFinished = false;
        fetch(${JSON.stringify(hostOrigin + '/network-probe?approved')}).then(
            r => r.text()).then(text => window.probeResult = text
        ).finally(() => window.probeFinished = true);</script>`;
    const proxy = await mount(page, { html, csp: { connectDomains: [hostOrigin] } });
    await expect.poll(() => proxy.childFrames().length).toBe(1);
    const view = proxy.childFrames()[0];
    await expect.poll(() => view.evaluate(() => window.probeFinished)).toBe(true);
    expect(await view.evaluate(() => window.probeResult)).toBe('owned network probe');
    expect(networkRequests).toEqual(['/network-probe?approved']);
    const document = await proxy.locator('iframe').getAttribute('srcdoc');
    expect(document).toContain("frame-src 'none'");
    expect(document).toContain("base-uri 'none'");
    expect(document).toContain("object-src 'none'");
});

test('View sandbox-control spoofing is never forwarded to the host', async ({ page }) => {
    const proxy = await mount(page);
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    const view = proxy.childFrames()[0];
    await view.evaluate(() => {
        parent.postMessage({ jsonrpc: '2.0', method: 'ui/notifications/sandbox-proxy-ready', params: { spoof: true } }, '*');
        parent.postMessage({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'FIFO barrier' } }, '*');
    });
    await expect.poll(() => page.evaluate(() => messages.some(message => message.params?.data === 'FIFO barrier'))).toBe(true);
    expect(await page.evaluate(() => messages.some(message => message.params?.spoof))).toBe(false);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual([]);
});

test('host messages before initialization close the proxy instead of reaching the View', async ({ page }) => {
    const proxy = await mount(page, { html: '<script>window.incoming=[];addEventListener("message",e=>incoming.push(e.data));</script>' });
    await expect.poll(() => proxy.childFrames().length).toBe(1);
    await proxy.evaluate(() => {
        window.controlArrivals = [];
        addEventListener('message', event => controlArrivals.push(event.data.method));
    });
    await page.evaluate(origin => document.querySelector('#proxy').contentWindow.postMessage({
        jsonrpc: '2.0', method: 'ui/notifications/tool-input', params: { arguments: {} },
    }, origin), sandboxOrigin);
    await expect.poll(() => proxy.evaluate(() => window.controlArrivals.includes('ui/notifications/tool-input'))).toBe(true);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual(['Host sent a View message before initialization']);
    expect(await proxy.locator('iframe').count()).toBe(0);
});

test('a View navigation retires the proxy and its listeners', async ({ page }) => {
    const proxy = await mount(page);
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    await expect.poll(() => proxy.evaluate(() => window.viewLoads)).toBe(1);
    const view = proxy.childFrames()[0];
    await view.evaluate(() => { location.href = 'about:blank'; });
    await expect.poll(() => proxy.evaluate(() => window.viewLoads)).toBe(2);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual(['Sandbox View navigated away from its original resource']);
    expect(await proxy.locator('iframe').count()).toBe(0);
});

test('HTML byte limits and opaque-origin sandbox restrictions fail before loading content', async ({ page }) => {
    let proxy = await mount(page, { html: '字'.repeat(400_000) });
    await expect.poll(() => proxy.evaluate(() => window.resourceNotifications)).toBe(1);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual(['Sandbox HTML exceeds its byte limit']);
    expect(await proxy.locator('iframe').count()).toBe(0);
    proxy = await mount(page, { sandbox: 'allow-scripts allow-same-origin' });
    await expect.poll(() => proxy.evaluate(() => window.resourceNotifications)).toBe(1);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual(['The View must retain an opaque sandbox origin']);
    expect(await proxy.locator('iframe').count()).toBe(0);
});

test('a sibling frame cannot replace the original View and explicit disposal removes the listener', async ({ page }) => {
    const proxy = await mount(page);
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    await proxy.evaluate(() => {
        window.arrivals = [];
        addEventListener('message', event => arrivals.push(event.data));
    });
    await page.evaluate(async () => {
        const sibling = document.createElement('iframe');
        sibling.id = 'sibling';
        const loaded = new Promise(resolve => sibling.addEventListener('load', resolve, { once: true }));
        sibling.src = '/';
        document.body.append(sibling);
        await loaded;
    });
    const sibling = page.frames().find(frame => frame.parentFrame() === page.mainFrame() && frame.url() === hostOrigin + '/');
    await sibling.evaluate(origin => {
        parent.document.querySelector('#proxy').contentWindow.postMessage({
            jsonrpc: '2.0', method: 'ui/notifications/sandbox-resource-ready',
            params: { html: '<p>attacker replacement</p>' },
        }, origin);
    }, sandboxOrigin);
    await expect.poll(() => proxy.evaluate(() => window.arrivals.some(item => item.params?.html?.includes('attacker replacement')))).toBe(true);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual([]);
    expect(await proxy.locator('iframe').getAttribute('srcdoc')).not.toContain('attacker replacement');
    await proxy.evaluate(() => { disposeProxy(); disposeProxy(); });
    expect(await proxy.evaluate(() => proxyListeners.size)).toBe(1); // only this test's arrival observer
    expect(await proxy.evaluate(() => proxyRemoveCalls)).toBe(1);
    await page.evaluate(origin => document.querySelector('#proxy').contentWindow.postMessage({
        jsonrpc: '2.0', method: 'ui/notifications/sandbox-resource-ready', params: { html: '<p>revival</p>' },
    }, origin), sandboxOrigin);
    await expect.poll(() => proxy.evaluate(() => window.arrivals.some(item => item.params?.html === '<p>revival</p>'))).toBe(true);
    expect(await proxy.locator('iframe').count()).toBe(0);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual([]);
});

test('the original resource cannot be replaced by a second host resource notification', async ({ page }) => {
    const proxy = await mount(page);
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    await page.evaluate(() => bridge.sendSandboxResourceReady({ html: '<p>replacement</p>' }));
    await expect.poll(() => proxy.evaluate(() => window.resourceNotifications)).toBe(2);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual(['Sandbox resource cannot be replaced']);
    expect(await proxy.locator('iframe').count()).toBe(0);
});

test('an opaque descendant cannot impersonate the original View', async ({ page }) => {
    const proxy = await mount(page);
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    await proxy.evaluate(() => {
        window.childMessages = [];
        addEventListener('message', event => childMessages.push(event.data));
    });
    const view = proxy.childFrames()[0];
    await view.evaluate(() => {
        const child = document.createElement('iframe');
        child.srcdoc = `<script>parent.parent.postMessage({ jsonrpc: '2.0', method: 'notifications/message',
            params: { level: 'info', data: 'forged descendant' } }, '*');<\/script>`;
        document.body.append(child);
    });
    await expect.poll(() => proxy.evaluate(() => childMessages.some(item => item.params?.data === 'forged descendant'))).toBe(true);
    await view.evaluate(() => parent.postMessage({ jsonrpc: '2.0', method: 'notifications/message',
        params: { level: 'info', data: 'original View barrier' } }, '*'));
    await expect.poll(() => page.evaluate(() => messages.some(item => item.params?.data === 'original View barrier'))).toBe(true);
    expect(await page.evaluate(() => messages.some(item => item.params?.data === 'forged descendant'))).toBe(false);
});

test('resource metadata cannot grant device permissions and malformed operator policy fails clearly', async ({ page }) => {
    const proxy = await mount(page, { permissions: { camera: {}, microphone: {}, geolocation: {} } });
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    const view = proxy.childFrames()[0];
    expect(await proxy.locator('iframe').getAttribute('allow')).toBe('');
    expect(await view.evaluate(() => ['camera', 'microphone', 'geolocation'].map(name => document.featurePolicy.allowsFeature(name)))).toEqual([false, false, false]);
    const errors = await page.evaluate(async () => {
        const { approveSandboxPolicy } = await import('/host.js');
        return [null, { connectDomains: 'https://example.com' },
            { connectDomains: ['https://example.com/path'] }, { permissions: 'camera' },
            { permissions: ['unknown-device'] }, { unexpected: true }].map(policy => {
            try { approveSandboxPolicy({}, {}, policy); return null; }
            catch (error) { return error.name; }
        });
    });
    expect(errors).toEqual(Array(6).fill('TypeError'));
});

for (const method of ['script', 'meta']) {
    test(`early ${method} navigation cannot replace the opaque resource before its first load`, async ({ page }) => {
        const target = hostOrigin + '/early-navigation?' + method;
        const html = method === 'script'
            ? `<script>location.href = ${JSON.stringify(target)};<\/script>`
            : `<meta http-equiv="refresh" content="0; url=${target}">`;
        const proxy = await mount(page, { html });
        await expect.poll(() => proxy.evaluate(() => window.viewLoads)).toBeGreaterThanOrEqual(1);
        expect(networkRequests).toEqual([]);
        const [view] = proxy.childFrames();
        if (view) {
            expect(view.url()).not.toMatch(/^https?:/);
            // Chromium may replace a refused navigation with its inert error page.
            expect(await view.evaluate(() => self.origin)).toBe('null');
        } else {
            expect(await proxy.evaluate(() => window.proxyErrors)).toEqual([
                'Sandbox View navigated away from its original resource',
            ]);
        }
    });
}


test('a resource head CSP can further restrict an approved host grant', async ({ page }) => {
    const html = `<!doctype html><html><head>
        <meta http-equiv="Content-Security-Policy" content="connect-src 'none'">
        </head><body><script>
        fetch(${JSON.stringify(hostOrigin + '/network-probe?resource-policy')}).then(
            () => window.resourcePolicyResult = 'escaped',
            () => window.resourcePolicyResult = 'denied');<\/script></body></html>`;
    const proxy = await mount(page, { html, csp: { connectDomains: [hostOrigin] } });
    await expect.poll(() => proxy.childFrames().length).toBe(1);
    const view = proxy.childFrames()[0];
    await expect.poll(() => view.evaluate(() => window.resourcePolicyResult)).toBeTruthy();
    expect(await view.evaluate(() => window.resourcePolicyResult)).toBe('denied');
    expect(networkRequests).toEqual([]);
});

test('noncanonical resource origin requests are denied without discarding a valid View', async ({ page }) => {
    const proxy = await mount(page, { csp: { connectDomains: [hostOrigin + '/'] } });
    await expect.poll(() => proxy.evaluate(() => window.resourceNotifications)).toBe(1);
    expect(await proxy.evaluate(() => window.proxyErrors)).toEqual([]);
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    expect(await proxy.locator('iframe').getAttribute('srcdoc')).toContain("connect-src 'none'");
});

test('operator frame grants fail clearly when the proxy cannot support them', async ({ page }) => {
    await page.goto(hostOrigin);
    const error = await page.evaluate(async origin => {
        const { approveSandboxPolicy } = await import('/host.js');
        try { approveSandboxPolicy({}, {}, { frameDomains: [origin] }); return null; }
        catch (error) { return error.message; }
    }, hostOrigin);
    expect(error).toBe('Sandbox proxy does not support nested network frame grants');
});


test('an approved resource domain can supply an actual View font', async ({ page }) => {
    const url = hostOrigin + '/view-test-font.ttf';
    const html = `<script>const face = new FontFace('OwnedTest', ${JSON.stringify('url(' + url + ')')});
        face.load().then(() => window.fontResult = face.status, () => window.fontResult = 'denied');<\/script>`;
    const proxy = await mount(page, { html, csp: { resourceDomains: [hostOrigin] },
        policy: { resourceDomains: [hostOrigin] } });
    await expect.poll(() => proxy.childFrames().length).toBe(1);
    const view = proxy.childFrames()[0];
    await expect.poll(() => view.evaluate(() => window.fontResult)).toBeTruthy();
    expect(await view.evaluate(() => window.fontResult)).toBe('loaded');
    expect(networkRequests).toEqual(['/view-test-font.ttf']);
});

test('an operator-approved device is delegated to the opaque View without granting others', async ({ page }) => {
    const proxy = await mount(page, { permissions: { camera: {}, microphone: {} },
        policy: { permissions: ['camera'] }, outerAllow: 'camera ' + sandboxOrigin });
    await expect.poll(() => page.evaluate(() => window.initialized)).toBe(true);
    const view = proxy.childFrames()[0];
    // This exercises browser delegation only; it never opens a physical device.
    expect(await view.evaluate(() => ['camera', 'microphone', 'geolocation'].map(
        name => document.featurePolicy.allowsFeature(name)))).toEqual([true, false, false]);
});
