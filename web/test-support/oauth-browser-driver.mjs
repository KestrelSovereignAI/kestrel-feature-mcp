import { chromium, expect } from '@playwright/test';
import { createInterface } from 'node:readline';

const input = createInterface({ input: process.stdin });
const lines = input[Symbol.asyncIterator]();
const configuration = JSON.parse((await lines.next()).value);
const origin = process.argv[2];
const browser = await chromium.launch({ args: [
    '--host-resolver-rules=MAP console.example 127.0.0.1, MAP issuer.example 127.0.0.1, MAP remote.example 127.0.0.1',
] });
try {
    const page = await browser.newPage({ ignoreHTTPSErrors: true });
    const errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => requests.push({ url: request.url(), method: request.method(), headers: request.headers() }));
    await page.goto(origin + '/#key=' + encodeURIComponent(configuration.key));
    await page.waitForFunction(() => window.ownedOAuthReady);
    if (configuration.agent_name) {
        await page.evaluate(async name => {
            const { default: api } = await import('/js/api.js');
            api.setHostAgent(name);
        }, configuration.agent_name);
        await page.getByRole('button', { name: 'Refresh connections', exact: true }).click();
    }
    await expect(page.getByRole('status')).toHaveText('No saved connectors for your account.');
    await page.getByLabel('MCP server URL', { exact: true }).fill(configuration.server);
    await page.getByLabel('Scopes', { exact: true }).fill('read');
    await page.getByRole('button', { name: 'Authorize connector', exact: true }).click();
    await page.waitForURL(url => url.origin === origin && url.pathname === '/oauth/mcp/callback');
    if (configuration.mode === 'hosted-consent') {
        await expect(page.locator('#oauth-status')).toContainText('Authorization response received.');
        expect(new URL(page.url()).search).toBe('');
        expect(requests.filter(request => request.method === 'POST' && new URL(request.url).pathname.endsWith('/callback'))).toHaveLength(1);
        for (const request of requests.filter(request => request.method === 'POST'
            && /\/(?:authorizations|callback)$/.test(new URL(request.url).pathname))) {
            expect(new URL(request.url).pathname.startsWith(configuration.agent_prefix + '/api/mcp/oauth/')).toBe(true);
        }
        expect(errors).toEqual([]);
        process.stdout.write(JSON.stringify({ original_hosted_agent: true, callback_once: true }) + '\n');
        input.close();
        await browser.close();
        process.exit(0);
    }
    if (configuration.mode === 'exchange-error') {
        await expect(page.locator('#oauth-status')).toContainText('Authorization could not be completed.');
        expect(new URL(page.url()).search).toBe('');
        await expect(page.getByRole('link', { name: 'Return to Console' })).toBeVisible();
        await page.getByRole('link', { name: 'Return to Console' }).click();
        await page.waitForFunction(() => window.ownedOAuthReady);
        await expect(page.getByText('Authorization outcome uncertain', { exact: true })).toBeVisible();
        expect(requests.filter(request => request.method === 'POST' && new URL(request.url).pathname.endsWith('/callback'))).toHaveLength(1);
        expect(errors).toEqual([]);
        process.stdout.write(JSON.stringify({ safe_console_return: true, unknown_outcome_visible: true, callback_once: true }) + '\n');
        input.close();
        await browser.close();
        process.exit(0);
    }
    await expect(page.locator('#oauth-status')).toContainText('Authorization response received.');
    expect(new URL(page.url()).search).toBe('');
    expect(await page.evaluate(() => Object.keys(sessionStorage).filter(key => key.startsWith('kestrel.mcp-oauth.')))).toEqual([]);
    await page.getByRole('link', { name: 'Return to Console' }).click();
    await page.waitForFunction(() => window.ownedOAuthReady);
    await expect(page.getByText('Authorized; ready to connect', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await expect(page.getByText('Connected', { exact: true })).toBeVisible();
    const name = await page.evaluate(async () => {
        const { default: api } = await import('/js/api.js');
        const value = await api.requestHost('/api/mcp/oauth/connections', {}, true);
        return value.connections[0].connection_id;
    });
    process.stdout.write(JSON.stringify({ phase: 'connected', name }) + '\n');
    const permission = JSON.parse((await lines.next()).value);
    expect(permission.approved).toBe(true);
    const result = await page.evaluate(async () => {
        const { default: api } = await import('/js/api.js');
        return api.requestHost('/api/owned-credential-call', { method: 'POST' }, true);
    });
    expect(result).toBeTruthy();
    await page.evaluate(async () => {
        const { bus } = await import('/js/ui-ext/bus.js');
        bus.emit('auth:change');
    });
    await expect(page.getByText('Connected', { exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Refresh connections', exact: true }).click();
    await expect(page.getByText('Connected', { exact: true })).toBeVisible();
    const refreshed = page.waitForResponse(response => response.url().endsWith('/connect')
        && response.request().method() === 'POST' && response.request().postDataJSON().refresh === true);
    await page.getByRole('button', { name: 'Refresh credentials', exact: true }).click();
    expect((await refreshed).status()).toBe(200);
    await expect(page.getByRole('button', { name: 'Refresh credentials', exact: true })).toBeEnabled();
    await expect(page.getByText('Connected', { exact: true })).toBeVisible();
    if (process.argv[3]) await page.screenshot({ path: process.argv[3], fullPage: true });
    await page.getByRole('button', { name: 'Disconnect locally', exact: true }).click();
    await expect(page.getByText('Disconnected locally', { exact: true })).toBeVisible();
    await expect(page.getByRole('status')).toContainText('Provider-side revocation was not attempted.');
    expect(requests.filter(request => request.method === 'POST' && new URL(request.url).pathname.endsWith('/callback'))).toHaveLength(1);
    for (const request of requests.filter(request => new URL(request.url).origin !== origin)) {
        expect(request.headers.authorization).toBeUndefined();
        expect(request.headers['x-api-key']).toBeUndefined();
        expect(request.headers.cookie).toBeUndefined();
    }
    expect(errors).toEqual([]);
    process.stdout.write(JSON.stringify({ native_console_consent: true, callback_query_removed: true,
        original_callback_once: true, native_connect: true, original_governed_call: true,
        auth_change_cleared_private_dom: true, refresh_without_new_consent: true,
        local_disconnect: true, foreign_origin_without_console_credentials: true }) + '\n');
} finally {
    input.close();
    await browser.close();
}
