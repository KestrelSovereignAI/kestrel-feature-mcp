import { chromium, expect } from '@playwright/test';
import { createInterface } from 'node:readline';

const [origin, kind] = process.argv.slice(2);
const input = createInterface({ input: process.stdin });
const commands = input[Symbol.asyncIterator]();
const credential = JSON.parse((await commands.next()).value);
const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP console.example 127.0.0.1', '--no-proxy-server'] });
const close = () => { input.close(); void browser.close(); };
process.once('SIGTERM', close);
const report = data => process.stdout.write(JSON.stringify(data) + '\n');
const replies = [];
try {
    const page = await browser.newPage({ ignoreHTTPSErrors: true });
    page.setDefaultTimeout(5000);
    await page.route('**/*', route => new URL(route.request().url()).origin === origin
        ? route.continue() : route.abort());
    await page.addInitScript(key => { window.fixtureKey = key; }, credential);
    const errors = [], posts = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {
        if (request.method() === 'POST' && new URL(request.url()).pathname.startsWith('/api/mcp/task-results/')) {
            posts.push(new URL(request.url()).pathname);
        }
    });
    page.on('response', response => {
        if (new URL(response.url()).pathname.startsWith('/api/mcp/task-results/')) {
            replies.push({ method: response.request().method(), status: response.status() });
        }
    });
    await page.goto(origin);
    const view = page.getByRole('button', { name: 'View Task', exact: true });
    await expect(view).toBeVisible({ timeout: 7000 }).catch(error => {
        throw new Error(`The published Task renderer did not mount: ${JSON.stringify(errors)}`, { cause: error });
    });
    report({ event: 'rendered' });
    expect((await commands.next()).value).toBe('continue');
    await view.click();
    const path = kind === 'update' ? '/responses' : '/cancel';
    if (kind === 'update') await page.getByLabel('label', { exact: true }).fill('native input');
    const [response] = await Promise.all([
        page.waitForResponse(reply => reply.request().method() === 'POST'
            && new URL(reply.url()).pathname.endsWith(path)),
        page.getByRole('button', { name: kind === 'update' ? 'Send input' : 'Request cancellation', exact: true }).click(),
    ]);
    expect(response.status()).toBe(503);
    await expect(page.getByText('The request outcome is unknown. Check the Task status.', { exact: true })).toBeVisible();
    report({ event: 'unknown', status: response.status() });
    expect((await commands.next()).value).toBe('continue');
    if (kind === 'update') {
        await expect(page.locator('.mcp-task-content pre')).toContainText('actual deferred result');
    } else {
        await expect(page.getByText('Task cancelled.', { exact: true })).toBeVisible();
    }
    expect(posts).toHaveLength(1);
    expect(errors).toEqual([]);
    report({ event: 'settled', posts: posts.length });
} catch (error) {
    process.stderr.write(`${error.stack}\nTask HTTP statuses ${JSON.stringify(replies)}\n`);
    process.exitCode = 1;
} finally {
    input.close();
    process.off('SIGTERM', close);
    await browser.close();
}
