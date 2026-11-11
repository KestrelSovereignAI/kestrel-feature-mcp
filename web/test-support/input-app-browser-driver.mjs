import { chromium, expect } from '@playwright/test';

const browser = await chromium.launch();
const expectedContent = JSON.parse(process.argv[4] ?? 'null') ?? { city: 'owned-private-answer' };
let closing;
const close = () => closing ??= browser.close();
const terminated = () => { void close(); };
process.once('SIGTERM', terminated);
try {
    const page = await browser.newPage(), errors = [], posts = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {
        if (request.method() === 'POST') posts.push(new URL(request.url()).pathname);
    });
    await page.goto(process.argv[2] + '?mode=app');
    await page.waitForFunction(() => window.nativeInputReady);
    await page.getByRole('button', { name: 'Open App', exact: true }).click();
    const app = page.frameLocator('iframe[title="MCP App"]').frameLocator('iframe');
    await expect(app.locator('#input-app-result')).toHaveText('native-result:original-marker');
    await app.getByRole('button', { name: 'Request operator input' }).click();
    await expect(app.locator('#input-app-result')).toHaveText('waiting-for-host-input');
    const city = page.getByRole('textbox', { name: 'city', exact: true });
    await expect(city).toBeVisible();
    expect(await page.locator('body').innerText()).not.toContain('private-witness');
    if (expectedContent.city.startsWith('https:')) {
        await city.fill('not a URI');
        const rejected = page.waitForResponse(response => response.request().method() === 'POST'
            && new URL(response.url()).pathname.endsWith('/responses'));
        await page.getByRole('button', { name: 'Continue tool', exact: true }).click();
        expect((await rejected).status()).toBe(400);
        await expect(page.getByRole('status').filter({ hasText: 'response was not accepted' })).toHaveCount(1);
        expect(await city.count(), 'Invalid input must preserve the form inside its original App View').toBe(1);
    }
    await city.fill(expectedContent.city);
    await page.getByRole('button', { name: 'Continue tool', exact: true }).click();
    await expect(app.locator('#input-app-result')).toHaveText('native-result:app-effect');
    await expect(city).toHaveCount(0);
    expect(posts.filter(path => path.endsWith('/tools/call'))).toHaveLength(1);
    expect(posts.filter(path => path.endsWith('/responses'))).toHaveLength(expectedContent.city.startsWith('https:') ? 2 : 1);
    await page.getByRole('button', { name: 'Close App', exact: true }).click();
    await expect(page.locator('iframe')).toHaveCount(0);
    expect(errors).toEqual([]);
    process.stdout.write(JSON.stringify({ actual_app_pause: true, host_form: true,
        native_private_result_notification: true, no_initial_replay: true, view_closed: true }) + '\n');
} finally {
    process.off('SIGTERM', terminated);
    await close();
}
