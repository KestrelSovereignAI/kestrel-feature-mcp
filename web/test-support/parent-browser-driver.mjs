import { chromium, expect } from '@playwright/test';
const browser = await chromium.launch();
try {
    const page = await browser.newPage();
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto(process.argv[2]);
    await page.waitForFunction(() => window.nativeParentReady).catch(error => {
        throw new Error(`Core parent startup failed: ${JSON.stringify(errors)}`, { cause: error });
    });
    await expect(page.locator('iframe')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Open App', exact: true })).toBeEnabled();
    await page.getByRole('button', { name: 'Open App', exact: true }).click();
    const frames = page.frameLocator('iframe[title="MCP App"]').frameLocator('iframe');
    await expect(frames.locator('#native-result')).toHaveText('{"view":"only"}');
    expect(await page.locator('body').innerText()).not.toContain('"view":"only"');
    expect(await frames.locator('body').evaluate(() => window.origin)).toBe('null');
    await frames.getByRole('button', { name: 'List App tools' }).click();
    await expect(frames.locator('#native-result')).toHaveText('catalog-filtered');
    await frames.getByRole('button', { name: 'Native governed call' }).click();
    await expect(frames.locator('#native-result')).toHaveText('native-call:{"view":"only"}');
    await frames.getByRole('button', { name: 'Try model-only tool' }).click();
    await expect(frames.locator('#native-result')).toHaveText('model-only-refused');
    await page.getByRole('button', { name: 'Close App', exact: true }).click();
    await expect(page.locator('iframe')).toHaveCount(0);
    await page.getByRole('button', { name: 'Open App', exact: true }).click();
    await expect(frames.locator('#native-result')).toHaveText('{"view":"only"}');
    await page.evaluate(() => window.leaveChat());
    await expect(page.locator('iframe')).toHaveCount(0);
    await page.evaluate(() => window.returnToChat());
    await page.getByRole('button', { name: 'Open App', exact: true }).click();
    await expect(frames.locator('#native-result')).toHaveText('{"view":"only"}');
    await page.evaluate(() => window.retireChat());
    await expect(page.locator('iframe')).toHaveCount(0);
    expect(errors).toEqual([]);
    process.stdout.write(JSON.stringify({ native_app_ready: true, governed_call: true,
        model_only_refused: true, catalog_filtered: true, opaque_view: true,
        explicit_open_close: true, navigation_closed: true, reopened: true, dom_retired: true }) + '\n');
} finally { await browser.close(); }
