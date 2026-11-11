import { chromium, expect } from '@playwright/test';

const browser = await chromium.launch();
const expectedContent = JSON.parse(process.argv[4] ?? 'null') ?? { city: 'owned-private-answer' };
const rich = 'count' in expectedContent, action = process.argv[5] ?? 'accept';
let closing;
const close = () => closing ??= browser.close();
const terminated = () => { void close(); };
process.once('SIGTERM', terminated);
try {
    const page = await browser.newPage(), errors = [], submissions = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {
        if (request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/responses')) {
            submissions.push(request.postDataJSON());
        }
    });
    const landing = await page.goto(process.argv[2]);
    expect(landing.status()).toBe(200);
    await page.waitForFunction(() => window.nativeInputReady).catch(error => {
        throw new Error('Actual Console input startup failed: ' + JSON.stringify(errors), { cause: error });
    });
    const review = page.getByRole('button', { name: 'Review MCP input', exact: true });
    await review.click();
    const city = page.getByRole('textbox', { name: 'city', exact: true });
    await expect(city).toBeVisible();
    await expect(page.locator('.mcp-input-card')).toContainText('Server: http://127.0.0.1:');
    await expect(page.locator('.mcp-input-card img')).toHaveCount(0);
    await city.fill('must-be-cleared');
    await page.evaluate(() => window.changeInputAuthentication());
    await expect(city).toHaveCount(0);
    await review.click(); await expect(city).toBeVisible();
    await page.evaluate(() => window.leaveChat()); await expect(city).toHaveCount(0);
    await page.evaluate(() => window.returnToChat());
    await review.click(); await expect(city).toBeVisible();
    await city.fill(expectedContent.city);
    if (expectedContent.city === '') {
        const valid = await page.evaluate(() => Array.from(document.querySelectorAll('input[aria-label="city"], select[aria-label="labels"]'))
            .map(input => input.checkValidity()));
        expect(valid, 'Required property presence must permit schema-valid empty values').toEqual([true, true]);
    }
    if (rich) {
        await expect(page.getByRole('spinbutton', { name: 'count', exact: true })).toHaveValue('2');
        await expect(page.getByRole('combobox', { name: 'enabled', exact: true })).toHaveValue('false');
        await expect(page.getByRole('combobox', { name: 'color', exact: true })).toHaveValue('0');
        await expect(page.getByRole('listbox', { name: 'labels', exact: true })).toHaveValues(['0']);
        await page.getByRole('spinbutton', { name: 'count', exact: true }).fill('3');
        await page.getByRole('spinbutton', { name: 'ratio', exact: true }).fill('.25');
        await page.getByRole('combobox', { name: 'color', exact: true }).selectOption({ label: 'Blue' });
        await page.getByRole('listbox', { name: 'labels', exact: true }).selectOption(['0', '2']);
        expect(await page.evaluate(() => Object.prototype.polluted)).toBeUndefined();
    }
    expect(submissions).toHaveLength(0);
    if (process.argv[3]) await page.screenshot({ path: process.argv[3], fullPage: true });
    const completed = page.waitForResponse(response => response.request().method() === 'POST'
        && new URL(response.url()).pathname.endsWith('/responses'));
    await page.evaluate(() => {
        window.inputClientRejected = false;
        document.addEventListener('submit', () => queueMicrotask(() => {
            window.inputClientRejected = Array.from(document.querySelectorAll('[role="status"]'))
                .some(node => node.textContent === 'Review the requested values before continuing.');
        }), { capture: true, once: true });
    });
    await page.getByRole('button', { name: { accept: 'Continue tool', decline: 'Decline', cancel: 'Cancel' }[action], exact: true }).click();
    expect(await page.evaluate(() => window.inputClientRejected), 'A schema-valid form was rejected by client value collection').toBe(false);
    expect((await completed).status()).toBe(200);
    await expect(page.getByRole('status')).toContainText(action === 'accept'
        ? 'Recorded: original-marker' : 'Operator input declined');
    await expect(page.getByRole('button', { name: 'Open App', exact: true })).toBeVisible();
    await expect(city).toHaveCount(0);
    expect(submissions).toHaveLength(1);
    expect(submissions[0].operation_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(submissions[0].responses).toEqual({ 'private-form-key': action === 'accept'
        ? { action, content: expectedContent } : { action } });
    await page.evaluate(() => window.reloadPart());
    await page.getByRole('button', { name: 'Review MCP input', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('already been handled');
    expect(submissions).toHaveLength(1);
    expect(errors).toEqual([]);
    process.stdout.write(JSON.stringify({ real_console_card: true, explicit_response_once: true,
        original_server_visible: true, auth_change_cleared_private_fields: true,
        navigation_cleared_private_fields: true, reload_without_tool_replay: true }) + '\n');
} finally {
    process.off('SIGTERM', terminated);
    await close();
}
