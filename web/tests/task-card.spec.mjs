import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';

const handle = '00000000-0000-4000-8000-000000000001';
const reference = 'a'.repeat(64);
const basePath = '/api/mcp/task-results';

for (const action of ['responses', 'cancel']) {
    test('Task controls send one original ' + action + ' request', async ({ page }) => {
        const posts = [];
        let status = action === 'responses' ? 'input_required' : 'working';
        const files = new Map(await Promise.all(['task-card.js', 'input-card.js'].map(async name =>
            ['/' + name, await readFile(new URL('../src/' + name, import.meta.url))])));
        const server = createServer(async (request, response) => {
            const url = new URL(request.url, 'http://localhost');
            if (files.has(url.pathname)) {
                response.setHeader('Content-Type', 'text/javascript');
                response.end(files.get(url.pathname));
                return;
            }
            if (url.pathname === '/') {
                response.setHeader('Content-Type', 'text/html');
                response.end('<!doctype html><div id="task"></div>');
                return;
            }
            if (!url.pathname.startsWith(basePath + '/' + handle)
                || url.searchParams.get('session_id') !== 'original-chat'
                || request.headers['x-kestrel-task-result'] !== reference) {
                response.writeHead(403).end();
                return;
            }
            response.setHeader('Content-Type', 'application/json');
            if (request.method === 'POST') {
                const chunks = [];
                for await (const chunk of request) chunks.push(chunk);
                posts.push({ path: url.pathname, body: JSON.parse(Buffer.concat(chunks).toString()) });
                status = action === 'responses' ? 'completed' : 'cancelled';
                response.end(JSON.stringify({ status: 'ok' }));
                return;
            }
            const forms = { entry: { message: 'Original MCP form',
                requestedSchema: { type: 'object', properties: { label: { type: 'string' } },
                    required: ['label'] } } };
            const row = status === 'input_required' ? { status, forms }
                : status === 'completed' ? { status, result: { resultType: 'complete',
                    content: [{ type: 'text', text: 'Native Task result' }] } }
                    : { status, can_cancel: status === 'working' };
            response.end(JSON.stringify(row));
        });
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        try {
            await page.goto('http://127.0.0.1:' + server.address().port);
            await page.evaluate(async options => {
                const { mountMCPTask } = await import('/task-card.js');
                window.card = mountMCPTask({ ...options, root: document.querySelector('#task'),
                    sessionId: 'original-chat', isCurrent: () => true,
                    async request(path, value) {
                        const response = await fetch(path, value);
                        if (!response.ok) throw new Error('Task read or action refused');
                        return await response.json();
                    } });
            }, { task: { handle, reference }, basePath });
            if (action === 'responses') {
                await page.getByLabel('label').fill('owned input');
                await page.getByRole('button', { name: 'Send input' }).click();
            } else {
                await page.getByRole('button', { name: 'Request cancellation' }).click();
            }
            const completed = await page.evaluate(() => window.card.completed);
            expect(completed.status).toBe(action === 'responses' ? 'completed' : 'cancelled');
            if (action === 'responses') expect(completed.result.content[0].text).toBe('Native Task result');
            expect(posts).toHaveLength(1);
            expect(posts[0].path).toBe(basePath + '/' + handle + '/' + action);
            expect(posts[0].body).toEqual({ operation_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
                ...(action === 'responses' ? {
                    input_responses: { entry: { action: 'accept', content: { label: 'owned input' } } },
                } : {}) });
            await page.evaluate(() => window.card.dispose());
            await expect(page.locator('#task')).toBeEmpty();
        } finally {
            server.closeAllConnections();
            await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
        }
    });
}
