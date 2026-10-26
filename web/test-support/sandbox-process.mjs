import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { buildSandboxAssets } from '../build-assets.mjs';

export async function createBuiltAssets() {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owned-mcp-sandbox-build-'));
    try {
        const assets = path.join(root, 'assets');
        const manifest = await buildSandboxAssets(assets);
        return { root, assets, manifest, dispose: () => fs.rm(root, { recursive: true, force: true }) };
    } catch (error) {
        await fs.rm(root, { recursive: true, force: true });
        throw error;
    }
}

/** Own only this fixture's Node process, built files and HTTP listener. */
export async function startBuiltSandbox(deployment, { signal } = {}) {
    const built = await createBuiltAssets();
    let child, exited, lines, stderr = '', started = false;
    const release = async () => {
        let timer;
        try {
            if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
            if (exited) {
                const result = await Promise.race([exited, new Promise((_, reject) => {
                    timer = setTimeout(() => reject(new Error('Owned sandbox process did not terminate')), 5_000);
                })]);
                if (started) assert.deepEqual(result, [0, null], stderr);
            }
        } finally {
            clearTimeout(timer);
            lines?.close();
            if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
            if (exited) await Promise.allSettled([exited]);
            await built.dispose();
        }
    };
    try {
        const config = path.join(built.root, 'deployment.json');
        await fs.writeFile(config, JSON.stringify(deployment));
        child = spawn(process.execPath, [path.join(built.assets, 'sandbox-service.mjs'), '--config', config],
            { stdio: ['ignore', 'pipe', 'pipe'], signal, env: { PATH: process.env.PATH, HOME: built.root } });
        child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
        exited = once(child, 'close');
        lines = createInterface({ input: child.stdout });
        const [line] = await Promise.race([once(lines, 'line'), exited.then(([code]) => {
            throw new Error(`Sandbox exited before listening: ${code}: ${stderr}`);
        })]);
        const ready = JSON.parse(line);
        assert.equal(ready.event, 'mcp-apps-sandbox-listening');
        started = true;
        let closing;
        return { origin: 'http://127.0.0.1:' + ready.address.port,
            get stderr() { return stderr; }, close: () => closing ??= release() };
    } finally {
        if (!started) await release();
    }
}
