import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { buildSandboxAssets, verifySandboxBuild } from '../build-assets.mjs';
import { validateDeploymentConfig } from '../src/sandbox-cli.js';
import { createBuiltAssets, startBuiltSandbox } from '../test-support/sandbox-process.mjs';

const deployment = () => ({ listen: { host: '127.0.0.1', port: 0 }, sandbox: {
    hostOrigin: 'https://host.example', policy: {}, maxMessageBytes: 8 * 1024 * 1024, maxHtmlBytes: 1024 * 1024,
} });

async function withBuilt(operation) {
    const built = await createBuiltAssets();
    try { await operation(built.root, built.manifest); }
    finally { await built.dispose(); }
}

test('sandbox deployment settings reject invalid listener and unknown fields', () => {
    assert.deepEqual(validateDeploymentConfig(deployment()), deployment());
    for (const invalid of [null, [], { ...deployment(), identity: 'forbidden' },
        { ...deployment(), listen: {} }, { ...deployment(), listen: { host: ' ', port: 8080 } },
        { ...deployment(), listen: { host: '127.0.0.1', port: -1 } },
        { ...deployment(), listen: { host: '127.0.0.1', port: 65536 } },
        { ...deployment(), listen: { host: '127.0.0.1', port: true } }]) {
        assert.throws(() => validateDeploymentConfig(invalid), TypeError);
    }
});

test('bundles are deterministic and include original dependency licenses and input hashes', async () => {
    await withBuilt(async (root, manifest) => {
        const other = path.join(root, 'again');
        assert.deepEqual(await buildSandboxAssets(other), manifest);
        const cliOutput = path.join(root, 'build-command');
        const builder = spawn(process.execPath, [fileURLToPath(new URL('../build.mjs', import.meta.url)),
            '--outdir', cliOutput], { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH, HOME: root } });
        let buildError = '';
        builder.stderr.setEncoding('utf8').on('data', chunk => { buildError += chunk; });
        assert.deepEqual(await once(builder, 'close'), [0, null], buildError);
        assert.deepEqual(JSON.parse(await fs.readFile(path.join(cliOutput, 'manifest.json'), 'utf8')), manifest);
        const first = path.join(root, 'assets');
        assert.deepEqual(await verifySandboxBuild(first), manifest);
        for (const name of await fs.readdir(first)) {
            assert.deepEqual(await fs.readFile(path.join(first, name)), await fs.readFile(path.join(other, name)));
        }
        const installed = JSON.parse(await fs.readFile(new URL('../node_modules/@modelcontextprotocol/ext-apps/package.json', import.meta.url), 'utf8'));
        assert.equal(manifest.dependencies.find(item => item.name === installed.name).version, installed.version);
        assert.ok(Object.keys(manifest.bundledInputs).some(name => name.startsWith('node_modules/@modelcontextprotocol/')));
        const notices = await fs.readFile(path.join(first, 'THIRD_PARTY_NOTICES.txt'), 'utf8');
        assert.match(notices, /Apache License/);
        assert.match(notices, /MIT License/);
        await fs.writeFile(path.join(other, 'operator-owned.txt'), 'preserve');
        await assert.rejects(buildSandboxAssets(other), /not owned/);
        assert.equal(await fs.readFile(path.join(other, 'operator-owned.txt'), 'utf8'), 'preserve');
    });
});

test('asset rebuild checks refuse changed bytes and preserve files outside the generated set', async () => {
    await withBuilt(async root => {
        const assets = path.join(root, 'assets');
        const browser = path.join(assets, 'sandbox-entry.js');
        const original = await fs.readFile(browser);
        await fs.appendFile(browser, '\n// changed fixture\n');
        await assert.rejects(verifySandboxBuild(assets), /differs from the clean build/);
        await fs.writeFile(browser, original);
        const unrelated = path.join(root, 'unrelated-owned-fixture');
        await fs.writeFile(unrelated, 'preserve');
        await fs.unlink(browser);
        await fs.link(unrelated, browser);
        await assert.rejects(buildSandboxAssets(assets), /ordinary generated files/);
        assert.equal(await fs.readFile(unrelated, 'utf8'), 'preserve');
    });
});

test('actual built standalone CLI serves the public sandbox and terminates on SIGTERM', { timeout: 30_000 }, async context => {
    const service = await startBuiltSandbox(deployment(), { signal: context.signal });
    try {
        const response = await fetch(service.origin + '/proxy');
        assert.equal(response.status, 200);
        assert.match(await response.text(), /sandbox-entry.js/);
        const browserModule = await fetch(service.origin + '/sandbox-entry.js');
        assert.equal(browserModule.status, 200);
        assert.match(await browserModule.text(), /ui\/notifications\/sandbox-proxy-ready/);
        const notices = await fetch(service.origin + '/THIRD_PARTY_NOTICES.txt');
        assert.equal(notices.status, 200);
        assert.match(await notices.text(), /Apache License/);
        assert.equal((await fetch(service.origin + '/config', { headers: { Authorization: 'Bearer fixture' } })).status, 400);
        assert.equal(service.stderr, '');
    } finally { await service.close(); }
});

for (const scenario of [
    { name: 'invalid JSON does not echo configuration contents', text: 'private-fixture-value', message: /must contain valid JSON/ },
    { name: 'corrupted browser bundle is refused before listening', message: /failed integrity verification/,
        mutate: async assets => fs.appendFile(path.join(assets, 'sandbox-entry.js'), '\n// corruption fixture\n') },
    { name: 'invalid manifest inventory is refused before any file access', message: /invalid file inventory/,
        mutate: async assets => {
            const filename = path.join(assets, 'manifest.json');
            const manifest = JSON.parse(await fs.readFile(filename, 'utf8'));
            manifest.assets['../operator-file'] = '0'.repeat(64);
            await fs.writeFile(filename, JSON.stringify(manifest));
        } },
    { name: 'invalid HTTP limits fail before listening', text: JSON.stringify({ ...deployment(), httpLimits: { requestTimeoutMs: 0 } }),
        message: /positive safe integer/ },
]) {
    test(scenario.name, { timeout: 30_000 }, async context => {
        await withBuilt(async root => {
            const config = path.join(root, 'deployment.json');
            await fs.writeFile(config, scenario.text ?? JSON.stringify(deployment()));
            if (scenario.mutate) await scenario.mutate(path.join(root, 'assets'));
            const child = spawn(process.execPath, [path.join(root, 'assets', 'sandbox-service.mjs'), '--config', config],
                { stdio: ['ignore', 'pipe', 'pipe'], signal: context.signal, env: { PATH: process.env.PATH, HOME: root } });
            let stderr = '', stdout = '';
            child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
            child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
            assert.deepEqual(await once(child, 'close'), [1, null]);
            assert.doesNotMatch(stderr, /private-fixture-value/);
            assert.doesNotMatch(stdout, /mcp-apps-sandbox-listening/);
            assert.match(stderr, scenario.message);
        });
    });
}
