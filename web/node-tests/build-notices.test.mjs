import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { embeddedPackageReferences, collectEmbeddedNotices } from '../build-notices.mjs';
import { sha256 } from '../src/sandbox-assets.js';

test('embedded source identity includes scoped packages and peer-qualified versions', () => {
    assert.deepEqual(embeddedPackageReferences([
        '../../core-internal/src/validators/ajvProvider.ts',
        '../../../node_modules/.pnpm/ajv-formats@3.0.1_ajv@8.18.0/node_modules/ajv-formats/dist/index.js',
        '../../../node_modules/.pnpm/@cfworker+json-schema@4.1.1/node_modules/@cfworker/json-schema/dist/esm/index.js',
    ]), ['@cfworker/json-schema@4.1.1', 'ajv-formats@3.0.1']);
    for (const invalid of [null, [1], ['../node_modules/unknown/index.js'],
        ['../node_modules/.pnpm/wrong@1.0.0/node_modules/other/index.js']]) {
        assert.throws(() => embeddedPackageReferences(invalid));
    }
});

test('a new embedded dependency or corrupt notice fails the build rather than losing attribution', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owned-embedded-notices-'));
    try {
        await fs.mkdir(path.join(root, 'licenses'));
        const license = 'Original fixture copyright and permission notice\n';
        await fs.writeFile(path.join(root, 'licenses/original.txt'), license);
        await fs.writeFile(path.join(root, 'input.mjs.map'), JSON.stringify({ version: 3,
            sources: ['../node_modules/.pnpm/original@1.0.0/node_modules/original/index.js'] }));
        await fs.writeFile(path.join(root, 'vendor-notices.json'), JSON.stringify({ format: 1, packages: [] }));
        await assert.rejects(collectEmbeddedNotices(root, ['input.mjs']), /Missing original notice/);
        const inventory = { format: 1, packages: [{ name: 'original', version: '1.0.0', license: 'MIT',
            licenseFiles: { 'licenses/original.txt': sha256(license) } }] };
        await fs.writeFile(path.join(root, 'vendor-notices.json'), JSON.stringify(inventory));
        const result = await collectEmbeddedNotices(root, ['input.mjs']);
        assert.equal(result.dependencies[0].licenses[0].text, license);
        assert.deepEqual(result.dependencies[0].embeddedIn, ['input.mjs']);
        assert.ok(result.sourceMaps['input.mjs.map']);
        await fs.appendFile(path.join(root, 'licenses/original.txt'), 'changed');
        await assert.rejects(collectEmbeddedNotices(root, ['input.mjs']), /notice hash mismatch/);
        inventory.packages[0].licenseFiles = { '../operator-file': sha256(license) };
        await fs.writeFile(path.join(root, 'vendor-notices.json'), JSON.stringify(inventory));
        await assert.rejects(collectEmbeddedNotices(root, ['input.mjs']), /hashed license file/);
    } finally { await fs.rm(root, { recursive: true, force: true }); }
});
