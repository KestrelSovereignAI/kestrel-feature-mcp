import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { build, version as esbuildVersion } from 'esbuild';
import { sha256 as digest, SANDBOX_GENERATED_FILES } from './src/sandbox-assets.js';

const webRoot = path.dirname(fileURLToPath(import.meta.url));
const generatedNames = new Set(SANDBOX_GENERATED_FILES);

async function licenseFor(input) {
    let folder = path.dirname(path.resolve(webRoot, input));
    const nodeModules = path.join(webRoot, 'node_modules');
    while (folder.startsWith(nodeModules + path.sep)) {
        let metadata;
        try { metadata = JSON.parse(await fs.readFile(path.join(folder, 'package.json'), 'utf8')); }
        catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
        if (metadata?.name && metadata.version) {
            const names = (await fs.readdir(folder)).filter(name => /^licen[cs]e(?:\.(?:txt|md))?$/i.test(name)).sort();
            if (!names.length) throw new Error('Bundled dependency has no license file: ' + metadata.name);
            const licenses = [];
            for (const name of names) licenses.push({ name, text: await fs.readFile(path.join(folder, name), 'utf8') });
            return { name: metadata.name, version: metadata.version, license: metadata.license, licenses };
        }
        folder = path.dirname(folder);
    }
    throw new Error('Cannot identify the bundled dependency: ' + input);
}

/** Rebuild shipped assets from the normal npm lock, without modifying any SDK. */
export async function buildSandboxAssets(outputDirectory) {
    const destination = path.resolve(outputDirectory);
    if (destination === webRoot || destination === path.parse(destination).root) {
        throw new TypeError('Build output must use a dedicated asset directory');
    }
    if (destination.startsWith(path.join(webRoot, 'node_modules') + path.sep)) {
        throw new TypeError('Build output cannot modify installed dependencies');
    }
    await fs.mkdir(destination, { recursive: true });
    const directory = await fs.lstat(destination);
    if (directory.isSymbolicLink() || !directory.isDirectory()) throw new TypeError('Build output must be a real directory');
    const existing = await fs.readdir(destination);
    for (const name of existing) {
        const file = await fs.lstat(path.join(destination, name));
        if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1) {
            throw new TypeError('Build output must contain only its own ordinary generated files');
        }
    }
    if (existing.some(name => !generatedNames.has(name))) {
        throw new Error('Build output directory contains files not owned by the Apps asset build');
    }
    const outputs = new Map(), inputs = new Map();
    for (const [entry, filename, platform, target] of [
        ['src/sandbox-entry.js', 'sandbox-entry.js', 'browser', 'es2022'],
        ['src/sandbox-server-entry.js', 'sandbox-service.mjs', 'node', 'node22'],
    ]) {
        const result = await build({ absWorkingDir: webRoot, entryPoints: [entry],
            outfile: path.join(destination, filename), bundle: true, format: 'esm',
            platform, target, minify: true, legalComments: 'inline', metafile: true, write: false,
            charset: 'utf8', logLevel: 'silent' });
        for (const output of result.outputFiles) {
            const name = path.basename(output.path);
            if (!generatedNames.has(name)) throw new Error('Unexpected build output: ' + name);
            outputs.set(name, output.contents);
        }
        for (const input of Object.keys(result.metafile.inputs)) {
            inputs.set(input, digest(await fs.readFile(path.resolve(webRoot, input))));
        }
    }
    const dependencies = new Map();
    for (const input of [...inputs.keys()].filter(name => name.startsWith('node_modules/')).sort()) {
        const item = await licenseFor(input);
        dependencies.set(item.name, item);
    }
    const ordered = [...dependencies.values()].sort((a, b) => a.name.localeCompare(b.name, 'en'));
    outputs.set('THIRD_PARTY_NOTICES.txt', Buffer.from(ordered.map(item =>
        `${item.name} ${item.version} (${item.license})\n` + item.licenses.map(license =>
            `--- ${license.name} ---\n${license.text.trim()}\n`).join('\n')).join('\n')));
    const sourceFiles = ['build.mjs', 'build-assets.mjs', 'package.json', 'package-lock.json',
        ...(await fs.readdir(path.join(webRoot, 'src'))).filter(name => name.endsWith('.js')).map(name => 'src/' + name)];
    const sourceHashes = {};
    for (const filename of sourceFiles.sort()) sourceHashes[filename] = digest(await fs.readFile(path.join(webRoot, filename)));
    const manifest = { format: 1, compiler: { name: 'esbuild', version: esbuildVersion },
        sources: sourceHashes, bundledInputs: Object.fromEntries([...inputs].sort(([a], [b]) => a.localeCompare(b, 'en'))),
        dependencies: ordered.map(item => ({ name: item.name, version: item.version, license: item.license,
            licenseFiles: Object.fromEntries(item.licenses.map(license => [license.name, digest(license.text)])) })),
        assets: Object.fromEntries([...outputs].sort(([a], [b]) => a.localeCompare(b, 'en'))
            .map(([name, bytes]) => [name, digest(bytes)])) };
    outputs.set('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2) + '\n'));
    for (const name of existing) if (!outputs.has(name)) await fs.unlink(path.join(destination, name));
    for (const [name, bytes] of outputs) await fs.writeFile(path.join(destination, name), bytes);
    return manifest;
}

/** Verify checked-in assets against a clean build, without rewriting them. */
export async function verifySandboxBuild(assetDirectory) {
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'owned-mcp-sandbox-check-'));
    try {
        const manifest = await buildSandboxAssets(scratch);
        const expected = (await fs.readdir(scratch)).sort();
        const actual = (await fs.readdir(assetDirectory)).sort();
        if (JSON.stringify(actual) !== JSON.stringify(expected)) {
            throw new Error('Shipped sandbox asset inventory differs from the clean build');
        }
        for (const name of expected) {
            const built = await fs.readFile(path.join(scratch, name));
            const shipped = await fs.readFile(path.join(assetDirectory, name));
            if (!built.equals(shipped)) throw new Error('Shipped sandbox asset differs from the clean build: ' + name);
        }
        return manifest;
    } finally { await fs.rm(scratch, { recursive: true, force: true }); }
}
