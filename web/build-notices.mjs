import * as fs from 'node:fs/promises';
import path from 'node:path';
import { sha256 } from './src/sandbox-assets.js';

/** Identify packages already embedded in an upstream distribution's source map. */
export function embeddedPackageReferences(sources) {
    if (!Array.isArray(sources) || sources.some(source => typeof source !== 'string')) {
        throw new TypeError('Dependency source map must contain source paths');
    }
    const packages = new Set();
    for (const source of sources) {
        if (!source.includes('node_modules/')) continue;
        const match = source.match(/(?:^|\/)node_modules\/\.pnpm\/([^/]+)\/node_modules\/((?:@[^/]+\/)?[^/]+)\//);
        if (!match) throw new Error('Unsupported embedded dependency source path: ' + source);
        const locator = match[1].split('_')[0], name = match[2];
        const version = locator.slice(locator.lastIndexOf('@') + 1);
        if (locator !== name.replace('/', '+') + '@' + version || !/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(version)) {
            throw new Error('Invalid embedded dependency identity: ' + source);
        }
        packages.add(name + '@' + version);
    }
    return [...packages].sort();
}

/** Offline notices for dependencies bundled inside otherwise ordinary npm inputs. */
export async function collectEmbeddedNotices(webRoot, inputNames) {
    const inventory = JSON.parse(await fs.readFile(path.join(webRoot, 'vendor-notices.json'), 'utf8'));
    if (inventory?.format !== 1 || !Array.isArray(inventory.packages)) {
        throw new TypeError('Embedded dependency notice inventory is invalid');
    }
    const known = new Map();
    for (const record of inventory.packages) {
        const key = record.name + '@' + record.version;
        if (known.has(key)) throw new Error('Duplicate embedded notice identity: ' + key);
        known.set(key, record);
    }
    const referenced = new Map(), sourceMaps = {};
    for (const input of [...inputNames].sort()) {
        let bytes;
        try { bytes = await fs.readFile(path.resolve(webRoot, input + '.map')); }
        catch (error) {
            if (error.code !== 'ENOENT') throw error;
            continue;
        }
        const map = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        if (map.version !== 3) throw new TypeError('Unsupported dependency source map version');
        const identities = embeddedPackageReferences(map.sources);
        if (!identities.length) continue;
        sourceMaps[input + '.map'] = sha256(bytes);
        for (const key of identities) {
            if (!known.has(key)) throw new Error('Missing original notice for embedded dependency: ' + key);
            if (!referenced.has(key)) referenced.set(key, new Set());
            referenced.get(key).add(input);
        }
    }
    const dependencies = [], sourceFiles = new Set(['vendor-notices.json']);
    for (const [key, inputs] of [...referenced].sort(([a], [b]) => a.localeCompare(b, 'en'))) {
        const record = known.get(key), licenses = [];
        if (typeof record.license !== 'string' || !record.licenseFiles
            || typeof record.licenseFiles !== 'object' || Array.isArray(record.licenseFiles)
            || !Object.keys(record.licenseFiles).length) {
            throw new TypeError('Embedded dependency requires original license files: ' + key);
        }
        for (const [filename, expected] of Object.entries(record.licenseFiles).sort(([a], [b]) => a.localeCompare(b, 'en'))) {
            const absolute = path.resolve(webRoot, filename);
            if (!filename.startsWith('licenses/') || !absolute.startsWith(path.join(webRoot, 'licenses') + path.sep)
                || typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)) {
                throw new TypeError('Embedded notice must name a hashed license file');
            }
            const stat = await fs.lstat(absolute);
            if (!stat.isFile() || stat.isSymbolicLink()) throw new TypeError('Embedded notice must be an ordinary file');
            const bytes = await fs.readFile(absolute);
            if (sha256(bytes) !== expected) throw new Error('Embedded dependency notice hash mismatch: ' + filename);
            licenses.push({ name: filename, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) });
            sourceFiles.add(filename);
        }
        dependencies.push({ name: record.name, version: record.version, license: record.license,
            licenses, embeddedIn: [...inputs].sort() });
    }
    return { dependencies, sourceMaps, sourceFiles: [...sourceFiles].sort() };
}
