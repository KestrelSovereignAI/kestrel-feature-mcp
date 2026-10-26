import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export const SANDBOX_GENERATED_FILES = Object.freeze(['sandbox-entry.js', 'sandbox-service.mjs', 'THIRD_PARTY_NOTICES.txt', 'manifest.json']);
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

/** Detect missing/corrupted packaged assets before creating a public listener. */
export async function readVerifiedSandboxAssets(serviceUrl) {
    let manifest;
    try { manifest = JSON.parse(await readFile(new URL('./manifest.json', serviceUrl), 'utf8')); }
    catch (error) {
        if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
        throw new TypeError('Sandbox built asset manifest is unavailable or invalid; rebuild the packaged assets');
    }
    const assets = manifest?.assets;
    if (manifest?.format !== 1 || !assets || typeof assets !== 'object' || Array.isArray(assets)
        || !['sandbox-entry.js', 'sandbox-service.mjs', 'THIRD_PARTY_NOTICES.txt'].every(name => Object.hasOwn(assets, name))
        || Object.keys(assets).some(name => name === 'manifest.json' || !SANDBOX_GENERATED_FILES.includes(name))) {
        throw new TypeError('Sandbox built asset manifest has an invalid file inventory');
    }
    const decoded = {};
    for (const [name, expected] of Object.entries(assets)) {
        if (typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)) {
            throw new TypeError('Sandbox built asset manifest requires SHA-256 hashes');
        }
        const bytes = await readFile(new URL('./' + name, serviceUrl));
        if (sha256(bytes) !== expected) throw new Error('Sandbox packaged asset failed integrity verification: ' + name);
        if (name === 'sandbox-entry.js' || name === 'THIRD_PARTY_NOTICES.txt') {
            decoded[name] = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        }
    }
    return { entryJavascript: decoded['sandbox-entry.js'], thirdPartyNotices: decoded['THIRD_PARTY_NOTICES.txt'] };
}
