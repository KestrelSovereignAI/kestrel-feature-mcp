import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { createSandboxService } from './sandbox-service.js';
import { readVerifiedSandboxAssets } from './sandbox-assets.js';
import { validateSandboxConfig } from './sandbox-config.js';

export function validateDeploymentConfig(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).some(key => !['listen', 'sandbox', 'httpLimits'].includes(key))) {
        throw new TypeError('Sandbox deployment configuration contains unsupported fields');
    }
    const config = structuredClone(value);
    if (!config.listen || typeof config.listen !== 'object' || Array.isArray(config.listen)
        || Object.keys(config.listen).some(key => !['host', 'port'].includes(key))
        || typeof config.listen.host !== 'string' || !config.listen.host.trim()
        || config.listen.host !== config.listen.host.trim()) {
        throw new TypeError('Sandbox listener requires an explicit host and port');
    }
    // Port zero is useful for an explicitly configured ephemeral listener.
    if (!Number.isSafeInteger(config.listen.port) || config.listen.port < 0 || config.listen.port > 65535) {
        throw new TypeError('Sandbox listener port must be an integer between 0 and 65535');
    }
    config.sandbox = validateSandboxConfig(config.sandbox);
    return config;
}

export async function runSandboxService({ deployment, entryJavascript, thirdPartyNotices }) {
    const config = validateDeploymentConfig(deployment);
    const server = createSandboxService({ config: config.sandbox, entryJavascript, thirdPartyNotices, httpLimits: config.httpLimits });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.listen.port, config.listen.host, () => {
            server.off('error', reject);
            resolve();
        });
    });
    return server;
}

export async function main(args = process.argv.slice(2)) {
    const { values } = parseArgs({ args, options: { config: { type: 'string' } }, allowPositionals: false });
    if (!values.config) throw new TypeError('Pass --config with a sandbox deployment JSON file');
    const text = await readFile(values.config, 'utf8');
    let deployment;
    try { deployment = JSON.parse(text); }
    catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
        throw new TypeError('Sandbox deployment configuration must contain valid JSON');
    }
    const assets = await readVerifiedSandboxAssets(import.meta.url);
    const server = await runSandboxService({ deployment, ...assets });
    console.info(JSON.stringify({ level: 'info', event: 'mcp-apps-sandbox-listening', address: server.address() }));
    const stop = () => {
        server.close(error => {
            if (error) {
                console.error(JSON.stringify({ level: 'error', event: 'mcp-apps-sandbox-close-failed', code: error.code }));
                process.exitCode = 1;
            }
        });
        server.closeAllConnections();
        process.removeListener('SIGTERM', stop);
        process.removeListener('SIGINT', stop);
    };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
    return server;
}
