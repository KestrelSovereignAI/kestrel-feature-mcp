import { approveSandboxPolicy } from './sandbox-proxy.js';

export function requirePositiveSafeInteger(value, name) {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${name} must be a positive safe integer`);
    }
    return value;
}

/** One public configuration contract for the isolated sandbox service. */
export function validateSandboxConfig(value) {
    const fields = ['hostOrigin', 'maxMessageBytes', 'maxHtmlBytes', 'policy'];
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).some(key => !fields.includes(key))) {
        throw new TypeError('Sandbox configuration contains unsupported fields');
    }
    const config = structuredClone(value);
    const host = new URL(config.hostOrigin);
    if (!['https:', 'http:'].includes(host.protocol) || host.origin !== config.hostOrigin) {
        throw new TypeError('Sandbox hostOrigin must be an exact HTTP(S) origin');
    }
    for (const field of ['maxMessageBytes', 'maxHtmlBytes']) {
        requirePositiveSafeInteger(config[field], `Sandbox ${field}`);
    }
    approveSandboxPolicy({}, {}, config.policy);
    return config;
}
