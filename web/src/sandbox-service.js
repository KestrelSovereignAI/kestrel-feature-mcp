import { createServer } from 'node:http';
import { validateSandboxConfig, requirePositiveSafeInteger } from './sandbox-config.js';
import { sandboxPermissionsPolicy } from './sandbox-proxy.js';

const DEFAULT_HTTP_LIMITS = Object.freeze({ maxHeaderBytes: 16 * 1024,
    requestTimeoutMs: 5_000, headersTimeoutMs: 5_000, keepAliveTimeoutMs: 5_000 });

/** Serve only the public sandbox, without an authentication or identity lane. */
export function createSandboxService({ config, entryJavascript, thirdPartyNotices, httpLimits = {} }) {
    if (!httpLimits || typeof httpLimits !== 'object' || Array.isArray(httpLimits)
        || Object.keys(httpLimits).some(key => !Object.hasOwn(DEFAULT_HTTP_LIMITS, key))) {
        throw new TypeError('Sandbox HTTP limits contain unsupported fields');
    }
    const limits = { ...DEFAULT_HTTP_LIMITS, ...httpLimits };
    for (const [key, value] of Object.entries(limits)) requirePositiveSafeInteger(value, key);
    const approved = validateSandboxConfig(config);
    if (typeof entryJavascript !== 'string' || !entryJavascript.trim()) {
        throw new TypeError('A built sandbox entry module is required');
    }
    if (typeof thirdPartyNotices !== 'string' || !thirdPartyNotices.trim()) {
        throw new TypeError('The sandbox requires its bundled third-party license notices');
    }
    // Serialize the snapshot once. Later caller mutations cannot widen a live
    // service's policy. Escaping '<' also keeps the JSON script element inert.
    const configJson = JSON.stringify(approved).replaceAll('<', '\\u003c');
    const html = '<!doctype html><html><head><meta charset="utf-8">'
        + '<meta name="referrer" content="no-referrer"></head><body>'
        + '<script type="application/json" id="sandbox-config">' + configJson + '</script>'
        + '<script type="module" src="/sandbox-entry.js"></script></body></html>';
    const permissionPolicy = sandboxPermissionsPolicy(approved.policy);
    const service = createServer({ maxHeaderSize: limits.maxHeaderBytes }, (request, response) => {
        response.setHeader('Cache-Control', 'no-store');
        response.setHeader('Referrer-Policy', 'no-referrer');
        response.setHeader('X-Content-Type-Options', 'nosniff');
        response.setHeader('Origin-Agent-Cluster', '?1');
        response.setHeader('Content-Security-Policy',
            `frame-ancestors ${approved.hostOrigin}; frame-src 'none'; object-src 'none'; `
            + "form-action 'none'; worker-src 'none'");
        // Network/script directives belong to the View's own CSP. Imposing
        // them (including base-uri) here would be inherited by srcdoc and
        // revoke approved grants. The View's own policy denies ungranted URLs.
        // Device delegation remains constrained by both iframe allow lists.
        response.setHeader('Permissions-Policy', permissionPolicy);
        const end = (status, text) => {
            response.statusCode = status;
            response.end(request.method === 'HEAD' ? undefined : text);
        };
        if (request.headers.cookie || request.headers.authorization || request.headers['x-api-key']) {
            response.setHeader('Connection', 'close');
            return end(400, 'Sandbox requests must not carry identity credentials');
        }
        if (!['GET', 'HEAD'].includes(request.method)) {
            response.setHeader('Allow', 'GET, HEAD');
            response.setHeader('Connection', 'close');
            return end(405, 'Sandbox service is read-only');
        }
        if (request.headers['transfer-encoding'] ||
            (request.headers['content-length'] !== undefined && request.headers['content-length'] !== '0')) {
            response.setHeader('Connection', 'close');
            return end(400, 'Sandbox requests must not carry bodies');
        }
        let target;
        try { target = new URL(request.url, 'http://sandbox.invalid'); }
        catch (error) {
            if (!(error instanceof TypeError)) throw error;
            return end(400, 'Invalid sandbox request target');
        }
        if (target.search || target.hash) return end(404, 'Sandbox resource not found');
        if (target.pathname === '/config') {
            if (request.headers.origin && request.headers.origin !== approved.hostOrigin) {
                return end(403, 'Sandbox host origin is not allowed');
            }
            response.setHeader('Access-Control-Allow-Origin', approved.hostOrigin);
            response.setHeader('Vary', 'Origin');
            response.setHeader('Content-Type', 'application/json');
            return end(200, configJson);
        }
        if (target.pathname === '/sandbox-entry.js') {
            response.setHeader('Content-Type', 'text/javascript; charset=utf-8');
            return end(200, entryJavascript);
        }
        if (target.pathname === '/THIRD_PARTY_NOTICES.txt') {
            response.setHeader('Content-Type', 'text/plain; charset=utf-8');
            return end(200, thirdPartyNotices);
        }
        if (target.pathname === '/proxy') {
            response.setHeader('Content-Type', 'text/html; charset=utf-8');
            return end(200, html);
        }
        if (target.pathname === '/health') {
            response.setHeader('Content-Type', 'application/json');
            return end(200, JSON.stringify({ status: 'ok' }));
        }
        return end(404, 'Sandbox resource not found');
    });
    service.requestTimeout = limits.requestTimeoutMs;
    service.headersTimeout = limits.headersTimeoutMs;
    service.keepAliveTimeout = limits.keepAliveTimeoutMs;
    return service;
}
