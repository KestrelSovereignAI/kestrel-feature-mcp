import {
    McpUiSandboxResourceReadyNotificationSchema,
    McpUiInitializedNotificationSchema,
    buildAllowAttribute,
} from '@modelcontextprotocol/ext-apps/app-bridge';
import { OriginBoundTransport } from './origin-transport.js';

const RESERVED = 'ui/notifications/sandbox-';
const DOMAIN_KEYS = ['connectDomains', 'resourceDomains', 'frameDomains', 'baseUriDomains'];
const DEVICE_KEYS = ['camera', 'microphone', 'geolocation', 'clipboardWrite'];

function exactOrigin(value) {
    const url = new URL(value);
    if (url.origin !== value || !['https:', 'http:'].includes(url.protocol)) {
        throw new TypeError('Sandbox policy requires exact HTTP(S) origins');
    }
    return value;
}

/** Metadata requests capabilities; only the operator's policy grants them. */
export function approveSandboxPolicy(requested = {}, permissions = {}, policy) {
    if (typeof policy !== 'object' || policy === null || Array.isArray(policy)
        || Object.keys(policy).some(key => !DOMAIN_KEYS.includes(key) && key !== 'permissions')) {
        throw new TypeError('Sandbox policy must contain only domain and device grants');
    }
    if (policy.permissions !== undefined && (!Array.isArray(policy.permissions)
        || policy.permissions.some(key => !DEVICE_KEYS.includes(key)))) {
        throw new TypeError('Sandbox device grants must name supported permissions');
    }
    const csp = {};
    for (const key of DOMAIN_KEYS) {
        if (policy[key] !== undefined && !Array.isArray(policy[key])) {
            throw new TypeError('Sandbox domain grants must be arrays of exact origins');
        }
        const allowed = new Set((policy[key] ?? []).map(exactOrigin));
        if (key === 'frameDomains' && allowed.size) {
            throw new TypeError('Sandbox proxy does not support nested network frame grants');
        }
        // The operator list is canonical. Unsupported resource requests are
        // simply ungranted; normalizing them could create an unintended grant.
        csp[key] = (requested[key] ?? []).filter(origin => allowed.has(origin));
    }
    const granted = {};
    for (const key of DEVICE_KEYS) {
        if (Object.hasOwn(permissions, key) && policy.permissions?.includes(key)) granted[key] = {};
    }
    return { csp, permissions: granted };
}

export function sandboxCsp(csp) {
    const domains = key => csp[key].length ? csp[key].join(' ') : "'none'";
    const resources = csp.resourceDomains.join(' ');
    // Omit 'self': the proxy origin must never become an implicit network grant.
    return [
        "default-src 'none'", `script-src 'unsafe-inline' ${resources}`,
        `style-src 'unsafe-inline' ${resources}`, `img-src data: ${resources}`,
        `media-src data: ${resources}`, `font-src ${domains('resourceDomains')}`,
        `connect-src ${domains('connectDomains')}`,
        `frame-src ${domains('frameDomains')}`, `base-uri ${domains('baseUriDomains')}`,
        "object-src 'none'", "form-action 'none'", "worker-src 'none'",
    ].join('; ');
}

/** The spec's different-origin proxy, containing an opaque-origin View. */
export function startSandboxProxy({ hostOrigin, maxMessageBytes, maxHtmlBytes, policy,
    onerror, eventWindow = window, container = eventWindow.document.body }) {
    exactOrigin(hostOrigin);
    if (hostOrigin === eventWindow.location.origin || eventWindow.parent === eventWindow) {
        throw new TypeError('Sandbox proxy requires a different-origin parent');
    }
    for (const limit of [maxMessageBytes, maxHtmlBytes]) {
        if (!Number.isSafeInteger(limit) || limit <= 0) throw new TypeError('Sandbox byte limits must be positive safe integers');
    }
    if (!policy || typeof onerror !== 'function') throw new TypeError('Sandbox policy and error handler are required');
    // Snapshot policy before accepting untrusted messages.
    const grants = structuredClone(policy);
    approveSandboxPolicy({}, {}, grants);
    // The View's WindowProxy survives navigation, including a navigation
    // before its first load event. Restrict the parent document before
    // creating the View so no foreign document can inherit its bridge.
    const navigationPolicy = eventWindow.document.createElement('meta');
    navigationPolicy.httpEquiv = 'Content-Security-Policy';
    navigationPolicy.content = "frame-src 'none'";
    eventWindow.document.head.append(navigationPolicy);
    const host = eventWindow.parent;
    let view, closed = false, initializeId, phase = 'empty';
    const postHost = message => host.postMessage(message, hostOrigin);
    const dispose = () => {
        if (closed) return;
        closed = true;
        eventWindow.removeEventListener('message', listener);
        view?.remove();
    };
    const loadResource = message => {
        if (phase !== 'empty') throw new Error('Sandbox resource cannot be replaced');
        const { params } = McpUiSandboxResourceReadyNotificationSchema.parse(message);
        if (new TextEncoder().encode(params.html).byteLength > maxHtmlBytes) {
            throw new RangeError('Sandbox HTML exceeds its byte limit');
        }
        if (params.sandbox !== undefined && params.sandbox !== 'allow-scripts') {
            throw new TypeError('The View must retain an opaque sandbox origin');
        }
        const approved = approveSandboxPolicy(params.csp, params.permissions, grants);
        const doc = eventWindow.document;
        const meta = doc.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        meta.content = sandboxCsp(approved.csp);
        view = doc.createElement('iframe');
        view.setAttribute('sandbox', 'allow-scripts');
        view.setAttribute('allow', buildAllowAttribute(approved.permissions));
        view.referrerPolicy = 'no-referrer';
        let loads = 0;
        view.addEventListener('load', () => {
            if (++loads > 1) {
                dispose();
                onerror(new Error('Sandbox View navigated away from its original resource'));
            }
        });
        // CSP is parsed before any untrusted markup, including nested HTML/head tags.
        view.srcdoc = '<!doctype html><html><head>' + meta.outerHTML
            + '<meta name="referrer" content="no-referrer">' + params.html + '</html>';
        phase = 'loaded';
        container.append(view);
    };
    const listener = event => {
        const fromHost = event.source === host && event.origin === hostOrigin;
        const fromView = view && event.source === view.contentWindow && event.origin === 'null';
        if (closed || (!fromHost && !fromView)) return;
        try {
            const message = OriginBoundTransport.validateMessage(event.data, maxMessageBytes);
            if (message.method?.startsWith(RESERVED)) {
                if (fromHost && message.method === 'ui/notifications/sandbox-resource-ready') loadResource(message);
                return;
            }
            if (!view) throw new Error('Sandbox View is not loaded');
            if (fromView) {
                if (phase !== 'initialized') {
                    if (phase === 'loaded' && message.method === 'ui/initialize' && Object.hasOwn(message, 'id')) {
                        initializeId = message.id;
                        phase = 'initializing';
                    } else if (phase === 'responded' && McpUiInitializedNotificationSchema.safeParse(message).success) {
                        phase = 'initialized';
                    } else throw new Error('Sandbox View used the bridge before initialization');
                }
                postHost(message);
            } else {
                if (phase !== 'initialized') {
                    if (phase !== 'initializing' || message.id !== initializeId || !Object.hasOwn(message, 'result')) {
                        throw new Error('Host sent a View message before initialization');
                    }
                    phase = 'responded';
                }
                // Opaque origins have no serializable targetOrigin. The exact
                // WindowProxy is fixed, and inbound messages must have origin null.
                view.contentWindow.postMessage(message, '*');
            }
        } catch (error) {
            dispose();
            onerror(error);
        }
    };
    eventWindow.addEventListener('message', listener);
    postHost({ jsonrpc: '2.0', method: 'ui/notifications/sandbox-proxy-ready', params: {} });
    return dispose;
}


/** HTTP-level maximum; the two iframe allow lists narrow it per View. */
export function sandboxPermissionsPolicy(policy) {
    approveSandboxPolicy({}, {}, policy);
    const features = keys => buildAllowAttribute(Object.fromEntries(keys.map(key => [key, {}])))
        .split(';').map(value => value.trim()).filter(Boolean);
    const granted = new Set(features(policy.permissions ?? []));
    return features(DEVICE_KEYS).map(name => `${name}=${granted.has(name) ? '*' : '()'}`).join(', ');
}
