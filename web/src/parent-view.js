import { AppBridge, buildAllowAttribute } from '@modelcontextprotocol/ext-apps/app-bridge';
import { OriginBoundTransport } from './origin-transport.js';
import { approveSandboxPolicy } from './sandbox-proxy.js';

/** One physical View. request() is the original authenticated host HTTP lane. */
export function mountMCPApp({ root, reference, sessionId, request, isCurrentChat,
    hostInfo = { name: 'Kestrel Sovereign', version: '1' }, eventWindow = window }) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(reference) || typeof sessionId !== 'string' || !sessionId
        || typeof request !== 'function' || typeof isCurrentChat !== 'function') {
        throw new TypeError('An original chat and authenticated App request lane are required');
    }
    let bridge, proxy, viewId, retired = false, cleanup;
    const calls = new AbortController();
    const query = '?session_id=' + encodeURIComponent(sessionId);
    const viewPath = () => '/api/mcp/apps/views/' + encodeURIComponent(viewId);
    const status = eventWindow.document.createElement('p');
    status.setAttribute('role', 'status'); status.textContent = 'Opening App…'; root.append(status);

    function current() {
        if (retired || !isCurrentChat()) throw new Error('The original App chat is no longer active');
    }

    async function closeServerView() {
        if (viewId) {
            await request(viewPath() + query, { method: 'DELETE' });
            viewId = undefined;
        }
    }

    async function dispose() {
        if (cleanup) return cleanup;
        retired = true;
        calls.abort();
        const bridgeClosed = bridge?.close();
        proxy?.remove();
        cleanup = (async () => {
            // Keep the bounded opening request owned: if its acknowledgement
            // arrives after navigation, close that exact View without rendering.
            const outcome = await openingSettled;
            const results = await Promise.allSettled([bridgeClosed, closeServerView()]);
            const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
            if (failures.length) throw new AggregateError(failures, 'MCP App cleanup did not complete');
            status.textContent = outcome.ok ? 'App closed.'
                : 'App unavailable; private View closed. The completed tool will not be replayed.';
        })();
        return cleanup;
    }

    function fail() {
        status.textContent = 'App unavailable. The completed tool will not be replayed.';
        void dispose().catch(() => {
            status.textContent = 'App closed locally; server cleanup could not be confirmed.';
        });
    }

    const opening = (async () => {
        current();
        const initial = await request('/api/mcp/apps/publications/' + reference + '/views' + query,
            { method: 'POST', body: JSON.stringify({}) });
        if (!initial || !/^[A-Za-z0-9_-]{43}$/.test(initial.view_id)) {
            throw new TypeError('Host returned no original physical App View');
        }
        viewId = initial.view_id;
        if (retired) return;
        current();
        if (initial.host_origin !== eventWindow.location.origin) {
            throw new TypeError('The App host origin does not match this console');
        }
        const sandboxUrl = new URL(initial.sandbox_url);
        if (sandboxUrl.username || sandboxUrl.password || sandboxUrl.search || sandboxUrl.hash
            || sandboxUrl.origin === eventWindow.location.origin
            || !['https:', 'http:'].includes(sandboxUrl.protocol)) {
            throw new TypeError('The App sandbox requires a different credential-free origin');
        }
        const ui = initial.resource?._meta?.ui ?? {};
        const approved = approveSandboxPolicy(ui.csp, ui.permissions, initial.policy);
        proxy = eventWindow.document.createElement('iframe');
        proxy.title = 'MCP App'; proxy.referrerPolicy = 'no-referrer';
        proxy.setAttribute('sandbox', 'allow-scripts allow-same-origin');
        proxy.setAttribute('allow', buildAllowAttribute(approved.permissions));
        proxy.style.width = '100%'; proxy.style.height = '360px'; proxy.style.border = '0';
        root.append(proxy);
        bridge = new AppBridge(null, hostInfo, { serverTools: {} });
        bridge.onerror = fail;
        bridge.oncalltool = async (params, extra) => {
            current();
            if (!params || Object.keys(params).some(key => !['name', 'arguments', '_meta'].includes(key))) {
                throw new TypeError('This App host supports ordinary governed tool calls; Tasks require separate host support');
            }
            const operationId = eventWindow.crypto.randomUUID();
            const result = await request(viewPath() + '/tools/call' + query, {
                method: 'POST', body: JSON.stringify({ name: params.name,
                    arguments: params.arguments ?? {}, operation_id: operationId }),
                signal: AbortSignal.any([calls.signal, extra.mcpReq.signal]),
            });
            current();
            return result;
        };
        bridge.setRequestHandler('tools/list', async (_params, extra) => {
            current();
            const result = await request(viewPath() + '/tools' + query, {
                signal: AbortSignal.any([calls.signal, extra.mcpReq.signal]),
            });
            current(); return result;
        });
        bridge.onsandboxready = () => {
            try {
                current();
                void bridge.sendSandboxResourceReady({ html: initial.resource.html,
                    csp: approved.csp, permissions: approved.permissions, sandbox: 'allow-scripts' }).catch(fail);
            } catch { fail(); }
        };
        let initialized = false;
        bridge.oninitialized = () => {
            if (initialized) return;
            initialized = true;
            void (async () => {
                current();
                await bridge.sendToolInput({ arguments: initial.arguments });
                current();
                await bridge.sendToolResult(initial.result);
                current();
                status.textContent = 'App ready.';
            })().catch(fail);
        };
        bridge.onsizechange = ({ height }) => {
            if (!retired && Number.isFinite(height)) proxy.style.height = Math.min(2048, Math.max(64, height)) + 'px';
        };
        await bridge.connect(new OriginBoundTransport({ targetWindow: proxy.contentWindow,
            origin: sandboxUrl.origin, maxMessageBytes: initial.max_message_bytes, eventWindow }));
        current();
        proxy.src = sandboxUrl.href;
    })();
    const openingSettled = opening.then(() => ({ ok: true }), error => ({ ok: false, error }));
    void opening.catch(fail);
    return { dispose, ready: opening };
}
