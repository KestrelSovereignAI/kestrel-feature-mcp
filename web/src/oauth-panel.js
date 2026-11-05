import API from '/js/api.js';
import { registerPanel } from '/js/ui-ext/panels.js';
import { bus } from '/js/ui-ext/bus.js';

const PANEL = 'mcp-connectors';
const ROOT = '/api/mcp/oauth';
const HINT = 'kestrel.mcp-oauth.';
const states = Object.freeze({ authorized: 'Authorized; ready to connect', connected: 'Connected',
    authorizing: 'Waiting for authorization', outcome_unknown: 'Authorization outcome uncertain',
    refresh_unknown: 'Refresh outcome uncertain', reauthorization_required: 'New authorization required',
    resource_rejected: 'The connector refused this grant', revoked: 'Disconnected locally' });

export function mountOAuthPanel(root, api = API, events = bus, browser = window) {
    const document = root.ownerDocument;
    let generation = 0, busy = false, disposed = false, controller;
    const element = (tag, text, parent = root) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        parent.append(node);
        return node;
    };
    root.replaceChildren();
    root.classList.add('mcp-connectors-panel');
    element('h2', 'MCP connectors');
    element('p', 'Authorize a connector for your signed-in account, then connect its tools to this agent.');
    const status = element('p', 'Choose Refresh to read your connections.');
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    const form = element('form');
    const input = (label, type) => {
        const wrapper = element('label', label, form);
        wrapper.className = type === 'checkbox' ? 'mcp-oauth-choice' : 'mcp-oauth-field';
        const node = element('input', undefined, wrapper);
        node.type = type;
        node.setAttribute('aria-label', label);
        if (type === 'checkbox') wrapper.prepend(node);
        return node;
    };
    const server = input('MCP server URL', 'url'); server.required = true;
    const scopes = input('Scopes', 'text'); scopes.required = true;
    const acknowledge = input('Start a new authorization after an uncertain outcome', 'checkbox');
    const authorize = element('button', 'Authorize connector', form); authorize.type = 'submit';
    authorize.className = 'btn btn-primary';
    const refresh = element('button', 'Refresh connections'); refresh.type = 'button';
    refresh.className = 'btn btn-secondary';
    const pending = element('div');
    const connections = element('div');

    const capture = () => {
        const base = api.buildAgentUrl(ROOT);
        const token = generation;
        const agent = api.getHostAgent();
        const check = () => {
            if (disposed || token !== generation || agent !== api.getHostAgent()) {
                throw new Error('The original Console actor changed');
            }
        };
        return { base, check, current: () => !disposed && token === generation && agent === api.getHostAgent() };
    };
    const request = async (owner, path, options = {}) => {
        owner.check();
        const result = await api.requestHost(owner.base + path, {
            ...options, credentials: 'same-origin', signal: controller.signal,
        }, true); // Native authentication/CSRF; never replay a mutation after a 401.
        owner.check();
        return result;
    };
    const setBusy = value => {
        busy = value;
        for (const node of root.querySelectorAll('button, input')) node.disabled = value;
    };
    async function perform(operation) {
        if (busy || disposed) return;
        const owner = capture();
        controller = new AbortController();
        setBusy(true);
        try {
            await operation(owner);
        } catch (error) {
            if (!owner.current()) return;
            status.textContent = error.status === 404 ? 'Enable OAuth in the MCP feature settings before connecting.'
                : error.status === 403 ? 'This account or host cannot use OAuth here.'
                : error.status === 503 ? 'The outcome is uncertain. Refresh connections before another action; do not repeat it.'
                : 'The request could not be completed. Check the URL and scopes, then refresh connections.';
        } finally {
            if (owner.current()) setBusy(false);
        }
    }
    const button = (parent, label, action) => {
        const node = element('button', label, parent);
        node.type = 'button'; node.className = 'btn btn-secondary';
        node.addEventListener('click', () => { void perform(action); });
        return node;
    };
    function renderPending(owner) {
        pending.replaceChildren();
        for (let index = 0; index < browser.sessionStorage.length; index++) {
            const key = browser.sessionStorage.key(index);
            if (!key?.startsWith(HINT)) continue;
            let hint;
            try { hint = JSON.parse(browser.sessionStorage.getItem(key)); }
            catch { continue; }
            if (!hint || hint.agentPrefix !== owner.base.slice(0, -ROOT.length)
                || !/^[A-Za-z0-9_-]{43}$/.test(hint.operationId)) continue;
            button(pending, 'Cancel pending authorization', async actor => {
                await request(actor, '/authorizations/' + hint.operationId, { method: 'DELETE' });
                browser.sessionStorage.removeItem(key);
                await load(actor);
            });
        }
    }
    async function load(owner) {
        const result = await request(owner, '/connections');
        if (!Array.isArray(result?.connections)) throw new Error('Invalid connection status');
        connections.replaceChildren();
        for (const row of result.connections) {
            const card = element('section', undefined, connections);
            card.className = 'mcp-connector-card';
            element('h3', row.server_url, card);
            element('p', row.issuer, card);
            element('p', 'Scopes: ' + row.scopes.join(' '), card);
            element('p', states[row.state] ?? 'Connection status unavailable', card);
            const actions = element('div', undefined, card);
            actions.className = 'mcp-connector-actions';
            const path = '/connections/' + encodeURIComponent(row.connection_id);
            if (['authorized', 'connected', 'resource_rejected'].includes(row.state)) {
                button(actions, row.connected ? 'Reconnect' : 'Connect', async actor => {
                    await request(actor, path + '/connect', { method: 'POST', body: JSON.stringify({ refresh: false }) });
                    await load(actor);
                });
                button(actions, 'Refresh credentials', async actor => {
                    await request(actor, path + '/connect', { method: 'POST', body: JSON.stringify({ refresh: true }) });
                    await load(actor);
                });
            }
            if (row.state !== 'revoked') button(actions, 'Disconnect locally', async actor => {
                await request(actor, path, { method: 'DELETE' });
                await load(actor);
                status.textContent = 'Local tokens and saved connection removed. Provider-side revocation was not attempted.';
            });
            button(actions, 'Prepare new authorization', async () => {
                server.value = row.server_url; scopes.value = row.scopes.join(' '); server.focus();
            });
        }
        renderPending(owner);
        status.textContent = result.connections.length ? 'Connections loaded for your account.' : 'No saved connectors for your account.';
    }
    const submit = event => {
        event.preventDefault();
        void perform(async owner => {
            const selected = new URL(server.value);
            const requested = scopes.value.trim().split(/\s+/);
            if (selected.protocol !== 'https:' || selected.username || selected.password || selected.hash
                || !requested[0] || new Set(requested).size !== requested.length) throw new Error('Invalid authorization');
            // Fail before Begin when this browser cannot retain its same-tab hint.
            browser.sessionStorage.setItem(HINT + 'storage-check', '1');
            browser.sessionStorage.removeItem(HINT + 'storage-check');
            const started = await request(owner, '/authorizations', { method: 'POST', body: JSON.stringify({
                server_url: server.value, scopes: requested, acknowledge_unknown: acknowledge.checked,
            }) });
            const destination = new URL(started.authorization_url);
            const state = destination.searchParams.getAll('state');
            if (destination.protocol !== 'https:' || destination.username || destination.password
                || destination.origin !== new URL(started.issuer).origin
                || state.length !== 1 || state[0].length < 16 || state[0].length > 1024
                || !/^[A-Za-z0-9_-]{43}$/.test(started.operation_id)) throw new Error('Invalid authorization owner');
            owner.check();
            browser.sessionStorage.setItem(HINT + state[0], JSON.stringify({
                agentPrefix: owner.base.slice(0, -ROOT.length), operationId: started.operation_id, returnTo: '/',
            }));
            owner.check();
            browser.location.assign(destination.href);
        });
    };
    const reload = () => { void perform(load); };
    function reset() {
        generation++;
        controller?.abort();
        connections.replaceChildren(); pending.replaceChildren();
        server.value = scopes.value = ''; acknowledge.checked = false;
        status.textContent = 'Choose Refresh to read the current account’s connections.';
        setBusy(false);
    }
    form.addEventListener('submit', submit);
    refresh.addEventListener('click', reload);
    const off = [api.onHostAgentChange(reset), events.on('auth:change', reset),
        events.on('panel:shown', value => { if (value?.panelId === PANEL) reload(); })];
    const observer = new MutationObserver(() => { if (!root.isConnected) dispose(); });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    function dispose() {
        if (disposed) return;
        reset(); disposed = true;
        observer.disconnect();
        form.removeEventListener('submit', submit); refresh.removeEventListener('click', reload);
        for (const unsubscribe of off) unsubscribe();
    }
    return { dispose, refresh: reload };
}

registerPanel({ panelId: PANEL, label: 'MCP connectors', render: root => mountOAuthPanel(root) });
