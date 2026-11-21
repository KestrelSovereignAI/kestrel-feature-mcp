import API from '/js/api.js';
import { registerPanel } from '/js/ui-ext/panels.js';
import { bus } from '/js/ui-ext/bus.js';

const PANEL = 'mcp-connectors';
const ROOT = '/api/mcp/oauth';
const CATALOG = '/api/mcp/connectors/catalog';
const HINT = 'kestrel.mcp-oauth.';
const states = Object.freeze({ authorized: 'Authorized; ready to connect', connected: 'Connected',
    authorizing: 'Waiting for authorization', outcome_unknown: 'Authorization outcome uncertain',
    refresh_unknown: 'Refresh outcome uncertain', reauthorization_required: 'New authorization required',
    resource_rejected: 'The connector refused this grant', revoked: 'Disconnected locally' });

export function mountOAuthPanel(root, api = API, events = bus, browser = window) {
    const document = root.ownerDocument;
    let generation = 0, busy = false, disposed = false, controller, catalogController, showingSearch = false;
    const element = (tag, text, parent = root) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        parent.append(node);
        return node;
    };
    root.replaceChildren();
    root.classList.add('mcp-connectors-panel');
    element('h2', 'MCP connectors');
    const discovery = element('form');
    discovery.className = 'mcp-connector-search';
    const searchLabel = element('label', 'Find a connector', discovery);
    searchLabel.className = 'mcp-oauth-field';
    const query = element('input', undefined, searchLabel);
    query.type = 'search';
    query.required = true;
    query.minLength = 3;
    query.maxLength = 200;
    const search = element('button', 'Search MCP Registry', discovery);
    search.type = 'submit';
    search.className = 'btn btn-secondary';
    const catalogStatus = element('p');
    catalogStatus.setAttribute('aria-live', 'polite');
    const catalog = element('div');
    catalog.className = 'mcp-connector-catalog';
    const setup = element('div');
    element('h3', 'Authorization', setup);
    const status = element('p', 'Choose Refresh to read your connections.', setup);
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    const form = element('form', undefined, setup);
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
    const refresh = element('button', 'Refresh connections', setup); refresh.type = 'button';
    refresh.className = 'btn btn-secondary';
    const pending = element('div', undefined, setup);
    const connections = element('div', undefined, setup);

    const capture = signal => {
        const agent = api.getHostAgent();
        let base = api.buildAgentUrl(ROOT);
        if (agent) {
            // Core's lossless address retains the same selected Unicode name
            // through consent and a fresh callback-page API instance.
            const bytes = new TextEncoder().encode(agent);
            const encoded = browser.btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''))
                .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
            base = `/api/agent-routes/${encoded}${ROOT}`;
        }
        const token = generation;
        const current = () => !disposed && !signal.aborted && token === generation && agent === api.getHostAgent();
        const check = () => {
            if (!current()) {
                throw new Error('The original Console actor changed');
            }
        };
        return { prefix: base.slice(0, -ROOT.length), current, check, signal };
    };
    const request = async (owner, path, options = {}) => {
        owner.check();
        const result = await api.requestHost(owner.prefix + path, {
            ...options, credentials: 'same-origin', signal: owner.signal,
        }, true); // Native authentication/CSRF; never replay a mutation after a 401.
        owner.check();
        return result;
    };
    const setBusy = value => {
        busy = value;
        for (const node of setup.querySelectorAll('button, input')) node.disabled = value;
        for (const node of catalog.querySelectorAll('[data-connector-select]')) node.disabled = value;
    };
    async function perform(operation) {
        if (busy || disposed) return;
        controller = new AbortController();
        const owner = capture(controller.signal);
        setBusy(true);
        let focus;
        try {
            focus = await operation(owner);
        } catch (error) {
            if (!owner.current()) return;
            status.textContent = error.status === 404 ? 'Enable OAuth in the MCP feature settings before connecting.'
                : error.status === 403 ? 'This account or host cannot use OAuth here.'
                : error.status === 503 ? 'The outcome is uncertain. Refresh connections before another action; do not repeat it.'
                : 'The request could not be completed. Check the URL and scopes, then refresh connections.';
        } finally {
            if (owner.current()) {
                setBusy(false);
                focus?.focus();
            }
        }
    }
    const makeButton = (parent, label, onClick) => {
        const node = element('button', label, parent);
        node.type = 'button'; node.className = 'btn btn-secondary';
        node.addEventListener('click', onClick);
        return node;
    };
    const button = (parent, label, action) => {
        const node = makeButton(parent, label, () => { void perform(action); });
        node.disabled = busy;
        return node;
    };
    const clearSearch = makeButton(discovery, 'Clear search', () => {
        query.value = '';
        void loadCatalog();
    });
    clearSearch.hidden = true;
    let prepared;
    function prepare(url, requested, fromCatalog = false) {
        prepared = { url, fromCatalog };
        server.value = url;
        scopes.value = requested.join(' ');
        acknowledge.checked = false;
        status.textContent = requested.length
            ? 'Review the requested scopes, then authorize the connector.'
            : 'Enter the scopes listed in the connector’s documentation.';
        return requested.length ? authorize : scopes;
    }
    async function loadCatalog(term, cursor) {
        if (disposed) return;
        catalogController?.abort();
        catalogController = new AbortController();
        const owner = capture(catalogController.signal);
        showingSearch = Boolean(term);
        if (!cursor) {
            catalog.replaceChildren();
            clearSearch.hidden = !term;
        }
        const parameters = new URLSearchParams();
        if (term) parameters.set('q', term);
        if (cursor) parameters.set('cursor', cursor);
        try {
            const result = await request(owner, CATALOG + (term ? '?' + parameters : ''));
            if (!Array.isArray(result?.connectors)) throw new Error('Invalid connector catalog');
            catalog.replaceChildren();
            if (term) {
                catalogStatus.textContent = result.connectors.length
                    ? 'MCP Registry results' : 'No selectable HTTPS connectors on this page.';
                if (result.rejected_records > 0) {
                    catalogStatus.textContent += ' The Registry returned invalid listings that could not be shown.';
                }
                if (result.truncated) {
                    catalogStatus.textContent += ' Some endpoints were omitted. Narrow the search or enter a server URL.';
                }
            } else {
                catalogStatus.textContent = result.connectors.length ? 'Quick setup' : '';
            }
            for (const entry of result.connectors) {
                const card = element('article', undefined, catalog);
                card.className = 'mcp-connector-card';
                element('h3', entry.title, card);
                if (entry.name !== entry.title) element('p', entry.name, card);
                element('p', entry.description, card);
                element('p', entry.url, card);
                if (entry.deprecated) {
                    element('p', entry.status_message ? 'Deprecated. ' + entry.status_message : 'Deprecated.', card);
                }
                const choose = button(card, 'Use connector', async () => prepare(entry.url, entry.scopes, true));
                choose.dataset.connectorSelect = '';
            }
            if (result.next_cursor) {
                makeButton(catalog, 'Next page', () => { void loadCatalog(term, result.next_cursor); });
            }
        } catch (error) {
            if (owner.current()) {
                if ([401, 403, 404].includes(error.status)) {
                    catalog.replaceChildren();
                    if (prepared?.fromCatalog) {
                        server.value = ''; scopes.value = ''; prepared = undefined; acknowledge.checked = false;
                    }
                    catalogStatus.textContent = 'Connectors are unavailable for the current account or agent.';
                } else {
                    catalogStatus.textContent = error.status === 422 ? 'Enter at least three characters.'
                        : 'Connector search is unavailable. You can still enter a server URL.';
                }
            }
        }
    }
    const searchCatalog = event => {
        event.preventDefault();
        const term = query.value;
        if (term.trim().length < 3) {
            catalogController?.abort();
            showingSearch = true;
            catalog.replaceChildren();
            clearSearch.hidden = false;
            catalogStatus.textContent = 'Enter at least three characters.';
            return;
        }
        void loadCatalog(term);
    };
    const updateManualUrl = () => {
        if (prepared && server.value !== prepared.url) {
            scopes.value = '';
            prepared = undefined;
        }
    };
    function renderPending(owner) {
        pending.replaceChildren();
        for (let index = 0; index < browser.sessionStorage.length; index++) {
            const key = browser.sessionStorage.key(index);
            if (!key?.startsWith(HINT)) continue;
            let hint;
            try { hint = JSON.parse(browser.sessionStorage.getItem(key)); }
            catch { continue; }
            if (!hint || hint.agentPrefix !== owner.prefix
                || !/^[A-Za-z0-9_-]{43}$/.test(hint.operationId)) continue;
            button(pending, 'Cancel pending authorization', async actor => {
                await request(actor, ROOT + '/authorizations/' + hint.operationId, { method: 'DELETE' });
                browser.sessionStorage.removeItem(key);
                await load(actor);
            });
        }
    }
    async function load(owner) {
        const result = await request(owner, ROOT + '/connections');
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
            const path = ROOT + '/connections/' + encodeURIComponent(row.connection_id);
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
            button(actions, 'Prepare new authorization', async () => prepare(row.server_url, row.scopes));
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
            const started = await request(owner, ROOT + '/authorizations', { method: 'POST', body: JSON.stringify({
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
                agentPrefix: owner.prefix, operationId: started.operation_id, returnTo: '/',
            }));
            owner.check();
            browser.location.assign(destination.href);
        });
    };
    const reload = () => {
        void perform(load);
        if (!showingSearch) void loadCatalog();
    };
    function reset() {
        generation++;
        controller?.abort();
        catalogController?.abort();
        connections.replaceChildren(); pending.replaceChildren();
        catalog.replaceChildren(); catalogStatus.textContent = '';
        showingSearch = false; query.value = ''; prepared = undefined; clearSearch.hidden = true;
        server.value = scopes.value = ''; acknowledge.checked = false;
        status.textContent = 'Choose Refresh to read the current account’s connections.';
        setBusy(false);
    }
    form.addEventListener('submit', submit);
    discovery.addEventListener('submit', searchCatalog);
    server.addEventListener('input', updateManualUrl);
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
        discovery.removeEventListener('submit', searchCatalog); server.removeEventListener('input', updateManualUrl);
        for (const unsubscribe of off) unsubscribe();
    }
    return { dispose, refresh: reload };
}

registerPanel({ panelId: PANEL, label: 'MCP connectors', render: root => mountOAuthPanel(root) });
