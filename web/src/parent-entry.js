import API from '/js/api.js';
import { registerRenderer } from '/js/ui-ext/renderers.js';
import { bus } from '/js/ui-ext/bus.js';
import { mountMCPApp } from './parent-view.js';

registerRenderer({
    id: 'mcp-apps-original-chat', match: { contentType: 'mcp_app' },
    render(data, context) {
        if (!data || Object.keys(data).some(key => !['reference', 'session_id'].includes(key))
            || !/^[A-Za-z0-9_-]{43}$/.test(data.reference)
            || typeof data.session_id !== 'string' || data.session_id !== context.sessionId
            || typeof context.isCurrentChat !== 'function') return '<p>App unavailable for this conversation.</p>';
        return '<div class="mcp-app-view"><button type="button" value="' + data.reference
            + '">Open App</button><button class="mcp-app-close" type="button" hidden>Close App</button></div>';
    },
    mount(root, context) {
        const container = root.querySelector('.mcp-app-view');
        if (!container) return;
        const button = container.querySelector('button');
        const closeButton = container.querySelector('.mcp-app-close');
        let view, closing, retired = false;
        function close() {
            const original = view; view = undefined;
            closeButton.hidden = true;
            if (!original) return;
            button.disabled = true;
            closing = original.dispose().catch(() => {
                const message = document.createElement('p');
                message.textContent = 'Server cleanup could not be confirmed. The completed tool will not be replayed.';
                container.append(message);
            }).finally(() => {
                closing = undefined;
                button.disabled = false;
            });
        }
        function open() {
            if (retired || view || closing || !context.isCurrentChat()) return;
            button.disabled = true;
            view = mountMCPApp({ root: container, reference: button.value,
                sessionId: context.sessionId, isCurrentChat: context.isCurrentChat,
                request: (path, options = {}) => API.requestForAgent(path,
                    { ...options, credentials: 'same-origin' }, context.ownerAgent, true),
            });
            closeButton.hidden = false;
        }
        button.addEventListener('click', open);
        closeButton.addEventListener('click', close);
        const off = ['agent:switch', 'session:change', 'auth:change'].map(event => bus.on(event, close));
        return () => {
            retired = true; button.removeEventListener('click', open);
            closeButton.removeEventListener('click', close);
            for (const unsubscribe of off) unsubscribe();
            close();
        };
    },
});
