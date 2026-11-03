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
        return '<div class="mcp-app-view"><button type="button" value="' + data.reference + '">Open App</button></div>';
    },
    mount(root, context) {
        const container = root.querySelector('.mcp-app-view');
        if (!container) return;
        const button = container.querySelector('button');
        let view, retired = false;
        function close() {
            const original = view; view = undefined;
            if (original) void original.dispose().catch(() => {
                const message = document.createElement('p');
                message.textContent = 'Server cleanup could not be confirmed. The completed tool will not be replayed.';
                container.append(message);
            });
            button.disabled = false;
        }
        function open() {
            if (retired || view || !context.isCurrentChat()) return;
            button.disabled = true;
            view = mountMCPApp({ root: container, reference: button.value,
                sessionId: context.sessionId, isCurrentChat: context.isCurrentChat,
                request: (path, options = {}) => API.requestForAgent(path,
                    { ...options, credentials: 'same-origin' }, context.ownerAgent, true),
            });
        }
        button.addEventListener('click', open);
        const off = ['agent:switch', 'session:change', 'auth:change'].map(event => bus.on(event, close));
        queueMicrotask(open);
        return () => {
            retired = true; button.removeEventListener('click', open);
            for (const unsubscribe of off) unsubscribe();
            close();
        };
    },
});
