import API from '/js/api.js';
import { registerRenderer } from '/js/ui-ext/renderers.js';
import { bus } from '/js/ui-ext/bus.js';
import { appendMessagePart } from '/js/chat.js';
import { isInputReference, mountMCPInput } from './input-card.js';
import './input-card.css';

registerRenderer({
    id: 'mcp-original-operator-input', match: { contentType: 'mcp_input' },
    render(data, context) {
        if (!data || Object.keys(data).some(key => !['reference', 'session_id'].includes(key))
            || !isInputReference(data.reference) || data.session_id !== context.sessionId
            || typeof context.isCurrentChat !== 'function') return '<p>Input unavailable for this conversation.</p>';
        return '<div class="mcp-input-card"><button type="button" value="' + data.reference
            + '">Review MCP input</button><button class="mcp-input-close" type="button" hidden>Close input</button>'
            + '<div class="mcp-input-content"></div></div>';
    },
    mount(root, context) {
        const container = root.querySelector('.mcp-input-card');
        if (!container) return;
        const button = container.querySelector('button'), content = container.querySelector('.mcp-input-content');
        const close = container.querySelector('.mcp-input-close');
        const published = new Set();
        let card, retired = false;
        function clear() { card?.dispose(); card = undefined; button.disabled = false; close.hidden = true; }
        function open() {
            if (retired || card || !context.isCurrentChat()) return;
            card = mountMCPInput({ root: content, reference: button.value,
                sessionId: context.sessionId, isCurrentChat: context.isCurrentChat,
                onResult(result) {
                    if (!context.isCurrentChat()) return;
                    for (const part of result.tool_result?.parts ?? []) {
                        if (part.type === 'mcp_input') continue;
                        const key = JSON.stringify(part);
                        if (!published.has(key)) {
                            appendMessagePart(part.type, part.data, context.paneElement); published.add(key);
                        }
                    }
                },
                request: (path, options) => API.requestForAgent(path, options, context.ownerAgent, true) });
            button.disabled = true;
            close.hidden = false;
        }
        button.addEventListener('click', open);
        close.addEventListener('click', clear);
        const off = ['agent:switch', 'session:change', 'auth:change'].map(event => bus.on(event, clear));
        return () => { retired = true; clear(); button.removeEventListener('click', open);
            close.removeEventListener('click', clear); for (const unsubscribe of off) unsubscribe(); };
    },
});
