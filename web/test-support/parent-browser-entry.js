import DOMPurify from 'dompurify';
window.DOMPurify = DOMPurify;
window.KESTREL_UI_CONFIG = { bearerToken: { getToken: () => 'owned-mcp-composition-api-key' } };
for (const file of ['parse.js', 'highlight.js', 'mermaid.js', 'katex.js', 'index.js']) {
    await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = '/shared/markdown/' + file;
        script.onload = resolve;
        script.onerror = reject;
        document.head.append(script);
    });
}
await import('/js/icons.js');
globalThis.kicon = window.kicon;
const chat = await import('/js/chat.js');
const ui = await import('/js/ui.js');
const { default: api } = await import('/js/api.js');
const { bus } = await import('/js/ui-ext/bus.js');
await import('/features/mcpagent/static/parent-entry.js');
const pane = ui.getOrCreateChatPane(null); pane.sessionId = 'original-chat';
document.body.append(pane.element);
chat.setChatDeps({ markdown: window.SharedMarkdown });
const envelope = await api.requestForAgent('/api/owned-turn', { method: 'POST' }, null, true);
const part = envelope.parts.find(value => value.type === 'mcp_app');
chat.appendMessagePart(part.type, part.data, pane.element);
window.leaveChat = () => { pane.sessionId = 'another-chat'; bus.emit('session:change'); };
window.returnToChat = () => { pane.sessionId = 'original-chat'; };
window.retireChat = () => chat.wipeAgentChatPane(null);
window.nativeParentReady = true;
