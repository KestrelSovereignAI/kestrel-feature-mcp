import DOMPurify from 'dompurify';

/** Real Console modules, original chat ownership and native HTTP credentials. */
export async function mountNativeConsole({ getToken, renderer, endpoint, body, partType }) {
    window.DOMPurify = DOMPurify;
    window.KESTREL_UI_CONFIG = { bearerToken: { getToken } };
    for (const file of ['parse.js', 'highlight.js', 'mermaid.js', 'katex.js', 'index.js']) {
        await new Promise((resolve, reject) => {
            const script = document.createElement('script'); script.src = '/shared/markdown/' + file;
            script.onload = resolve; script.onerror = reject; document.head.append(script);
        });
    }
    await import('/js/icons.js'); globalThis.kicon = window.kicon;
    const chat = await import('/js/chat.js'), ui = await import('/js/ui.js');
    const { default: api } = await import('/js/api.js');
    const { bus } = await import('/js/ui-ext/bus.js');
    for (const module of Array.isArray(renderer) ? renderer : [renderer]) await import(module);
    const pane = ui.getOrCreateChatPane(null); pane.sessionId = 'original-chat';
    document.body.append(pane.element); chat.setChatDeps({ markdown: window.SharedMarkdown });
    const envelope = await api.requestForAgent(endpoint, { method: 'POST',
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, null, true);
    const part = envelope.parts.find(value => value.type === partType);
    if (!part) throw new TypeError('The actual governed response supplied no expected Console part');
    function show() { chat.appendMessagePart(part.type, part.data, pane.element); }
    show();
    window.leaveChat = () => { pane.sessionId = 'another-chat'; bus.emit('session:change'); };
    window.returnToChat = () => { pane.sessionId = 'original-chat'; };
    window.retireChat = () => chat.wipeAgentChatPane(null);
    window.reloadPart = () => { chat.wipeAgentChatPane(null); pane.sessionId = 'original-chat';
        document.body.append(pane.element); show(); };
    return { chat, pane, api, bus, part };
}
