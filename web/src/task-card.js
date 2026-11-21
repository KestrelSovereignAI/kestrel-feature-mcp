import { isInputReference, renderMCPForm } from './input-card.js';

const pending = new Set(['working', 'input_required', 'suspended']);

export function isTaskReference(value) {
    return Boolean(value && isInputReference(value.handle)
        && typeof value.reference === 'string' && /^[0-9a-f]{64}$/.test(value.reference));
}

export function mountMCPTask({ root, task, basePath, sessionId, request, isCurrent, browser = window }) {
    if (!isTaskReference(task) || !sessionId || typeof request !== 'function'
        || typeof isCurrent !== 'function') {
        throw new TypeError('An authenticated MCP Task reference is required');
    }
    const doc = root.ownerDocument;
    const controller = new AbortController();
    const status = doc.createElement('p');
    status.setAttribute('role', 'status');
    const input = doc.createElement('div'), cancel = doc.createElement('button');
    cancel.type = 'button'; cancel.textContent = 'Request cancellation'; cancel.hidden = true;
    root.append(status, input, cancel);
    let retired = false, busy = false, timer, rendered, finish;
    const completed = new Promise(resolve => { finish = resolve; });
    const url = basePath + '/' + encodeURIComponent(task.handle);
    const query = '?session_id=' + encodeURIComponent(sessionId);
    const active = () => !retired && isCurrent();
    const call = async (suffix = '', options = {}) => {
        if (!active()) throw new Error('Original MCP Task delivery is unavailable');
        const value = await request(url + suffix + query, { ...options, credentials: 'same-origin',
            headers: { 'X-Kestrel-Task-Result': task.reference }, signal: controller.signal });
        if (!active()) throw new Error('Original MCP Task delivery is unavailable');
        return value;
    };

    function schedule(delay = 1000) {
        browser.clearTimeout(timer);
        if (active()) timer = browser.setTimeout(() => void refresh(), delay);
    }

    async function submit(path, fields) {
        if (!active() || busy) return;
        busy = true;
        browser.clearTimeout(timer);
        try {
            const reply = await call(path, { method: 'POST', body: JSON.stringify({
                operation_id: browser.crypto.randomUUID(), ...fields }) });
            status.textContent = reply.status === 'ok' ? 'Request acknowledged.' : 'The request was refused.';
            if (reply.status === 'ok' && path === '/responses') {
                rendered = undefined; input.replaceChildren();
            }
        } catch {
            if (active()) status.textContent = 'The request outcome is unknown. Check the Task status.';
        } finally {
            busy = false;
            schedule();
        }
    }

    function showForms(forms) {
        const signature = JSON.stringify(forms ?? {});
        if (signature === rendered) return;
        rendered = signature;
        input.replaceChildren();
        const entries = Object.entries(forms ?? {});
        if (!entries.length) return;
        const form = doc.createElement('form');
        input.append(form);
        const readers = [];
        let supported = true;
        for (const [key, request] of entries) {
            const group = doc.createElement('fieldset'), legend = doc.createElement('legend');
            legend.textContent = request.message;
            group.append(legend); form.append(group);
            try { readers.push([key, renderMCPForm(group, request.requestedSchema)]); }
            catch { supported = false; }
        }
        for (const [action, label] of [['accept', 'Send input'], ['decline', 'Decline input']]) {
            const button = doc.createElement('button');
            button.type = 'button'; button.textContent = label; form.append(button);
            button.disabled = action === 'accept' && !supported;
            button.addEventListener('click', () => {
                if (busy || (action === 'accept' && !form.reportValidity())) return;
                try {
                    const responses = action === 'accept'
                        ? Object.fromEntries(readers.map(([key, read]) => [key, { action, content: read() }]))
                        : Object.fromEntries(entries.map(([key]) => [key, { action }]));
                    void submit('/responses', { input_responses: responses });
                } catch {
                    status.textContent = 'Review the requested values.';
                }
            });
        }
    }

    async function refresh() {
        if (!active() || busy) return;
        try {
            const row = await call();
            if (busy) return;
            if (row.result_withheld) status.textContent = 'The Task result is withheld.';
            else status.textContent = {
                working: 'Task running.', input_required: 'The Task needs input.',
                suspended: 'Task observation paused.', completed: 'Task completed.',
                cancelled: 'Task cancelled.', failed: 'Task failed.',
            }[row.status] ?? 'The Task outcome is unknown.';
            cancel.hidden = row.can_cancel !== true;
            showForms(row.forms);
            if (pending.has(row.status)) schedule();
            else finish(row);
        } catch {
            if (active()) status.textContent = 'Task status unavailable.';
            finish(null);
        }
    }

    const onCancel = () => { if (!cancel.hidden) void submit('/cancel'); };
    cancel.addEventListener('click', onCancel);
    void refresh();
    return { completed, dispose() {
        retired = true; controller.abort(); browser.clearTimeout(timer);
        cancel.removeEventListener('click', onCancel);
        status.remove(); input.remove(); cancel.remove(); finish(null);
    } };
}
