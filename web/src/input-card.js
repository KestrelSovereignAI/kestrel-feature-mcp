const referencePattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isInputReference(value) {
    return typeof value === 'string' && referencePattern.test(value);
}

function enumChoices(schema) {
    if (Array.isArray(schema.enum) && schema.enum.every(value => typeof value === 'string')) {
        return schema.enum.map(value => ({ value, title: value }));
    }
    const choices = schema.oneOf ?? schema.anyOf;
    if (Array.isArray(choices) && choices.every(item => typeof item?.const === 'string')) {
        return choices.map(item => ({ value: item.const, title: item.title ?? item.const }));
    }
    return null;
}

/** Render the standard flat primitive form; server text never becomes markup. */
export function renderMCPForm(parent, schema) {
    if (!schema || schema.type !== 'object' || !schema.properties || Array.isArray(schema.properties)) {
        throw new TypeError('The server requested an unsupported form');
    }
    const document = parent.ownerDocument, fields = [];
    for (const [key, property] of Object.entries(schema.properties)) {
        if (!property || typeof property !== 'object') throw new TypeError('Invalid form field');
        const label = document.createElement('label');
        label.textContent = property.title ?? key;
        const required = Array.isArray(schema.required) && schema.required.includes(key);
        let input, read, htmlRequired = required;
        const choices = enumChoices(property.type === 'array' ? property.items ?? {} : property);
        if (choices) {
            input = document.createElement('select');
            input.multiple = property.type === 'array';
            if (input.multiple) htmlRequired = required && (property.minItems ?? 0) > 0;
            if (!input.multiple) {
                const option = document.createElement('option');
                option.value = ''; option.textContent = 'Choose a value'; input.append(option);
            }
            for (const [index, choice] of choices.entries()) {
                const option = document.createElement('option');
                option.value = String(index); option.textContent = choice.title;
                option.selected = input.multiple ? Array.isArray(property.default) && property.default.includes(choice.value)
                    : property.default === choice.value;
                input.append(option);
            }
            read = () => {
                const values = Array.from(input.selectedOptions).filter(option => option.value !== '')
                    .map(option => choices[Number(option.value)].value);
                if (input.multiple) {
                    if (!values.length && !required) return undefined;
                    if (values.length < (property.minItems ?? 0) || values.length > (property.maxItems ?? Infinity)) {
                        throw new TypeError('Review the number of selected values');
                    }
                    return values.length || required ? values : undefined;
                }
                return values[0];
            };
        } else if (property.type === 'boolean') {
            input = document.createElement('select');
            for (const [value, title] of [['', 'Choose a value'], ['true', 'Yes'], ['false', 'No']]) {
                const option = document.createElement('option');
                option.value = value; option.textContent = title; input.append(option);
            }
            if (typeof property.default === 'boolean') input.value = String(property.default);
            read = () => input.value === '' ? undefined : input.value === 'true';
        } else if (['string', 'number', 'integer'].includes(property.type)) {
            input = document.createElement('input');
            if (property.type === 'string') htmlRequired = required && (property.minLength ?? 0) > 0;
            input.type = property.type === 'string' ? (property.format === 'date' ? 'date' : 'text') : 'number';
            if (property.type === 'string' && property.format === 'email') input.inputMode = 'email';
            if (property.type !== 'string') {
                // HTML's step base follows min, which may be fractional even for integers.
                // The original JSON Schema validator owns integer validation.
                input.step = 'any';
                if (typeof property.minimum === 'number') input.min = String(property.minimum);
                if (typeof property.maximum === 'number') input.max = String(property.maximum);
            }
            // HTML string lengths count UTF-16 code units and its email grammar
            // differs from JSON Schema. Validate those with the original schema.
            if (property.default !== undefined) input.value = String(property.default);
            read = () => input.value === '' && !required ? undefined
                : property.type === 'string' ? input.value : input.valueAsNumber;
        } else {
            throw new TypeError('The server requested an unsupported form field');
        }
        // JSON Schema requires the property, not a nonempty string/array.
        // read() supplies required empty values; the schema owns their limits.
        input.required = htmlRequired;
        input.setAttribute('aria-label', property.title ?? key);
        input.autocomplete = 'off';
        label.append(input); parent.append(label);
        if (property.description) {
            const description = document.createElement('p');
            description.textContent = property.description; parent.append(description);
        }
        fields.push([key, read]);
    }
    return () => Object.fromEntries(fields.map(([key, read]) => [key, read()])
        .filter(([, value]) => value !== undefined));
}

/** One explicit operator interaction, bound to the current account and chat. */
export function mountMCPInput({ root, reference, sessionId, isCurrentChat, request, onResult, browser = window }) {
    if (!isInputReference(reference) || typeof sessionId !== 'string' || !sessionId
        || typeof isCurrentChat !== 'function' || typeof request !== 'function' || typeof onResult !== 'function') {
        throw new TypeError('An original input reference and authenticated chat are required');
    }
    const document = root.ownerDocument, controller = new AbortController();
    let retired = false, busy = false, currentReference = reference;
    const status = document.createElement('p');
    status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
    const content = document.createElement('div'); root.append(status, content);
    const check = () => { if (retired || !isCurrentChat()) throw new Error('The original input chat changed'); };
    const call = async (path, options = {}) => {
        check();
        const result = await request('/api/mcp/inputs/' + currentReference + path
            + '?session_id=' + encodeURIComponent(sessionId), { ...options,
            credentials: 'same-origin', signal: controller.signal });
        check(); return result;
    };
    const element = (tag, text, parent = content) => {
        const node = document.createElement(tag); node.textContent = text; parent.append(node); return node;
    };
    const buttons = value => { for (const button of content.querySelectorAll('button')) button.disabled = value; };
    async function load() {
        const row = await call(''); content.replaceChildren();
        element('p', 'Server: ' + row.server_url);
        if (row.state === 'RESOLVED' && row.continuation) {
            await onResult({ request_id: row.request_id, state: row.state, ...row.continuation }); check();
            if (row.continuation.next_request_id) {
                if (!isInputReference(row.continuation.next_request_id)) throw new TypeError('Invalid next input reference');
                currentReference = row.continuation.next_request_id; await load(); return;
            }
        }
        if (row.state !== 'WAITING' || !row.resumable) {
            status.textContent = row.state === 'RESOLVED' ? 'This input has already been handled.'
                : ['RESPONDING', 'UNKNOWN'].includes(row.state) ? 'The continuation outcome is uncertain. Do not repeat the original call.'
                : 'This continuation is unavailable. The original tool will not be replayed.';
            return;
        }
        const form = document.createElement('form'); content.append(form);
        const readers = [], keys = Object.keys(row.forms);
        let supported = true;
        try {
            for (const [key, input] of Object.entries(row.forms)) {
                const group = document.createElement('fieldset'); form.append(group);
                element('legend', input.message, group);
                readers.push([key, renderMCPForm(group, input.requestedSchema)]);
            }
        } catch {
            supported = false;
        }
        const submit = element('button', 'Continue tool', form); submit.type = 'submit'; submit.disabled = !supported;
        const decline = element('button', 'Decline', form); decline.type = 'button';
        const cancel = element('button', 'Cancel', form); cancel.type = 'button';
        status.textContent = supported ? 'Review the information before sending it to this server.'
            : 'This form cannot be displayed. You can decline or cancel it.';
        async function send(action) {
            if (busy) return;
            if (action === 'accept' && (!supported || !form.reportValidity())) return;
            let responses;
            try {
                responses = action === 'accept' ? Object.fromEntries(readers.map(([key, read]) =>
                    [key, { action, content: read() }])) : Object.fromEntries(keys.map(key => [key, { action }]));
            } catch {
                status.textContent = 'Review the requested values before continuing.'; return;
            }
            busy = true; buttons(true);
            try {
                const result = await call('/responses', { method: 'POST', body: JSON.stringify({
                    revision: row.revision, operation_id: browser.crypto.randomUUID(), responses }) });
                check(); await onResult(result); check();
                content.replaceChildren();
                if (result.next_request_id) {
                    if (!isInputReference(result.next_request_id)) throw new TypeError('Invalid next input reference');
                    currentReference = result.next_request_id; await load();
                } else if (result.state === 'WAITING') {
                    await load(); status.textContent = 'The current tool policy refused this continuation.';
                } else {
                    status.textContent = [result.tool_result?.confirmation, result.tool_result?.error]
                        .filter(value => typeof value === 'string' && value).join(' ') || 'The input was handled.';
                }
            } catch (error) {
                if (retired || !isCurrentChat()) return;
                if (error.status === 400) {
                    status.textContent = 'The response was not accepted. Review the form and try again.';
                    buttons(false); submit.disabled = !supported;
                    return;
                }
                content.replaceChildren();
                status.textContent = error.status === 403 || error.status === 409 ? 'This input is unavailable for the current account or conversation.'
                    : 'The continuation outcome is uncertain. Reopen the card to inspect its state; do not repeat the tool call.';
            } finally { busy = false; }
        }
        form.addEventListener('submit', event => { event.preventDefault(); void send('accept'); });
        decline.addEventListener('click', () => { void send('decline'); });
        cancel.addEventListener('click', () => { void send('cancel'); });
    }
    const ready = load().catch(() => {
        if (!retired && isCurrentChat()) status.textContent = 'This input is unavailable for this account or conversation.';
    });
    return { ready, dispose() { retired = true; controller.abort(); content.replaceChildren(); status.remove(); content.remove(); } };
}
