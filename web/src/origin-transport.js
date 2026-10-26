import { JSONRPCMessageSchema, JSONValueSchema } from '@modelcontextprotocol/core';

/** Public MCP Transport for the host's dedicated, different-origin sandbox. */
export class OriginBoundTransport {
    #target;
    #origin;
    #window;
    #limit;
    #listener;
    #started = false;
    #closed = false;

    constructor({ targetWindow, origin, maxMessageBytes, eventWindow = window }) {
        const parsed = new URL(origin);
        if (parsed.origin !== origin || !['https:', 'http:'].includes(parsed.protocol)) {
            throw new TypeError('Sandbox origin must be an exact HTTP(S) origin');
        }
        if (origin === eventWindow.location.origin) {
            throw new TypeError('Sandbox must use a different origin from the host');
        }
        if (!Number.isSafeInteger(maxMessageBytes) || maxMessageBytes <= 0) {
            throw new TypeError('Sandbox message byte limit must be a positive safe integer');
        }
        this.#target = targetWindow;
        this.#origin = origin;
        this.#window = eventWindow;
        this.#limit = maxMessageBytes;
        this.#listener = (event) => {
            if (event.source !== this.#target || event.origin !== this.#origin) return;
            let message;
            try {
                message = this.#validate(event.data);
            } catch (error) {
                if (!(error instanceof TypeError || error instanceof RangeError)) throw error;
                this.onerror?.(error);
                return;
            }
            this.onmessage?.(message);
        };
    }

    #validate(value) {
        // Bound validation work before the official recursive JSON schemas.
        // Stringification rejects cycles/BigInts; JSONValueSchema also refuses
        // non-JSON structured-clone values rather than coercing them on wire.
        const encoded = JSON.stringify(value);
        if (typeof encoded !== 'string' || encoded.length > this.#limit
            || new TextEncoder().encode(encoded).byteLength > this.#limit) {
            throw new TypeError('Sandbox message exceeds its byte limit or is not JSON');
        }
        const json = JSONValueSchema.safeParse(value);
        const message = json.success && JSONRPCMessageSchema.safeParse(json.data);
        if (!message || !message.success) throw new TypeError('Sandbox sent an invalid MCP JSON-RPC message');
        return message.data;
    }

    async start() {
        if (this.#closed || this.#started) throw new Error('Sandbox transport cannot be restarted');
        this.#started = true;
        this.#window.addEventListener('message', this.#listener);
    }

    async send(message) {
        if (!this.#started || this.#closed) throw new Error('Sandbox transport is not active');
        this.#target.postMessage(this.#validate(message), this.#origin);
    }

    async close() {
        if (this.#closed) return;
        this.#closed = true;
        this.#window.removeEventListener('message', this.#listener);
        this.onclose?.();
    }
}
