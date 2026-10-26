import { McpUiRequestTeardownNotificationSchema } from '@modelcontextprotocol/ext-apps/app-bridge';
import { startSandboxProxy } from './sandbox-proxy.js';
import { validateSandboxConfig } from './sandbox-config.js';

const config = validateSandboxConfig(JSON.parse(document.getElementById('sandbox-config').textContent));
startSandboxProxy({ ...config, onerror(error) {
    console.error('MCP Apps sandbox rejected a resource:', error.name);
    // This is the standard teardown request, not a new proxy-control verb.
    // Before initialization the host's loading deadline owns failed startup.
    const notification = McpUiRequestTeardownNotificationSchema.parse({
        method: 'ui/notifications/request-teardown', params: {},
    });
    window.parent.postMessage({ jsonrpc: '2.0', ...notification }, config.hostOrigin);
} });
