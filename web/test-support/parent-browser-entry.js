import { mountNativeConsole } from './native-console.js';
await mountNativeConsole({ getToken: () => 'owned-mcp-composition-api-key',
    renderer: '/features/mcpagent/static/parent-entry.js', endpoint: '/api/owned-turn', partType: 'mcp_app' });
window.nativeParentReady = true;
