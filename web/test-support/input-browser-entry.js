import { mountNativeConsole } from './native-console.js';
const appMode = new URLSearchParams(location.search).get('mode') === 'app';
const original = await mountNativeConsole({ getToken: () => 'owned-apps-host-api-key',
    renderer: ['/features/mcpagent/static/parent-entry.js', '/features/mcpagent/static/input-entry.js'],
    endpoint: '/api/owned-initial',
    body: { marker: 'original-marker', session_id: 'original-chat' }, partType: appMode ? 'mcp_app' : 'mcp_input' });
window.changeInputAuthentication = () => original.bus.emit('auth:change');
window.nativeInputReady = true;
