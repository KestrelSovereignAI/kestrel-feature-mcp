import { mountNativeConsole } from './native-console.js';

await mountNativeConsole({
    getToken: () => window.fixtureKey,
    renderer: '/features/mcpagent/static/input-entry.js',
    endpoint: '/api/owned-credential-call',
    partType: 'mcp_task',
    sessionId: 'credential-chat',
});
