import { main } from './sandbox-cli.js';

main().catch(error => {
    console.error(JSON.stringify({ level: 'error', event: 'mcp-apps-sandbox-start-failed',
        name: error.name, message: error.message }));
    process.exitCode = 1;
});
