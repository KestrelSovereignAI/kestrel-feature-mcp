import { build } from 'esbuild';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const host = process.argv[2] === 'host';
const input = process.argv[2] === 'input';
const inputApp = process.argv[2] === 'input-app';
const task = process.argv[2] === 'task';
const result = await build({ absWorkingDir: root,
    entryPoints: [input ? 'test-support/input-browser-entry.js'
        : host ? 'test-support/parent-browser-entry.js'
        : task ? 'test-support/task-activation-entry.js'
        : inputApp ? 'test-support/input-native-app.js' : 'test-support/native-parent-app.js'],
    external: ['/js/*', '/shared/*', '/features/*'],
    bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true, write: false });
const script = result.outputFiles[0].text.replaceAll('</script', '<\\/script');
process.stdout.write(host || input || task ? script : '<!doctype html><body><script type="module">' + script + '</script>');
