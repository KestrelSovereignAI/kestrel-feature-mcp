import { build } from 'esbuild';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const host = process.argv[2] === 'host';
const result = await build({ absWorkingDir: root,
    entryPoints: [host ? 'test-support/parent-browser-entry.js' : 'test-support/native-parent-app.js'],
    external: ['/js/*', '/shared/*'],
    bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true, write: false });
const script = result.outputFiles[0].text.replaceAll('</script', '<\\/script');
process.stdout.write(host ? script : '<!doctype html><body><script type="module">' + script + '</script>');
