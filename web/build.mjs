import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { buildSandboxAssets, verifySandboxBuild } from './build-assets.mjs';

const { values } = parseArgs({ options: { outdir: { type: 'string' }, check: { type: 'boolean' } }, allowPositionals: false });
const webRoot = path.dirname(fileURLToPath(import.meta.url));
const destination = values.outdir ?? path.resolve(webRoot, '../kestrel_feature_mcp/apps_sandbox');
if (values.check) await verifySandboxBuild(destination);
else await buildSandboxAssets(destination);
