// Build script — esbuild via JS API (avoids Windows shell-quoting issues
// with the shebang banner that the CLI form trips on).
import { build } from 'esbuild';

await build({
  entryPoints: ['src/index.ts', 'src/cli.ts'],
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  outdir: 'dist',
  banner: { js: '#!/usr/bin/env node' },
});
console.log('built dist/index.js + dist/cli.js');
