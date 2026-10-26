import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { 'cli/main': 'src/cli/main.ts' },
  outDir: 'dist',
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  clean: true,
  banner: { js: '#!/usr/bin/env node' },
  noExternal: [/.*/],
  removeNodeProtocol: false, // keep node: prefixes so the bundle imports only node: built-ins
});
