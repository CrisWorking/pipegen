import { defineConfig, type Options } from 'tsup';

// Exported so the package test can build a probe entry with exactly the same settings.
export const tsupOptions = {
  entry: { 'cli/main': 'src/cli/main.ts' },
  outDir: 'dist',
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  clean: true,
  // ESM output; the CommonJS libraries bundled in (fast-glob, picomatch, ...) call require() for Node built-ins,
  // which esbuild's shim refuses in ESM unless a real `require` exists, so the banner creates one.
  banner: { js: "#!/usr/bin/env node\nimport { createRequire as __pipegenCreateRequire } from 'node:module';\nconst require = __pipegenCreateRequire(import.meta.url);" },
  noExternal: [/.*/],
  removeNodeProtocol: false, // keep node: prefixes so the bundle imports only node: built-ins
} satisfies Options;

export default defineConfig(tsupOptions);
