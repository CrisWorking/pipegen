import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { defineConfig, type Options } from 'tsup';

// Where the release build writes its esbuild metafile (ruling B4): outside dist/, so it is never packed. It lists every
// input file in the bundle; scripts/notices.ts turns it into THIRD_PARTY_NOTICES.
export const METAFILE_PATH = '.build/meta.json';

// Exported so the package test can build a probe entry with exactly the same settings.
export const tsupOptions = {
  entry: { 'cli/main': 'src/cli/main.ts' },
  outDir: 'dist',
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  clean: true,
  // one file: the Anthropic SDK (bundled since `audit --ai`) has dynamic import()s, which ESM code splitting would put in
  // chunk files next to main.js; without splitting esbuild inlines them, so dist/cli/main.js stays a single file
  splitting: false,
  // ESM output; the CommonJS libraries bundled in (fast-glob, picomatch, ...) call require() for Node built-ins,
  // which esbuild's shim refuses in ESM unless a real `require` exists, so the banner creates one.
  banner: { js: "#!/usr/bin/env node\nimport { createRequire as __pipegenCreateRequire } from 'node:module';\nconst require = __pipegenCreateRequire(import.meta.url);" },
  noExternal: [/.*/],
  removeNodeProtocol: false, // keep node: prefixes so the bundle imports only node: built-ins
  // marks the bundle as a release build: loadReviewed then refuses reviewed-tools entries still PENDING review (ruling S21)
  define: { 'process.env.PIPEGEN_RELEASE': '"1"' },
} satisfies Options;

// Only the default (release) build writes the metafile; the dev build and the package test's probe build use tsupOptions as is.
// tsup's own `metafile` option would write into outDir, so an esbuild plugin writes it instead (the bundle is unchanged).
export default defineConfig({
  ...tsupOptions,
  esbuildOptions(options) {
    options.metafile = true;
  },
  esbuildPlugins: [
    {
      name: 'pipegen-metafile',
      setup(build) {
        build.onEnd((result) => {
          if (!result.metafile) throw new Error('esbuild produced no metafile');
          mkdirSync(dirname(METAFILE_PATH), { recursive: true });
          writeFileSync(METAFILE_PATH, JSON.stringify(result.metafile));
        });
      },
    },
  ],
});
