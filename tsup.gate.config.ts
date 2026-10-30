import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { defineConfig, type Options } from 'tsup';
import { gateViewModule } from './scripts/gate-view.js';
import { loadReviewed } from './src/engine/reviewed.js';

// The gate action's bundle (C6). GitHub runs the COMMITTED gate/dist/index.js (`runs.main` of gate/action.yml), so CI rebuilds it and fails
// on any difference (job gate-dist). The entry is gate/src/index.ts, which always calls main; never main.ts, which runs nothing on import.
export const GATE_BUNDLE = 'gate/dist/index.js';
// like the CLI's metafile (ruling B4): scripts/notices.ts turns it into gate/dist/THIRD_PARTY_NOTICES (S24); outside dist/
export const GATE_METAFILE_PATH = '.build/gate-meta.json';
export const GATE_VIEW_FILE = 'gate/src/generated/gate-view.ts';

// ESM: the repo's package.json says "type": "module", which makes gate/dist/index.js ESM wherever the action is checked out (the whole
// repository is, at the pinned commit), and Node 24 runs it directly. Everything is bundled (no node_modules at run time); only node: imports.
export const gateTsupOptions = {
  entry: { index: 'gate/src/index.ts' },
  outDir: 'gate/dist',
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  // gate/dist also holds README.md, which a clean would delete
  clean: false,
  splitting: false,
  sourcemap: false,
  minify: false,
  noExternal: [/.*/],
  removeNodeProtocol: false, // keep node: prefixes, so the bundle imports only node: built-ins
} satisfies Options;

/** Writes the gate view module from data/reviewed-tools.yml before esbuild reads it (only when it changed). */
const generateGateView = {
  name: 'pipegen-gate-view',
  setup(build: { onStart: (fn: () => void) => void }): void {
    build.onStart(() => {
      const next = gateViewModule(loadReviewed());
      let current = '';
      try { current = readFileSync(GATE_VIEW_FILE, 'utf8'); } catch { /* not there yet */ }
      if (current !== next) writeFileSync(GATE_VIEW_FILE, next);
    });
  },
};

export default defineConfig({
  ...gateTsupOptions,
  esbuildOptions(options) { options.metafile = true; },
  esbuildPlugins: [
    generateGateView,
    {
      name: 'pipegen-gate-metafile',
      setup(build) {
        build.onEnd((result) => {
          if (!result.metafile) throw new Error('esbuild produced no metafile');
          mkdirSync(dirname(GATE_METAFILE_PATH), { recursive: true });
          writeFileSync(GATE_METAFILE_PATH, JSON.stringify(result.metafile));
        });
      },
    },
  ],
});
