import { defineConfig, type Options } from 'tsup';
import { tsupOptions } from './tsup.config.js';

// The DEV build (Plan U ruling B3), for internal runs only (Task 4 Step 4, the v0.1 definition-of-done repos) before the
// owner's review of data/reviewed-tools.yml and data/pinned-binaries.yml: the release options without the `define`
// that marks a release build, so loadReviewed and loadPinnedBinaries accept entries still PENDING review. Output goes to
// .dev-dist/, which is gitignored, not in package.json `files`, and never packed or published.
//   npx tsup --config tsup.dev.config.ts   →   node .dev-dist/cli/main.js audit --dir <repo>
const { define: _releaseOnly, ...shared } = tsupOptions;
export const devTsupOptions = { ...shared, outDir: '.dev-dist' } satisfies Options;

export default defineConfig(devTsupOptions);
