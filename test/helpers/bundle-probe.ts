// Built by the package test with the same tsup options as dist/cli/main.js, then run with plain `node`, to prove
// the bundled readers (and the CommonJS libraries they pull in) really work as a single ESM file.
import { makeProvider } from '../../src/ai/provider.js';
import { loadToolSignatures, mapCoverage } from '../../src/audit/coverage.js';
import { bundleCode } from '../../src/ai/redact.js';
import { floorNeeds, jobCategories, jobCounts, needsSchema } from '../../src/engine/needs.js';
import { loadPinnedBinaries } from '../../src/engine/linters.js';
import { loadBundledMemory } from '../../src/engine/memory.js';
import { checkQualityBar, loadQualityBar } from '../../src/engine/quality-bar.js';
import { loadReviewed } from '../../src/engine/reviewed.js';
import { estimate, loadAiPrices, loadGitHubPlans } from '../../src/estimate/estimate.js';
import { readProject } from '../../src/read/project.js';
import type { Capabilities, RepoProfile } from '../../src/types.js';

const dir = process.argv[2];
if (!dir) throw new Error('usage: bundle-probe <repo dir>');
const profile = await readProject(dir);
const bundle = await bundleCode(dir); // no gitleaks path: count-only mode
// Builds each provider (the Anthropic SDK client included) without sending anything, so the bundled SDK is exercised too.
const probeEnv = Object.fromEntries(['ANTHROPIC_API_KEY', 'OPENAI_API_KEY'].map((name) => [name, 'probe']));
const providers = [
  makeProvider({ env: probeEnv }),
  makeProvider({ ai: 'openai', model: 'probe', env: probeEnv }),
  makeProvider({ ai: 'ollama', env: {} }),
].map((p) => p.name);
// The GitHub fields (filled by Plan A Task 6 in a real run) and capabilities of a private Free repo.
const full: RepoProfile = { ...profile, private: true, ownerType: 'User', plan: 'free' };
const capNames = ['branchProtection', 'environments', 'deploymentBranchPolicies', 'envRequiredReviewers', 'attestations', 'codeScanning', 'keylessSigningAllowed'];
const caps = Object.fromEntries(capNames.map((n) => [n, false])) as unknown as Capabilities;
// data/quality-bar.yml is found through packageDataPath from the bundled file (the probe sits in <pkg>/dist/cli/)
const qualityBar = loadQualityBar();
// data/reviewed-tools.yml through the bundled loader: a release build (PIPEGEN_RELEASE defined by tsup, ruling S21)
// refuses entries nobody has reviewed yet
let reviewed: { loaded: number } | { refused: string };
try {
  reviewed = { loaded: loadReviewed().length };
} catch (e) {
  reviewed = { refused: e instanceof Error ? e.message : String(e) };
}
// data/pinned-binaries.yml through the bundled loader: the release build refuses it the same way while any entry is
// still PENDING review (final review I2)
let pinnedBinaries: { loaded: unknown } | { refused: string };
try {
  pinnedBinaries = { loaded: loadPinnedBinaries() };
} catch (e) {
  pinnedBinaries = { refused: e instanceof Error ? e.message : String(e) };
}
const verdict = checkQualityBar({ repo: 'o/r', stars: 1, archived: false, lastReleaseAt: null, scorecard: null, scorecardAt: null, verifiedPublisher: false, license: 'MIT', advisories: null }, qualityBar, new Date());
console.log(JSON.stringify({
  owner: profile.owner,
  repo: profile.repo,
  services: profile.services.map((s) => s.path),
  files: bundle.files.length,
  bytes: bundle.bytes,
  gitleaksChecked: bundle.gitleaksChecked,
  providers,
  // the needs planner's rules and its zod → JSON schema step work when bundled
  pushJobs: jobCounts(floorNeeds(full, caps)).push,
  needsSchemaKeys: Object.keys((needsSchema(full).jsonSchema as { properties: object }).properties),
  qualityBar,
  qualityReasons: verdict.reasons.length,
  // data/pinned-binaries.yml, read and validated by the bundled loader (refused while any entry is PENDING)
  pinnedBinaries,
  // data/memory.json, read and validated by the bundled loader
  bundledMemory: await loadBundledMemory(),
  reviewed,
  // data/ai-prices.yml and data/github-plans.yml, read and validated by the bundled loaders, and used by estimate()
  aiPrices: loadAiPrices(),
  githubPlans: loadGitHubPlans(),
  // data/tool-signatures.yml through the bundled loader, and the coverage mapper run on the repo with it (Plan U ruling S1)
  toolSignatures: loadToolSignatures(),
  coverage: (await mapCoverage(full, floorNeeds(full, caps), dir)).map((c) => c.status),
  floorNeeds: floorNeeds(full, caps).length,
  estimate: (({ setupMinutes, includedMinutes, aiCostCapUsd }) => ({ setupMinutes, includedMinutes, aiCostCapUsd }))(
    estimate(full, jobCategories(floorNeeds(full, caps)), 2, { pushes: 10, prs: 2, capped: false }, { name: 'claude', model: 'claude-opus-5-5' }),
  ),
}));
