// Built by the package test with the same tsup options as dist/cli/main.js, then run with plain `node`, to prove
// the bundled readers (and the CommonJS libraries they pull in) really work as a single ESM file.
import { makeProvider } from '../../src/ai/provider.js';
import { bundleCode } from '../../src/ai/redact.js';
import { readProject } from '../../src/read/project.js';

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
console.log(JSON.stringify({
  owner: profile.owner,
  repo: profile.repo,
  services: profile.services.map((s) => s.path),
  files: bundle.files.length,
  bytes: bundle.bytes,
  gitleaksChecked: bundle.gitleaksChecked,
  providers,
}));
