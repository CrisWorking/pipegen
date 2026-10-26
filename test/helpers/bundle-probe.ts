// Built by the package test with the same tsup options as dist/cli/main.js, then run with plain `node`, to prove
// the bundled readers (and the CommonJS libraries they pull in) really work as a single ESM file.
import { bundleCode } from '../../src/ai/redact.js';
import { readProject } from '../../src/read/project.js';

const dir = process.argv[2];
if (!dir) throw new Error('usage: bundle-probe <repo dir>');
const profile = await readProject(dir);
const bundle = await bundleCode(dir); // no gitleaks path: count-only mode
console.log(JSON.stringify({
  owner: profile.owner,
  repo: profile.repo,
  services: profile.services.map((s) => s.path),
  files: bundle.files.length,
  bytes: bundle.bytes,
  gitleaksChecked: bundle.gitleaksChecked,
}));
