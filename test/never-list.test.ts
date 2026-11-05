// J3b (DECISIONS #122, ruling S6): a never-use action pinned to a commit SHA is judged by that SHA, for
// aquasecurity/trivy-action only and only where the coverage mapper judges an existing step. The loader, discovery and
// the chooser keep refusing the name. Every positive case uses two different invented workflow shapes.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { chooseTools } from '../src/audit/choose.js';
import { mapCoverage, type Coverage } from '../src/audit/coverage.js';
import { NEVER_REPOS, NEVER_SAFE_SHAS, neverListed, neverListedStep, type StepInputs } from '../src/engine/never-list.js';
import { lowerInputs } from '../src/audit/coverage/settings.js';
import { SAFE_SHA_NOTE } from '../src/audit/coverage/walk.js';
import { floorNeeds } from '../src/engine/needs.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { readPrecommit, readWorkflows } from '../src/read/workflows.js';
import type { Capabilities, Layer, RepoProfile, ReviewedTool, Service } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const TRIVY = 'aquasecurity/trivy-action';
const SAFE = (NEVER_SAFE_SHAS[TRIVY] ?? []).map((x) => x.sha);
const NONE: StepInputs = lowerInputs({});
const step = (uses: string, w: StepInputs = NONE) => neverListedStep(uses, w);
const caps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: false,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};
const svc = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['test', 'start'],
  frameworks: [], quality: emptyServiceQuality(), dockerfile: 'Dockerfile', ...over,
});
async function coverage(files: Record<string, string>): Promise<Coverage[]> {
  const dir = makeTempDir();
  for (const [rel, body] of Object.entries(files)) writeIn(dir, rel, body);
  const p: RepoProfile = {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services: [svc()],
    terraformDirs: [], hasCompose: false, existingWorkflows: await readWorkflows(dir), precommit: readPrecommit(dir), repoFiles: emptyRepoFiles(),
  };
  return mapCoverage(p, floorNeeds(p, caps), dir);
}
const rowOf = (rows: Coverage[], layer: Layer, category: string) => {
  const r = rows.find((x) => x.need.layer === layer && x.need.category === category);
  if (r === undefined) throw new Error(`no ${category} row in ${layer}`);
  return r;
};

/** Two invented shapes of a scan step with the action: a dependency scan of the folder, and an image scan after a build. */
const SHAPES: { name: string; category: string; layer: Layer; file: (ref: string, extra?: string) => Record<string, string> }[] = [
  {
    name: 'folder scan on pull requests and pushes', category: 'deps', layer: 'merge',
    file: (ref, extra = '') => ({ '.github/workflows/scan.yml': `on: [push, pull_request]\njobs:\n  deps:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ${ref}\n        with:\n          scan-type: fs\n${extra}          exit-code: '1'\n` }),
  },
  {
    name: 'image scan after a docker build, two jobs', category: 'image-scan', layer: 'merge',
    file: (ref, extra = '') => ({
      Dockerfile: 'FROM scratch\n',
      '.github/workflows/image.yaml': `on:\n  pull_request:\n  push:\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo lint\n  image:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: docker build -t app:ci .\n      - name: scan\n        uses: ${ref}\n        with:\n          image-ref: app:ci\n          exit-code: 3\n${extra}          severity: HIGH,CRITICAL\n`,
    }),
  },
];

describe('never-list by SHA (S6)', () => {
  it('the safe-SHA list: only trivy-action, only 40-hex commits, never a key outside the never-list', () => {
    expect(Object.keys(NEVER_SAFE_SHAS)).toEqual([TRIVY]);
    expect(Object.isFrozen(NEVER_SAFE_SHAS)).toBe(true);
    for (const [repo, shas] of Object.entries(NEVER_SAFE_SHAS)) {
      expect(NEVER_REPOS).toHaveProperty([repo]);
      expect(Object.isFrozen(shas)).toBe(true);
      for (const x of shas) {
        expect(x.sha).toMatch(/^[0-9a-f]{40}$/);
        expect(Object.isFrozen(x) && Object.isFrozen(x.inputs)).toBe(true);
        // review I2: the version the commit installs by default, and setup-trivy not skipped
        expect(Object.keys(x.inputs).sort()).toEqual(['skip-setup-trivy', 'version']);
        expect(x.inputs['skip-setup-trivy']).toEqual(['false']);
        expect(x.inputs.version).toHaveLength(1);
        expect(x.inputs.version?.[0]).toMatch(/^v\d+\.\d+\.\d+$/);
      }
      expect(new Set(shas.map((x) => x.sha)).size).toBe(shas.length);
    }
    // setup-trivy (all tags replaced) and gitleaks-action (licence, not the pin) are never exempt
    expect(NEVER_SAFE_SHAS).not.toHaveProperty(['aquasecurity/setup-trivy']);
    expect(NEVER_SAFE_SHAS).not.toHaveProperty(['gitleaks/gitleaks-action']);
  });

  it('trivy-action at a safe SHA → not never-listed; at a tag → listed', async () => {
    expect(SAFE.length).toBeGreaterThan(0);
    const sha = SAFE[0] as string;
    for (const s of SAFE) expect(step(`${TRIVY}@${s}`), s).toBeNull();
    expect(step(`AquaSecurity/Trivy-Action@${sha}`)).toBeNull(); // GitHub reads owner and name in any case
    for (const ref of [`${TRIVY}@v0.36.0`, `${TRIVY}@master`, TRIVY, `${TRIVY}@${'0'.repeat(40)}`, `${TRIVY}@${sha.toUpperCase()}`, `${TRIVY}@${sha.slice(0, 7)}`,
      `${TRIVY}@${sha}x`, ` ${TRIVY}@${sha}`, `${TRIVY}/sub@${sha}`, `${TRIVY}@${sha}#x`, `docker://${TRIVY}@${sha}`, `https://github.com/${TRIVY}@${sha}`,
      `aquasecurity/setup-trivy@${sha}`, `${TRIVY.replace('/', '%2F')}@${sha}`]) {
      expect(step(ref), ref).not.toBeNull();
    }
    for (const shape of SHAPES) {
      const safe = rowOf(await coverage(shape.file(`${TRIVY}@${sha}`)), shape.layer, shape.category);
      expect(safe.status, shape.name).toBe('covered');
      // ruling I3: the stated limit, in plain words
      expect(safe.why, shape.name).toContain("the action's cache isn't re-checked");
      expect(safe.why.endsWith(SAFE_SHA_NOTE), shape.name).toBe(true);
      // a push row covered by the J3a push credit keeps the note too
      if (shape.category === 'deps') {
        const pushed = shape.file(`${TRIVY}@${sha}`);
        for (const k of Object.keys(pushed)) pushed[k] = (pushed[k] as string).replace(/^on:[\s\S]*?\njobs:/, 'on:\n  pull_request:\n  push:\n    branches: [main]\njobs:');
        const credited = rowOf(await coverage(pushed), 'push', 'deps');
        expect(credited.creditKind, shape.name).toBe('push-default');
        expect(credited.why.endsWith(SAFE_SHA_NOTE), shape.name).toBe(true);
      }
      expect(safe.by, shape.name).toBe(shape.category === 'deps' ? 'trivy-fs' : 'trivy-image');
      for (const ref of [`${TRIVY}@v0.36.0`, `${TRIVY}@${'1'.repeat(40)}`]) {
        const tag = rowOf(await coverage(shape.file(ref)), shape.layer, shape.category);
        expect(tag.status, `${shape.name} ${ref}`).toBe('partial');
        expect(tag.why, `${shape.name} ${ref}`).toContain('never-use list');
      }
    }
  });

  it('trivy-action at a safe SHA with another Trivy version or setup skipped → listed (review I2)', async () => {
    const at = (NEVER_SAFE_SHAS[TRIVY] ?? [])[0];
    if (at === undefined) throw new Error('no safe SHA');
    const own = at.inputs.version?.[0] as string;
    const w = (o: Record<string, unknown>) => lowerInputs(o);
    // the commit's own default version, or setup-trivy explicitly not skipped: still judged by the SHA
    for (const o of [{ version: own }, { Version: own }, { 'skip-setup-trivy': false }, { 'skip-setup-trivy': 'false' }, { cache: 'false', format: 'sarif' }]) {
      expect(step(`${TRIVY}@${at.sha}`, w(o)), JSON.stringify(o)).toBeNull();
    }
    for (const o of [{ version: 'latest' }, { version: 'v0.60.0' }, { version: '${{ inputs.v }}' }, { version: own.slice(1) }, { 'skip-setup-trivy': true },
      { 'skip-setup-trivy': 'true' }, { 'skip-setup-trivy': '${{ inputs.skip }}' }, { version: own, VERSION: 'latest' }, { version: [own] }]) {
      expect(step(`${TRIVY}@${at.sha}`, w(o)), JSON.stringify(o)).not.toBeNull();
    }
    // another listed commit's default is not this one's
    const other = (NEVER_SAFE_SHAS[TRIVY] ?? []).find((x) => x.inputs.version?.[0] !== own);
    if (other !== undefined) expect(step(`${TRIVY}@${at.sha}`, w({ version: other.inputs.version?.[0] }))).not.toBeNull();
    // more inputs than pipegen reads
    expect(step(`${TRIVY}@${at.sha}`, w(Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`k${i}`, 'x']))))).not.toBeNull();
    // `with:` as one expression: any input may be set
    const expr = `on: [push, pull_request]\njobs:\n  image:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: docker build -t app:ci .\n      - uses: ${TRIVY}@${at.sha}\n        with: \${{ fromJSON(vars.SCAN_INPUTS) }}\n`;
    const exprRow = rowOf(await coverage({ Dockerfile: 'FROM scratch\n', '.github/workflows/scan.yml': expr }), 'merge', 'image-scan');
    expect(exprRow.status).toBe('partial');
    expect(exprRow.why).toContain('never-use list');
    for (const shape of SHAPES) {
      expect(rowOf(await coverage(shape.file(`${TRIVY}@${at.sha}`, `          version: ${own}\n`)), shape.layer, shape.category).status, shape.name).toBe('covered');
      for (const extra of ['          version: latest\n', '          version: v0.60.0\n', '          skip-setup-trivy: true\n', "          version: ${{ inputs.v }}\n"]) {
        const r = rowOf(await coverage(shape.file(`${TRIVY}@${at.sha}`, extra)), shape.layer, shape.category);
        expect(r.status, `${shape.name} ${extra}`).toBe('partial');
        expect(r.why, `${shape.name} ${extra}`).toContain('never-use list');
      }
    }
  });

  it('look-alike owner at a safe SHA → listed', async () => {
    const sha = SAFE[0] as string;
    for (const ref of [`aquasecurlty/trivy-action@${sha}`, `aquasecurity-labs/trivy-action@${sha}`, `someone/trivy-action@${sha}`, `aquasecurity/trivy-actions@${sha}`,
      `aquasecurity/trivy-action-fork@${sha}`, `aquasec/trivy-action@${sha}`]) {
      expect(step(ref), ref).not.toBeNull();
      expect(step(ref)?.key, ref).toBe(neverListed(ref)?.key);
    }
    for (const shape of SHAPES) {
      const r = rowOf(await coverage(shape.file(`aquasecurlty/trivy-action@${sha}`)), shape.layer, shape.category);
      expect(r.status, shape.name).not.toBe('covered');
    }
  });

  it('safe-SHA exemption only in coverage: reviewed loader, discovery and chooser still refuse it', () => {
    const sha = SAFE[0] as string;
    // the rule the loader, discovery and the chooser use is unchanged: by name, at any ref
    expect(neverListed(`${TRIVY}@${sha}`)).not.toBeNull();
    expect(neverListed(TRIVY)).not.toBeNull();
    // the reviewed-list loader refuses the action at that SHA
    const entry = {
      id: 'trivy-image', categories: ['image-scan'], languages: ['any'], releasedAt: '2026-01-01T00:00:00Z',
      candidate: { id: 'trivy-image', name: TRIVY, kind: 'action', repo: TRIVY, version: 'v0.36.0', pin: { sha }, source: 'reviewed', reviewed: true, categories: ['image-scan'] },
      step: { action: { uses: `${TRIVY}@${sha}`, with: {} }, output: { path: '', format: 'none' } },
      fixedInputs: { with: {} }, choices: {}, configFiles: [], reviewedBy: 'PENDING', reviewedAt: 'PENDING', proofs: 0,
    };
    const dir = makeTempDir();
    writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: '2026-10-26T00:00:00Z', tools: [entry] }));
    expect(() => loadReviewed(join(dir, 'reviewed-tools.yml'))).toThrow(/never adds/);
    // the chooser never picks it from a list that holds it
    const listed: ReviewedTool = { ...(entry as unknown as ReviewedTool), reviewedBy: 'maintainer', reviewedAt: '2026-09-01' };
    const p: RepoProfile = {
      owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services: [svc()],
      terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
    };
    const need = { id: 'image-scan', layer: 'merge' as const, category: 'image-scan', service: 'app', why: '', blocking: true, floor: true };
    expect(chooseTools(need, p.services[0], p, caps, [listed]).tool).toBeNull();
    // discovery takes plain owner/name repos, refused by name (test/discover.test.ts); and nothing outside the coverage
    // mapper's step walk calls the SHA-aware check
    const src = resolve(import.meta.dirname, '../src');
    const callers: string[] = [];
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const f = join(d, n);
        if (statSync(f).isDirectory()) walk(f);
        else if (f.endsWith('.ts') && readFileSync(f, 'utf8').includes('neverListedStep')) callers.push(f.slice(src.length + 1));
      }
    };
    walk(src);
    expect(callers.sort()).toEqual(['audit/coverage/walk.ts', 'engine/never-list.ts']);
  });
});
