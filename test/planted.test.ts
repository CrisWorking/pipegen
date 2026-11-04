// v0.2 Plan F, F5: the planted problems every proof carries (plan Task 4, rulings B4, B5, S15-S18).
// - plantedFiles: a generic secret and (with Terraform) an open security group at the repo root's pipegen-planted/; a SQL query
//   built from request input and a manifest with a known-vulnerable dependency under each scanned service's own pipegen-planted/.
// - matchPlanted: Plan E's injected matcher (EvalContext.matchPlanted): the category's tool, the item's file (no glob), a severity
//   floor of high, one finding per item.
// - isPlantedPath: the delivery exclusion rule (Plan G), a pipegen-planted segment at any depth.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import { findSecretLike } from '../src/ai/redact.js';
import {
  isPlantedPath, matchPlanted, PLANTED_CATEGORIES, PLANTED_DIR, PLANTED_FIXTURES, PLANTED_ITEM_TEXT, PLANTED_SECRET_LENGTH, PlantedError, plantedFiles, plantedSecret,
  type PlantedItem,
} from '../src/debate/planted.js';
import { floorNeeds } from '../src/engine/needs.js';
import type { EvalContext, PlantedItem as EvalPlantedItem } from '../src/proof/evaluate.js';
import { isWorkflowPath, plantedSecretPlacements, type ProofFile } from '../src/proof/snapshot.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Finding, RepoProfile, Service, Severity } from '../src/types.js';
import { safeText } from '../src/util/safe-text.js';
import { root, walkFiles } from './helpers/repo-files.js';

// Count every call of the real crypto source, so a test can show the default secret comes from it (and never Math.random).
const cryptoCalls = vi.hoisted(() => ({ n: 0 }));
vi.mock('node:crypto', async (orig) => {
  const real = await orig<typeof import('node:crypto')>();
  return { ...real, randomBytes: (n: number) => { cryptoCalls.n++; return real.randomBytes(n); } };
});

// ---------- builders ----------

const svc = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: [], frameworks: [], quality: emptyServiceQuality(), ...over,
});
const profile = (over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free',
  monorepo: 'none', services: [svc()], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(), ...over,
});
const CAP_NAMES = ['branchProtection', 'environments', 'deploymentBranchPolicies', 'envRequiredReviewers', 'attestations', 'codeScanning', 'keylessSigningAllowed'] as const;
const caps = Object.fromEntries(CAP_NAMES.map((n) => [n, true])) as unknown as Capabilities;

/** A repeatable random source (a counter through a multiplier): every byte value 0..255 shows up. */
const seq = (seed = 1) => {
  let x = seed;
  return (n: number) => { const b = new Uint8Array(n); for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; b[i] = (x >>> 16) & 0xff; } return b; };
};
/** A random source that replays `bytes`, then the fallback. */
const replay = (bytes: number[], fallback = seq(7)) => {
  const q = [...bytes];
  return (n: number) => { const b = new Uint8Array(n); const f = fallback(n); for (let i = 0; i < n; i++) b[i] = q.length > 0 ? (q.shift() as number) : (f[i] as number); return b; };
};

const MONO = profile({
  monorepo: 'folders',
  services: [
    svc({ name: 'web', path: '.' }),
    svc({ name: 'api', path: './services/api/', language: 'python', packageManager: 'pip' }),
    svc({ name: 'worker', path: 'services/api', language: 'python', packageManager: 'pip' }),
    svc({ name: 'lib', path: 'packages/lib', language: 'node' }),
    svc({ name: 'tool', path: 'tools/go', language: 'go', packageManager: undefined }),
  ],
  terraformDirs: ['infra'],
});

const byPath = (files: readonly ProofFile[]) => new Map(files.map((f) => [f.path as string, f.content as string]));
const finding = (tool: string, file: string | undefined, severity: Severity = 'high', ruleId = 'r'): Finding => ({
  tool, ruleId, severity, ...(file === undefined ? {} : { file }), message: `${ruleId} (x)`, fingerprint: `x:${tool}:${ruleId}:${file ?? ''}`,
});
// the planted file's one line, spelled at run time (a key word before '=' in a committed file trips test/no-secret-literals)
const KEY_LINE = new RegExp(`^${['api', 'key'].join('_')} = "[A-Za-z0-9]{40}"\\n$`);
const TOOLS = new Map([['secrets', 'gitleaks'], ['sast', 'semgrep'], ['deps', 'osv-scanner'], ['iac', 'trivy-config']]);
/** A finding by the right tool on every expected item's own file. */
const allCaught = (expected: readonly PlantedItem[], severity: Severity = 'high') => expected.map((e) => finding(TOOLS.get(e.category) as string, e.file, severity));

// ---------- placement ----------

describe('planted files', () => {
  it('planted: files only under pipegen-planted/', () => {
    for (const p of [profile(), profile({ services: [svc({ language: 'python', packageManager: 'pip' })] }), MONO, profile({ services: [] })]) {
      const { files, expected } = plantedFiles(p, { random: seq() });
      expect(files.length).toBeGreaterThan(0);
      const roots = new Set(['', ...p.services.map((s) => s.path.split('/').filter((x) => x !== '' && x !== '.').join('/'))]);
      for (const f of files) {
        const path = f.path as string;
        expect(isPlantedPath(path), path).toBe(true);
        const at = path.split('/').indexOf(PLANTED_DIR);
        expect(at, path).toBeGreaterThanOrEqual(0);
        // the planted folder sits at the repo root or at a service root, never deeper and never twice
        expect(roots.has(path.split('/').slice(0, at).join('/')), path).toBe(true);
        expect(path.split('/').filter((x) => x === PLANTED_DIR)).toHaveLength(1);
        // nothing planted sits in a service's own install folder (its root): only inside pipegen-planted/
        expect(path.split('/').length).toBeGreaterThan(at + 1);
      }
      for (const e of expected) expect(files.some((f) => f.path === e.file), e.file).toBe(true);
    }
  });

  it("planted: sast and deps files sit under each scanned service's own folder; secrets and iac at the root", () => {
    const { files, expected } = plantedFiles(MONO, { random: seq() });
    const paths = files.map((f) => f.path as string).sort();
    expect(paths).toEqual([
      'packages/lib/pipegen-planted/deps-node-packages-lib/package-lock.json',
      'packages/lib/pipegen-planted/deps-node-packages-lib/package.json',
      'packages/lib/pipegen-planted/sast-node-packages-lib.js',
      'pipegen-planted/config.txt',
      'pipegen-planted/deps-node/package-lock.json',
      'pipegen-planted/deps-node/package.json',
      'pipegen-planted/main.tf',
      'pipegen-planted/sast-node.js',
      'services/api/pipegen-planted/deps-python-services-api/requirements.txt',
      'services/api/pipegen-planted/sast-python-services-api.py',
    ]);
    const items = Object.fromEntries(expected.filter((e) => e.category !== 'secrets').map((e) => [e.id, { category: e.category, file: e.file, critical: e.critical }]));
    const repoWide = expected.filter((e) => e.category === 'secrets').map((e) => [e.id, e.file, e.critical]);
    expect(repoWide).toEqual([['secret', 'pipegen-planted/config.txt', true]]);
    expect(items).toEqual({
      iac: { category: 'iac', file: 'pipegen-planted/main.tf', critical: false },
      'sast-node': { category: 'sast', file: 'pipegen-planted/sast-node.js', critical: false },
      'deps-node': { category: 'deps', file: 'pipegen-planted/deps-node/package-lock.json', critical: true },
      'sast-python--services-api': { category: 'sast', file: 'services/api/pipegen-planted/sast-python-services-api.py', critical: false },
      'deps-python--services-api': { category: 'deps', file: 'services/api/pipegen-planted/deps-python-services-api/requirements.txt', critical: true },
      'sast-node--packages-lib': { category: 'sast', file: 'packages/lib/pipegen-planted/sast-node-packages-lib.js', critical: false },
      'deps-node--packages-lib': { category: 'deps', file: 'packages/lib/pipegen-planted/deps-node-packages-lib/package-lock.json', critical: true },
    });
    // the go service (no planted template for its language) gets nothing, and no file lands in its folder
    expect(paths.some((p) => p.startsWith('tools/'))).toBe(false);
    // two services in one folder with one language share one item; a second language in that folder gets its own
    const two = plantedFiles(profile({ services: [svc({ name: 'a' }), svc({ name: 'b', language: 'python', packageManager: 'pip' }), svc({ name: 'c' })] }), { random: seq() });
    expect(two.expected.map((e) => e.id)).toEqual(['secret', 'sast-node', 'deps-node', 'sast-python', 'deps-python']);
    // folders whose slugs are the same get distinct names, so a service-relative path never names two items
    const clash = plantedFiles(profile({ services: [svc({ name: 'x', path: 'a/b' }), svc({ name: 'y', path: 'a-b' })] }), { random: seq() });
    const rel = clash.expected.filter((e) => e.category !== 'secrets').map((e) => e.file.slice(e.file.indexOf(PLANTED_DIR)));
    expect(new Set(rel).size).toBe(rel.length);
    expect(new Set(clash.expected.map((e) => e.id)).size).toBe(clash.expected.length);
    // a folder with no letters or digits still gets a name of its own
    const odd = plantedFiles(profile({ services: [svc({ name: 'x', path: '__' }), svc({ name: 'y', path: '_-_' })] }), { random: seq() });
    expect(new Set(odd.files.map((f) => f.path)).size).toBe(odd.files.length);
    expect(new Set(odd.expected.map((e) => e.id)).size).toBe(odd.expected.length);
    // a service folder that is not a plain path inside the repo, or that is inside a planted folder, is refused (no repo text in the message)
    for (const path of ['../up', '/abs', 'a/../b', 'with space', '-flag', 'a\\b', 'x/pipegen-planted', 'Pipegen-Planted/x', 'pipegen-planted']) {
      expect(() => plantedFiles(profile({ services: [svc({ path })] }), { random: seq() }), path).toThrow(PlantedError);
      try { plantedFiles(profile({ services: [svc({ path })] }), { random: seq() }); } catch (e) { if (path !== PLANTED_DIR) expect((e as Error).message).not.toContain(path); }
    }
    // no service found: the floor's repo-wide sast and deps have no language, so only the secret is planted
    expect(plantedFiles(profile({ services: [] }), { random: seq() }).expected.map((e) => e.id)).toEqual(['secret']);
  });

  it('planted: the deps manifest folder is two levels deep (no one-level workspace glob matches it)', () => {
    const { files, expected } = plantedFiles(MONO, { random: seq() });
    const MANIFESTS = new Set(['package.json', 'package-lock.json', 'requirements.txt']);
    const deps = expected.filter((e) => e.category === 'deps');
    expect(deps).toHaveLength(3);
    const oneLevel = (glob: string, folder: string) => {
      // a workspace glob of one segment ('*' or 'name'): matches exactly one folder level below the service root
      const g = glob.split('/'), f = folder.split('/');
      return g.length === f.length && g.every((s, i) => s === '*' || s === f[i]);
    };
    for (const f of files) {
      const path = f.path as string;
      const parts = path.split('/');
      const name = parts.at(-1) as string;
      if (!MANIFESTS.has(name)) continue;
      const at = parts.indexOf(PLANTED_DIR);
      const inService = parts.slice(at, -1);
      expect(inService, path).toHaveLength(2);
      expect(inService[0]).toBe(PLANTED_DIR);
      for (const glob of ['*', PLANTED_DIR, 'packages', 'pipegen-*', 'p*']) expect(oneLevel(glob, inService.join('/')), `${glob} ${path}`).toBe(false);
    }
    // no manifest directly at a planted folder's top (a '*' workspace glob would take that folder into the install)
    for (const f of files) expect(f.path as string).not.toMatch(/(?:^|\/)pipegen-planted\/(?:package(?:-lock)?\.json|requirements\.txt)$/);
    // each deps item names the lockfile osv-scanner reads, in its own manifest folder
    for (const e of deps) expect(e.file).toMatch(/\/pipegen-planted\/deps-(?:node|python)[a-z0-9-]*\/(?:package-lock\.json|requirements\.txt)$|^pipegen-planted\/deps-(?:node|python)\/(?:package-lock\.json|requirements\.txt)$/);
  });

  it('planted: files are ProofFiles, never CreatedFiles; no planted path is a workflow or bot config', () => {
    const { files } = plantedFiles(MONO, { random: seq() });
    expectTypeOf(files).toEqualTypeOf<ProofFile[]>();
    // @ts-expect-error a planted file has no part, reason or repo, so it can't go into a CreatedFile list (a delivery)
    const asCreated: CreatedFile[] = files;
    void asCreated;
    const BOT = /^(?:\.github\/dependabot\.ya?ml|renovate\.json5?|\.github\/renovate\.json5?|\.gitlab\/renovate\.json5?|\.renovaterc(?:\.json5?)?)$/i;
    for (const f of files) {
      expect(Object.keys(f).every((k) => k === 'path' || k === 'content' || k === 'mode'), String(f.path)).toBe(true);
      expect(f).not.toHaveProperty('part');
      expect(f).not.toHaveProperty('repo');
      expect(f).not.toHaveProperty('reason');
      expect(typeof f.path).toBe('string');
      expect(typeof f.content).toBe('string');
      expect(isWorkflowPath(f.path as string)).toBe(false);
      expect(BOT.test(f.path as string)).toBe(false);
      expect(f.path as string).not.toMatch(/^\.github\//i);
    }
    // a service under .github/workflows would put a planted file in a workflow path: refused
    expect(() => plantedFiles(profile({ services: [svc({ path: '.github/workflows' })] }), { random: seq() })).toThrow(PlantedError);
  });

  it('planted: iac only when terraform present', () => {
    const withTf = plantedFiles(profile({ terraformDirs: ['infra'] }), { random: seq() });
    const iac = withTf.expected.filter((e) => e.category === 'iac');
    expect(iac).toEqual([{ id: 'iac', category: 'iac', item: PLANTED_ITEM_TEXT.iac, file: 'pipegen-planted/main.tf', critical: false, minSeverity: 'high' }]);
    const tf = byPath(withTf.files).get('pipegen-planted/main.tf') as string;
    expect(tf).toContain('resource "aws_security_group"');
    expect(tf).toMatch(/from_port\s*=\s*22\b/);
    expect(tf).toMatch(/to_port\s*=\s*22\b/);
    expect(tf).toContain('cidr_blocks = ["0.0.0.0/0"]');
    // Kubernetes alone also makes an iac need, but there is no planted Terraform for it (ruling S18: recorded, not planted)
    for (const p of [profile(), profile({ repoFiles: { ...emptyRepoFiles(), kubernetes: true } })]) {
      const r = plantedFiles(p, { random: seq() });
      expect(r.expected.some((e) => e.category === 'iac')).toBe(false);
      expect(r.files.some((f) => (f.path as string).endsWith('.tf'))).toBe(false);
    }
  });

  it('planted: expected list covers every blocking category that has a planted item', () => {
    expect([...PLANTED_CATEGORIES]).toEqual(['secrets', 'deps', 'sast', 'iac']);
    const cases = [
      profile(),
      profile({ services: [svc({ language: 'python', packageManager: 'pip' })] }),
      profile({ terraformDirs: ['infra'] }),
      MONO,
    ];
    for (const p of cases) {
      const { expected } = plantedFiles(p, { random: seq() });
      const cats = new Set(expected.map((e) => e.category));
      // the covered categories are pinned: secrets, deps and sast always; iac only with Terraform; nothing else (S18)
      expect([...cats].sort()).toEqual(['deps', 'sast', 'secrets', ...(p.terraformDirs.length > 0 ? ['iac'] : [])].sort());
      for (const c of cats) expect(PLANTED_CATEGORIES).toContain(c);
      // every blocking floor need of a planted category has an item it is proven on: per service for sast and deps
      for (const n of floorNeeds(p, caps)) {
        if (!n.blocking || !(PLANTED_CATEGORIES as readonly string[]).includes(n.category)) continue;
        if (n.category === 'iac' && p.terraformDirs.length === 0) continue;
        const s = p.services.find((x) => x.name === n.service);
        if (s !== undefined && s.language !== 'node' && s.language !== 'python') continue;   // no template for its language (recorded)
        const folder = s === undefined ? '' : s.path.split('/').filter((x) => x !== '' && x !== '.').join('/');
        const prefix = folder === '' ? `${PLANTED_DIR}/` : `${folder}/${PLANTED_DIR}/`;
        expect(expected.some((e) => e.category === n.category && e.file.startsWith(prefix)), `${n.layer} ${n.id} ${n.service ?? ''}`).toBe(true);
      }
      // the ids are unique (evaluate reports an item by id)
      expect(new Set(expected.map((e) => e.id)).size).toBe(expected.length);
    }
  });

  it("planted: each item has an item text for evaluate's message", () => {
    const { expected } = plantedFiles(MONO, { random: seq() });
    const texts = new Set<string>(Object.values(PLANTED_ITEM_TEXT));
    for (const e of expected) {
      expect(typeof e.item).toBe('string');
      expect(e.item.length).toBeGreaterThan(5);
      expect(e.item.length).toBeLessThanOrEqual(120);
      expect(texts.has(e.item), e.item).toBe(true);
      // fixed English: no repo text (service names, folders), unchanged by safeText, no article (evaluate writes "the planted <item>")
      for (const s of MONO.services) { expect(e.item).not.toContain(s.name); expect(e.item).not.toContain('services/'); }
      expect(safeText(e.item, 200)).toBe(e.item);
      expect(e.item).not.toMatch(/^(?:a|an|the) /i);
    }
    expect(expected.find((e) => e.id === 'secret')?.item).toBe(PLANTED_ITEM_TEXT.secret);
    expect(expected.find((e) => e.id === 'deps-node')?.item).toBe(PLANTED_ITEM_TEXT['deps-node']);
    expect(expected.find((e) => e.id === 'deps-python--services-api')?.item).toBe(PLANTED_ITEM_TEXT['deps-python']);
    expect(expected.find((e) => e.id === 'sast-node')?.item).toBe(PLANTED_ITEM_TEXT['sast-node']);
    expect(expected.find((e) => e.id === 'sast-python--services-api')?.item).toBe(PLANTED_ITEM_TEXT['sast-python']);
    expect(expected.find((e) => e.id === 'iac')?.item).toBe(PLANTED_ITEM_TEXT.iac);
  });

  it('planted: no path collides with a C1b placement or with a base file', () => {
    const base = new Set(['package.json', 'src/index.js', 'services/api/app.py', 'packages/lib/index.js', 'infra/main.tf', 'go.sum']);
    const c1b = plantedSecretPlacements(base, { random: seq(3) });
    const ours = plantedFiles(MONO, { random: seq(), basePaths: base });
    const all = [...base, ...c1b.files.map((f) => (typeof f.path === 'string' ? f.path : Buffer.from(f.path).toString('latin1'))), ...ours.files.map((f) => f.path as string)];
    expect(new Set(all).size).toBe(all.length);
    // no path is a folder of another (a file where the other needs a folder)
    for (const a of all) for (const b of all) if (a !== b) expect(b.startsWith(`${a}/`), `${a} / ${b}`).toBe(false);
    // the C1b placements stay E's: none of them is a planted path, none of ours is a C1b path
    for (const e of c1b.expected) expect(isPlantedPath(e.path)).toBe(false);
    for (const f of ours.files) expect(f.path as string).not.toMatch(/(?:^|\/)pipegen-c1b(?:\/|$)/);
    // a base that already holds a planted path, a file at one of its folders, or anything in a planted folder: refused
    for (const taken of ['pipegen-planted/config.txt', 'pipegen-planted', 'services/api/pipegen-planted', 'packages/lib/pipegen-planted/x.md', 'services', 'Pipegen-Planted/notes.txt']) {
      expect(() => plantedFiles(MONO, { random: seq(), basePaths: new Set([...base, taken]) }), taken).toThrow(PlantedError);
    }
    // the base's own files elsewhere are fine
    expect(() => plantedFiles(MONO, { random: seq(), basePaths: new Set([...base, 'services/api/other/x.py', 'pipegen-plantedx/y']) })).not.toThrow();
  });
});

// ---------- the secret ----------

describe('planted secret', () => {
  const PROVIDER = [/AKIA/, /ASIA/, /ghp_/, /gho_/, /ghs_/, /github_pat_/, /sk_live_/, /sk_test_/, /rk_live_/, /xox[abposr]-/, /AIza/, /glpat-/, /npm_/, /sk-/, /hf_/, /SG\./];

  it('planted: secret is high-entropy and not a provider format', () => {
    const entropy = (s: string) => { const c = new Map<string, number>(); for (const ch of s) c.set(ch, (c.get(ch) ?? 0) + 1); let h = 0; for (const n of c.values()) { const p = n / s.length; h -= p * Math.log2(p); } return h; };
    for (let i = 0; i < 300; i++) {
      const v = plantedSecret(seq(i + 1));
      expect(v).toMatch(/^[A-Za-z0-9]{40}$/);
      expect(PLANTED_SECRET_LENGTH).toBe(40);
      expect(entropy(v)).toBeGreaterThanOrEqual(4);
      for (const re of PROVIDER) expect(re.test(v), `${re}`).toBe(false);
      expect(findSecretLike(v)).toEqual([]);
    }
    // in the file: a generic api_key assignment in pipegen-planted/config.txt, still no provider format
    const { files, expected } = plantedFiles(profile(), { random: seq(5) });
    const body = byPath(files).get('pipegen-planted/config.txt') as string;
    expect(body).toMatch(KEY_LINE);
    expect(findSecretLike(body)).toEqual([]);
    expect(expected.find((e) => e.id === 'secret')).toEqual({ id: 'secret', category: 'secrets', item: PLANTED_ITEM_TEXT.secret, file: 'pipegen-planted/config.txt', critical: true, minSeverity: 'high' });
    // a fresh value per call
    expect(plantedFiles(profile()).files[0]?.content).not.toBe(plantedFiles(profile()).files[0]?.content);
  });

  it('planted: secret value from crypto random bytes by rejection sampling; digit, upper and lower present; no run of 3 or more letters', () => {
    // the default source is node:crypto randomBytes, never Math.random
    const mathRandom = vi.spyOn(Math, 'random');
    const before = cryptoCalls.n;
    const v = plantedSecret();
    const fromFiles = plantedFiles(profile()).files.find((f) => f.path === 'pipegen-planted/config.txt');
    expect(cryptoCalls.n).toBeGreaterThanOrEqual(before + 2);
    expect(mathRandom).not.toHaveBeenCalled();
    mathRandom.mockRestore();
    expect(v).toMatch(/^[A-Za-z0-9]{40}$/);
    expect(fromFiles?.content).toMatch(KEY_LINE);

    // every value: a digit, an upper and a lower letter, and never three letters in a row
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const s = plantedSecret(seq(i + 11));
      expect(s).toMatch(/[0-9]/);
      expect(s).toMatch(/[A-Z]/);
      expect(s).toMatch(/[a-z]/);
      expect(s).not.toMatch(/[A-Za-z]{3}/);
      expect(s).not.toMatch(/md5|000000/i);
      for (const ch of s) seen.add(ch);
    }
    // the whole alphabet is used (no letter or digit dropped)
    expect(seen.size).toBe(62);

    // rejection sampling: a byte ≥ 248 is dropped for a base62 draw (248 = 4 × 62), so no character is favoured.
    // 250 % 62 = 2 ('C') if it were kept; 1 → 'B'.
    expect(plantedSecret(replay([250, 1, 52, 27])).slice(0, 3)).toBe('B0b');
    expect(plantedSecret(replay([247, 52])).slice(0, 2)).toBe('90');
    // after two letters the next draw is a digit, and a byte ≥ 250 is dropped there (250 = 25 × 10): 252 → '2' if it were kept
    expect(plantedSecret(replay([0, 26, 252, 3])).slice(0, 3)).toBe('Aa3');
    expect(plantedSecret(replay([0, 26, 249])).slice(0, 3)).toBe('Aa9');
    // a value missing a class is drawn again, never returned: only upper letters and digits first, then the sequence
    const upperOnly = Array.from({ length: 40 }, (_, i) => (i % 3 === 2 ? 1 : 0));
    const again = plantedSecret(replay(upperOnly));
    expect(again).toMatch(/[a-z]/);
    expect(again).not.toBe('AA1'.repeat(14).slice(0, 40));
    // each rule on its own, with values that pass every other rule (high entropy, no 3-letter run): drawn again, never returned.
    // two letters of one case then a digit, 13 times and one more letter: 26 distinct letters, 10 digits
    const oneCase = (first: number) => Array.from({ length: 40 }, (_, i) => (i % 3 === 2 ? (i / 3) % 10 | 0 : first + ((i - Math.floor(i / 3)) % 26)));
    const lowerOnly = oneCase(26), upperOnlyHigh = oneCase(0);
    const spell = (bytes: number[]) => bytes.map((b, i) => (i % 3 === 2 ? String(b % 10) : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[b % 62])).join('');
    expect(spell(lowerOnly)).toMatch(/^(?:[a-z]{2}[0-9])+[a-z]$/);
    for (const bytes of [lowerOnly, upperOnlyHigh]) {
      const v = plantedSecret(replay(bytes));
      expect(v).not.toBe(spell(bytes));
      expect(v).toMatch(/[A-Z]/);
      expect(v).toMatch(/[a-z]/);
    }
    // entropy under 4 with every class present ('Ab1' over and over): drawn again
    const low = Array.from({ length: 40 }, (_, i) => [0, 27, 1][i % 3] as number);
    expect(spell(low)).toBe('Ab1'.repeat(14).slice(0, 40));
    expect(plantedSecret(replay(low))).not.toBe('Ab1'.repeat(14).slice(0, 40));
    // a digit ends a letter run: letter, digit, letter, letter is drawn as is (the fourth draw is not forced to a digit)
    expect(plantedSecret(replay([0, 52, 26, 27])).slice(0, 4)).toBe('A0ab');
    // the scanners' stopwords a value with no 3-letter run can still hold (measured on the pinned gitleaks 8.30.1 and betterleaks
    // 1.9.0: a value holding one is dropped): md5 in any case, and six zeros. Drawn again, never returned.
    for (const head of [[38, 29, 5], [12, 3, 5], [38, 3, 5], [12, 29, 5], [52, 52, 52, 52, 52, 52]]) {
      const v = plantedSecret(replay(head));
      expect(v.slice(0, head.length), v).not.toMatch(/^(?:md5|000000)$/i);
      expect(v).not.toMatch(/md5|000000/i);
    }
    // (the heads above really spell them: the same bytes with a stopword-free tail are kept as drawn)
    expect(plantedSecret(replay([38, 29, 6])).slice(0, 3)).toBe('md6');
    expect(plantedSecret(replay([52, 52, 52, 52, 52, 53])).slice(0, 6)).toBe('000001');
    // a source that never gives a lower-case letter (or gives nothing) fails closed, never returns a weak value
    expect(() => plantedSecret(() => new Uint8Array(64))).toThrow(PlantedError);
    expect(() => plantedSecret(() => new Uint8Array(0))).toThrow(PlantedError);
    expect(() => plantedSecret(() => new Uint8Array(64).fill(255))).toThrow(PlantedError);
  });
});

// ---------- fixtures ----------

describe('planted fixtures', () => {
  it('planted: no file under data/ is named package.json, package-lock.json or requirements.txt', () => {
    const MANIFEST = /^(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[\w.-]*\.txt|pipfile(?:\.lock)?|poetry\.lock|pyproject\.toml|uv\.lock|setup\.py|setup\.cfg|go\.mod|go\.sum|gemfile(?:\.lock)?|cargo\.(?:toml|lock)|composer\.(?:json|lock)|pom\.xml|build\.gradle(?:\.kts)?)$/i;
    const files = walkFiles('data');
    expect(files).toEqual(expect.arrayContaining(['data/planted/node/package.json.planted', 'data/planted/node/package-lock.json.planted', 'data/planted/python/requirements.txt.planted']));
    for (const f of files) expect(MANIFEST.test(f.split('/').at(-1) as string), f).toBe(false);
    // the check itself refuses the three names
    for (const n of ['package.json', 'package-lock.json', 'requirements.txt', 'Package.JSON']) expect(MANIFEST.test(n)).toBe(true);
    // every fixture the module reads is a .planted file under data/planted/
    for (const list of Object.values(PLANTED_FIXTURES)) for (const fx of list) expect(fx.data).toMatch(/^planted\/(?:node|python)\/[a-z.-]+\.planted$/);
  });

  it('planted: the written manifests equal the fixtures byte for byte (lodash 4.17.11, PyYAML 5.3)', () => {
    const { files } = plantedFiles(MONO, { random: seq() });
    const got = byPath(files);
    const fx = (rel: string) => readFileSync(join(root, 'data', rel));
    const node = { 'package.json': fx('planted/node/package.json.planted'), 'package-lock.json': fx('planted/node/package-lock.json.planted') };
    const python = { 'requirements.txt': fx('planted/python/requirements.txt.planted') };
    for (const dir of ['pipegen-planted/deps-node', 'packages/lib/pipegen-planted/deps-node-packages-lib']) {
      for (const [name, bytes] of Object.entries(node)) expect(Buffer.from(got.get(`${dir}/${name}`) as string, 'utf8').equals(bytes), `${dir}/${name}`).toBe(true);
    }
    expect(Buffer.from(got.get('services/api/pipegen-planted/deps-python-services-api/requirements.txt') as string, 'utf8').equals(python['requirements.txt'])).toBe(true);
    // the vulnerable versions, exact
    const pkg = JSON.parse(node['package.json'].toString('utf8')) as { dependencies: Record<string, string>; private: boolean };
    expect(pkg.dependencies).toEqual({ lodash: '4.17.11' });
    expect(pkg.private).toBe(true);
    const lock = JSON.parse(node['package-lock.json'].toString('utf8')) as { lockfileVersion: number; packages: Record<string, { version?: string; dependencies?: Record<string, string> }> };
    expect(lock.lockfileVersion).toBe(3);
    expect(lock.packages['node_modules/lodash']?.version).toBe('4.17.11');
    expect(lock.packages['']?.dependencies).toEqual({ lodash: '4.17.11' });
    expect(Object.keys(lock.packages).sort()).toEqual(['', 'node_modules/lodash']);
    const req = python['requirements.txt'].toString('utf8').split('\n').filter((l) => l.trim() !== '' && !l.startsWith('#'));
    expect(req).toEqual(['PyYAML==5.3']);
    expect(PLANTED_FIXTURES.node.map((f) => f.name)).toEqual(['package.json', 'package-lock.json']);
    expect(PLANTED_FIXTURES.python.map((f) => f.name)).toEqual(['requirements.txt']);
    // the SQL files: request input concatenated into the query (plain .js / .py, never .ts)
    const js = got.get('pipegen-planted/sast-node.js') as string;
    expect(js).toMatch(/db\.query\(\s*"SELECT [^"]*'" \+ req\.query\.\w+ \+ "'"/);
    const py = got.get('services/api/pipegen-planted/sast-python-services-api.py') as string;
    expect(py).toMatch(/cursor\.execute\(\s*"SELECT [^"]*'" \+ request\.args\.get\("\w+"\) \+ "'"/);
    expect(files.some((f) => /\.tsx?$/.test(f.path as string))).toBe(false);
  });
});

// ---------- the matcher ----------

describe('matchPlanted', () => {
  const { expected } = plantedFiles(MONO, { random: seq() });
  const ids = expected.map((e) => e.id);

  it('match: finding in planted file with severity ≥ min → caught', () => {
    expect(matchPlanted(allCaught(expected), expected, TOOLS)).toEqual({ caught: ids, missed: [] });
    expect(matchPlanted(allCaught(expected, 'critical'), expected, TOOLS)).toEqual({ caught: ids, missed: [] });
    // a per-service scanner that reports paths relative to its service folder (it ran there) still matches its own item
    const rel = expected.map((e) => finding(TOOLS.get(e.category) as string, e.file.slice(e.file.indexOf(PLANTED_DIR)), 'high'));
    expect(matchPlanted(rel, expected, TOOLS)).toEqual({ caught: ids, missed: [] });
    // extra findings (other files, other tools) change nothing
    const noise = [finding('semgrep', 'src/app.js', 'critical'), finding('eslint', 'pipegen-planted/sast-node.js', 'critical')];
    expect(matchPlanted([...noise, ...allCaught(expected)], expected, TOOLS)).toEqual({ caught: ids, missed: [] });
    // an item E built (no minSeverity, no critical) reads as high
    const e: EvalPlantedItem[] = [{ id: 'x', category: 'sast', item: 'thing', file: 'pipegen-planted/sast-node.js' }];
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/sast-node.js', 'high')], e, TOOLS)).toEqual({ caught: ['x'], missed: [] });
  });

  it("match: a finding on another item's file or by another tool never counts", () => {
    const sast = expected.find((e) => e.id === 'sast-node') as PlantedItem;
    const keyItem = expected.find((e) => e.id === 'secret') as PlantedItem;
    // semgrep on the secret's file: not the sast item; gitleaks on the sast file: not the sast item either
    const r = matchPlanted([finding('semgrep', keyItem.file, 'critical'), finding('gitleaks', sast.file, 'critical')], [sast, keyItem], TOOLS);
    expect(r).toEqual({ caught: [], missed: ['sast-node', 'secret'] });
    // a file in the same planted folder or a glob-like neighbour is not the item's file
    for (const file of ['pipegen-planted/sast-node.js.bak', 'pipegen-planted/sast-node', 'x/pipegen-planted/sast-node.js', 'pipegen-planted/./sast-node.js', './pipegen-planted/sast-node.js', 'PIPEGEN-PLANTED/sast-node.js', 'pipegen-planted/sast-node-packages-lib.js']) {
      expect(matchPlanted([finding('semgrep', file, 'critical')], [sast], TOOLS).caught, file).toEqual([]);
    }
    // a finding with no file never counts
    expect(matchPlanted([finding('semgrep', undefined, 'critical')], [sast], TOOLS).missed).toEqual(['sast-node']);
    // one finding counts for one item only: two items on one file need two findings
    const twin: EvalPlantedItem[] = [{ id: 'a', category: 'sast', item: 'x', file: 'pipegen-planted/sast-node.js' }, { id: 'b', category: 'sast', item: 'x', file: 'pipegen-planted/sast-node.js' }];
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/sast-node.js')], twin, TOOLS)).toEqual({ caught: ['a'], missed: ['b'] });
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/sast-node.js', 'high', 'r1'), finding('semgrep', 'pipegen-planted/sast-node.js', 'high', 'r2')], twin, TOOLS)).toEqual({ caught: ['a', 'b'], missed: [] });
    // a service-relative path that two items share (one's repo path, the other's service path) is credited to neither by that form
    const amb: EvalPlantedItem[] = [{ id: 'root', category: 'sast', item: 'x', file: 'pipegen-planted/s.js' }, { id: 'svc', category: 'sast', item: 'x', file: 'a/pipegen-planted/s.js' }];
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/s.js', 'high', 'r1'), finding('semgrep', 'pipegen-planted/s.js', 'high', 'r2')], amb, TOOLS)).toEqual({ caught: ['root'], missed: ['svc'] });
    expect(matchPlanted([finding('semgrep', 'a/pipegen-planted/s.js')], amb, TOOLS)).toEqual({ caught: ['svc'], missed: ['root'] });
    const amb2: EvalPlantedItem[] = [{ id: 'p', category: 'sast', item: 'x', file: 'a/pipegen-planted/s.js' }, { id: 'q', category: 'sast', item: 'x', file: 'b/pipegen-planted/s.js' }];
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/s.js', 'high', 'r1'), finding('semgrep', 'pipegen-planted/s.js', 'high', 'r2')], amb2, TOOLS)).toEqual({ caught: [], missed: ['p', 'q'] });
    // the secret (repo-wide) is never matched by a service-relative form of another item: per-service sast findings in lib's folder
    const lib = expected.find((e) => e.id === 'sast-node--packages-lib') as PlantedItem;
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/sast-node-packages-lib.js')], [lib, sast], TOOLS)).toEqual({ caught: ['sast-node--packages-lib'], missed: ['sast-node'] });
  });

  it('match: a finding below minSeverity → missed; minSeverity is high for every item', () => {
    for (const e of expected) expect(e.minSeverity).toBe('high');
    for (const sev of ['medium', 'low', 'info'] as const) expect(matchPlanted(allCaught(expected, sev), expected, TOOLS)).toEqual({ caught: [], missed: ids });
    // a severity that is not one of the five is not a severity
    const odd = allCaught(expected).map((f) => ({ ...f, severity: 'HIGH' as unknown as Severity }));
    expect(matchPlanted(odd, expected, TOOLS).caught).toEqual([]);
    // the floor is high: an item that asks for less still needs high; one that asks for critical needs critical
    const sast = expected.find((e) => e.id === 'sast-node') as PlantedItem;
    const asking = (minSeverity: Severity): PlantedItem[] => [{ ...sast, minSeverity }];
    expect(matchPlanted([finding('semgrep', sast.file, 'medium')], asking('low'), TOOLS).caught).toEqual([]);
    expect(matchPlanted([finding('semgrep', sast.file, 'high')], asking('critical'), TOOLS).caught).toEqual([]);
    expect(matchPlanted([finding('semgrep', sast.file, 'critical')], asking('critical'), TOOLS).caught).toEqual(['sast-node']);
    expect(matchPlanted([finding('semgrep', sast.file, 'high')], asking('bogus' as Severity), TOOLS).caught).toEqual(['sast-node']);
    expect(matchPlanted([finding('semgrep', sast.file, 'medium')], asking('bogus' as Severity), TOOLS).caught).toEqual([]);
    // a low finding on the file does not use up the item: a later high one still catches it
    expect(matchPlanted([finding('semgrep', sast.file, 'low', 'r1'), finding('semgrep', sast.file, 'high', 'r2')], [sast], TOOLS).caught).toEqual(['sast-node']);
  });

  it('match: an expected item with no file, or ids nobody expected → missed / ignored', () => {
    const noFile: EvalPlantedItem[] = [{ id: 'n', category: 'sast', item: 'x' }, { id: 'e', category: 'sast', item: 'x', file: '' }];
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/sast-node.js', 'critical'), finding('semgrep', undefined, 'critical')], noFile, TOOLS)).toEqual({ caught: [], missed: ['n', 'e'] });
    // a category with no tool in the map: missed (nothing ran that could catch it)
    const sast = expected.find((e) => e.id === 'sast-node') as PlantedItem;
    expect(matchPlanted(allCaught([sast]), [sast], new Map([['secrets', 'gitleaks']]))).toEqual({ caught: [], missed: ['sast-node'] });
    // findings for files nobody expected, and ids nobody expected, never show up
    const r = matchPlanted([finding('semgrep', 'pipegen-planted/other.js', 'critical'), ...allCaught([sast])], [sast], TOOLS);
    expect(r).toEqual({ caught: ['sast-node'], missed: [] });
    expect(matchPlanted(allCaught(expected), [], TOOLS)).toEqual({ caught: [], missed: [] });
    // the same id twice: caught only when both entries are caught, and listed once
    const dup: EvalPlantedItem[] = [{ id: 'd', category: 'sast', item: 'x', file: 'pipegen-planted/a.js' }, { id: 'd', category: 'sast', item: 'x', file: 'pipegen-planted/b.js' }];
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/a.js')], dup, TOOLS)).toEqual({ caught: [], missed: ['d'] });
    expect(matchPlanted([finding('semgrep', 'pipegen-planted/a.js'), finding('semgrep', 'pipegen-planted/b.js')], dup, TOOLS)).toEqual({ caught: ['d'], missed: [] });
    // malformed entries (no string id) can't be reported and are skipped; a bad category is missed
    const junk = [null, 7, { category: 'sast', item: 'x', file: 'pipegen-planted/sast-node.js' }, { id: 'c', category: 7, item: 'x', file: 'pipegen-planted/sast-node.js' }] as unknown as EvalPlantedItem[];
    expect(matchPlanted(allCaught([sast]), junk, TOOLS)).toEqual({ caught: [], missed: ['c'] });
  });

  it("match: the type fits EvalContext.matchPlanted (compile-time check with evaluate's PlantedItem)", () => {
    // Plan G's wiring: F's expected as EvalContext.plantedItems, F's matcher as EvalContext.matchPlanted
    const m: NonNullable<EvalContext['matchPlanted']> = matchPlanted;
    const items: NonNullable<EvalContext['plantedItems']> = expected;
    const wiring: Pick<EvalContext, 'plantedItems' | 'matchPlanted'> = { plantedItems: plantedFiles(profile()).expected, matchPlanted };
    expectTypeOf<PlantedItem>().toMatchTypeOf<EvalPlantedItem>();
    expectTypeOf(matchPlanted).parameter(1).toEqualTypeOf<readonly EvalPlantedItem[]>();
    expectTypeOf(matchPlanted).parameter(0).toEqualTypeOf<Finding[]>();
    expectTypeOf(matchPlanted).returns.toEqualTypeOf<{ caught: string[]; missed: string[] }>();
    // as evaluate calls it: spread copies of the items, a fresh map
    expect(m(allCaught(expected), items.map((w) => ({ ...w })), new Map(TOOLS))).toEqual({ caught: ids, missed: [] });
    expect(wiring.matchPlanted).toBe(matchPlanted);
  });
});

// ---------- the delivery exclusion ----------

describe('isPlantedPath', () => {
  it('isPlantedPath: pipegen-planted at any depth', () => {
    for (const p of ['pipegen-planted', 'pipegen-planted/', 'pipegen-planted/config.txt', 'a/pipegen-planted/x.js', 'a/b/c/pipegen-planted/d/e/f', './pipegen-planted/x', 'a\\pipegen-planted\\x', 'Pipegen-Planted/x', 'PIPEGEN-PLANTED', 'a/pipegen-planted./x', 'a/pipegen-planted /x', '/pipegen-planted/x']) {
      expect(isPlantedPath(p), p).toBe(true);
    }
    for (const p of ['', 'pipegen-plantedx/y', 'xpipegen-planted/y', 'pipegen-planted-old/y', 'src/planted.ts', 'pipegen-c1b/x', 'docs/pipegen-planted.md', 'pipegen_planted/x', 'a/pipegen/planted/x']) {
      expect(isPlantedPath(p), p).toBe(false);
    }
    expect(isPlantedPath(Buffer.from('a/pipegen-planted/k\xe9y', 'latin1'))).toBe(true);
    expect(isPlantedPath(Buffer.from('a/b', 'latin1'))).toBe(false);
    // every file plantedFiles makes is caught by it
    for (const f of plantedFiles(MONO, { random: seq() }).files) expect(isPlantedPath(f.path)).toBe(true);
  });
});
