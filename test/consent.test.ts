// Plan A Task 8: the consent screen shown before any code leaves the machine. Two modes (Plan U ruling B2): 'full'
// (the whole run: repos, Actions minutes, AI cost and cap, time, write permissions) and 'audit-ai' (`audit --ai`:
// files, provider, refusal note, the audit's own AI cost and cap, read-only permissions; no minutes, no repos).
// Repos are described per DECISIONS #87: pipegen's App creates them; with a token the user does (gh repo create).
import { realpathSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { askConsent, consentScreen, consentText, ConsentScreen } from '../src/cli/consent.js';
import { claimTokenMinter, ConsentToken, countingSummary, CountingSummary } from '../src/audit/consent-token.js';
import { clackPrompter, PromptCancelledError, type Prompter } from '../src/cli/io.js';
import { REFUSAL_FALLBACK_NOTE } from '../src/ai/provider.js';
import { ollamaProvider } from '../src/ai/ollama.js';
import { BundleSummary, bundleCode, bundleSummary, EXCLUDED_KEPT, EXCLUDED_PATTERN_GROUPS, EXCLUDED_PATTERNS, GitleaksRequiredError, type CodeBundle } from '../src/ai/redact.js';
import { floorNeeds, jobCategories } from '../src/engine/needs.js';
import { estimate, estimateAuditAi, type Estimates } from '../src/estimate/estimate.js';
import { permissionsTable } from '../src/github/client.js';
import { DEFAULT_MODEL, type AiProvider, type Capabilities, type RepoProfile, type Service } from '../src/types.js';
import { hostileNames } from './fixtures/hostile-names.js';
import { CLEAN, makeStub } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const svc = (over: Partial<Service> = {}): Service => ({
  name: 'web', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['test'], frameworks: ['express'], ...over,
});
const profile = (over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'acme', repo: 'shop', defaultBranch: 'main', private: true, ownerType: 'User', plan: 'free',
  monorepo: 'none', services: [svc()], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, ...over,
});
const CAPS: Capabilities = { branchProtection: false, environments: true, deploymentBranchPolicies: false, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false };
const provider = (name: AiProvider['name'], model: string): AiProvider => ({ name, model, complete: async () => { throw new Error('no AI call in consent tests'); } });
const claude = provider('claude', DEFAULT_MODEL);
/** A real Ollama provider (it carries its host); the default host is this computer. Nothing is sent. */
const ollamaAt = (host?: string) => ollamaProvider({ host, model: 'llama3.1' });
const ollama = ollamaAt();
const openai = provider('openai', 'gpt-5');

/** The estimate for this provider: the provider itself is passed, so an Ollama estimate knows its host. */
const fullEst = (p: RepoProfile, ai: AiProvider): Estimates =>
  estimate(p, jobCategories(floorNeeds(p, CAPS)), 2, { pushes: 40, prs: 6, capped: false }, ai);

/** A real code bundle of `files` (each a small text file), checked by the gitleaks stub. */
async function checkedBundle(files: string[]): Promise<CodeBundle> {
  const dir = makeTempDir();
  for (const f of files) writeIn(dir, f, `// ${f.length}\n`);
  return bundleCode(dir, { gitleaks: makeStub(CLEAN).bin });
}
/** The consent facts of that bundle: only bundleSummary() makes a BundleSummary (final review batch 2, I1). */
const summaryOf = async (files: string[]) => bundleSummary(await checkedBundle(files));
const FILES = ['src/a.ts', 'src/b.ts', 'src/c.ts', 'test/a.test.ts', 'test/b.test.ts', '.github/workflows/ci.yml', 'README.md'];
let checked: CodeBundle;
let bundle: BundleSummary;
beforeAll(async () => {
  checked = await checkedBundle(FILES);
  bundle = bundleSummary(checked);
});
afterAll(() => { cleanupRepos(); });
const usd = (n: number) => `$${n.toFixed(2)}`;
const n = (x: number) => x.toLocaleString('en-US');
const repos = (p: RepoProfile, exists: [boolean, boolean]) => [{ name: 'pipelines', exists: exists[0] }, { name: `pipegen-proof-${p.repo}`, exists: exists[1] }];

const full = (over: { p?: RepoProfile; ai?: AiProvider; exists?: [boolean, boolean]; app?: boolean } = {}) => {
  const p = over.p ?? profile();
  const ai = over.ai ?? claude;
  const est = fullEst(p, ai);
  const app = over.app ?? false;
  const text = consentText(p, ai, est, bundle, permissionsTable('write', { appCreatesRepos: app }), repos(p, over.exists ?? [false, true]), 'full', { appCreatesRepos: app, gitleaksVersion: '8.30.1' });
  return { p, est, text };
};
const audit = (ai: AiProvider = claude, extra: { p?: RepoProfile; bundle?: BundleSummary } = {}) => {
  const p = extra.p ?? profile();
  const est = estimateAuditAi(ai, 3, 50_000);
  const text = consentText(p, ai, est, extra.bundle ?? bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' });
  return { p, est, text };
};

const noErr = (s: string) => { throw new Error(`unexpected error report: ${s}`); };

/** A Prompter that answers from a script and records the questions. */
function scripted(answer: (msg: string, def: boolean) => Promise<boolean>): Prompter & { asked: { msg: string; def: boolean }[] } {
  const asked: { msg: string; def: boolean }[] = [];
  return {
    asked,
    confirm: async (msg, def) => { asked.push({ msg, def }); return answer(msg, def); },
    select: async (_m, _o, def) => def,
    text: async () => '',
  };
}

describe('consentText (full)', () => {
  it('consent: lists provider, repos used, setup + monthly minutes, AI cost, time and permissions', () => {
    const { est, text } = full();
    expect(text).toContain(`Claude (${DEFAULT_MODEL})`);
    expect(text).toContain('Anthropic');
    expect(text).toContain('acme/pipelines');
    expect(text).toContain('acme/pipegen-proof-shop');
    expect(text).toContain(`Setup: about ${n(est.setupMinutes)} minutes`);
    expect(text).toContain(`hard limit ${n(est.setupMinutesCap)} minutes`);
    expect(est.setupMinutesCap).toBe(2 * est.setupMinutes);
    expect(text).toContain(`Afterwards: about ${n(est.monthlyMinutes)} minutes a month`);
    expect(text).toContain('your free plan includes 2,000 minutes a month');
    expect(text).toMatch(/Total: \$\d+\.\d\d–\$\d+\.\d\d/);
    expect(text).toContain(`About ${est.durationMinutes.low}–${est.durationMinutes.high} minutes`);
    for (const row of permissionsTable('write', { appCreatesRepos: false })) expect(text).toContain(`${row.permission}: ${row.why}`);
    // the files that will be read: counted from the checked bundle itself
    expect(text).toContain('7 files');
    expect(text).toContain('Top folders: src, test, .github');
  });

  it('consent: token mode — repos are described as used, not created; missing repos show gh repo create --private commands', () => {
    const { text } = full({ exists: [false, true], app: false });
    expect(text).toContain('gh repo create acme/pipelines --private');
    expect(text).not.toContain('gh repo create acme/pipegen-proof-shop'); // it exists already
    expect(text).toMatch(/uses/);
    expect(text).not.toMatch(/pipegen (will )?creates? /i);
    // nothing on the screen (the permissions included) says pipegen creates or deletes a repo (#87, review I1)
    expect(text).not.toMatch(/create the private helper repos|delete the scratch repo|App creates|App deletes/i);
    expect(text).toContain('never creates or deletes repos');
    const both = full({ exists: [false, false], app: false }).text;
    expect(both).toContain('gh repo create acme/pipelines --private');
    expect(both).toContain('gh repo create acme/pipegen-proof-shop --private');
    const none = full({ exists: [true, true], app: false }).text;
    expect(none).not.toContain('gh repo create');
  });

  it("consent: App mode — pipegen's App creates the missing repos (DECISIONS #87), no gh commands", () => {
    const { text } = full({ exists: [false, true], app: true });
    expect(text).not.toContain('gh repo create');
    expect(text).toMatch(/acme\/pipelines: doesn't exist yet; pipegen's GitHub App creates it \(private\)/);
    expect(text).toMatch(/acme\/pipegen-proof-shop: exists; pipegen uses it/);
    // the repos section and the Administration permission say the same thing about the scratch repo (review M3)
    expect(text).toContain('deletes the scratch repo acme/pipegen-proof-shop after the proof if you allow it.');
    expect(text).toMatch(/Administration: read and write: .*delete the scratch repo after the proof if you allow it\./);
  });

  it('consent: token mode refuses a permissions table built for the App (it would say pipegen creates repos)', () => {
    const p = profile();
    expect(() => consentText(p, claude, fullEst(p, claude), bundle, permissionsTable('write', { appCreatesRepos: true }), repos(p, [false, true]), 'full', { appCreatesRepos: false, gitleaksVersion: '8.30.1' }))
      .toThrow(/never creates or deletes repos/);
  });

  it('consent: AI cost shown split into input and output, with the 2× hard cap', () => {
    const { est, text } = full();
    if (est.aiCostUsd === 'local' || est.aiCostCapUsd === null) throw new Error('expected a priced estimate');
    const c = est.aiCostUsd;
    expect(text).toContain(`Input: ${usd(c.input.low)}–${usd(c.input.high)}`);
    expect(text).toContain(`Output: ${usd(c.output.low)}–${usd(c.output.high)}`);
    expect(text).toContain(`Total: ${usd(c.low)}–${usd(c.high)}`);
    expect(est.aiCostCapUsd).toBeCloseTo(2 * c.high, 10);
    expect(text).toContain(`pipegen stops if the AI cost reaches ${usd(est.aiCostCapUsd)}.`);
  });

  it('consent: Administration permission explained in one line', () => {
    for (const app of [true, false]) {
      const lines = full({ app }).text.split('\n').filter((l) => /Administration/.test(l));
      expect(lines).toHaveLength(1);
      expect(lines[0]).toMatch(/^ {2}- Administration: read and write: Apply the merge rules \(rulesets\), create the deploy and signing environments/);
    }
    // read-only runs never ask for write: one read row only
    const read = audit().text.split('\n').filter((l) => /Administration/.test(l));
    expect(read).toEqual([expect.stringMatching(/^ {2}- Administration: read: /)]);
  });

  it('consent: claude shows the refusal fallback note', () => {
    expect(full().text).toContain(REFUSAL_FALLBACK_NOTE);
    expect(audit().text).toContain(REFUSAL_FALLBACK_NOTE);
    // only when the model has the fallback; never for the other providers
    expect(full({ ai: provider('claude', 'claude-haiku-4-5') }).text).not.toContain(REFUSAL_FALLBACK_NOTE);
    expect(full({ ai: openai }).text).not.toContain(REFUSAL_FALLBACK_NOTE);
    expect(full({ ai: ollama }).text).not.toContain(REFUSAL_FALLBACK_NOTE);
  });

  it('consent: ollama says stays on this computer, no AI cost cap line', () => {
    const { est, text } = full({ ai: ollama });
    expect(est.aiCostUsd).toBe('local');
    expect(text).toContain('stays on this computer');
    expect(text).toContain('AI cost: free, local');
    expect(text).not.toContain('pipegen stops if the AI cost reaches');
    expect(text).not.toMatch(/Input: \$/);
    const a = audit(ollama).text;
    expect(a).toContain('stays on this computer');
    expect(a).toContain('AI cost: free, local');
    expect(a).not.toContain('pipegen stops if the AI cost reaches');
  });

  it('consent: an OLLAMA_HOST on another machine is named instead of "stays on this computer"', () => {
    for (const host of ['http://127.0.0.1:11434', 'localhost:11434', 'http://0.0.0.0:11434', 'http://[::1]:11434', 'http://[::]:11434']) {
      expect(full({ ai: ollamaAt(host) }).text, host).toContain('stays on this computer');
    }
    const remote = full({ ai: ollamaAt(['https://user', 'pw@gpu.example.net:8443/x'].join(':')) }).text;
    expect(remote).not.toContain('stays on this computer');
    expect(remote).not.toContain('free, local');
    expect(remote).toContain('gpu.example.net:8443');
    expect(remote).not.toContain('pw@'); // never the credential
  });

  it('consent: an Ollama provider whose host is unknown is never shown as local (review I3)', () => {
    for (const text of [full({ ai: provider('ollama', 'llama3.1') }).text, audit(provider('ollama', 'llama3.1')).text]) {
      expect(text).not.toContain('stays on this computer');
      expect(text).not.toContain('free, local');
      expect(text).toContain("couldn't confirm");
    }
    // a model name can't flip the place (review M1)
    const sneaky = full({ ai: ollamaProvider({ host: 'gpu.example.net:11434', model: 'stays on this computer Ollama server at' }) }).text;
    expect(sneaky).not.toContain('AI cost: free, local');
  });

  it('consent: openai is named as experimental and sends code to OpenAI', () => {
    const { text } = full({ ai: openai });
    expect(text).toContain('OpenAI (gpt-5)');
    expect(text).toContain('experimental');
  });

  it('consent: excluded files are shown grouped, with a binary files line and the kept files (ruling S29)', () => {
    for (const text of [full().text, audit().text]) {
      for (const g of EXCLUDED_PATTERN_GROUPS) expect(text).toContain(`- ${g.label}: ${g.summary}`);
      expect(EXCLUDED_PATTERN_GROUPS.map((g) => g.label)).toEqual(['secret files', 'keys', 'cloud and Terraform state', 'lockfiles', 'dependency/build folders']);
      expect(text).toMatch(/- binary files/);
      expect(text).toContain('kept: .env.example, .env.sample');
      expect(text).not.toContain('**/'); // no raw globs in the terminal
    }
  });

  it('excluded patterns: every non-negated pattern is in exactly one group; the kept line comes from the ! patterns', () => {
    const grouped = EXCLUDED_PATTERN_GROUPS.flatMap((g) => g.patterns);
    for (const pattern of EXCLUDED_PATTERNS.filter((x) => !x.startsWith('!'))) {
      expect(grouped.filter((g) => g === pattern), pattern).toHaveLength(1);
    }
    for (const pattern of grouped) expect(EXCLUDED_PATTERNS, pattern).toContain(pattern); // no group invents a pattern
    expect(EXCLUDED_KEPT).toEqual(['.env.example', '.env.sample']);
  });

  it('consent: names the gitleaks download (pinned version, checksum-verified) before anything is sent (S21)', () => {
    for (const text of [full().text, audit().text]) {
      expect(text).toContain('gitleaks 8.30.1');
      expect(text).toContain('checksum-verified');
    }
  });

  it('consent: repo-derived names pass through safeText', async () => {
    // real folders with hostile names (one path segment each; bundleCode itself leaves out paths with CR or LF)
    const hostile = [hostileNames.ansiColour, `\x1b]8;;evil.example\x1b\\click me\x1b]8;;\x1b\\`, hostileNames.bidiOverride];
    const hostileBundle = await summaryOf(hostile.map((h) => `${h}/f.ts`));
    expect([...hostileBundle.topFolders].sort()).toEqual([...hostile].sort());
    const { text } = audit(claude, { bundle: hostileBundle });
    expect(text).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/);
    expect(text).toContain('red-app');
    expect(text).toContain('appfdp.exe');
    // a very long folder name is cut
    const long = audit(claude, { bundle: await summaryOf([`${'a'.repeat(250)}/x.ts`]) }).text;
    expect(long).not.toContain('a'.repeat(200));
    // the repo name in the helper repo lines too
    const fullText = consentText(profile({ repo: 'shop' }), claude, fullEst(profile(), claude), bundle, permissionsTable('write', { appCreatesRepos: false }),
      [{ name: `pipegen-proof-${hostileNames.ansiColour}`, exists: false }], 'full', { appCreatesRepos: false, gitleaksVersion: '8.30.1' });
    expect(fullText).not.toContain('\x1b');
  });
});

describe('consentText (audit-ai, ruling B2)', () => {
  it('consent: audit-ai mode (B2) → files, provider, refusal note, audit AI cost + cap, read-only permissions; no Actions minutes, no repos', () => {
    const { est, text } = audit();
    if (est.costUsd === 'local' || est.capUsd === null) throw new Error('expected a priced estimate');
    expect(text).toContain('7 files');
    expect(text).toContain('Top folders: src, test, .github');
    expect(text).toContain(`Claude (${DEFAULT_MODEL})`);
    expect(text).toContain(REFUSAL_FALLBACK_NOTE);
    expect(text).toContain(`Input: ${usd(est.costUsd.input.low)}–${usd(est.costUsd.input.high)}`);
    expect(text).toContain(`Output: ${usd(est.costUsd.output.low)}–${usd(est.costUsd.output.high)}`);
    expect(text).toContain(`pipegen stops if the AI cost reaches ${usd(est.capUsd)}.`);
    for (const row of permissionsTable('read')) expect(text).toContain(`${row.permission}: ${row.why}`);
    expect(text).not.toMatch(/minutes/i);
    expect(text).not.toMatch(/pipelines|pipegen-proof|gh repo create/);
    expect(text).not.toMatch(/read and write/);
  });

  it('consent: audit-ai refuses an estimate for a model with no price (no hard cost limit can be kept; U14)', () => {
    const p = profile();
    const pro = provider('openai', 'gpt-5-pro');
    const est = estimateAuditAi(pro, 3, 50_000);
    expect(est.unpriced?.message).toBe("pipegen doesn't know the price of gpt-5-pro, so it can't keep a hard cost limit. Choose one of: gpt-5, gpt-5-mini, gpt-5.5.");
    expect(() => consentText(p, pro, est, bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(est.unpriced?.message);
  });

  it('consent: audit-ai mode ignores repos and refuses write permissions', () => {
    const p = profile();
    const est = estimateAuditAi(claude, 3, 50_000);
    const text = consentText(p, claude, est, bundle, permissionsTable('read'), repos(p, [false, false]), 'audit-ai', { gitleaksVersion: '8.30.1' });
    expect(text).not.toMatch(/pipelines|pipegen-proof|gh repo create/);
    expect(() => consentText(p, claude, est, bundle, permissionsTable('write', { appCreatesRepos: false }), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(/read-only/);
  });
});

describe('consent facts tied to their sources (final review batch 2, I1)', () => {
  it('bundleSummary: counted from a gitleaks-checked bundle; an unchecked bundle is refused', async () => {
    expect(bundle.files).toBe(checked.files.length);
    expect(bundle.files).toBe(7);
    expect(bundle.bytes).toBe(checked.bytes);
    expect(bundle.topFolders).toEqual(['src', 'test', '.github']); // most files first; README.md is at the top level
    expect(Object.isFrozen(bundle)).toBe(true);
    expect(Object.isFrozen(bundle.topFolders)).toBe(true);
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', 'x\n');
    const unchecked = await bundleCode(dir); // no gitleaks: for counting only
    expect(() => bundleSummary(unchecked)).toThrow(GitleaksRequiredError);
    expect(() => bundleSummary({ ...checked })).toThrow(GitleaksRequiredError); // a copy is not the checked bundle
  });

  it('consent: only a BundleSummary made by bundleSummary() is accepted', () => {
    const p = profile();
    const est = estimateAuditAi(claude, 3, 50_000);
    const fake = { files: 1, bytes: 1, topFolders: [] };
    // @ts-expect-error a plain object is not a BundleSummary (it has no private brand)
    expect(() => consentText(p, claude, est, fake, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(/bundleSummary/);
    const cast = fake as unknown as BundleSummary;
    expect(() => consentText(p, claude, est, cast, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(/bundleSummary/);
    const copy = Object.assign(Object.create(BundleSummary.prototype) as BundleSummary, { files: 1, bytes: 1, topFolders: [] });
    expect(() => consentText(p, claude, est, copy, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(/bundleSummary/);
    // @ts-expect-error the constructor is private: only bundleSummary() makes one
    expect(() => new BundleSummary(1, 1, [])).toBeDefined();
  });

  it('consent: refuses an estimate priced for another provider or model', () => {
    const p = profile();
    const fable = provider('claude', 'claude-fable-5-1');
    const opusFull = fullEst(p, claude);
    expect(() => consentText(p, fable, opusFull, bundle, permissionsTable('write', { appCreatesRepos: false }), repos(p, [true, true]), 'full', { appCreatesRepos: false, gitleaksVersion: '8.30.1' }))
      .toThrow(/priced for claude \/ claude-opus-5-5.*claude \/ claude-fable-5-1/);
    expect(() => consentText(p, openai, estimateAuditAi(claude, 3, 50_000), bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(/priced for/);
    // an estimate with no provider can't back a consent screen that sends code to one
    const none = estimate(p, jobCategories(floorNeeds(p, CAPS)), 2, { pushes: 1, prs: 1, capped: false }, null);
    expect(() => consentText(p, claude, none, bundle, permissionsTable('write', { appCreatesRepos: false }), repos(p, [true, true]), 'full', { appCreatesRepos: false, gitleaksVersion: '8.30.1' })).toThrow(/priced for no AI provider/);
    // Ollama: the estimate must be for the same host (its basis says where the model runs)
    const remote = ollamaAt('gpu.example.net:11434');
    expect(() => consentText(p, remote, estimateAuditAi({ name: 'ollama', model: 'llama3.1' }, 3, 50_000), bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(/priced for/);
    expect(() => consentText(p, remote, estimateAuditAi(ollama, 3, 50_000), bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toThrow(/priced for/);
    expect(consentText(p, remote, estimateAuditAi(remote, 3, 50_000), bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' })).toContain('gpu.example.net:11434');
  });
});

describe('consent shows how the estimates were made (final review batch 2, M3)', () => {
  it('consent: every basis line is shown under the cost lines', () => {
    for (const { est, text } of [full(), audit()]) {
      const basis = 'basis' in est ? est.basis : [];
      expect(basis.length).toBeGreaterThan(0);
      const lines = text.split('\n');
      const cost = lines.findIndex((l) => l.startsWith('  Total: '));
      for (const b of basis) {
        const at = lines.indexOf(`  - ${b}`);
        expect(at, b).toBeGreaterThan(cost);
      }
    }
    // the assumptions a user should see at the decision point
    const capped = consentText(profile(), claude, estimate(profile(), jobCategories(floorNeeds(profile(), CAPS)), 2, { pushes: 300, prs: 2, capped: true }, claude), bundle,
      permissionsTable('write', { appCreatesRepos: false }), repos(profile(), [true, true]), 'full', { appCreatesRepos: false, gitleaksVersion: '8.30.1' });
    expect(capped).toContain('at least 300 pushes');
    expect(capped).toMatch(/disputes/);
    const unknownModel = provider('claude', 'claude-future-9');
    expect(full({ ai: unknownModel }).text).toMatch(/has no price for the model "claude-future-9".*most expensive/);
  });

  it('consent: basis lines pass through safeText', () => {
    const hostile = provider('openai', `gpt\x1b[2J\u202e-x`);
    const text = full({ ai: hostile }).text;
    expect(text).not.toMatch(/[\u001b\u202e]/);
    expect(text).toContain('has no price for the model');
    // audit --ai refuses a model with no price (ruling U14); the refusal text is cleaned too
    const est = estimateAuditAi(hostile, 3, 50_000);
    expect(est.unpriced?.message).not.toMatch(/[\u001b\u202e]/);
    expect(() => audit(hostile)).toThrow(/doesn't know the price of/);
  });

  it('consent: the Ollama basis matches where it runs', () => {
    expect(full({ ai: ollama }).text).toContain('Ollama runs on your machine');
    const remote = full({ ai: ollamaAt('gpu.example.net:8443') }).text;
    expect(remote).not.toContain('Ollama runs on your machine');
    expect(remote).toMatch(/Ollama server at gpu\.example\.net:8443.*no AI cost and no cost cap/);
  });
});

describe('askConsent', () => {
  /** The audit --ai screen for the shared checked bundle. */
  const screen = () => consentScreen(profile(), claude, estimateAuditAi(claude, 3, 50_000), bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' });

  it('consent: default answer is No', async () => {
    const io = scripted(async (_m, def) => def); // the user just presses Enter
    const s = screen();
    expect(await askConsent(io, s, noErr)).toBeNull();
    expect(io.asked).toHaveLength(1);
    expect(io.asked[0]?.def).toBe(false);
    expect(io.asked[0]?.msg).toContain(s.text);
    expect(await askConsent(scripted(async () => true), screen(), noErr)).toBeInstanceOf(ConsentToken);
  });

  it('askConsent: a cancelled or failed prompt counts as No; only a real failure is reported (review M5)', async () => {
    const errs: string[] = [];
    expect(await askConsent(scripted(async () => { throw new PromptCancelledError(); }), screen(), (s) => { errs.push(s); })).toBeNull();
    expect(errs).toEqual([]); // the user cancelled: nothing to report
    expect(await askConsent(scripted(async () => { throw new Error(`broken prompt ${hostileNames.ansiColour}`); }), screen(), (s) => { errs.push(s); })).toBeNull();
    expect(errs).toHaveLength(1);
    expect(errs[0]).toContain("couldn't ask for your consent");
    expect(errs[0]).toContain('broken prompt red-app');
    expect(errs[0]).not.toContain('\x1b');
  });

  it('clackPrompter: without an interactive terminal it never guesses; consent is No', async () => {
    const notTty = { isTTY: false } as unknown as NodeJS.ReadStream & NodeJS.WriteStream;
    const prompter = clackPrompter(notTty, notTty);
    await expect(prompter.confirm('ok?', true)).rejects.toBeInstanceOf(PromptCancelledError);
    await expect(prompter.select('which?', [{ value: 'a', label: 'A' }], 'a')).rejects.toBeInstanceOf(PromptCancelledError);
    await expect(prompter.text('name?')).rejects.toBeInstanceOf(PromptCancelledError);
    expect(await askConsent(prompter, screen(), noErr)).toBeNull();
  });
});

describe('consent token (T4b: no AI call without consent, by type)', () => {
  it('consent grant (yes) gives a ConsentToken that carries what the screen showed (mode, provider, cap, files)', async () => {
    const est = estimateAuditAi(claude, 3, 50_000);
    const s = consentScreen(profile(), claude, est, bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' });
    expect(s).toBeInstanceOf(ConsentScreen);
    expect(Object.isFrozen(s)).toBe(true);
    expect(s.text).toBe(consentText(profile(), claude, est, bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' }));
    const granted = await askConsent(scripted(async () => true), s, noErr);
    if (granted === null) throw new Error('expected a yes');
    expect(ConsentToken.isToken(granted)).toBe(true);
    expect(Object.isFrozen(granted)).toBe(true);
    expect(granted.terms).toEqual({ mode: 'audit-ai', pricedFor: est.pricedFor, capUsd: est.capUsd, files: bundle, dir: null });
    const f = full();
    const fullScreen = consentScreen(f.p, claude, f.est, bundle, permissionsTable('write', { appCreatesRepos: false }), repos(f.p, [true, true]), 'full', { appCreatesRepos: false, gitleaksVersion: '8.30.1' });
    expect(fullScreen.terms).toMatchObject({ mode: 'full', capUsd: f.est.aiCostCapUsd });
  });

  it('consent grant (ConsentToken) only from askConsent, and only from a screen consentScreen() made', async () => {
    // @ts-expect-error the constructor is private: only askConsent makes a token
    expect(() => new ConsentToken({ mode: 'audit-ai' })).toBeDefined();
    expect(ConsentToken.isToken({ terms: { mode: 'audit-ai' } })).toBe(false);
    expect(ConsentToken.isToken(Object.create(ConsentToken.prototype))).toBe(false);
    const yes = scripted(async () => true);
    // @ts-expect-error a string is not a ConsentScreen
    await expect(askConsent(yes, 'the consent text', noErr)).rejects.toThrow(/consentScreen/);
    const hand = { text: 'x', terms: { mode: 'audit-ai' } } as unknown as ConsentScreen;
    await expect(askConsent(yes, hand, noErr)).rejects.toThrow(/consentScreen/);
    // runtime forgery (review M1): `new` through a cast, or a subclass, is not a screen pipegen made
    const real = consentScreen(profile(), claude, estimateAuditAi(claude, 3, 50_000), bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' });
    const Screen = ConsentScreen as unknown as new (text: string, terms: unknown) => ConsentScreen;
    class SubScreen extends Screen {}
    for (const forged of [new Screen('x', real.terms), new SubScreen('x', real.terms)]) {
      expect(ConsentScreen.isScreen(forged)).toBe(false);
      await expect(askConsent(yes, forged, noErr)).rejects.toThrow(/consentScreen/);
    }
    const Minted = ConsentToken as unknown as new (terms: unknown) => object;
    class SubToken extends Minted {}
    expect(ConsentToken.isToken(new Minted(real.terms))).toBe(false);
    expect(ConsentToken.isToken(new SubToken(real.terms))).toBe(false);
    expect(yes.asked).toEqual([]); // nothing was asked
    // the token minter is claimed once, by the consent module; nobody else gets it
    expect(() => claimTokenMinter()).toThrow(/already claimed/);
  });
});

describe('counting summary (audit --ai: consent comes before the gitleaks download, ruling S21)', () => {
  it('countingSummary: only from bundleCode\'s own counting-only bundle; a checked bundle or a copy is refused', async () => {
    const dir = makeTempDir();
    for (const f of FILES) writeIn(dir, f, `// ${f.length}\n`);
    const counted = await bundleCode(dir);
    const c = countingSummary(counted);
    expect(CountingSummary.isSummary(c)).toBe(true);
    expect(c.files).toBe(7);
    expect(c.bytes).toBe(counted.bytes);
    expect(c.topFolders).toEqual(['src', 'test', '.github']);
    expect(Object.isFrozen(c)).toBe(true);
    expect(() => countingSummary(checked)).toThrow(/counting-only/);
    expect(() => countingSummary({ ...counted })).toThrow(/counting-only/);
    expect(CountingSummary.isSummary({ files: 1, bytes: 1, topFolders: [] })).toBe(false);
    const Summary = CountingSummary as unknown as new (...a: unknown[]) => object;
    class SubSummary extends Summary {}
    expect(CountingSummary.isSummary(new Summary(1, 1, [], dir, new Set()))).toBe(false);
    expect(CountingSummary.isSummary(new SubSummary(1, 1, [], dir, new Set()))).toBe(false);
    const Checked = BundleSummary as unknown as new (...a: unknown[]) => object;
    expect(BundleSummary.isSummary(new Checked(1, 1, []))).toBe(false);
    expect(BundleSummary.isSummary(bundle)).toBe(true);
    // bound to the folder it counted (its real path) and to its exact file list; paths() hands out a copy
    expect(c.dir).toBe(realpathSync(dir));
    const ps = c.paths();
    expect([...ps].sort()).toEqual([...FILES].sort());
    ps.add('src/evil.ts');
    expect(c.paths().has('src/evil.ts')).toBe(false);
    // covers(): the checked bundle of the same files is inside what was counted; a bundle with another file is not
    expect(c.covers(await bundleCode(dir, { gitleaks: makeStub(CLEAN).bin }))).toBe(true);
    writeIn(dir, 'src/new.ts', '// new\n');
    expect(c.covers(await bundleCode(dir, { gitleaks: makeStub(CLEAN).bin }))).toBe(false);
    // onlyPaths (review I1): the walk reads only the counted files, so the checked bundle stays inside the count
    const only = await bundleCode(dir, { gitleaks: makeStub(CLEAN).bin, onlyPaths: c.paths() });
    expect(only.files.map((f) => f.path)).not.toContain('src/new.ts');
    expect(c.covers(only)).toBe(true);
  });

  it('consent (audit-ai): a counting summary says "at most" and that gitleaks runs after the yes; the full screen refuses it', async () => {
    const dir = makeTempDir();
    for (const f of FILES) writeIn(dir, f, `// ${f.length}\n`);
    const c = countingSummary(await bundleCode(dir));
    const p = profile();
    const est = estimateAuditAi(claude, 3, 50_000);
    const text = consentText(p, claude, est, c, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' });
    expect(text).toContain('pipegen sends at most 7 files');
    expect(text).toContain('Top folders: src, test, .github');
    expect(text).toContain('These counts were made before the gitleaks check');
    expect(text).toContain('gitleaks 8.30.1, which pipegen downloads (checksum-verified) into its cache');
    expect(text).not.toMatch(/gitleaks was not run|counting only/);
    const f = full();
    // @ts-expect-error the full run's screen takes only the checked bundle's summary
    expect(() => consentText(f.p, claude, f.est, c, permissionsTable('write', { appCreatesRepos: false }), repos(f.p, [true, true]), 'full', { appCreatesRepos: false, gitleaksVersion: '8.30.1' })).toThrow(/bundleSummary/);
  });
});
