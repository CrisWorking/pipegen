// Plan A Task 8: the consent screen shown before any code leaves the machine. Two modes (Plan U ruling B2): 'full'
// (the whole run: repos, Actions minutes, AI cost and cap, time, write permissions) and 'audit-ai' (`audit --ai`:
// files, provider, refusal note, the audit's own AI cost and cap, read-only permissions; no minutes, no repos).
// Repos are described per DECISIONS #87: pipegen's App creates them; with a token the user does (gh repo create).
import { describe, expect, it } from 'vitest';
import { askConsent, consentText, type BundleSummary } from '../src/cli/consent.js';
import { clackPrompter, PromptCancelledError, type Prompter } from '../src/cli/io.js';
import { REFUSAL_FALLBACK_NOTE } from '../src/ai/provider.js';
import { EXCLUDED_PATTERNS } from '../src/ai/redact.js';
import { floorNeeds, jobCategories } from '../src/engine/needs.js';
import { estimate, estimateAuditAi, type Estimates } from '../src/estimate/estimate.js';
import { permissionsTable } from '../src/github/client.js';
import { DEFAULT_MODEL, type AiProvider, type Capabilities, type RepoProfile, type Service } from '../src/types.js';
import { hostileNames } from './fixtures/hostile-names.js';

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
const ollama = provider('ollama', 'llama3.1');
const openai = provider('openai', 'gpt-5');

const fullEst = (p: RepoProfile, ai: AiProvider): Estimates =>
  estimate(p, jobCategories(floorNeeds(p, CAPS)), 2, { pushes: 40, prs: 6, capped: false }, { name: ai.name, model: ai.model });
const bundle: BundleSummary = { files: 42, bytes: 123_456, topFolders: ['src', 'test', '.github'] };
const usd = (n: number) => `$${n.toFixed(2)}`;
const n = (x: number) => x.toLocaleString('en-US');
const repos = (p: RepoProfile, exists: [boolean, boolean]) => [{ name: 'pipelines', exists: exists[0] }, { name: `pipegen-proof-${p.repo}`, exists: exists[1] }];

const full = (over: { p?: RepoProfile; ai?: AiProvider; exists?: [boolean, boolean]; app?: boolean; ollamaHost?: string } = {}) => {
  const p = over.p ?? profile();
  const ai = over.ai ?? claude;
  const est = fullEst(p, ai);
  const text = consentText(p, ai, est, bundle, permissionsTable('write'), repos(p, over.exists ?? [false, true]), 'full', { appCreatesRepos: over.app ?? false, gitleaksVersion: '8.30.1', ollamaHost: over.ollamaHost });
  return { p, est, text };
};
const audit = (ai: AiProvider = claude, extra: { p?: RepoProfile; bundle?: BundleSummary } = {}) => {
  const p = extra.p ?? profile();
  const est = estimateAuditAi({ name: ai.name, model: ai.model }, 3);
  const text = consentText(p, ai, est, extra.bundle ?? bundle, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: '8.30.1' });
  return { p, est, text };
};

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
    for (const row of permissionsTable('write')) expect(text).toContain(`${row.permission}: ${row.why}`);
    // the files that will be read
    expect(text).toContain('42 files');
    expect(text).toContain('Top folders: src, test, .github');
  });

  it('consent: token mode — repos are described as used, not created; missing repos show gh repo create --private commands', () => {
    const { text } = full({ exists: [false, true], app: false });
    expect(text).toContain('gh repo create acme/pipelines --private');
    expect(text).not.toContain('gh repo create acme/pipegen-proof-shop'); // it exists already
    expect(text).toMatch(/uses/);
    expect(text).not.toMatch(/pipegen (will )?creates? /i);
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
    expect(text).toContain('deletes the scratch repo acme/pipegen-proof-shop after the proof');
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
      const lines = full({ app }).text.split('\n').filter((l) => /^\s*Administration \(write\):/.test(l));
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('to apply the merge rules (rulesets), deploy environments and Actions settings after you merge the setup PR');
    }
    expect(full({ app: true }).text).toMatch(/Administration \(write\):.*delete the scratch repo after the proof if you allow it/);
    // read-only runs never ask for it
    expect(audit().text).not.toMatch(/Administration \(write\)|Administration: read and write/);
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
    expect(full({ ai: ollama, ollamaHost: 'http://127.0.0.1:11434' }).text).toContain('stays on this computer');
    expect(full({ ai: ollama, ollamaHost: 'localhost:11434' }).text).toContain('stays on this computer');
    const remote = full({ ai: ollama, ollamaHost: ['https://user', 'pw@gpu.example.net:8443/x'].join(':') }).text;
    expect(remote).not.toContain('stays on this computer');
    expect(remote).toContain('gpu.example.net:8443');
    expect(remote).not.toContain('pw@'); // never the credential
  });

  it('consent: openai is named as experimental and sends code to OpenAI', () => {
    const { text } = full({ ai: openai });
    expect(text).toContain('OpenAI (gpt-5)');
    expect(text).toContain('experimental');
  });

  it('consent: lists every EXCLUDED_PATTERNS entry and a binary files line', () => {
    for (const text of [full().text, audit().text]) {
      for (const pattern of EXCLUDED_PATTERNS) expect(text).toContain(pattern);
      expect(text).toMatch(/binary files/i);
    }
  });

  it('consent: names the gitleaks download (pinned version, checksum-verified) before anything is sent (S21)', () => {
    for (const text of [full().text, audit().text]) {
      expect(text).toContain('gitleaks 8.30.1');
      expect(text).toContain('checksum-verified');
    }
  });

  it('consent: repo-derived names pass through safeText', () => {
    const hostile = [hostileNames.ansiColour, hostileNames.osc8Link, hostileNames.bidiOverride, hostileNames.nulAndCr, hostileNames.newlines];
    const { text } = audit(claude, { bundle: { files: 3, bytes: 10, topFolders: hostile } });
    expect(text).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩]/);
    expect(text).toContain('red-app');
    expect(text).toContain('appfdp.exe');
    // a very long folder name is cut
    const long = audit(claude, { bundle: { files: 1, bytes: 1, topFolders: [hostileNames.veryLong] } }).text;
    expect(long).not.toContain('a'.repeat(200));
    // the repo name in the helper repo lines too
    const fullText = consentText(profile({ repo: 'shop' }), claude, fullEst(profile(), claude), bundle, permissionsTable('write'),
      [{ name: `pipegen-proof-${hostileNames.ansiColour}`, exists: false }], 'full', { appCreatesRepos: false });
    expect(fullText).not.toContain('\x1b');
  });
});

describe('consentText (audit-ai, ruling B2)', () => {
  it('consent: audit-ai mode (B2) → files, provider, refusal note, audit AI cost + cap, read-only permissions; no Actions minutes, no repos', () => {
    const { est, text } = audit();
    if (est.costUsd === 'local' || est.capUsd === null) throw new Error('expected a priced estimate');
    expect(text).toContain('42 files');
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

  it('consent: audit-ai mode ignores repos and refuses write permissions', () => {
    const p = profile();
    const est = estimateAuditAi({ name: 'claude', model: DEFAULT_MODEL }, 3);
    const text = consentText(p, claude, est, bundle, permissionsTable('read'), repos(p, [false, false]), 'audit-ai');
    expect(text).not.toMatch(/pipelines|pipegen-proof|gh repo create/);
    expect(() => consentText(p, claude, est, bundle, permissionsTable('write'), [], 'audit-ai')).toThrow(/read-only/);
  });
});

describe('askConsent', () => {
  it('consent: default answer is No', async () => {
    const io = scripted(async (_m, def) => def); // the user just presses Enter
    expect(await askConsent(io, 'the consent text')).toBe(false);
    expect(io.asked).toHaveLength(1);
    expect(io.asked[0]?.def).toBe(false);
    expect(io.asked[0]?.msg).toContain('the consent text');
    expect(await askConsent(scripted(async () => true), 'x')).toBe(true);
  });

  it('askConsent: a cancelled or failed prompt counts as No', async () => {
    expect(await askConsent(scripted(async () => { throw new Error('cancelled'); }), 'x')).toBe(false);
  });

  it('clackPrompter: without an interactive terminal it never guesses; consent is No', async () => {
    const notTty = { isTTY: false } as unknown as NodeJS.ReadStream & NodeJS.WriteStream;
    const prompter = clackPrompter(notTty, notTty);
    await expect(prompter.confirm('ok?', true)).rejects.toBeInstanceOf(PromptCancelledError);
    await expect(prompter.select('which?', [{ value: 'a', label: 'A' }], 'a')).rejects.toBeInstanceOf(PromptCancelledError);
    await expect(prompter.text('name?')).rejects.toBeInstanceOf(PromptCancelledError);
    expect(await askConsent(prompter, 'the consent text')).toBe(false);
  });
});
