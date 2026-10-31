// D5: a vault value (or its base64 or URL form) inside any created file is an issue, in the guard and in the referee.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { guardCreatedFiles, type GuardCtx } from '../src/create/guard.js';
import { SecretVault } from '../src/create/secrets.js';
import { CREATED_RULES } from '../src/engine/created-files.js';
import { referee, type Linters } from '../src/engine/referee.js';
import type { CreatedFile, PipelineDraft } from '../src/types.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

// built at runtime: no secret-looking literal is committed (test/no-secret-literals.test.ts)
const SKT = 'sk' + '_test_';
const VALUE = SKT + 'Zx9/Qq+Wl 7788';
function vault(): SecretVault {
  const v = new SecretVault();
  v.set('K_STRIPE', VALUE);
  return v;
}
const forms = [VALUE, Buffer.from(VALUE).toString('base64'), encodeURIComponent(VALUE)];
const mkDraft = (): PipelineDraft => ({
  profile: profile([service({ name: 'api', path: 'api', port: 3000, scripts: ['start'] })]), capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true },
  needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const file = (content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path: 'api/Dockerfile', content, part: 'docker', reason: 'test', repo: 'app', ...over });

function guardCtx(v?: SecretVault): GuardCtx {
  const root = mkdtempSync(join(tmpdir(), 'pg-guard-'));
  dirs.push(root);
  return { root, baseTree: { complete: true, entries: new Map() }, installRecord: null, profile: mkDraft().profile, ...(v === undefined ? {} : { vault: v }) };
}

describe('guard: vault values', () => {
  it('a vault value, its base64 or URL form inside a created file is refused', async () => {
    for (const f of forms) {
      const r = await guardCreatedFiles([file(`FROM node:24\nENV X=${f}\n`)], guardCtx(vault()));
      expect(r.ok, f).toEqual([]);
      expect(r.refused[0]?.reason, f).toMatch(/secret/i);
      expect(JSON.stringify(r)).not.toContain('Zx9');
    }
  });

  it('also in the path and in the reason', async () => {
    const v = new SecretVault();
    v.set('K_ONE', 'abcdefgh12345678');
    const r1 = await guardCreatedFiles([file('FROM node:24\n', { path: 'api/abcdefgh12345678/Dockerfile' })], guardCtx(v));
    expect(r1.ok).toEqual([]);
    expect(JSON.stringify(r1)).not.toContain('abcdefgh12345678');
    const r3 = await ref([file('FROM node:24\n', { path: 'api/abcdefgh12345678/Dockerfile' })], v);
    expect(JSON.stringify(r3)).not.toContain('abcdefgh12345678');
    expect(r3.issues.some((i) => i.check === 'secret-value')).toBe(true);
    const r2 = await guardCreatedFiles([file('FROM node:24\n', { reason: 'because abcdefgh12345678' })], guardCtx(v));
    expect(r2.ok).toEqual([]);
  });

  it('with no vault, or a vault without the value, nothing changes', async () => {
    const plain = file('FROM node:24\n');
    expect((await guardCreatedFiles([plain], guardCtx())).ok).toHaveLength(1);
    expect((await guardCreatedFiles([plain], guardCtx(new SecretVault()))).ok).toHaveLength(1);
    expect((await guardCreatedFiles([plain], guardCtx(vault()))).ok).toHaveLength(1);
  });
});

const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
const ref = (files: CreatedFile[], v?: SecretVault) => referee(files, mkDraft(), platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], ...(v === undefined ? {} : { vault: v }) });

describe('referee: vault values', () => {
  it('referee/guard: a vault value inside any created file → issue (all three forms, any kind of file)', async () => {
    for (const f of forms) {
      for (const make of [() => file(`FROM node:24\nENV X=${f}\n`), () => file(`# ${f}\n`, { path: 'PIPEGEN.md', part: 'docs' })]) {
        const r = await ref([make()], vault());
        const hit = r.issues.find((i) => i.check === 'secret-value' && /you gave pipegen/.test(i.message));
        expect(hit, f).toBeDefined();
        expect(JSON.stringify(r)).not.toContain('Zx9');
      }
    }
  });

  it('with no vault nothing changes', async () => {
    const a = await ref([file(`FROM node:24\nENV X=${VALUE}\n`)]);
    expect(a.issues.some((i) => /you gave pipegen/.test(i.message))).toBe(false);
    const b = await ref([file('FROM node:24\n')], vault());
    expect(b.issues.some((i) => /you gave pipegen/.test(i.message))).toBe(false);
  });
});

describe('referee: a file holding a value gets only the fixed secret-value issue (I1)', () => {
  const LONG = 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';   // 24 characters: a cut by safeText must never leave a piece of it
  const PRE = 'j'.repeat(40);
  const wf = (path: string, content: string): CreatedFile => ({ path, content, part: 'pipeline', reason: 'r', repo: 'central' });

  it('a value straddling the safeText cut in a job id, a step name, broken YAML or a compose service: one fixed issue per file, no piece of the value anywhere', async () => {
    const v = new SecretVault();
    v.set('K_LONG', LONG);
    const files: CreatedFile[] = [
      wf('.github/workflows/ci.yml', `name: ci\non: [push]\njobs:\n  ${PRE + LONG}:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${LONG}\n        name: ${PRE + PRE + LONG}\n`),
      wf('.github/workflows/bad.yml', `on: [push\n  ${LONG}: : :\n`),
      { path: 'docker-compose.pipegen.yml', content: `services:\n  ${LONG}:\n    image: x\n`, part: 'docker', reason: 'r', repo: 'app' },
    ];
    const r = await ref(files, v);
    expect(r.issues.length).toBe(3);
    expect(r.issues.every((i) => i.check === 'secret-value' && /you gave pipegen/.test(i.message))).toBe(true);
    const shown = JSON.stringify(r);
    for (let k = 0; k + 8 <= LONG.length; k++) expect(shown, LONG.slice(k, k + 8)).not.toContain(LONG.slice(k, k + 8));
  });

  it('a value in the reason alone makes the file a secret-value issue', async () => {
    const v = new SecretVault();
    v.set('K_LONG', LONG);
    const r = await ref([file('FROM node:24\n', { reason: `because ${LONG}` })], v);
    expect(r.issues.map((i) => i.check)).toEqual(['secret-value']);
    expect(JSON.stringify(r)).not.toContain(LONG.slice(0, 8));
  });

  it('every issue text is scrubbed where issues are built: a judge that quotes a value is shown redacted (the whole text, before any cut)', async () => {
    const v = new SecretVault();
    v.set('K_LONG', LONG);
    const quoting = CREATED_RULES.map((r) => (r.id === 'dockerfile' ? { ...r, judge: () => [`the base image ${LONG} is not allowed`] } : r));
    const r = await referee([file('FROM node:24\n')], mkDraft(), platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: v, createdRules: quoting });
    expect(r.issues.length).toBeGreaterThan(0);
    expect(JSON.stringify(r)).not.toContain(LONG);
    expect(r.issues.some((i) => i.message.includes('[REDACTED]'))).toBe(true);
  });
});

describe('guard: the service-folder note is scrubbed', () => {
  it('a service folder name that holds a value is shown redacted in the note', async () => {
    const v = new SecretVault();
    v.set('K_ONE', 'abcdefgh12345678');
    const ctx = guardCtx(v);
    ctx.profile = profile([service({ name: 'api', path: 'bad folder abcdefgh12345678' })]);
    const r = await guardCreatedFiles([file('FROM node:24\n')], ctx);
    expect(r.notes.join('\n')).toMatch(/service folder/);
    expect(JSON.stringify(r)).not.toContain('abcdefgh12345678');
  });
});

describe('guard: a file holding a value gets only the fixed refusal (I1)', () => {
  it('even when other rules would also refuse it (a bad path), the reason is the fixed one and the path is scrubbed', async () => {
    const v = new SecretVault();
    v.set('K_ONE', 'abcdefgh12345678');
    const r = await guardCreatedFiles([file('FROM node:24\n', { path: '../abcdefgh12345678/Dockerfile' })], guardCtx(v));
    expect(r.refused).toHaveLength(1);
    expect(r.refused[0]?.reason).toMatch(/value you gave pipegen/);
    expect(JSON.stringify(r)).not.toContain('abcdefgh12345678');
  });
});
