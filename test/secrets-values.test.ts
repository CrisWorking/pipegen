// D5: a vault value (or its base64 or URL form) inside any created file is an issue, in the guard and in the referee.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { guardCreatedFiles, type GuardCtx } from '../src/create/guard.js';
import { SecretVault } from '../src/create/secrets.js';
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
