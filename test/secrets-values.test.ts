// D5: a vault value (or its base64 or URL form) inside any created file is an issue, in the guard and in the referee.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { guardCreatedFiles, type GuardCtx } from '../src/create/guard.js';
import { SecretVault } from '../src/create/secrets.js';
import { activeSafeText } from '../src/util/known-values.js';
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

const INVISIBLE: [string, string][] = [['U+200B', '\u200b'], ['U+2060', '\u2060'], ['U+FEFF', '\ufeff'], ['bidi override U+202E', '\u202e'], ['soft hyphen U+00AD', '\u00ad']];
const VAL = 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';
const splitVal = (ch: string): string => `${VAL.slice(0, 6)}${ch}${VAL.slice(6)}`;
function vaultOf(value: string): SecretVault {
  const v = new SecretVault();
  v.set('K_LONG', value);
  return v;
}

describe('B1: a value split by an invisible character is found on the displayed text', () => {
  for (const [name, ch] of INVISIBLE) {
    it(`referee, ${name}: job id and step name hold the split value -> the whole draft is refused with fixed secret-value issues, nothing else is judged, no piece shows`, async () => {
      const PRE = 'j'.repeat(40);
      const wf: CreatedFile = { path: '.github/workflows/ci.yml', content: `name: ci\non: [push]\njobs:\n  ${PRE}${splitVal(ch)}:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        name: ${PRE}${PRE}${splitVal(ch)}\n`, part: 'pipeline', reason: 'r', repo: 'central' };
      const clean = file('FROM node:24\nENV A=b\nENV A=;;;broken\n');
      const r = await ref([wf, clean], vaultOf(VAL));
      expect(r.ok).toBe(false);
      expect(r.issues.every((i) => i.check === 'secret-value' && /you gave pipegen/.test(i.message))).toBe(true);
      expect(r.issues.length).toBeGreaterThan(0);
      const shown = JSON.stringify(r);
      for (let k = 0; k + 6 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 6)).not.toContain(VAL.slice(k, k + 6));
    });

    it(`guard, ${name}: a Dockerfile holding the split value is refused`, async () => {
      const r = await guardCreatedFiles([file(`FROM node:24\nENV X=${splitVal(ch)}\n`)], guardCtx(vaultOf(VAL)));
      expect(r.ok).toEqual([]);
      expect(r.refused[0]?.reason).toMatch(/value you gave pipegen/);
    });
  }

  it('the reason, the repo field and a draft that holds the value (split) refuse the whole draft too', async () => {
    const v = vaultOf(VAL);
    const a = await ref([file('FROM node:24\n', { reason: splitVal('\u200b') })], v);
    expect(a.issues.map((i) => i.check)).toEqual(['secret-value']);
    const d = mkDraft();
    d.profile = profile([service({ name: `svc-${splitVal('\u2060')}`, path: 'api', port: 3000, scripts: ['start'] })]);
    const b = await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: v });
    expect(b.ok).toBe(false);
    expect(b.issues.every((i) => i.check === 'secret-value')).toBe(true);
    expect(JSON.stringify(b)).not.toContain(VAL.slice(0, 6));
  });

  it('a clean draft with no tainted file is judged as before (nothing changes without a hit)', async () => {
    const r = await ref([file('FROM node:24\n')], vaultOf(VAL));
    expect(r.issues.some((i) => i.check === 'secret-value')).toBe(false);
  });

  it('referee notes are scrubbed before they are cut: a linter finding on the user\'s own lines that quotes a value across the 300-character cut', async () => {
    const v = vaultOf(VAL);
    const original = 'name: deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh\n';
    const content = `${original}  pipegen-verify:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: echo x\n`;
    const wf: CreatedFile = { path: '.github/workflows/deploy.yml', content, part: 'deploy-verify', reason: 'r', repo: 'app', inserted: { original, jobs: ['pipegen-verify'], needs: [] } };
    const loud = async () => [{ file: '.github/workflows/deploy.yml', repo: 'app' as const, check: 'actionlint', message: `${'j'.repeat(295)}${VAL}`, line: 5 }];
    const r = await referee([wf], mkDraft(), platform(), reviewedList(), LINTERS, 'tok', { runLinters: loud as never, vault: v });
    expect(r.notes.some((n) => /own lines/.test(n))).toBe(true);
    const shown = JSON.stringify(r);
    for (let k = 0; k + 4 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 4)).not.toContain(VAL.slice(k, k + 4));
  });

  it('referee: a repo field holding the value refuses the draft', async () => {
    const r = await ref([file('FROM node:24\n', { repo: VAL as never })], vaultOf(VAL));
    expect(r.issues.map((i) => i.check)).toEqual(['secret-value']);
    expect(JSON.stringify(r)).not.toContain(VAL.slice(0, 6));
  });
});

describe('B2: the guard cleans before it cuts or escapes', () => {
  it('service-folder note: a non-ASCII value and a value across the 80-character cut never show', async () => {
    for (const value of [`${VAL}é`, VAL]) {
      for (const lead of ['my app/', `my app/${'x'.repeat(70)}`]) {
        const ctx = guardCtx(vaultOf(value));
        ctx.profile = profile([service({ name: 'api', path: `${lead}${value}` })]);
        const r = await guardCreatedFiles([file('FROM node:24\n')], ctx);
        expect(r.notes.join('\n')).toMatch(/service folder/);
        const shown = JSON.stringify(r);
        for (let k = 0; k + 6 <= VAL.length; k++) expect(shown, `${value} ${lead.length} ${VAL.slice(k, k + 6)}`).not.toContain(VAL.slice(k, k + 6));
      }
    }
  });

  it('f.repo holding the value is the fixed refusal (not echoed)', async () => {
    const f = file('FROM node:24\n', { repo: VAL as never });
    const r = await guardCreatedFiles([f], guardCtx(vaultOf(VAL)));
    expect(r.refused[0]?.reason).toMatch(/value you gave pipegen/);
    expect(JSON.stringify(r)).not.toContain(VAL.slice(0, 6));
  });

  it('a reason that quotes an existing disk name (a case clash) never shows a value, even a non-ASCII one', async () => {
    for (const value of ['Abcdefgh12345678', '\uff41bcdefgh12345678']) {   // the second: a full-width a, which folds to the created path's letter
      const ctx = guardCtx(vaultOf(value));
      mkdirSync(join(ctx.root, 'api'));
      writeFileSync(join(ctx.root, 'api', value), 'x');
      const created = file('FROM node:24\n', { path: `api/a${value.slice(1)}` });   // ASCII a first: the value only matches case/width-folded
      const r = await guardCreatedFiles([created], ctx);
      expect(r.refused.length + r.notes.length, value).toBeGreaterThan(0);
      expect(JSON.stringify(r), value).not.toMatch(/Abcdefgh12345678|\?bcdefgh12345678|\uff41/);
    }
  });
});

describe('B4 layer 1 in the judges: decoded text (YAML escapes, JSON escapes, draft strings) is checked', () => {
  const PRE = 'j'.repeat(40);
  const fixedOnly = (r: Awaited<ReturnType<typeof ref>>): void => {
    expect(r.ok).toBe(false);
    expect(r.issues.length).toBeGreaterThan(0);
    expect(r.issues.every((i) => i.check === 'secret-value')).toBe(true);
    const shown = JSON.stringify(r);
    for (let k = 0; k + 4 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 4)).not.toContain(VAL.slice(k, k + 4));
  };
  const wfFile = (body: string): CreatedFile => ({ path: '.github/workflows/ci.yml', content: `name: ci\non: [push]\njobs:\n${body}`, part: 'pipeline', reason: 'r', repo: 'central' });
  // the value with one character written as a YAML escape: the raw text does not hold it, the parsed text does
  const esc = `${VAL.slice(0, 6)}\\x6d${VAL.slice(7)}`;   // \x6d is "m"

  it('referee: a YAML \\x escape in a step name and in a job id', async () => {
    fixedOnly(await ref([wfFile(`  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        name: "${PRE}${esc}"\n`)], vaultOf(VAL)));
    fixedOnly(await ref([wfFile(`  "${PRE}${esc}":\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n`)], vaultOf(VAL)));
  });

  it('referee: a YAML escaped line break (a folded double-quoted scalar) in a step name', async () => {
    const folded = `${VAL.slice(0, 6)}\\\n            ${VAL.slice(6)}`;
    fixedOnly(await ref([wfFile(`  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        name: "${PRE}${folded}"\n`)], vaultOf(VAL)));
  });

  it('referee: ESC inside a raw file (the display would eat it and a character)', async () => {
    fixedOnly(await ref([file(`FROM node:24\nENV X=${VAL.slice(0, 6)}\u001b${VAL.slice(6)}\n`)], vaultOf(VAL)));
  });

  it('referee: draft strings and keys split by BEL, NUL or ESC (JSON.stringify would write them as \\u escapes)', async () => {
    for (const ch of ['\u0007', '\u0000', '\u001b']) {
      const d = mkDraft();
      (d as unknown as { steps: unknown[] }).steps = [{ needId: `${PRE}${VAL.slice(0, 6)}${ch}${VAL.slice(6)}` }];
      fixedOnly(await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: vaultOf(VAL) }));
      const k = mkDraft();
      (k as unknown as { notProven: unknown[] }).notProven = [{ [`${VAL.slice(0, 6)}${ch}${VAL.slice(6)}`]: 1 }];
      fixedOnly(await referee([file('FROM node:24\n')], k, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: vaultOf(VAL) }));
    }
  });

  it('referee: a custom judge that cuts a value with the shared cutter is scrubbed first (the vault is active inside the referee)', async () => {
    const quoting = CREATED_RULES.map((r) => (r.id === 'dockerfile' ? { ...r, judge: () => [`base ${activeSafeText(`${'j'.repeat(180)}${VAL}`, 200)}`] } : r));
    const r = await referee([file('FROM node:24\n')], mkDraft(), platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: vaultOf(VAL), createdRules: quoting });
    expect(r.issues.length).toBeGreaterThan(0);
    const shown = JSON.stringify(r);
    for (let k = 0; k + 4 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 4)).not.toContain(VAL.slice(k, k + 4));
  });

  it('referee: JSON escapes in a package file and YAML escapes in a compose file are checked decoded', async () => {
    const enc = `${VAL.slice(0, 6)}\\u006d${VAL.slice(7)}`;
    fixedOnly(await ref([file(`{"devDependencies": {"${PRE}${enc}": "1.0.0"}}`, { path: 'api/package.json', part: 'tests', edited: { original: '{}' } })], vaultOf(VAL)));
    fixedOnly(await ref([file(`services:\n  "${PRE}${esc}":\n    image: x\n`, { path: 'docker-compose.pipegen.yml', part: 'compose' })], vaultOf(VAL)));
  });

  it('referee: NFD value, NFC text', async () => {
    const nfc = 'caf\u00e9-key-12345';
    const v = new SecretVault();
    v.set('K_UNI', nfc.normalize('NFD'));
    const r = await ref([file(`FROM node:24\nENV X=${nfc}\n`)], v);
    expect(r.issues.map((i) => i.check)).toEqual(['secret-value']);
  });

  it('guard: a JSON \\u escape in a package.json key, a lock key and a script name is refused before any judge reads it', async () => {
    const enc = `${VAL.slice(0, 6)}\\u006d${VAL.slice(7)}`;   // the key as written holds a \u006d escape
    for (const [path, text] of [
      ['api/package.json', `{"devDependencies": {"${PRE}${enc}": "1.0.0"}}`],
      ['api/package.json', `{"scripts": {"${enc}": "x"}}`],
      ['api/package-lock.json', `{"packages": {"node_modules/${enc}": {"version": "1.0.0"}}}`],
    ] as const) {
      const f = file(text, { path, part: 'tests', edited: { original: '{}' } });
      const r = await guardCreatedFiles([f], guardCtx(vaultOf(VAL)));
      expect(r.ok, path).toEqual([]);
      expect(r.refused[0]?.reason, path).toMatch(/value you gave pipegen/);
      const shown = JSON.stringify(r);
      for (let k = 0; k + 4 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 4)).not.toContain(VAL.slice(k, k + 4));
    }
  });

  it('guard: ESC in a raw Dockerfile', async () => {
    const r = await guardCreatedFiles([file(`FROM node:24\nENV X=${VAL.slice(0, 6)}\u001b${VAL.slice(6)}\n`)], guardCtx(vaultOf(VAL)));
    expect(r.ok).toEqual([]);
  });
});
