// D5: a vault value (or its base64 or URL form) inside any created file is an issue, in the guard and in the referee.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { guardCreatedFiles, type GuardCtx } from '../src/create/guard.js';
import { SecretVault } from '../src/create/secrets.js';
import { activeSafeText, withActiveVault } from '../src/util/known-values.js';
import { displayForm } from '../src/util/safe-text.js';
import { runLinters } from '../src/engine/linters.js';
import { CREATED_RULES } from '../src/engine/created-files.js';
import { referee, type Linters, type RefereeDeps } from '../src/engine/referee.js';
import type { CreatedFile, KnownValueCheck, PipelineDraft } from '../src/types.js';
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
    const plain = [file('FROM node:24\n'), file('.env\n', { path: 'api/.dockerignore' })];   // a Dockerfile goes with its .dockerignore (final review m1)
    expect((await guardCreatedFiles(plain, guardCtx())).ok).toHaveLength(2);
    expect((await guardCreatedFiles(plain, guardCtx(new SecretVault()))).ok).toHaveLength(2);
    expect((await guardCreatedFiles(plain, guardCtx(vault()))).ok).toHaveLength(2);
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

describe('fix round 4: ESC and C1 fail closed under a vault (B6), unparsed workflows (B7), linter output scrubbed', () => {
  // every string of a result, as written (JSON) and as displayed: no four-character piece of the value
  const strings = (r: unknown): string[] => { const out: string[] = []; const walk = (x: unknown): void => { if (typeof x === 'string') out.push(x); else if (Array.isArray(x)) x.forEach(walk); else if (typeof x === 'object' && x !== null) Object.values(x).forEach(walk); }; walk(r); return out; };
  const noPiece = (r: unknown): void => {
    const shown = [JSON.stringify(r), ...strings(r).map(displayForm)].join('\n');
    for (let k = 0; k + 4 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 4)).not.toContain(VAL.slice(k, k + 4));
  };
  const fixedOnly = (r: Awaited<ReturnType<typeof referee>>): void => {
    expect(r.ok).toBe(false);
    expect(r.issues.length).toBeGreaterThan(0);
    expect(r.issues.every((i) => i.check === 'secret-value' && /you gave pipegen/.test(i.message))).toBe(true);
    noPiece(r);
  };
  // the reviewer's B6 repro: ESC eats the first character, a CSI / OSC / C1 CSI splits the rest
  const combos: [string, string][] = [
    ['ESC + CSI', `\u001b${VAL.slice(0, 11)}\u001b[0m${VAL.slice(11)}`],
    ['ESC + OSC', `\u001b${VAL.slice(0, 11)}\u001b]0;t\u0007${VAL.slice(11)}`],
    ['ESC + C1 CSI', `\u001b${VAL.slice(0, 11)}\u009b0m${VAL.slice(11)}`],
  ];
  const wf = (body: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path: '.github/workflows/ci.yml', content: body, part: 'pipeline', reason: 'r', repo: 'central', ...over });
  const deps = (v: KnownValueCheck | undefined, runL: RefereeDeps['runLinters'] = async () => []) => ({ runLinters: runL, ...(v === undefined ? {} : { vault: v }) });

  for (const [name, combo] of combos) {
    it(`B6 ${name}: draft string, draft key, job id, step name (decoded YAML) and a raw file give the fixed issue, 0 pieces shown`, async () => {
      const d = mkDraft();
      (d as unknown as { steps: unknown[] }).steps = [{ needId: combo }];
      fixedOnly(await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', deps(vaultOf(VAL))));
      const k = mkDraft();
      (k as unknown as { notProven: unknown[] }).notProven = [{ [combo]: 1 }];
      fixedOnly(await referee([file('FROM node:24\n')], k, platform(), reviewedList(), LINTERS, 'tok', deps(vaultOf(VAL))));
      // written as YAML double-quoted escapes (\u001b, \x9b): the raw text holds no ESC or C1, the decoded job id and step name do
      const yq = (t: string): string => JSON.stringify(t).replace(/[\u0080-\u009f]/g, (c) => `\\x${c.charCodeAt(0).toString(16)}`);
      const w = wf(`name: ci\non: [push]\njobs:\n  ${yq(combo)}:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        name: ${yq(combo)}\n`);
      expect(w.content).not.toMatch(/[\u001b\u0080-\u009f]/);
      fixedOnly(await ref([w], vaultOf(VAL)));
      fixedOnly(await ref([file(`FROM node:24\nENV X=${combo}\n`)], vaultOf(VAL)));
      // a decoded YAML string in another .yml (compose)
      fixedOnly(await ref([file(`services:\n  api:\n    image: ${yq(combo)}\n`, { path: 'docker-compose.pipegen.yml', part: 'compose' })], vaultOf(VAL)));
    });

    it(`B6 ${name}: the guard refuses a raw file holding it with the fixed reason, 0 pieces shown`, async () => {
      const r = await guardCreatedFiles([file(`FROM node:24\nENV X=${combo}\n`)], guardCtx(vaultOf(VAL)));
      expect(r.ok).toEqual([]);
      expect(r.refused[0]?.reason).toMatch(/value you gave pipegen/);
      noPiece(r);
    });
  }

  it('B6: the taint passes fail closed themselves, also with a check that only matches the value as written', async () => {
    const plain: KnownValueCheck = { containsKnownValue: (t) => t.includes(VAL), scrubber: () => (t) => t.split(VAL).join('[REDACTED]') };
    const r = await referee([file(`FROM node:24\n# \u001b[0m\n`)], mkDraft(), platform(), reviewedList(), LINTERS, 'tok', deps(plain));
    expect(r.issues.map((i) => i.check)).toEqual(['secret-value']);
    const d = mkDraft();
    (d as unknown as { steps: unknown[] }).steps = [{ needId: 'x\u0085y' }];
    expect((await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', deps(plain))).issues.map((i) => i.check)).toEqual(['secret-value']);
    const g = await guardCreatedFiles([file('FROM node:24\n# \u009b0m\n')], { ...guardCtx(), vault: plain });
    expect(g.ok).toEqual([]);
    expect(g.refused[0]?.reason).toMatch(/value you gave pipegen/);
  });

  it('B6: with no vault, a file holding ESC is judged as before (no secret-value issue, the guard does not refuse it for that)', async () => {
    const r = await ref([file('FROM node:24\n# \u001b[0m\n')]);
    expect(r.issues.some((i) => i.check === 'secret-value')).toBe(false);
    const g = await guardCreatedFiles([file('FROM node:24\n# \u001b[0m\n')], guardCtx());
    expect(g.refused.some((x) => /value you gave pipegen/.test(x.reason))).toBe(false);
  });

  // B7: the value written with every second character as a YAML \x escape (the raw text holds runs of 2), in a file the strict parse refuses
  const enc = [...VAL].map((c, i) => (i % 2 === 1 ? `\\x${c.charCodeAt(0).toString(16)}` : c)).join('');
  const lintBait = (pre: string): string => `${pre}\non: [push]\npermissions: {}\njobs:\n  build:\n    runs-on: "${'j'.repeat(272)}${enc}"\n    steps:\n      - run: echo hi\n`;

  it('B7: a workflow or action the strict parse refuses is decoded leniently in the taint pass (a tag, an anchor, two documents)', async () => {
    for (const pre of ['name: !!str ci', 'name: &a ci', '---\nname: ci\n---\nname: ci']) fixedOnly(await ref([wf(lintBait(pre))], vaultOf(VAL)));
    const action = `name: !!str a\ndescription: "${enc}"\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n`;
    fixedOnly(await ref([wf(action, { path: '.github/actions/x/action.yml' })], vaultOf(VAL)));
    // another .yml file with two documents (the plain one-document parse throws on it)
    fixedOnly(await ref([file(`services: {}\n---\nx: "${enc}"\n`, { path: 'docker-compose.pipegen.yml', part: 'compose' })], vaultOf(VAL)));
  });

  it('B7: with a vault, a workflow the strict parse refuses is not sent to the linters; it gets the parse-failure issue only. Without a vault it is linted as before', async () => {
    const bad = wf('name: !!str ci\non: [push]\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n');
    const seen: string[][] = [];
    const spy = async (files: CreatedFile[]) => { seen.push(files.map((f) => f.path)); return [{ file: bad.path, check: 'actionlint' as const, message: 'linted' }]; };
    const r = await referee([bad], mkDraft(), platform(), reviewedList(), LINTERS, 'tok', deps(vaultOf(VAL), spy));
    expect(seen).toEqual([]);
    expect(r.issues.some((i) => i.check === 'injection' && /pipegen refuses this file/.test(i.message))).toBe(true);
    expect(r.issues.some((i) => i.message === 'linted')).toBe(false);
    const n = await referee([bad], mkDraft(), platform(), reviewedList(), LINTERS, 'tok', deps(undefined, spy));
    expect(seen).toEqual([[bad.path]]);
    expect(n.issues.some((i) => i.message === 'linted')).toBe(true);
  });

  const AL = join(homedir(), '.cache/pipegen/tools/actionlint-1.7.12/actionlint');
  it.skipIf(!existsSync(AL))('B7 repro with the real actionlint (a tag or an anchor plus the escaped value): 0 pieces shown', async () => {
    const real: Linters = { actionlint: async () => AL, zizmor: async () => '/nonexistent/zizmor' };
    for (const pre of ['name: !!str ci', 'name: &a ci']) {
      const r = await referee([wf(lintBait(pre))], mkDraft(), platform(), reviewedList(), real, null, { vault: vaultOf(VAL) });
      fixedOnly(r);
    }
  }, 120_000);

  it('B7: linters.ts cuts its output with the active vault: a value across the 80- and the 300-character cuts never shows', async () => {
    const odd = file('FROM node:24\n', { path: `x/${'j'.repeat(60)}${VAL}.txt`, repo: 'central' });
    const good = wf('name: ci\non: [push]\njobs: {}\n');
    const failing: Linters = { actionlint: async () => { throw new Error(`${'j'.repeat(260)}${VAL}`); }, zizmor: async () => '/nonexistent/zizmor' };
    const plain = await runLinters([odd, good], failing, null);
    // the control: without an active vault both cuts leave a piece of the value
    expect(plain.some((i) => i.message.includes(VAL.slice(0, 4)))).toBe(true);
    expect(plain.filter((i) => i.message.includes(VAL.slice(0, 4))).length).toBe(2);
    const scrubbed = await withActiveVault(vaultOf(VAL), () => runLinters([odd, good], failing, null));
    expect(scrubbed.length).toBe(plain.length);
    noPiece(scrubbed);
  });
});

describe('fix round 5 (O1): decoded number leaves and keys are checked against the vault', () => {
  const DIG = '12345678901234567890';   // an all-digit value (valueProblem accepts it)
  const D8 = '12345678';
  const noPieceOf = (value: string, r: unknown): void => {
    const all: string[] = [];
    const walk = (x: unknown): void => { if (typeof x === 'string') all.push(x); else if (Array.isArray(x)) x.forEach(walk); else if (typeof x === 'object' && x !== null) Object.values(x).forEach(walk); };
    walk(r);
    const shown = [JSON.stringify(r), ...all.map(displayForm)].join('\n');
    for (let k = 0; k + 4 <= value.length; k++) expect(shown, value.slice(k, k + 4)).not.toContain(value.slice(k, k + 4));
  };
  const fixed = (value: string, r: Awaited<ReturnType<typeof referee>>): void => {
    expect(r.ok).toBe(false);
    expect(r.issues.length).toBeGreaterThan(0);
    expect(r.issues.every((i) => i.check === 'secret-value' && /you gave pipegen/.test(i.message))).toBe(true);
    noPieceOf(value, r);
  };
  const step = (name: string, pre = 'name: ci'): CreatedFile => ({ path: '.github/workflows/ci.yml', content: `${pre}\non: [push]\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        name: ${name}\n`, part: 'pipeline', reason: 'r', repo: 'central' });

  it('the reviewer\'s repro: a hex step name that decodes to a rounded number (not a safe integer) gives the fixed issue, 0 pieces', async () => {
    expect(String(0xab54a98ceb1f0ad2)).toBe('12345678901234567000');
    fixed(DIG, await ref([step('0xab54a98ceb1f0ad2')], vaultOf(DIG)));
  });

  it('a safe integer written as hex or octal is checked as its decimal text', async () => {
    fixed(D8, await ref([step(`0x${(12345678).toString(16).toUpperCase()}`)], vaultOf(D8)));
    fixed(D8, await ref([step(`0o${(12345678).toString(8)}`)], vaultOf(D8)));
  });

  it('float exponent forms: a rounded one fails closed, an exact one is checked as its decimal text', async () => {
    fixed(DIG, await ref([step('1.2345678901234567890e19')], vaultOf(DIG)));
    fixed(D8, await ref([step('1.2345678e7')], vaultOf(D8)));
  });

  it('a number as a mapping key (the strict parse refuses it, the lenient decode checks it), in a workflow and in another .yml', async () => {
    const keyed = (k: string): CreatedFile => ({ path: '.github/workflows/ci.yml', content: `name: ci\non: [push]\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      ${k}: x\n    steps:\n      - run: echo hi\n`, part: 'pipeline', reason: 'r', repo: 'central' });
    fixed(D8, await ref([keyed('0xBC614E')], vaultOf(D8)));
    fixed(DIG, await ref([keyed('0xab54a98ceb1f0ad2')], vaultOf(DIG)));
    fixed(D8, await ref([file('services:\n  0xBC614E:\n    image: x\n', { path: 'docker-compose.pipegen.yml', part: 'compose' })], vaultOf(D8)));
  });

  it('a draft number leaf: a rounded number fails closed, a safe integer is checked as its decimal text', async () => {
    for (const [value, n] of [[DIG, 12345678901234567000], [D8, 12345678]] as const) {
      const d = mkDraft();
      (d as unknown as { steps: unknown[] }).steps = [{ needId: n }];
      fixed(value, await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: vaultOf(value) }));
    }
    for (const n of [Number.NaN, Number.POSITIVE_INFINITY, 1234.56789]) {
      const d = mkDraft();
      (d as unknown as { steps: unknown[] }).steps = [{ needId: n }];
      const r = await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: new SecretVault() });
      expect(r.issues.map((i) => i.check), String(n)).toEqual(['secret-value']);   // a vault given, even an empty one: fail closed
    }
  });

  it('package files: a JSON number that is not a safe integer, or a safe one that is the value, is refused by the guard and the referee', async () => {
    for (const [value, text] of [[DIG, '{"version": "1.0.0", "x": 12345678901234567890}'], [D8, '{"version": "1.0.0", "x": 1.2345678e7}']] as const) {
      const f = file(text, { path: 'api/package.json', part: 'tests', edited: { original: '{}' } });
      const g = await guardCreatedFiles([f], guardCtx(vaultOf(value)));
      expect(g.ok).toEqual([]);
      expect(g.refused[0]?.reason).toMatch(/value you gave pipegen/);
      noPieceOf(value, g);
      fixed(value, await ref([f], vaultOf(value)));
    }
  });

  it('round 5 amendment: short fractional numbers (3.11, 22.5, 0.5) are no hit; one with 8 or more digits fails closed; one whose text is a value is a hit', async () => {
    for (const n of ['3.11', '22.5', '0.5']) {
      const r = await ref([step(n)], vaultOf(DIG));
      expect(r.issues.some((i) => i.check === 'secret-value'), n).toBe(false);
      const d = mkDraft();
      (d as unknown as { steps: unknown[] }).steps = [{ needId: Number(n) }];
      const rd = await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: vaultOf(DIG) });
      expect(rd.issues.some((i) => i.check === 'secret-value'), n).toBe(false);
    }
    fixed(DIG, await ref([step('1234.56789')], vaultOf(DIG)));
    // the value "1.234567" (8 characters, 7 digits): written as 0.1234567e1, the raw text does not hold it, the decoded number's text does
    const DOT = '1.234567';
    fixed(DOT, await ref([step('0.1234567e1')], vaultOf(DOT)));
    const d = mkDraft();
    (d as unknown as { steps: unknown[] }).steps = [{ needId: 1.234567 }];
    fixed(DOT, await referee([file('FROM node:24\n')], d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], vault: vaultOf(DOT) }));
  });

  it('with no vault, numbers are judged as before; with a vault, ordinary safe integers are not a hit', async () => {
    const r = await ref([step('0xab54a98ceb1f0ad2')]);
    expect(r.issues.some((i) => i.check === 'secret-value')).toBe(false);
    const ok = await ref([file('{"version": "1.0.0", "lockfileVersion": 3}', { path: 'api/package-lock.json', part: 'tests', edited: { original: '{}' } })], vaultOf(D8));
    expect(ok.issues.some((i) => i.check === 'secret-value')).toBe(false);
  });
});
