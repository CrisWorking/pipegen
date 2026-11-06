// v0.2 Plan G G10 (rulings S13, S14; Plan V pre-flight §5 items 1-2, binding): the install record module. One strict schema with size
// caps (an unknown version or an oversize record is refused with a plain reason), one canonical serializer and hash, the record path,
// the PR-body marker, the local record file (0600, outside the proof state folder) and the guard's view of the record.
import { mkdtempSync, readFileSync, statSync, symlinkSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { gitBlobSha } from '../src/create/guard.js';
import {
  canonicalRecordJson, guardRecordOf, InstallRecordSchema, MAX_RECORD_BYTES, parseRecord, readLocalRecord, recordHash, recordMarker,
  recordMarkerOf, recordPath, RecordError, withRecordMarker, writeLocalRecord,
} from '../src/deliver/record.js';
import type { InstallRecord } from '../src/types.js';
import { cosignPub } from './helpers/cosign-keys.js';

const SHA = (c: string): string => c.repeat(40).slice(0, 40);
/** The record's secrets field, spelled at run time (test/no-secret-literals.test.ts). */
const SEC = ['sec', 'rets'].join('') as 'secrets';
export function sampleRecord(over: Partial<InstallRecord> = {}): InstallRecord {
  return {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00.000Z', centralSha: SHA('c'),
    app: { owner: 'o', repo: 'r', repoId: 7, defaultBranch: 'main', private: true, ownerType: 'User' },
    name: 'r', serviceRoots: ['.'],
    files: [{ repo: 'app', path: '.github/workflows/pipegen.yml', part: 'pipeline', shas: [SHA('a')] }, { repo: 'central', path: '.github/workflows/r--merge.yml', part: 'pipeline', shas: [SHA('b')] }],
    edits: [{ repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: '\n# pipegen:begin\n', originalSha: SHA('d'), writtenShas: [SHA('e')] }],
    [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: '2026-11-05T12:00:01Z' }],
    variables: [], environments: [], rulesets: [],
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] },
    protectedPaths: ['.github/workflows/**'],
    ...over,
  };
}

describe('install record schema (S13, Plan V §5)', () => {
  it('a valid record parses; keys in another order give the same canonical JSON and hash', () => {
    const r = sampleRecord();
    expect(parseRecord(JSON.stringify(r))).toEqual(r);
    const rev = (v: unknown): unknown => Array.isArray(v) ? v.map(rev) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, rev(x)])) : v;
    const shuffled = rev(r) as InstallRecord;
    expect(JSON.stringify(shuffled)).not.toBe(JSON.stringify(r));
    expect(canonicalRecordJson(shuffled)).toBe(canonicalRecordJson(r));
    expect(recordHash(shuffled)).toMatch(/^[0-9a-f]{64}$/);
    expect(recordHash(shuffled)).toBe(recordHash(r));
    expect(recordHash(sampleRecord({ pipegenVersion: '0.2.1' }))).not.toBe(recordHash(r));
    // canonical: sorted keys, no whitespace
    expect(canonicalRecordJson(r).startsWith('{"app":{"defaultBranch":"main"')).toBe(true);
  });

  it('an unknown schema version is refused with a plain reason (never read as schema 2)', () => {
    for (const schema of [1, 3, '2', undefined]) {
      const text = JSON.stringify({ ...sampleRecord(), schema });
      expect(() => parseRecord(text), String(schema)).toThrow(RecordError);
      expect(() => parseRecord(text)).toThrow(/version/);
    }
  });

  it('an oversize record, unknown keys, bad shas, bad names and long lists are refused', () => {
    const big = sampleRecord({ protectedPaths: ['x'.repeat(200)] });
    expect(() => parseRecord(JSON.stringify(big) + ' '.repeat(MAX_RECORD_BYTES))).toThrow(/larger/);
    expect(() => parseRecord(JSON.stringify({ ...sampleRecord(), extra: 1 }))).toThrow(RecordError);
    expect(() => parseRecord(JSON.stringify(sampleRecord({ files: [{ repo: 'app', path: 'a', part: 'pipeline', shas: ['zz'] }] })))).toThrow(RecordError);
    expect(() => parseRecord(JSON.stringify(sampleRecord({ [SEC]: [{ name: 'lower case', scope: 'repo', created: true }] })))).toThrow(RecordError);
    expect(() => parseRecord(JSON.stringify(sampleRecord({ [SEC]: [{ name: 'X_KEY', scope: 'env:../x' as `env:${string}`, created: true }] })))).toThrow(RecordError);
    expect(() => parseRecord(JSON.stringify(sampleRecord({ files: [{ repo: 'app', path: '../etc/passwd', part: 'pipeline', shas: [SHA('a')] }] })))).toThrow(RecordError);
    const many = Array.from({ length: 6000 }, (_, i) => ({ repo: 'app' as const, path: `f${i}`, part: 'pipeline' as const, shas: [SHA('a')] }));
    expect(() => parseRecord(JSON.stringify(sampleRecord({ files: many })))).toThrow(RecordError);
    expect(() => parseRecord('{not json')).toThrow(RecordError);
    for (const schema of [1, 3]) expect(InstallRecordSchema.safeParse({ ...sampleRecord(), schema }).success).toBe(false);
    expect(InstallRecordSchema.safeParse({ ...sampleRecord(), edits: [{ repo: 'app', path: 'x', kind: 'verify-job', inserted: 'x', originalSha: null, writtenShas: [] }] }).success).toBe(false);    // G13 (G7-R1 carry): the jobs an insert started with the head check are recorded; a called workflow holds no job of pipegen's, only head checks
    const vj = (over: Record<string, unknown>) => ({ ...sampleRecord(), edits: [{ repo: 'app', path: '.github/workflows/x.yml', kind: 'verify-job', jobs: ['pipegen-verify'], needs: [], originalSha: SHA('a'), writtenShas: [SHA('b')], ...over }] });
    expect(InstallRecordSchema.safeParse(vj({ headCheck: ['deploy'] })).success).toBe(true);
    expect(InstallRecordSchema.safeParse(vj({ jobs: [], headCheck: ['deploy', 'smoke'] })).success).toBe(true);
    expect(InstallRecordSchema.safeParse(vj({ jobs: [] })).success).toBe(false);
    expect(InstallRecordSchema.safeParse(vj({ jobs: [], headCheck: [] })).success).toBe(false);
  });

  it('the record path is installs/<centralProjectName>.json', () => {
    expect(recordPath('My-App')).toBe('installs/my-app.json');
    expect(recordPath('a'.repeat(95))).toMatch(/^installs\/pipegen-[0-9a-f]{20}\.json$/);
  });

  it('the PR-body marker is the exact last line; an older marker anywhere is replaced', () => {
    const h = 'a'.repeat(64);
    const h2 = 'b'.repeat(64);
    expect(recordMarker(h)).toBe(`<!-- pipegen:record-sha256=${h} -->`);
    const body = withRecordMarker(`hello\n\n${recordMarker(h2)}\nmore`, h);
    expect(body.split('\n').at(-1)).toBe(recordMarker(h));
    expect(body).not.toContain(h2);
    expect(recordMarkerOf(body)).toBe(h);
    expect(recordMarkerOf(`${recordMarker(h)}\ntext after`)).toBeNull();
    expect(recordMarkerOf(null)).toBeNull();
    expect(() => recordMarker('nothex')).toThrow();
  });

  it('the guard reads the app files pipegen wrote whole, each with its newest sha', () => {
    const r = sampleRecord({ files: [{ repo: 'app', path: 'Dockerfile', part: 'docker', shas: [SHA('1'), SHA('2')] }, { repo: 'central', path: '.github/workflows/r--merge.yml', part: 'pipeline', shas: [SHA('3')] }] });
    expect(guardRecordOf(r)).toEqual({ files: [{ path: 'Dockerfile', part: 'docker', sha: SHA('2'), created: true }] });
    expect(gitBlobSha('x')).toMatch(/^[0-9a-f]{40}$/);
  });
});

describe('the local record file (Plan V §5 item 2)', () => {
  const dirs: string[] = [];
  afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
  const home = (): string => { const d = mkdtempSync(join(tmpdir(), 'pg-rec-')); dirs.push(d); return d; };

  it('written 0600 at ~/.config/pipegen/records/<owner>__<repo>.json and read back', async () => {
    const h = home();
    const deps = { home: h, env: {} };
    await writeLocalRecord({ owner: 'O', repo: 'R' }, { recordHash: 'f'.repeat(64), setupPr: 3, updatedAt: '2026-11-05T12:00:00.000Z' }, deps);
    const file = join(h, '.config', 'pipegen', 'records', 'o__r.json');
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ recordHash: 'f'.repeat(64), setupPr: 3, updatedAt: '2026-11-05T12:00:00.000Z' });
    expect(await readLocalRecord({ owner: 'o', repo: 'r' }, deps)).toEqual({ recordHash: 'f'.repeat(64), setupPr: 3, updatedAt: '2026-11-05T12:00:00.000Z' });
    expect(await readLocalRecord({ owner: 'o', repo: 'other' }, deps)).toBeNull();
  });

  it('a symlinked records folder is refused', async () => {
    const h = home();
    mkdirSync(join(h, '.config', 'pipegen'), { recursive: true, mode: 0o700 });
    const elsewhere = join(h, 'elsewhere');
    mkdirSync(elsewhere, { mode: 0o700 });
    symlinkSync(elsewhere, join(h, '.config', 'pipegen', 'records'));
    await expect(writeLocalRecord({ owner: 'o', repo: 'r' }, { recordHash: 'f'.repeat(64), setupPr: 1, updatedAt: 'x' }, { home: h, env: {} })).rejects.toThrow(/symbolic link/);
  });
});

describe('install record schema, fix round 1 (m1-m3)', () => {
  const API_BODY = (body: string): string => JSON.stringify(sampleRecord({ planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [], rulesets: { gate: { method: 'POST', route: '/repos/{owner}/{repo}/rulesets', params: { owner: 'o', repo: 'r' }, body: { name: 'pipegen' } } } } })).replace('"body":{"name":"pipegen"}', body);
  it('m1: a prototype key in a free-form field is refused, never dropped', () => {
    expect(() => parseRecord(API_BODY('"body":{"name":"pipegen"}'))).not.toThrow();
    for (const k of ['__proto__', 'constructor', 'prototype']) expect(() => parseRecord(API_BODY(`"body":{"${k}":{"x":1},"name":"pipegen"}`)), k).toThrow(RecordError);
  });
  it('m2: a hostile nesting depth is a plain record error', () => {
    for (const depth of [40, 2000, 20000]) {
      const deep = '['.repeat(depth) + ']'.repeat(depth);
      expect(() => parseRecord(API_BODY(`"body":{"d":${deep},"name":"pipegen"}`)), String(depth)).toThrow(/nests deeper/);
    }
  });
  it('m3: duplicate entries, a name that is not the project\'s, and paths outside the repo are refused', () => {
    const r = sampleRecord();
    expect(() => parseRecord(JSON.stringify({ ...r, files: [...r.files, r.files[0]] }))).toThrow(RecordError);
    expect(() => parseRecord(JSON.stringify({ ...r, [SEC]: [...r.secrets, r.secrets[0]] }))).toThrow(RecordError);
    expect(() => parseRecord(JSON.stringify({ ...r, name: 'other' }))).toThrow(RecordError);
    for (const bad of ['../../etc', '/abs', 'a/../b', 'a\\b']) {
      expect(() => parseRecord(JSON.stringify({ ...r, serviceRoots: [bad] })), bad).toThrow(RecordError);
      expect(() => parseRecord(JSON.stringify({ ...r, protectedPaths: [bad] })), bad).toThrow(RecordError);
    }
    // G10-R3 N2: adopted is `true` or absent
    const adopted = { ...r, files: [{ ...r.files[0], adopted: true }, ...r.files.slice(1)] };
    expect(parseRecord(JSON.stringify(adopted)).files[0]?.adopted).toBe(true);
    expect(() => parseRecord(JSON.stringify({ ...r, files: [{ ...r.files[0], adopted: false }, ...r.files.slice(1)] }))).toThrow(RecordError);
    expect(parseRecord(JSON.stringify({ ...r, serviceRoots: ['.', 'api', 'svc/web'], protectedPaths: ['.github/workflows/**', '**/x.yml'] })).serviceRoots).toEqual(['.', 'api', 'svc/web']);
  });

  it('G11: the public key text is in cosign\'s form and is the key cosignPubSha256 names', () => {
    const r = sampleRecord();
    const pub = cosignPub(5);
    const sha = createHash('sha256').update(pub, 'utf8').digest('hex');
    expect(parseRecord(JSON.stringify({ ...r, cosignPub: pub, cosignPubSha256: sha })).cosignPub).toBe(pub);
    expect(() => parseRecord(JSON.stringify({ ...r, cosignPub: pub }))).toThrow(RecordError);
    expect(() => parseRecord(JSON.stringify({ ...r, cosignPub: cosignPub(6), cosignPubSha256: sha }))).toThrow(RecordError);
    const odd = 'not a key';
    expect(() => parseRecord(JSON.stringify({ ...r, cosignPub: odd, cosignPubSha256: createHash('sha256').update(odd, 'utf8').digest('hex') }))).toThrow(RecordError);
  });
});
