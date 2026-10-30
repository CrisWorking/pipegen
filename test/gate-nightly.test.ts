// Plan C Task C7: the gate action's nightly mode (gate/src/nightly.ts). It opens or updates ISSUES only: warn mode is ending, the setup PR
// merged but `finish` is missing, a pipegen update is available (with an exact patch). It never writes a file or a workflow. Its issue
// text mixes repo data and release data, so everything dynamic is escaped. Fake GitHub only: no network. Written first (strict test-first).
import { createHash, createHmac } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { BASELINE_ARTIFACT } from '../src/engine/artifact-names.js';
import { GATE_MODES, PIPEGEN_GATE_USES, RENDERER_INPUTS } from '../src/engine/tool-flags.js';
import { WORKFLOW_PATH, type RepoRef, type RunQuery } from '../gate/src/baseline.js';
import { keyId } from '../gate/src/fingerprint.js';
import { GATE_VERSION } from '../gate/src/generated/gate-view.js';
import { API_ROOT, githubAdapter, type AdapterOptions } from '../gate/src/github-adapter.js';
import { main, MODE_INPUTS, type MainDeps } from '../gate/src/main.js';
import {
  BOT_LOGIN, effectiveBlockFrom, finishMissing, ISSUE_PAGE_CAP, runNightly, updateAvailable, updatePatch, upsertIssue, warnEnding, type NightlyAdapter,
} from '../gate/src/nightly.js';
import { CRED, FPKEY, outputsOf, runner } from './helpers/gate-world.js';

const ROOT = resolve(import.meta.dirname, '..');
const NOW = new Date('2026-10-30T12:00:00Z');
const REPO: RepoRef = { owner: 'acme', name: 'app', id: 7, defaultBranch: 'main' };
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');
const SHA = (c: string): string => c.repeat(40);
const TIP = SHA('e');
const OLD = SHA('1');
const NEW = SHA('a');
const DAY = 86_400_000;
const ago = (days: number, hours = 0): string => new Date(NOW.getTime() - days * DAY - hours * 3_600_000).toISOString();
type Obj = Record<string, unknown>;

// ---------- the workflow file ----------

const pin = (sha: string, v: string): string => `crisworking/pipegen/gate@${sha} # gate-v${v}`;
const WF = (sha = OLD, v = GATE_VERSION): string => [
  'name: pipegen', 'on:', '  push:', '    branches: [main]', 'jobs:', '  gate:', '    runs-on: ubuntu-24.04', '    steps:',
  '      - name: gate', `        uses: ${pin(sha, v)}`, '        with:', '          mode: gate',
  '  nightly:', '    runs-on: ubuntu-24.04', '    steps:', '      - uses: actions/checkout@' + SHA('9') + ' # v6.0.0', `      - uses: ${pin(sha, v)}`, '        with:', '          mode: nightly', '',
].join('\n');

// ---------- a fake GitHub that records every call ----------

class FakeGh implements NightlyAdapter {
  calls: string[] = [];
  issues: Obj[] = [];                                  // newest first, as the API lists them
  nextNumber = 100;
  releases: unknown = [];
  tags = new Map<string, unknown>();                   // tag -> ref answer
  tagObjects = new Map<string, unknown>();             // sha -> annotated tag answer
  pulls: unknown = [];
  file: string | null = WF();
  fileAnswer: unknown;                                 // overrides the contents answer
  tip: unknown = { ref: 'refs/heads/main', object: { type: 'commit', sha: TIP } };
  failing = new Set<string>();                         // method names that throw
  baseline: unknown = null;                            // the loadBaseline artifacts (see baselineWorld)
  runsAnswer: unknown = [];
  runArtifacts = new Map<number, unknown>();
  blobs = new Map<number, Uint8Array>();
  listLimit = 100;
  private t(name: string): void { this.calls.push(name); if (this.failing.has(name)) throw new Error(`${name} failed`); }
  // ---- the GateGithub reads nightly uses ----
  async branchHead(): Promise<unknown> { this.t('branchHead'); return this.tip; }
  async fileAt(_o: string, _n: string, path: string, ref: string): Promise<unknown> {
    this.t('fileAt');
    expect(path).toBe(WORKFLOW_PATH);
    expect(ref).toBe(TIP);
    if (this.fileAnswer !== undefined) return this.fileAnswer;
    if (this.file === null) return null;
    return { type: 'file', encoding: 'base64', size: Buffer.byteLength(this.file), content: Buffer.from(this.file).toString('base64'), sha: SHA('0') };
  }
  async listRuns(_o: string, _n: string, q: RunQuery): Promise<unknown> { this.t('listRuns'); return { workflow_runs: Array.isArray(this.runsAnswer) ? this.runsAnswer.slice((q.page - 1) * q.perPage, q.page * q.perPage) : this.runsAnswer }; }
  async listRunArtifacts(_o: string, _n: string, runId: number): Promise<unknown> { this.t('listRunArtifacts'); return this.runArtifacts.get(runId) ?? { artifacts: [] }; }
  async downloadArtifact(_o: string, _n: string, id: number): Promise<Uint8Array> { this.t('downloadArtifact'); const b = this.blobs.get(id); if (b === undefined) throw new Error('404'); return b; }
  async compare(): Promise<unknown> { this.t('compare'); return { status: 'ahead' }; }
  async tagExists(): Promise<boolean> { this.t('tagExists'); return false; }
  // ---- nightly reads ----
  async listSetupPulls(): Promise<unknown> { this.t('listSetupPulls'); return this.pulls; }
  async listReleases(): Promise<unknown> { this.t('listReleases'); if (this.releases instanceof Error) throw this.releases; return this.releases; }
  async tagRef(_o: string, _n: string, tag: string): Promise<unknown> { this.t('tagRef'); const a = this.tags.get(tag); if (a === undefined || a instanceof Error) throw (a ?? new Error('404')); return a; }
  async gitTag(_o: string, _n: string, sha: string): Promise<unknown> { this.t('gitTag'); const a = this.tagObjects.get(sha); if (a === undefined || a instanceof Error) throw (a ?? new Error('404')); return a; }
  async listIssues(_o: string, _n: string, page: number, perPage: number): Promise<unknown> {
    this.t('listIssues');
    return this.issues.slice((page - 1) * perPage, page * perPage).slice(0, this.listLimit);
  }
  // ---- the only writes ----
  async createIssue(_o: string, _n: string, i: { title: string; body: string; labels?: readonly string[] }): Promise<unknown> {
    this.t('createIssue');
    const n = this.nextNumber++;
    this.issues.unshift({ number: n, state: 'open', title: i.title, body: i.body, labels: (i.labels ?? []).map((name) => ({ name })), user: { login: BOT_LOGIN, type: 'Bot' } });
    return { number: n };
  }
  async updateIssue(_o: string, _n: string, number: number, i: { title: string; body: string }): Promise<unknown> {
    this.t('updateIssue');
    const x = this.issues.find((y) => y.number === number);
    if (x === undefined) throw new Error('404');
    x.title = i.title; x.body = i.body;
    return { number };
  }
  // ---- everything else: not used by nightly (a call would be a bug) ----
  async downloadArtifactZip(): Promise<Uint8Array> { throw new Error('unused'); }
  async getPull(): Promise<unknown> { throw new Error('unused'); }
  async listPullFiles(): Promise<unknown> { throw new Error('unused'); }
  async listPullReviews(): Promise<unknown> { throw new Error('unused'); }
  async compareFiles(): Promise<unknown> { throw new Error('unused'); }
  async collaboratorPermission(): Promise<unknown> { throw new Error('unused'); }
  async rawFileAt(): Promise<unknown> { throw new Error('unused'); }
  async listAttemptJobs(): Promise<unknown> { throw new Error('unused'); }
  async getCommit(): Promise<unknown> { throw new Error('unused'); }
}
const writesOf = (gh: FakeGh): string[] => gh.calls.filter((c) => c === 'createIssue' || c === 'updateIssue');

const rel = (tag: string, daysAgo: number, over: Obj = {}): Obj => ({ tag_name: tag, published_at: ago(daysAgo), draft: false, prerelease: false, body: '', ...over });
/** A gate release gate-v0.3.0 (10 days old) whose tag is a plain commit NEW. */
function withUpdate(gh = new FakeGh(), version = '0.3.0', sha = NEW, days = 10): FakeGh {
  gh.releases = [rel(`gate-v${version}`, days), rel('v0.1.0', 40)];
  gh.tags.set(`gate-v${version}`, { ref: `refs/tags/gate-v${version}`, object: { type: 'commit', sha } });
  return gh;
}
const ctx = (over: Obj = {}): Parameters<typeof runNightly>[1] => ({ repo: REPO, now: NOW, ...over }) as Parameters<typeof runNightly>[1];
const bodyOf = (gh: FakeGh, i = 0): string => String(gh.issues[i]?.body);
const titleOf = (gh: FakeGh, i = 0): string => String(gh.issues[i]?.title);
const keyOfIssue = (gh: FakeGh, i = 0): string => /^<!-- pipegen:key=([^ ]+) -->/.exec(bodyOf(gh, i))?.[1] ?? '';

// ======================================================================================================
// the pure rules
// ======================================================================================================

describe('warnEnding', () => {
  it('2 days before block-from with old findings → open', () => {
    expect(warnEnding('2026-11-01', NOW, 3)).toEqual({ open: true, daysLeft: 2, unknown: false });
    expect(warnEnding('2026-10-31', NOW, 1)).toEqual({ open: true, daysLeft: 1, unknown: false });
  });
  it('no old findings → null', () => { expect(warnEnding('2026-11-01', NOW, 0)).toBeNull(); });
  it('more than 2 days left → not open; the day itself or past → null (block mode starts at 00:00 UTC of block-from); no or invalid date → null', () => {
    expect(warnEnding('2026-11-02', NOW, 3)).toEqual({ open: false, daysLeft: 3, unknown: false });
    expect(warnEnding('2026-10-30', NOW, 3)).toBeNull();
    expect(warnEnding('2026-10-01', NOW, 3)).toBeNull();
    for (const bad of [undefined, '', 'soon', '2026-02-30', '2026-11-1']) expect(warnEnding(bad, NOW, 3), String(bad)).toBeNull();
    expect(warnEnding('2026-11-01', new Date('nope'), 3)).toBeNull();
  });
  it('old findings unknown (no trusted baseline) → the softer issue is still open, flagged unknown; never "none"', () => {
    expect(warnEnding('2026-11-01', NOW, 'unknown')).toEqual({ open: true, daysLeft: 2, unknown: true });
    expect(warnEnding('2026-11-05', NOW, 'unknown')).toEqual({ open: false, daysLeft: 6, unknown: true });
  });
  it('the day count is by UTC day, not by hours', () => {
    expect(warnEnding('2026-11-01', new Date('2026-10-30T23:59:59Z'), 1)?.daysLeft).toBe(2);
    expect(warnEnding('2026-11-01', new Date('2026-10-31T00:00:00Z'), 1)?.daysLeft).toBe(1);
  });
  it('effectiveBlockFrom is the earlier of the two valid dates (S13), and ignores an invalid one', () => {
    expect(effectiveBlockFrom('2026-11-09', '2026-11-01')).toBe('2026-11-01');
    expect(effectiveBlockFrom('2026-11-01', '2026-11-09')).toBe('2026-11-01');
    expect(effectiveBlockFrom('soon', '2026-11-09')).toBe('2026-11-09');
    expect(effectiveBlockFrom(undefined, undefined)).toBeUndefined();
    expect(effectiveBlockFrom('2026-02-30', 'x')).toBeUndefined();
  });
});

describe('finishMissing', () => {
  it('merged 30 h ago and no variable → true', () => { expect(finishMissing(undefined, ago(1, 6), NOW)).toBe(true); });
  it('merged less than 24 h ago, exactly 24 h ago (not yet more), or in the future → false', () => {
    expect(finishMissing(undefined, ago(0, 23), NOW)).toBe(false);
    expect(finishMissing(undefined, ago(1), NOW)).toBe(false);
    expect(finishMissing(undefined, new Date(NOW.getTime() + 3_600_000).toISOString(), NOW)).toBe(false);
  });
  it('a valid PIPEGEN_BLOCK_FROM means finish ran → false; an empty or garbage value counts as unset (a writer can not silence the issue with junk)', () => {
    expect(finishMissing('2026-11-06', ago(3), NOW)).toBe(false);
    for (const junk of [undefined, '', 'x', '2026-13-01', 'tomorrow']) expect(finishMissing(junk, ago(3), NOW), String(junk)).toBe(true);
  });
  it('no merge time, or one that is not a date → false (opened only when a merge is proven)', () => {
    for (const bad of [undefined, '', 'yesterday', '2026-10-28', '2026-10-28T10:00:00']) expect(finishMissing(undefined, bad, NOW), String(bad)).toBe(false);
    expect(finishMissing(undefined, 'x'.repeat(5000), NOW)).toBe(false);
  });
  it('an invalid clock → false', () => { expect(finishMissing(undefined, ago(3), new Date('nope'))).toBe(false); });
});

describe('updateAvailable', () => {
  const l = (version: string, published: string): { version: string; publishedAt: string } => ({ version, publishedAt: published });
  it('newer release older than 7 days → true', () => { expect(updateAvailable('0.2.0', l('0.3.0', ago(8)), NOW)).toBe(true); });
  it('newer release inside the 7-day cooldown → false; exactly 7 days → true', () => {
    expect(updateAvailable('0.2.0', l('0.3.0', ago(6, 23)), NOW)).toBe(false);
    expect(updateAvailable('0.2.0', l('0.3.0', ago(7)), NOW)).toBe(true);
    expect(updateAvailable('0.2.0', l('0.3.0', ago(7, -1)), NOW)).toBe(false);
  });
  it('same or older version, no release, a bad version or date → false; a release dated in the future → false', () => {
    expect(updateAvailable('0.2.0', l('0.2.0', ago(30)), NOW)).toBe(false);
    expect(updateAvailable('0.2.1', l('0.2.0', ago(30)), NOW)).toBe(false);
    expect(updateAvailable('0.2.0', null, NOW)).toBe(false);
    for (const v of ['0.3', 'v0.3.0', '0.3.0-rc1', '0.3.0 ', '', '1e3.0.0', '99999999999.0.0']) expect(updateAvailable('0.2.0', l(v, ago(30)), NOW), v).toBe(false);
    for (const p of ['', 'x', ago(30).slice(0, 10), '2099-01-01T00:00:00Z']) expect(updateAvailable('0.2.0', l('0.3.0', p), NOW), p).toBe(false);
    expect(updateAvailable('nope', l('0.3.0', ago(30)), NOW)).toBe(false);
  });
  it('versions compare as numbers, not text (0.10.0 is newer than 0.9.0)', () => {
    expect(updateAvailable('0.9.0', l('0.10.0', ago(30)), NOW)).toBe(true);
    expect(updateAvailable('0.10.0', l('0.9.0', ago(30)), NOW)).toBe(false);
  });
});

// ---------- updatePatch ----------

/** git apply, in a folder that is not a repository (the patch is a plain unified diff). */
function gitApply(files: { path: string; text: string }[], patch: string): { ok: boolean; out: Record<string, string>; err: string } {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-c7-patch-'));
  for (const f of files) { spawnSync('mkdir', ['-p', join(dir, f.path, '..')]); writeFileSync(join(dir, f.path), f.text); }
  writeFileSync(join(dir, 'p.diff'), patch);
  const r = spawnSync('git', ['apply', '--whitespace=nowarn', 'p.diff'], { cwd: dir, encoding: 'utf8' });
  return { ok: r.status === 0, err: r.stderr, out: Object.fromEntries(files.map((f) => [f.path, readFileSync(join(dir, f.path), 'utf8')])) };
}
const swapped = (text: string, from: { sha: string; version: string }, to: { sha: string; version: string }): string => text.split(pin(from.sha, from.version)).join(pin(to.sha, to.version));
const FROM = { sha: OLD, version: GATE_VERSION };
const TO = { sha: NEW, version: '0.3.0' };

describe('updatePatch', () => {
  const PATH = WORKFLOW_PATH;
  it('swaps only the pinned pipegen SHA and version comment: applying the patch equals the text with exactly those lines changed', () => {
    const text = WF();
    const patch = updatePatch([{ path: PATH, text }], FROM, TO);
    expect(patch).toContain(`--- a/${PATH}`);
    expect(patch).toContain(`+++ b/${PATH}`);
    const r = gitApply([{ path: PATH, text }], patch);
    expect(r.err).toBe('');
    expect(r.ok).toBe(true);
    expect(r.out[PATH]).toBe(swapped(text, FROM, TO));
    // two lines changed, nothing else: a line diff of the result against the input
    const a = text.split('\n'); const b = (r.out[PATH] as string).split('\n');
    expect(b.length).toBe(a.length);
    expect(a.map((x, i) => (x === b[i] ? null : i)).filter((x) => x !== null).length).toBe(2);
  });
  it('round trip: patch then the same diff run backwards restores the input byte for byte (git apply -R)', () => {
    const text = WF();
    const patch = updatePatch([{ path: PATH, text }], FROM, TO);
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-c7-rt-'));
    spawnSync('mkdir', ['-p', join(dir, '.github/workflows')]);
    writeFileSync(join(dir, PATH), swapped(text, FROM, TO));
    writeFileSync(join(dir, 'p.diff'), patch);
    expect(spawnSync('git', ['apply', '-R', '--whitespace=nowarn', 'p.diff'], { cwd: dir }).status).toBe(0);
    expect(readFileSync(join(dir, PATH), 'utf8')).toBe(text);
  });
  it('every other byte stays: CRLF line ends, a missing final newline, tabs, a BOM-less file with other similar lines', () => {
    const lines = WF().split('\n');
    const variants = [
      lines.join('\r\n'),                              // CRLF
      lines.join('\n').replace(/\n$/, ''),             // no final newline
      lines.join('\n').replace(/\n$/, '') + '\r',     // a lone CR at the very end
    ];
    for (const text of variants) {
      const patch = updatePatch([{ path: PATH, text }], FROM, TO);
      const r = gitApply([{ path: PATH, text }], patch);
      expect(r.ok, r.err).toBe(true);
      expect(r.out[PATH]).toBe(swapped(text, FROM, TO));
    }
  });
  it('a pin on the last line without a final newline is patched too', () => {
    const text = `jobs:\n  a:\n    steps:\n      - uses: ${pin(OLD, GATE_VERSION)}`;
    const r = gitApply([{ path: PATH, text }], updatePatch([{ path: PATH, text }], FROM, TO));
    expect(r.ok, r.err).toBe(true);
    expect(r.out[PATH]).toBe(swapped(text, FROM, TO));
  });
  it('swaps only the exact pin line: another action, another sha, another version comment, other spacing, a quoted or commented line stay as they are', () => {
    const keep = [
      `      - uses: crisworking/pipegen/gate@${SHA('2')} # gate-v${GATE_VERSION}`,       // another sha
      `      - uses: crisworking/pipegen/gate@${OLD} # gate-v0.1.0`,                       // another version
      `      - uses: crisworking/pipegen/gate@${OLD}  # gate-v${GATE_VERSION}`,            // other spacing: not the rendered form
      `      - uses: crisworking/pipegen/gate@${OLD}`,                                     // no comment
      `      # uses: ${pin(OLD, GATE_VERSION)}`,                                          // a comment line
      `      - uses: other/pipegen/gate@${OLD} # gate-v${GATE_VERSION}`,                  // another repository
      `      - uses: crisworking/pipegen/gate-x@${OLD} # gate-v${GATE_VERSION}`,
      `      - uses: crisworking/pipegen/gate@${OLD} # gate-v${GATE_VERSION}0`,
      `      - run: echo ${pin(OLD, GATE_VERSION)}`,                                      // a shell line
      `      - uses: "${pin(OLD, GATE_VERSION)}"`,
    ];
    const text = ['a:', ...keep, `      - uses: ${pin(OLD, GATE_VERSION)}`, ''].join('\n');
    const patch = updatePatch([{ path: PATH, text }], FROM, TO);
    const r = gitApply([{ path: PATH, text }], patch);
    expect(r.ok, r.err).toBe(true);
    const out = (r.out[PATH] as string).split('\n');
    expect(out.slice(1, 1 + keep.length)).toEqual(keep);
    expect(out[1 + keep.length]).toBe(`      - uses: ${pin(NEW, '0.3.0')}`);
  });
  it('keeps a trailing space and a `- ` list marker of the swapped line', () => {
    const text = `x:\n  - uses: ${pin(OLD, GATE_VERSION)}  \n`;
    const r = gitApply([{ path: PATH, text }], updatePatch([{ path: PATH, text }], FROM, TO));
    expect(r.ok, r.err).toBe(true);
    expect(r.out[PATH]).toBe(`x:\n  - uses: ${pin(NEW, '0.3.0')}  \n`);
  });
  it('pin lines close together share one hunk: the patch has no overlapping hunks and applies', () => {
    const text = ['a:', `  - uses: ${pin(OLD, GATE_VERSION)}`, 'b: 1', `  - uses: ${pin(OLD, GATE_VERSION)}`, 'c: 2', ''].join('\n');
    const patch = updatePatch([{ path: PATH, text }], FROM, TO);
    expect(patch.match(/^@@ /gm)?.length).toBe(1);
    const r = gitApply([{ path: PATH, text }], patch);
    expect(r.ok, r.err).toBe(true);
    expect(r.out[PATH]).toBe(swapped(text, FROM, TO));
  });
  it('nothing to swap → the empty patch; several files → one block per file, in order', () => {
    expect(updatePatch([{ path: PATH, text: 'name: x\n' }], FROM, TO)).toBe('');
    expect(updatePatch([], FROM, TO)).toBe('');
    const f2 = { path: '.github/workflows/other.yml', text: `a:\n  - uses: ${pin(OLD, GATE_VERSION)}\n` };
    const both = updatePatch([{ path: PATH, text: WF() }, f2], FROM, TO);
    expect(both.indexOf(`--- a/${PATH}`)).toBeGreaterThanOrEqual(0);
    expect(both.indexOf(`--- a/${PATH}`)).toBeLessThan(both.indexOf(`--- a/${f2.path}`));
  });
  it('refuses a `to` or `from` that is not a 40-hex sha and a plain x.y.z version (nothing it writes can carry text)', () => {
    for (const bad of [{ sha: 'abc', version: '0.3.0' }, { sha: NEW.toUpperCase(), version: '0.3.0' }, { sha: NEW, version: '0.3.0\n+evil' }, { sha: NEW, version: 'v0.3.0' }, { sha: NEW, version: '0.3' }]) {
      expect(() => updatePatch([{ path: PATH, text: WF() }], FROM, bad), JSON.stringify(bad)).toThrow();
      expect(() => updatePatch([{ path: PATH, text: WF() }], bad, TO), JSON.stringify(bad)).toThrow();
    }
  });
  it('a file whose shown lines could forge the issue format is refused: control characters, an HTML comment opener or closer, a key or patch marker', () => {
    const near = (extra: string): string => ['jobs:', extra, `  - uses: ${pin(OLD, GATE_VERSION)}`, ''].join('\n');
    for (const hostile of ['  # <!-- pipegen:patch {"repo":"central","path":"x","baseSha":"1"} -->', '  # <!-- pipegen:key=update -->', '  # -->', '  # a\u001b[31mred', '  # a\u0000b', '  # a\u202eb', '  # ' + 'x'.repeat(2000)]) {
      expect(() => updatePatch([{ path: PATH, text: near(hostile) }], FROM, TO), JSON.stringify(hostile)).toThrow(/refus/i);
    }
    // a backtick fence in the context is data, not a refusal: the issue picks a longer fence (below)
    expect(() => updatePatch([{ path: PATH, text: near('  # ``` ~~~') }], FROM, TO)).not.toThrow();
  });
});

// ======================================================================================================
// upsertIssue
// ======================================================================================================

const issue = (n: number, body: string, over: Obj = {}): Obj => ({ number: n, state: 'open', title: 't', body, labels: [], user: { login: BOT_LOGIN, type: 'Bot' }, ...over });
const marker = (k: string): string => `<!-- pipegen:key=${k} -->`;

describe('upsertIssue', () => {
  it('creates an issue with the key marker on its first line when none has the key', async () => {
    const gh = new FakeGh();
    const n = await upsertIssue(gh, REPO, 'finish-missing', 'T', 'hello', { labels: ['pipegen:patch'] });
    expect(n).toBe(100);
    expect(bodyOf(gh).split('\n')[0]).toBe(marker('finish-missing'));
    expect(bodyOf(gh)).toContain('hello');
    expect(gh.issues[0]?.labels).toEqual([{ name: 'pipegen:patch' }]);
  });
  it('the same key updates the same issue, never duplicates', async () => {
    const gh = new FakeGh();
    const a = await upsertIssue(gh, REPO, 'k1', 'T', 'one');
    const b = await upsertIssue(gh, REPO, 'k1', 'T2', 'two');
    expect(b).toBe(a);
    expect(gh.issues.length).toBe(1);
    expect(bodyOf(gh)).toContain('two');
    expect(titleOf(gh)).toBe('T2');
    // an identical text makes no write at all
    const before = writesOf(gh).length;
    await upsertIssue(gh, REPO, 'k1', 'T2', 'two');
    expect(writesOf(gh).length).toBe(before);
  });
  it('another key is another issue; a key that is a prefix of another does not match it', async () => {
    const gh = new FakeGh();
    await upsertIssue(gh, REPO, 'update', 'T', 'a');
    await upsertIssue(gh, REPO, 'update-0.3.0', 'T', 'b');
    expect(gh.issues.length).toBe(2);
  });
  it('an issue opened by a person with the key marker is never edited, and does not stop ours from being created', async () => {
    const gh = new FakeGh();
    gh.issues = [issue(5, `${marker('k1')}\nmine`, { user: { login: 'mallory', type: 'User' } })];
    const n = await upsertIssue(gh, REPO, 'k1', 'T', 'ours');
    expect(n).not.toBe(5);
    expect(gh.issues.find((i) => i.number === 5)?.body).toBe(`${marker('k1')}\nmine`);
    expect(writesOf(gh)).toEqual(['createIssue']);
  });
  it('only github-actions[bot] of type Bot counts: another bot, a user called like it, a missing user, a lookalike login are all ignored', async () => {
    for (const user of [{ login: 'dependabot[bot]', type: 'Bot' }, { login: BOT_LOGIN, type: 'User' }, { login: 'github-actions', type: 'Bot' }, { login: `${BOT_LOGIN}x`, type: 'Bot' }, { login: BOT_LOGIN.toUpperCase(), type: 'Bot' }, null, undefined, 'github-actions[bot]']) {
      const gh = new FakeGh();
      gh.issues = [issue(5, `${marker('k1')}\nx`, { user })];
      const n = await upsertIssue(gh, REPO, 'k1', 'T', 'ours');
      expect(n, JSON.stringify(user)).not.toBe(5);
      expect(gh.issues.find((i) => i.number === 5)?.body, JSON.stringify(user)).toBe(`${marker('k1')}\nx`);
    }
  });
  it('the marker must be the first line of the body: a marker in the middle (a quote, a comment of a person pasted into the bot issue) is not a key', async () => {
    const gh = new FakeGh();
    gh.issues = [issue(5, `hello\n${marker('k1')}\nx`), issue(6, ` ${marker('k1')}`), issue(7, `${marker('k1')} trailing`)];
    const n = await upsertIssue(gh, REPO, 'k1', 'T', 'ours');
    expect(n).toBe(100);
  });
  it('pull requests in the issue list (they carry pull_request) are skipped', async () => {
    const gh = new FakeGh();
    gh.issues = [issue(5, `${marker('k1')}\nx`, { pull_request: { url: 'u' } })];
    expect(await upsertIssue(gh, REPO, 'k1', 'T', 'ours')).toBe(100);
  });
  it('a closed issue of ours is left alone (a person closed it): no edit, no reopening, no duplicate', async () => {
    const gh = new FakeGh();
    gh.issues = [issue(5, `${marker('k1')}\nold`, { state: 'closed' })];
    expect(await upsertIssue(gh, REPO, 'k1', 'T', 'new')).toBe(5);
    expect(writesOf(gh)).toEqual([]);
  });
  it('finds the issue on a later page, within the cap', async () => {
    const gh = new FakeGh();
    gh.issues = [...Array.from({ length: 250 }, (_, i) => issue(1000 + i, 'noise')), issue(5, `${marker('k1')}\nold`)];
    expect(await upsertIssue(gh, REPO, 'k1', 'T', 'new')).toBe(5);
    expect(gh.calls.filter((c) => c === 'listIssues').length).toBe(3);
    expect(bodyOf({ issues: [gh.issues.find((i) => i.number === 5) as Obj] } as unknown as FakeGh)).toContain('new');
  });
  it('hitting the page cap fails closed: it throws and creates nothing (no blind duplicate)', async () => {
    const gh = new FakeGh();
    gh.issues = Array.from({ length: ISSUE_PAGE_CAP * 100 + 50 }, (_, i) => issue(1000 + i, 'noise'));
    await expect(upsertIssue(gh, REPO, 'k1', 'T', 'x')).rejects.toThrow(/cap|too many/i);
    expect(writesOf(gh)).toEqual([]);
    expect(gh.calls.filter((c) => c === 'listIssues').length).toBe(ISSUE_PAGE_CAP);
  });
  it('a list that ends exactly at the cap with a full last page also fails closed (more may follow)', async () => {
    const gh = new FakeGh();
    gh.issues = Array.from({ length: ISSUE_PAGE_CAP * 100 }, (_, i) => issue(1000 + i, 'noise'));
    await expect(upsertIssue(gh, REPO, 'k1', 'T', 'x')).rejects.toThrow();
    expect(writesOf(gh)).toEqual([]);
  });
  it('an API error or a malformed list fails closed: no write', async () => {
    const gh = new FakeGh(); gh.failing.add('listIssues');
    await expect(upsertIssue(gh, REPO, 'k1', 'T', 'x')).rejects.toThrow();
    for (const bad of [{ not: 'a list' }, null, 'x', [null], [{ number: 'x' }]]) {
      const g = new FakeGh();
      g.listIssues = async () => bad;
      await expect(upsertIssue(g, REPO, 'k1', 'T', 'x'), JSON.stringify(bad)).rejects.toThrow();
      expect(writesOf(g)).toEqual([]);
    }
  });
  it('a key that is not plain (text in a marker) is refused before any call', async () => {
    const gh = new FakeGh();
    for (const k of ['', 'a b', 'a-->b', '<!--', 'A', 'k\n', 'x'.repeat(100)]) await expect(upsertIssue(gh, REPO, k, 'T', 'b'), k).rejects.toThrow();
    expect(gh.calls).toEqual([]);
  });
  it('if the title or body would be over GitHub\'s limit it is refused', async () => {
    const gh = new FakeGh();
    await expect(upsertIssue(gh, REPO, 'k1', 'T', 'x'.repeat(70_000))).rejects.toThrow();
    await expect(upsertIssue(gh, REPO, 'k1', 'x'.repeat(300), 'b')).rejects.toThrow();
    expect(writesOf(gh)).toEqual([]);
  });
  it('two bot issues with the key: the newest open one is edited', async () => {
    const gh = new FakeGh();
    gh.issues = [issue(9, `${marker('k1')}\nb`), issue(5, `${marker('k1')}\na`)];
    expect(await upsertIssue(gh, REPO, 'k1', 'T', 'new')).toBe(9);
  });
});

// ======================================================================================================
// the three issues
// ======================================================================================================

describe('update available', () => {
  it('opens the update issue with the exact patch and the pipegen update command, in the shared patch-issue format', async () => {
    const gh = withUpdate();
    const r = await runNightly(gh, ctx());
    expect(r.errors).toEqual([]);
    expect(gh.issues.length).toBe(1);
    const body = bodyOf(gh);
    expect(keyOfIssue(gh)).toBe('update-0.3.0');
    expect(body.split('\n')[0]).toBe('<!-- pipegen:key=update-0.3.0 -->');
    expect(body).toContain('npx pipegen@0.3.0 update');
    expect(body.match(/^`{3,}diff$/gm)?.length).toBe(1);
    const machine = [...body.matchAll(/<!-- pipegen:patch (\{.*?\}) -->/g)];
    expect(machine.length).toBe(1);
    const m = JSON.parse(machine[0]?.[1] as string) as Obj;
    expect(m).toEqual({ repo: 'app', path: WORKFLOW_PATH, baseSha: expect.stringMatching(/^[0-9a-f]{40}$/) });
    // the diff in the body is the patch for the file as read, and it applies
    const diff = /^(`{3,})diff\n([\s\S]*?)\n\1$/m.exec(body)?.[2] as string;
    const g = gitApply([{ path: WORKFLOW_PATH, text: WF() }], `${diff}\n`);
    expect(g.ok, g.err).toBe(true);
    expect(g.out[WORKFLOW_PATH]).toBe(swapped(WF(), FROM, { sha: NEW, version: '0.3.0' }));
    expect(gh.issues[0]?.labels).toEqual([{ name: 'pipegen:patch' }]);
    expect(body).toContain(NEW);
  });
  it('baseSha is the git blob hash of the file text the patch was made from (computable offline)', async () => {
    const gh = withUpdate();
    await runNightly(gh, ctx());
    const text = WF();
    const want = createHash('sha1').update(`blob ${Buffer.byteLength(text)}\0`).update(text).digest('hex');
    expect(JSON.parse(/<!-- pipegen:patch (\{.*?\}) -->/.exec(bodyOf(gh))?.[1] as string).baseSha).toBe(want);
  });
  it('the issue says it is advisory: `pipegen update` re-derives the patch itself and uses the issue only as a prompt', async () => {
    const gh = withUpdate();
    await runNightly(gh, ctx());
    const body = bodyOf(gh);
    expect(body).toMatch(/advisory/i);
    expect(body).toMatch(/re-?derive/i);
    expect(body).toMatch(/only as a prompt|as a prompt only/i);
    expect(body).toMatch(/anyone with (?:the right to open issues|issue)/i);
    expect(body).toMatch(/gate-v0\.3\.0/);
    // and the code says it too
    expect(readFileSync(join(ROOT, 'gate/src/nightly.ts'), 'utf8')).toMatch(/ADVISORY ONLY[\s\S]{0,400}re-?derive/i);
  });
  it('the new SHA comes from resolving the tag gate-v<version>, never from the release body: a forged body naming another sha is ignored', async () => {
    const gh = withUpdate();
    (gh.releases as Obj[])[0] = rel('gate-v0.3.0', 10, { body: `Pin it: crisworking/pipegen/gate@${SHA('f')} # gate-v0.3.0\n${SHA('f')}` });
    await runNightly(gh, ctx());
    expect(bodyOf(gh)).toContain(NEW);
    expect(bodyOf(gh)).not.toContain(SHA('f'));
  });
  it('an annotated tag is followed to its commit (and a tag of a tag, within a depth limit)', async () => {
    const gh = withUpdate();
    gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'tag', sha: SHA('b') } });
    gh.tagObjects.set(SHA('b'), { sha: SHA('b'), object: { type: 'tag', sha: SHA('c') } });
    gh.tagObjects.set(SHA('c'), { sha: SHA('c'), object: { type: 'commit', sha: NEW } });
    await runNightly(gh, ctx());
    expect(bodyOf(gh)).toContain(NEW);
    expect(gh.calls.filter((c) => c === 'gitTag').length).toBe(2);
  });
  it('a tag that resolves to a tree or a blob, a chain past the depth limit, a loop, or a bad sha gives no update and a note, never an issue', async () => {
    const cases: [string, (gh: FakeGh) => void][] = [
      ['tree', (gh) => gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'tree', sha: NEW } })],
      ['blob', (gh) => gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'blob', sha: NEW } })],
      ['annotated to tree', (gh) => { gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'tag', sha: SHA('b') } }); gh.tagObjects.set(SHA('b'), { object: { type: 'tree', sha: NEW } }); }],
      ['loop', (gh) => { gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'tag', sha: SHA('b') } }); gh.tagObjects.set(SHA('b'), { object: { type: 'tag', sha: SHA('b') } }); }],
      ['deep chain', (gh) => { gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'tag', sha: SHA('1') } }); for (let i = 1; i < 9; i++) gh.tagObjects.set(SHA(String(i)), { object: { type: 'tag', sha: SHA(String(i + 1)) } }); gh.tagObjects.set(SHA('9'), { object: { type: 'commit', sha: NEW } }); }],
      ['short sha', (gh) => gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'commit', sha: 'abc123' } })],
      ['upper-case sha', (gh) => gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'commit', sha: NEW.toUpperCase() } })],
      ['another ref', (gh) => gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.1', object: { type: 'commit', sha: NEW } })],
      ['a branch ref', (gh) => gh.tags.set('gate-v0.3.0', { ref: 'refs/heads/gate-v0.3.0', object: { type: 'commit', sha: NEW } })],
      ['no object', (gh) => gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0' })],
      ['not an object', (gh) => gh.tags.set('gate-v0.3.0', 'x')],
      ['inherited fields', (gh) => gh.tags.set('gate-v0.3.0', Object.create({ ref: 'refs/tags/gate-v0.3.0', object: { type: 'commit', sha: NEW } }))],
      ['api error', (gh) => gh.tags.set('gate-v0.3.0', new Error('boom'))],
      ['no such tag', (gh) => gh.tags.delete('gate-v0.3.0')],
    ];
    for (const [name, set] of cases) {
      const gh = withUpdate();
      set(gh);
      const r = await runNightly(gh, ctx());
      expect(gh.issues, name).toEqual([]);
      expect(r.notes.join(' '), name).toMatch(/gate-v0\.3\.0|update/i);
      expect(r.errors, name).toEqual([]);
    }
  });
  it('a tag object whose type is not commit or tag is refused even if the object it names answers like a tag; an annotated tag object that is not the one asked for is refused', async () => {
    const odd = withUpdate();
    odd.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'tree', sha: SHA('b') } });
    odd.tagObjects.set(SHA('b'), { sha: SHA('b'), object: { type: 'commit', sha: NEW } });
    await runNightly(odd, ctx());
    expect(odd.issues).toEqual([]);
    const swapped2 = withUpdate();
    swapped2.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'tag', sha: SHA('b') } });
    swapped2.tagObjects.set(SHA('b'), { sha: SHA('c'), object: { type: 'commit', sha: NEW } });
    await runNightly(swapped2, ctx());
    expect(swapped2.issues).toEqual([]);
  });
  it('a release inside the 7-day cooldown gives no update and no issue', async () => {
    const gh = withUpdate(new FakeGh(), '0.3.0', NEW, 6);
    const r = await runNightly(gh, ctx());
    expect(gh.issues).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(gh.calls).not.toContain('tagRef');
  });
  it('the highest eligible gate release wins; one in its cooldown is skipped in favour of an older eligible one; CLI v* tags, drafts, prereleases and odd tags are ignored', async () => {
    const gh = new FakeGh();
    gh.releases = [
      rel('gate-v0.5.0', 2), rel('gate-v0.4.0', 20), rel('gate-v0.3.0', 30), rel('v9.9.9', 50), rel('gate-v1.0.0', 50, { draft: true }),
      rel('gate-v1.1.0', 50, { prerelease: true }), rel('gate-v2.0.0-rc1', 50), rel('gate-v02.0.0', 50), rel('gate-v1.0', 50), rel('xgate-v3.0.0', 50), rel('gate-v0.1.0', 90),
    ];
    for (const v of ['0.5.0', '0.4.0', '0.3.0']) gh.tags.set(`gate-v${v}`, { ref: `refs/tags/gate-v${v}`, object: { type: 'commit', sha: v === '0.4.0' ? NEW : SHA('d') } });
    await runNightly(gh, ctx());
    expect(keyOfIssue(gh)).toBe('update-0.4.0');
    expect(bodyOf(gh)).toContain(NEW);
    expect(gh.calls.filter((c) => c === 'tagRef').length).toBe(1);
  });
  it('a 404 on the private pipegen repository (or any API error) gives no update with a note; it is not an error and not a fake update', async () => {
    for (const err of [Object.assign(new Error('GET /repos/crisworking/pipegen/releases: GitHub answered 404'), { status: 404 }), new Error('boom')]) {
      const gh = new FakeGh();
      gh.releases = err;
      const r = await runNightly(gh, ctx());
      expect(gh.issues).toEqual([]);
      expect(r.errors).toEqual([]);
      expect(r.notes.join(' ')).toMatch(/update/i);
    }
  });
  it('malformed release lists give no update (a note): not a list, entries that are not objects, a published_at that is not a date, inherited fields', async () => {
    for (const bad of [{ not: 'a list' }, 'x', null, [null, 5, 'x'], [rel('gate-v0.3.0', 10, { published_at: 'x' })], [rel('gate-v0.3.0', 10, { published_at: null })], [Object.create(rel('gate-v0.3.0', 10))]]) {
      const gh = withUpdate();
      gh.releases = bad;
      const r = await runNightly(gh, ctx());
      expect(gh.issues, JSON.stringify(bad)).toEqual([]);
      expect(r.errors).toEqual([]);
    }
  });
  it('no update when the newest release is not newer than the built-in version', async () => {
    const gh = withUpdate(new FakeGh(), GATE_VERSION);
    await runNightly(gh, ctx());
    expect(gh.issues).toEqual([]);
  });
  it('no pin line in the file (a private repository: the pin is in the central repository): the issue names the version and the command, with no patch, no diff block, no label', async () => {
    for (const set of [(gh: FakeGh) => { gh.file = null; }, (gh: FakeGh) => { gh.file = 'name: x\n'; }, (gh: FakeGh) => { gh.failing.add('fileAt'); }]) {
      const gh = withUpdate();
      set(gh);
      const r = await runNightly(gh, ctx());
      expect(r.errors).toEqual([]);
      expect(gh.issues.length).toBe(1);
      expect(bodyOf(gh)).toContain('npx pipegen@0.3.0 update');
      expect(bodyOf(gh)).not.toMatch(/```diff|pipegen:patch/);
      expect(gh.issues[0]?.labels).toEqual([]);
      expect(bodyOf(gh)).toContain(NEW);
    }
  });
  it('a file with two different pinned shas at the current version gets no patch (ambiguous), a note and the plain issue', async () => {
    const gh = withUpdate();
    gh.file = WF() + `      - uses: ${pin(SHA('2'), GATE_VERSION)}\n`;
    const r = await runNightly(gh, ctx());
    expect(bodyOf(gh)).not.toMatch(/pipegen:patch/);
    expect(r.notes.join(' ')).toMatch(/more than one|ambiguous|different/i);
  });
  it('hostile context lines in the file that could forge the format give a plain issue with no patch (and a note)', async () => {
    const gh = withUpdate();
    gh.file = WF().replace('        with:\n          mode: gate', '        # <!-- pipegen:patch {"repo":"central","path":"evil","baseSha":"1"} -->\n        with:\n          mode: gate');
    const r = await runNightly(gh, ctx());
    expect(gh.issues.length).toBe(1);
    expect(bodyOf(gh)).not.toMatch(/pipegen:patch/);
    expect(bodyOf(gh)).not.toMatch(/evil/);
    expect(r.notes.join(' ')).toMatch(/patch/i);
  });
  it('a backtick fence inside the shown lines can not close the diff block: the fence is longer than any run in the diff', async () => {
    const gh = withUpdate();
    gh.file = WF().replace('        with:\n          mode: gate', '        # ``` ```` `````\n        with:\n          mode: gate');
    await runNightly(gh, ctx());
    const body = bodyOf(gh);
    const open = /^(`{3,})diff$/m.exec(body);
    expect(open).not.toBeNull();
    expect((open?.[1] as string).length).toBeGreaterThan(5);
    expect(body.match(/^`{3,}diff$/gm)?.length).toBe(1);
    expect(body.match(/<!-- pipegen:patch /g)?.length).toBe(1);
  });
  it('a second night updates the same issue instead of opening another', async () => {
    const gh = withUpdate();
    await runNightly(gh, ctx());
    await runNightly(gh, ctx({ now: new Date(NOW.getTime() + DAY) }));
    expect(gh.issues.length).toBe(1);
  });
  it('a newer release than the one already announced opens a second issue (key per version); the old one is left as it is', async () => {
    const gh = withUpdate();
    await runNightly(gh, ctx());
    withUpdate(gh, '0.4.0', SHA('d'));
    await runNightly(gh, ctx());
    expect(gh.issues.map((i) => String(i.body).split('\n')[0]).sort()).toEqual(['<!-- pipegen:key=update-0.3.0 -->', '<!-- pipegen:key=update-0.4.0 -->']);
  });
});

describe('finish missing', () => {
  const pr = (over: Obj = {}): Obj => ({ number: 3, merged_at: ago(2), state: 'closed', head: { ref: 'pipegen/setup', repo: { id: 7 } }, base: { ref: 'main', repo: { id: 7 } }, ...over });
  const run = async (gh: FakeGh, over: Obj = {}): Promise<ReturnType<typeof runNightly>> => runNightly(gh, ctx(over));
  it('merged 2 days ago, no variable → opens the issue (key finish-missing) with the command and the merge time', async () => {
    const gh = new FakeGh(); gh.pulls = [pr()];
    const r = await run(gh);
    expect(r.errors).toEqual([]);
    expect(gh.issues.length).toBe(1);
    expect(keyOfIssue(gh)).toBe('finish-missing');
    expect(bodyOf(gh)).toContain('npx pipegen finish');
    expect(bodyOf(gh)).toContain(ago(2));
    expect(bodyOf(gh)).not.toMatch(/pipegen:patch|```diff/);
  });
  it('the variable is set → no issue and no pulls call; merged under 24 h ago → no issue', async () => {
    const gh = new FakeGh(); gh.pulls = [pr()];
    await run(gh, { blockFrom: '2026-11-06' });
    expect(gh.issues).toEqual([]);
    expect(gh.calls).not.toContain('listSetupPulls');
    const g2 = new FakeGh(); g2.pulls = [pr({ merged_at: ago(0, 5) })];
    await run(g2);
    expect(g2.issues).toEqual([]);
  });
  it('the latest merged setup PR counts (not the first listed, not an unmerged one)', async () => {
    const gh = new FakeGh();
    gh.pulls = [pr({ number: 9, merged_at: null }), pr({ number: 8, merged_at: ago(0, 2) }), pr({ number: 7, merged_at: ago(5) })];
    await run(gh);
    expect(gh.issues).toEqual([]);   // the latest merge is 2 h ago
    const g2 = new FakeGh();
    g2.pulls = [pr({ number: 7, merged_at: ago(5) }), pr({ number: 8, merged_at: ago(9) })];
    await run(g2);
    expect(bodyOf(g2)).toContain(ago(5));
  });
  it('a fork is ignored: the head repo id must equal the base repo id and this repository\'s id; the head branch must be exactly pipegen/setup; the base the default branch', async () => {
    for (const bad of [
      pr({ head: { ref: 'pipegen/setup', repo: { id: 99 } } }), pr({ head: { ref: 'pipegen/setup', repo: null } }), pr({ head: { ref: 'pipegen/setup' } }),
      pr({ head: { ref: 'pipegen/setup2', repo: { id: 7 } } }), pr({ head: { ref: 'Pipegen/setup', repo: { id: 7 } } }), pr({ base: { ref: 'other', repo: { id: 7 } } }),
      pr({ base: { ref: 'main', repo: { id: 99 } } }), pr({ head: { ref: 'pipegen/setup', repo: { id: 99 } }, base: { ref: 'main', repo: { id: 99 } } }),
      pr({ head: { ref: 'pipegen/setup', repo: { id: '7' } } }),
    ]) {
      const gh = new FakeGh(); gh.pulls = [bad];
      await run(gh);
      expect(gh.issues, JSON.stringify(bad)).toEqual([]);
    }
  });
  it('API errors and malformed answers are fail-closed: no issue, a note, no error exit', async () => {
    for (const set of [(gh: FakeGh) => gh.failing.add('listSetupPulls'), (gh: FakeGh) => { gh.pulls = { not: 'a list' }; }, (gh: FakeGh) => { gh.pulls = [null, 'x', 5]; },
      (gh: FakeGh) => { gh.pulls = [pr({ merged_at: 'x' })]; }, (gh: FakeGh) => { gh.pulls = [pr({ merged_at: '2026-10-28' })]; }, (gh: FakeGh) => { gh.pulls = [Object.create(pr())]; }, (gh: FakeGh) => { gh.pulls = []; }]) {
      const gh = new FakeGh(); set(gh);
      const r = await run(gh);
      expect(gh.issues).toEqual([]);
      expect(r.errors).toEqual([]);
    }
  });
  it('a merge time in the future is skipped, not chosen: an older valid merge still counts', async () => {
    const gh = new FakeGh();
    gh.pulls = [pr({ number: 9, merged_at: new Date(NOW.getTime() + DAY).toISOString() }), pr({ number: 7, merged_at: ago(5) })];
    await run(gh);
    expect(gh.issues.length).toBe(1);
    expect(bodyOf(gh)).toContain(ago(5));
  });
  it('a merge time in the future is not a merge proof', async () => {
    const gh = new FakeGh(); gh.pulls = [pr({ merged_at: new Date(NOW.getTime() + DAY).toISOString() })];
    await run(gh);
    expect(gh.issues).toEqual([]);
  });
  it('a garbage PIPEGEN_BLOCK_FROM does not silence it', async () => {
    const gh = new FakeGh(); gh.pulls = [pr()];
    await run(gh, { blockFrom: 'garbage' });
    expect(gh.issues.length).toBe(1);
  });
});

describe('warn mode ending', () => {
  const KEY = 'test-fp-key-'.repeat(4);
  const RUN_ID = 100;
  const COUNTS = { [`fp\0semgrep\0semgrep\0${'ab'.repeat(32)}`]: 2, [`unmapped\0iac\0trivy-config\0AVD-1`]: 3 };
  const sub = (key: string): string => createHmac('sha256', key).update('pipegen-artifact-mac-v1').digest('hex');
  const signed = (key: string, counts: Record<string, number>, mutate: (d: Obj) => Obj = (d) => d): Uint8Array => {
    const kid = keyId(key);
    const pairs = Object.entries(counts).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const mac = createHmac('sha256', sub(key)).update(JSON.stringify(['pipegen-baseline-v1', RUN_ID, kid, pairs])).digest('hex');
    return new TextEncoder().encode(JSON.stringify(mutate({ runId: RUN_ID, keyId: kid, counts, mac })));
  };
  /** A fake in which a trusted push run holds the baseline blob given. */
  function baselineWorld(blob: Uint8Array | null): FakeGh {
    const gh = new FakeGh();
    gh.runsAnswer = [{ id: RUN_ID, event: 'push', conclusion: 'success', path: WORKFLOW_PATH, head_branch: 'main', head_sha: SHA('1'), head_repository: { id: 7 } }];
    if (blob !== null) {
      gh.runArtifacts.set(RUN_ID, { artifacts: [{ id: 55, name: BASELINE_ARTIFACT, expired: false, expires_at: '2027-01-20T00:00:00Z', created_at: ago(1), size_in_bytes: 500, workflow_run: { id: RUN_ID, head_branch: 'main', head_sha: SHA('1'), head_repository_id: 7 } }] });
      gh.blobs.set(55, blob);
    }
    return gh;
  }
  const IN_WINDOW = { blockFrom: '2026-11-01', key: KEY };

  it('two days before block-from, old findings in the trusted (MAC-verified) baseline → opens the issue with their count', async () => {
    const gh = baselineWorld(signed(KEY, COUNTS));
    const r = await runNightly(gh, ctx(IN_WINDOW));
    expect(r.errors).toEqual([]);
    expect(gh.issues.length).toBe(1);
    expect(keyOfIssue(gh)).toBe('warn-ending');
    expect(titleOf(gh)).toMatch(/2 days/);
    expect(bodyOf(gh)).toMatch(/5 existing findings|5 old findings/);
    expect(bodyOf(gh)).not.toMatch(/unknown/i);
  });
  it('a forged baseline (wrong MAC, other key) is not trusted: the softer "old findings unknown" issue opens, never "none" and never a count', async () => {
    for (const blob of [signed('other-fp-key-'.repeat(4), COUNTS), signed(KEY, COUNTS, (d) => ({ ...d, counts: { ...(d.counts as Obj), x: 1 } })), new TextEncoder().encode('{}'), new TextEncoder().encode('not json')]) {
      const gh = baselineWorld(blob);
      await runNightly(gh, ctx(IN_WINDOW));
      expect(gh.issues.length).toBe(1);
      expect(titleOf(gh)).toMatch(/unknown/i);
      expect(bodyOf(gh)).toMatch(/unknown/i);
      expect(bodyOf(gh)).not.toMatch(/\b5\b/);
    }
  });
  it('no baseline at all, no key (a missing fp-key input), or an API error in the lookup → the softer issue', async () => {
    for (const [gh, c] of [[baselineWorld(null), IN_WINDOW], [baselineWorld(signed(KEY, COUNTS)), { blockFrom: '2026-11-01' }], [(() => { const g = baselineWorld(signed(KEY, COUNTS)); g.failing.add('listRuns'); return g; })(), IN_WINDOW]] as const) {
      await runNightly(gh, ctx(c));
      expect(gh.issues.length).toBe(1);
      expect(titleOf(gh)).toMatch(/unknown/i);
    }
  });
  it('a trusted baseline with no findings → no issue (nothing to warn about); more than 2 days left, or block-from passed or absent → no issue and no baseline lookup', async () => {
    const gh = baselineWorld(signed(KEY, {}));
    await runNightly(gh, ctx(IN_WINDOW));
    expect(gh.issues).toEqual([]);
    for (const c of [{ blockFrom: '2026-11-05', key: KEY }, { blockFrom: '2026-10-30', key: KEY }, { blockFrom: '2026-10-01', key: KEY }, { key: KEY }, { blockFrom: 'junk', key: KEY }]) {
      const g = baselineWorld(signed(KEY, COUNTS));
      await runNightly(g, ctx(c));
      expect(g.issues, JSON.stringify(c)).toEqual([]);
      expect(g.calls, JSON.stringify(c)).not.toContain('listRuns');
    }
  });
  it('the recorded date counts too: the earlier of PIPEGEN_BLOCK_FROM and the recorded date ends warn mode', async () => {
    const gh = baselineWorld(signed(KEY, COUNTS));
    await runNightly(gh, ctx({ blockFrom: '2026-12-01', recorded: '2026-11-01', key: KEY }));
    expect(gh.issues.length).toBe(1);
    const g2 = baselineWorld(signed(KEY, COUNTS));
    await runNightly(g2, ctx({ blockFrom: '2026-11-01', recorded: '2026-12-01', key: KEY }));
    expect(g2.issues.length).toBe(1);
  });
  it('a clean-run marker never suppresses the issue or the warning: nightly does not even ask for one', async () => {
    const gh = baselineWorld(signed(KEY, COUNTS));
    gh.runArtifacts.set(RUN_ID, { artifacts: [...((gh.runArtifacts.get(RUN_ID) as { artifacts: unknown[] }).artifacts), { id: 56, name: 'pipegen-clean-run', expired: false, expires_at: '2027-01-20T00:00:00Z', created_at: ago(1), size_in_bytes: 90, workflow_run: { id: RUN_ID, head_branch: 'main', head_sha: SHA('1'), head_repository_id: 7 } }] });
    gh.blobs.set(56, new TextEncoder().encode('{"marker":true}'));
    await runNightly(gh, ctx(IN_WINDOW));
    expect(gh.issues.length).toBe(1);
    expect(gh.calls.filter((c) => c === 'listRunArtifacts').length).toBeGreaterThan(0);
    expect(readFileSync(join(ROOT, 'gate/src/nightly.ts'), 'utf8')).not.toMatch(/cleanRunSeen|resolveMode|decideMode/);
  });
  it('the issue is updated in place on later nights (the days left change), and it is never closed', async () => {
    const gh = baselineWorld(signed(KEY, COUNTS));
    await runNightly(gh, ctx(IN_WINDOW));
    await runNightly(gh, ctx({ ...IN_WINDOW, now: new Date(NOW.getTime() + DAY) }));
    expect(gh.issues.length).toBe(1);
    expect(titleOf(gh)).toMatch(/1 day\b/);
    // the day block mode starts, and after: the issue stays open (nobody closes it but a person)
    await runNightly(gh, ctx({ ...IN_WINDOW, now: new Date(NOW.getTime() + 3 * DAY) }));
    expect(gh.issues[0]?.state).toBe('open');
    expect(gh.calls.filter((c) => c === 'updateIssue').length).toBe(1);
  });
});

// ======================================================================================================
// escaping, and nothing but issue writes
// ======================================================================================================

describe('hostile repo and release strings', () => {
  const HOSTILE = 'ev`il_<img src=x onerror=alert(1)> @mallory [x](http://e.vil) #12 **b**\n# head | cell';
  it('the repository name, branch and notes are escaped once in every issue (no raw HTML, no mention, no link, no new line)', async () => {
    const repo: RepoRef = { owner: 'ac@me', name: HOSTILE, id: 7, defaultBranch: HOSTILE };
    const gh = withUpdate();
    gh.pulls = [{ number: 3, merged_at: ago(2), head: { ref: 'pipegen/setup', repo: { id: 7 } }, base: { ref: HOSTILE, repo: { id: 7 } } }];
    gh.failing.add('listRuns');
    await runNightly(gh, ctx({ repo, blockFrom: undefined, recorded: '2026-11-01', key: 'k'.repeat(40) }));
    expect(gh.issues.length).toBeGreaterThanOrEqual(2);
    for (const i of gh.issues) {
      const body = String(i.body);
      const prose = body.replace(/^(`{3,})diff\n[\s\S]*?\n\1$/gm, '').replace(/`[^`\n]*`/g, '');
      expect(prose, body).not.toContain('<img');
      expect(prose).not.toMatch(/@mallory/);
      expect(prose).not.toMatch(/\[x\]\(http/);
      expect(prose).not.toMatch(/(^|[^&\\])#12/);
      expect(prose).not.toMatch(/^# head/m);
      expect(prose).not.toMatch(/<!-- pipegen:(?!key=)/);
      expect(body.split('\n')[0]).toMatch(/^<!-- pipegen:key=[a-z0-9.-]+ -->$/);
    }
  });
  it('safeMarkdown runs once on a string: the escaped form of the hostile name appears exactly, not double-escaped', async () => {
    const { safeMarkdown } = await import('../src/util/safe-text.js');
    const repo: RepoRef = { owner: 'acme', name: 'a_b*c', id: 7, defaultBranch: 'main' };
    const gh = new FakeGh();
    gh.pulls = [{ number: 3, merged_at: ago(2), head: { ref: 'pipegen/setup', repo: { id: 7 } }, base: { ref: 'main', repo: { id: 7 } } }];
    await runNightly(gh, ctx({ repo }));
    expect(bodyOf(gh)).toContain(safeMarkdown('acme/a_b*c', 200));
    expect(bodyOf(gh)).not.toContain(safeMarkdown(safeMarkdown('acme/a_b*c', 200), 200));
  });
  it('the baseline note in the warn-ending issue is escaped once', async () => {
    const gh = new FakeGh();
    const note = '<img src=x> @mallory [x](http://e.vil) a_b';
    await runNightly(gh, ctx({ blockFrom: '2026-11-01' }), { loadBaseline: async () => ({ baseline: null, note }) });
    const { safeMarkdown } = await import('../src/util/safe-text.js');
    expect(bodyOf(gh)).toContain(safeMarkdown(note, 300));
    expect(bodyOf(gh)).not.toContain('<img');
    expect(bodyOf(gh)).not.toContain('@mallory');
  });
  it('a release tag name is never printed unless it matched the strict gate-v<semver> form, and then it is escaped as text', async () => {
    const gh = new FakeGh();
    gh.releases = [rel('gate-v0.3.0\n# pwn', 10), rel('gate-v0.3.0 @x', 10), rel('gate-v0.3.0', 10)];
    gh.tags.set('gate-v0.3.0', { ref: 'refs/tags/gate-v0.3.0', object: { type: 'commit', sha: NEW } });
    await runNightly(gh, ctx());
    expect(bodyOf(gh)).not.toMatch(/pwn|@x/);
  });
});

describe('nightly never writes anything but issues', () => {
  it('a full run on a world with all three issues only calls reads, listIssues, createIssue and updateIssue', async () => {
    const gh = withUpdate();
    gh.pulls = [{ number: 3, merged_at: ago(2), head: { ref: 'pipegen/setup', repo: { id: 7 } }, base: { ref: 'main', repo: { id: 7 } } }];
    await runNightly(gh, ctx({ blockFrom: undefined, recorded: '2026-11-01' }));
    await runNightly(gh, ctx({ blockFrom: undefined, recorded: '2026-11-01' }));
    expect(gh.issues.length).toBe(3);
    const allowed = new Set(['branchHead', 'fileAt', 'listRuns', 'listRunArtifacts', 'downloadArtifact', 'compare', 'tagExists', 'listSetupPulls', 'listReleases', 'tagRef', 'gitTag', 'listIssues', 'createIssue', 'updateIssue']);
    expect([...new Set(gh.calls)].filter((c) => !allowed.has(c))).toEqual([]);
    expect(writesOf(gh).every((c) => c === 'createIssue' || c === 'updateIssue')).toBe(true);
  });
  it('through the real adapter: every request that is not a GET is a POST to /issues or a PATCH to /issues/<n>, and nothing else', async () => {
    const seen: { method: string; url: string; body?: string }[] = [];
    const issues: Obj[] = [];
    const reply = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
    const fetchFn = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      seen.push({ method, url: url.pathname + url.search, ...(typeof init?.body === 'string' ? { body: init.body } : {}) });
      const p = url.pathname;
      if (method === 'POST' && p === '/repos/acme/app/issues') { const b = JSON.parse(String(init?.body)) as Obj; issues.unshift({ number: 41, state: 'open', ...b, labels: ((b.labels ?? []) as string[]).map((name) => ({ name })), user: { login: BOT_LOGIN, type: 'Bot' } }); return reply({ number: 41 }, 201); }
      if (method === 'PATCH' && p === '/repos/acme/app/issues/41') return reply({ number: 41 });
      if (method !== 'GET') return reply({}, 405);
      if (p === '/repos/acme/app/issues') return reply(issues);
      if (p === '/repos/crisworking/pipegen/releases') return reply([rel('gate-v0.3.0', 10)]);
      if (p === '/repos/crisworking/pipegen/git/ref/tags/gate-v0.3.0') return reply({ ref: 'refs/tags/gate-v0.3.0', object: { type: 'commit', sha: NEW } });
      if (p === '/repos/acme/app/git/ref/heads/main') return reply({ ref: 'refs/heads/main', object: { type: 'commit', sha: TIP } });
      if (p.startsWith('/repos/acme/app/contents/')) return reply({ type: 'file', encoding: 'base64', size: Buffer.byteLength(WF()), content: Buffer.from(WF()).toString('base64'), sha: SHA('0') });
      if (p === '/repos/acme/app/pulls') return reply([{ number: 3, merged_at: ago(2), head: { ref: 'pipegen/setup', repo: { id: 7 } }, base: { ref: 'main', repo: { id: 7 } } }]);
      return reply({}, 404);
    }) as typeof fetch;
    const gh = githubAdapter({ [['to', 'ken'].join('')]: CRED, fetch: fetchFn } as unknown as AdapterOptions);
    const r = await runNightly(gh, ctx({ blockFrom: undefined }));
    expect(r.errors).toEqual([]);
    expect(issues.length).toBeGreaterThanOrEqual(2);
    await runNightly(gh, ctx({ blockFrom: undefined, now: new Date(NOW.getTime() + DAY) }));
    const writes = seen.filter((s) => s.method !== 'GET');
    expect(writes.length).toBeGreaterThan(0);
    for (const w of writes) expect(`${w.method} ${w.url}`).toMatch(/^(?:POST \/repos\/acme\/app\/issues|PATCH \/repos\/acme\/app\/issues\/41)$/);
    // the reads: only these paths (no contents write, no ref write, no PR write exists as a method)
    for (const s of seen.filter((x) => x.method === 'GET')) expect(s.url.split('?')[0], s.url).toMatch(/^\/repos\/(?:acme\/app|crisworking\/pipegen)\/(?:issues|releases|git\/ref\/tags\/[\w.-]+|git\/tags\/[0-9a-f]{40}|git\/ref\/heads\/main|contents\/\.github\/workflows\/pipegen\.yml|pulls|actions\/workflows\/pipegen\.yml\/runs)$/);
    expect(JSON.stringify(seen)).not.toContain(CRED);
  });
  it('the adapter has no method that writes contents, workflows, refs or pull requests, and its write path refuses any other target', () => {
    const src = readFileSync(join(ROOT, 'gate/src/github-adapter.ts'), 'utf8');
    for (const m of ['createRef', 'updateRef', 'deleteRef', 'createPull', 'mergePull', 'putFile', 'createFile', 'updateFile', 'dispatch']) expect(src, m).not.toContain(m);
    const nightly = readFileSync(join(ROOT, 'gate/src/nightly.ts'), 'utf8');
    expect(nightly).not.toMatch(/writeFile|appendFile|createWriteStream|child_process|\bcontents\b[^\n]{0,40}(?:PUT|DELETE)|git\/refs|pulls\/\d+\/merge/);
  });
  it('a write to a path that is not an issue is refused by the adapter before any request', async () => {
    const seen: string[] = [];
    const fetchFn = (async (input: string | URL | Request) => { seen.push(String(input)); return new Response('{}', { status: 200 }); }) as typeof fetch;
    const gh = githubAdapter({ [['to', 'ken'].join('')]: CRED, fetch: fetchFn } as unknown as AdapterOptions) as unknown as NightlyAdapter;
    await expect(gh.updateIssue('acme', 'app', 0, { title: 't', body: 'b' })).rejects.toThrow();
    await expect(gh.updateIssue('acme', 'app', -1, { title: 't', body: 'b' })).rejects.toThrow();
    await expect(gh.createIssue('../x', 'app', { title: 't', body: 'b' })).rejects.toThrow();
    await expect(gh.createIssue('acme', 'app', { title: 't', body: 'b', labels: ['a b\n'] })).rejects.toThrow();
    await expect(gh.createIssue('acme', 'app', { title: '', body: 'b' })).rejects.toThrow();
    expect(seen).toEqual([]);
  });
});

// ======================================================================================================
// the action: main.ts mode nightly, action.yml, the row
// ======================================================================================================

const PAYLOAD = (over: Obj = {}): Obj => ({ repository: { id: 7, name: 'app', full_name: 'acme/app', owner: { login: 'acme' }, default_branch: 'main', private: false, ...over } });
async function go(inputs: Record<string, string | undefined>, gh?: FakeGh): Promise<{ code: number; out: string; lines: string[]; summary: string; r: ReturnType<typeof runner> }> {
  const r = runner(inputs, { event: 'schedule', sha: SHA('d'), payload: PAYLOAD() });
  const chunks: string[] = [];
  const nightly: MainDeps['nightly'] = gh === undefined ? undefined : () => gh;
  const code = await main({ env: r.env, now: () => NOW, write: (t) => { chunks.push(t); }, ...(nightly === undefined ? {} : { nightly }) });
  const out = chunks.join('');
  return { code, out, lines: out.split('\n').filter((l) => l !== ''), summary: readFileSync(r.summary, 'utf8'), r };
}
const NIGHT = (over: Record<string, string | undefined> = {}): Record<string, string | undefined> => ({ mode: 'nightly', [GH_IN]: CRED, [FP_IN]: FPKEY, 'block-from': '', 'block-from-recorded': '', ...over });

describe('mode nightly in main.ts', () => {
  it('runs end to end on a fixture world: exit 0, the issues opened, the summary lists them, the token is masked first', async () => {
    const gh = withUpdate();
    gh.pulls = [{ number: 3, merged_at: ago(2), head: { ref: 'pipegen/setup', repo: { id: 7 } }, base: { ref: 'main', repo: { id: 7 } } }];
    const x = await go(NIGHT(), gh);
    expect(x.code, x.out).toBe(0);
    expect(gh.issues.map((i) => String(i.body).split('\n')[0]).sort()).toEqual(['<!-- pipegen:key=finish-missing -->', '<!-- pipegen:key=update-0.3.0 -->']);
    expect(x.lines.slice(0, 2).sort()).toEqual([`::add-mask::${CRED}`, `::add-mask::${FPKEY}`].sort());
    expect(x.summary).toMatch(/update-0\.3\.0|0\.3\.0/);
    expect(x.lines.filter((l) => !l.startsWith('::add-mask::')).join('\n')).not.toContain(CRED.slice(8));
  });
  it('a write failure (the issue could not be created) is an error exit; a read failure (the pipegen repo is private) is not', async () => {
    const bad = withUpdate(); bad.failing.add('createIssue');
    const x = await go(NIGHT(), bad);
    expect(x.code).toBe(1);
    expect(x.out).toMatch(/::error::/);
    const priv = new FakeGh(); priv.releases = new Error('GET /repos/crisworking/pipegen/releases: GitHub answered 404');
    const y = await go(NIGHT(), priv);
    expect(y.code, y.out).toBe(0);
    expect(y.out).toMatch(/update/i);
  });
  it('an issue list at its cap fails closed with an error exit and no issue created', async () => {
    const gh = withUpdate();
    gh.issues = Array.from({ length: ISSUE_PAGE_CAP * 100 + 1 }, (_, i) => issue(1000 + i, 'noise'));
    const x = await go(NIGHT(), gh);
    expect(x.code).toBe(1);
    expect(writesOf(gh)).toEqual([]);
  });
  it('a missing token, a bad key, or an input of another mode fails closed with no GitHub call', async () => {
    for (const inputs of [NIGHT({ [GH_IN]: undefined }), NIGHT({ [FP_IN]: 'short' }), { ...NIGHT(), sha: SHA('a') }, { ...NIGHT(), jobs: '${{ toJSON(needs) }}' }]) {
      const gh = withUpdate();
      const x = await go(inputs, gh);
      expect(x.code).toBe(1);
      expect(gh.calls).toEqual([]);
    }
  });
  it('the inputs block-from and block-from-recorded drive the dates; an invalid recorded date counts as absent', async () => {
    const gh = new FakeGh(); gh.runsAnswer = [];
    const x = await go(NIGHT({ 'block-from': '2026-11-01' }), gh);
    expect(x.code, x.out).toBe(0);
    expect(gh.issues.length).toBe(1);
    expect(keyOfIssue(gh)).toBe('warn-ending');
  });
  it('without fp-key (not a fork case: a repo without the secret) the warning is the soft one', async () => {
    const gh = new FakeGh();
    await go(NIGHT({ 'block-from': '2026-11-01', [FP_IN]: undefined }), gh);
    expect(titleOf(gh)).toMatch(/unknown/i);
  });
  it('nothing else is written: no file in the runner temp folder, the workspace is not read', async () => {
    const gh = withUpdate();
    const r = runner(NIGHT(), { event: 'schedule', sha: SHA('d'), payload: PAYLOAD() });
    const read: string[] = [];
    const env = new Proxy(r.env, { get(t, k) { if (typeof k === 'string') read.push(k); return Reflect.get(t, k); } });
    await main({ env, now: () => NOW, write: () => undefined, nightly: () => gh });
    expect(read).not.toContain('GITHUB_WORKSPACE');
    expect(outputsOf(r.output)).toEqual({});
  });
});

describe('action.yml and the renderer row for nightly agree', () => {
  const ROW = RENDERER_INPUTS[PIPEGEN_GATE_USES] as Record<string, { whenWith?: { check: (a: Record<string, string>) => boolean } }>;
  const ACTION = parse(readFileSync(join(ROOT, 'gate/action.yml'), 'utf8')) as { inputs: Record<string, { description: string }>; runs: Obj };
  it('MODE_INPUTS.nightly is mode, block-from, block-from-recorded, github-token, fp-key', () => {
    expect([...MODE_INPUTS.nightly].sort()).toEqual(['block-from', 'block-from-recorded', 'fp-key', 'github-token', 'mode'].sort());
  });
  it('every input of the action is a row input and the other way round, and the row says nightly for exactly the inputs of MODE_INPUTS.nightly', () => {
    expect(Object.keys(ACTION.inputs).sort()).toEqual(Object.keys(ROW).sort());
    const base: Record<string, string> = { mode: 'nightly' };
    for (const name of Object.keys(ROW)) {
      const inNightly = (MODE_INPUTS.nightly as readonly string[]).includes(name);
      const spec = ROW[name] as { whenWith?: { check: (a: Record<string, string>) => boolean } };
      if (spec.whenWith !== undefined) expect(spec.whenWith.check({ ...base }), name).toBe(inNightly);
      else expect(inNightly || name === 'mode', name).toBe(true);
    }
    expect(GATE_MODES).toContain('nightly');
  });
  it('merged-at is gone (the merge time is read from the API, which proves it)', () => {
    expect(Object.keys(ACTION.inputs)).not.toContain('merged-at');
    expect(Object.keys(ROW)).not.toContain('merged-at');
  });
  it('the descriptions of the nightly inputs name nightly', () => {
    for (const n of ['block-from', 'block-from-recorded', 'github-token', 'fp-key']) expect(ACTION.inputs[n]?.description, n).toMatch(/nightly/);
  });
});

describe('GATE_VERSION', () => {
  it('is the version of the pipegen-gate entry of the reviewed list, as plain x.y.z', async () => {
    const { loadReviewed } = await import('../src/engine/reviewed.js');
    const entry = loadReviewed().find((t) => t.id === 'pipegen-gate');
    expect(GATE_VERSION).toBe(entry?.candidate.version);
    expect(GATE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

// ======================================================================================================
// the bundle
// ======================================================================================================

describe('the bundle runs nightly end to end on a fixture world', () => {
  const BUNDLE = join(ROOT, 'gate/dist/index.js');
  const PRELOAD = join(ROOT, 'test/helpers/fake-github-preload.mjs');
  function runNode(env: Record<string, string>): Promise<{ code: number | null; stdout: string }> {
    return new Promise((done) => {
      const child = spawn(process.execPath, ['--import', PRELOAD, BUNDLE], { env: { PATH: process.env.PATH ?? '', ...env }, cwd: tmpdir() });
      let stdout = '';
      child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      child.stderr.on('data', (d: Buffer) => { stdout += d.toString(); });
      child.on('close', (code) => { done({ code, stdout }); });
    });
  }
  it('opens the update issue and the finish issue through the real adapter; the only writes are issue POSTs', async () => {
    // the bundle reads the real clock, so the dates of this world are relative to it
    const real = (days: number): string => new Date(Date.now() - days * DAY).toISOString();
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-c7-bundle-'));
    const file = join(dir, 'fake-gh.json');
    const log = join(dir, 'writes.jsonl');
    const A = '/repos/acme/app';
    const P = '/repos/crisworking/pipegen';
    writeFileSync(file, JSON.stringify({
      routes: {
        [`${P}/releases?per_page=100&page=1`]: [{ ...rel('gate-v0.3.0', 10, { body: `crisworking/pipegen/gate@${SHA('f')}` }), published_at: real(10) }],
        [`${P}/git/ref/tags/gate-v0.3.0`]: { ref: 'refs/tags/gate-v0.3.0', object: { type: 'commit', sha: NEW } },
        [`${A}/git/ref/heads/main`]: { ref: 'refs/heads/main', object: { type: 'commit', sha: TIP } },
        [`${A}/contents/.github/workflows/pipegen.yml?ref=${TIP}`]: { type: 'file', encoding: 'base64', size: Buffer.byteLength(WF()), content: Buffer.from(WF()).toString('base64'), sha: SHA('0') },
        [`${A}/pulls?state=closed&head=acme%3Apipegen%2Fsetup&sort=updated&direction=desc&per_page=100&page=1`]: [{ number: 3, merged_at: real(2), head: { ref: 'pipegen/setup', repo: { id: 7 } }, base: { ref: 'main', repo: { id: 7 } } }],
      },
      issues: [], zips: {}, runs: {},
    }));
    const r = runner(NIGHT(), { event: 'schedule', sha: SHA('d'), payload: PAYLOAD() });
    const x = await runNode({ ...r.env, PIPEGEN_FAKE_GH: file, PIPEGEN_FAKE_GH_LOG: log });
    expect(x.code, x.stdout).toBe(0);
    const writes = readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { method: string; path: string; body: { title: string; body: string; labels?: string[] } });
    expect(writes.map((w) => `${w.method} ${w.path}`)).toEqual([`POST ${A}/issues`, `POST ${A}/issues`]);
    const update = writes.find((w) => w.body.body.includes('pipegen:key=update-0.3.0'));
    expect(update?.body.body).toContain(NEW);
    expect(update?.body.body).not.toContain(SHA('f'));
    expect(update?.body.labels).toEqual(['pipegen:patch']);
    expect(writes.some((w) => w.body.body.includes('pipegen:key=finish-missing'))).toBe(true);
    expect(x.stdout.split('\n').filter((l) => !l.startsWith('::add-mask::')).join('\n')).not.toContain(CRED.slice(8));
  });
  it('the bundle has the nightly mode (no "built in C7" stub left) and no contents/ref/pull write path', () => {
    const t = readFileSync(BUNDLE, 'utf8');
    expect(t).not.toContain('built in C7');
    expect(t).toContain('pipegen:key=');
    expect(t).not.toMatch(/method:\s*['"](?:PUT|DELETE)['"]/);
  });
});

void API_ROOT;
