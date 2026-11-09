// v0.2 Plan G G13 (plan Task 7 CLI part; carries 17, 18, 59, 61, 63): `pipegen finish [--print] [--rotate-key]`, `pipegen verify` and
// `pipegen update`, each on the install record of the folder's origin repo. main.ts runs unsafeFolderStop before each (carry 1, ruling
// G13-R0 14). One local record folder for all of them (carry 17: `local`, from the CLI's environment), and `interactive` only for a terminal
// outside CI (carry 18). Exit codes: 0 done; 1 a stop, an error, or (verify) drift.
import type { Octokit } from '@octokit/rest';
import { finish, githubFinishProbe, type FinishOpts } from '../deliver/finish.js';
import type { LocalRecordDeps } from '../deliver/record.js';
import { update } from '../deliver/update.js';
import { verify } from '../deliver/verify.js';
import { newRateBudget, type RateClock } from '../engine/github-rate.js';
import { ensurePinnedBinary } from '../engine/linters.js';
import { loadReviewed } from '../engine/reviewed.js';
import { getAuth, GITHUB_TIMEOUT_MS, makeOctokit } from '../github/client.js';
import { readOrigin } from '../read/project.js';
import type { StateStore } from '../proof/state.js';
import { CENTRAL_REPO } from '../proof/target.js';
import type { RepoRef } from '../deliver/git-data.js';
import type { Auth } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { tokenLogin } from './inspect.js';
import type { CliIO } from './io.js';

/** Interactive only when it is real (carry 18): a terminal, not CI. */
export const interactiveRun = (io: Pick<CliIO, 'interactive' | 'env'>): boolean => io.interactive === true && (io.env.CI ?? '') === '';

/** What finish, verify and update need of GitHub (tests pass a fake). */
/**
 * `lease` (Plan V M5): the app's lease a caller already holds (run, which finishes in its own process); undefined → finish and update take it
 * themselves. A required key, so a caller that holds one can't leave it out by accident (that would stop on its own process).
 */
export interface CommandGitHub { gh: Octokit; login: string | null; local?: LocalRecordDeps; clock?: RateClock; lease: StateStore | undefined }

/** The folder's origin repo, a token for it and its central repo (least privilege: `write` for finish and update, `read` for verify). */
export async function connect(io: CliIO, dir: string, o: { allowBroad: boolean; mode: 'read' | 'write' }): Promise<{ app: RepoRef; g: CommandGitHub; token: string | null; canDeleteRepos: boolean; kind: Auth['kind'] }> {
  const app = await readOrigin(dir);
  const clock: RateClock = { budget: newRateBudget() };
  const auth = await getAuth({ owner: app.owner, repos: [app.repo, CENTRAL_REPO], allowBroad: o.allowBroad, mode: o.mode }, { env: io.env, ...(io.fetch === undefined ? {} : { fetch: io.fetch }), clock });
  const gh = makeOctokit(auth.token, { fetch: io.fetch, clock, timeoutMs: GITHUB_TIMEOUT_MS, log: (s) => { io.err(s); } });
  const notes: string[] = [];
  const login = await tokenLogin(gh, auth, clock, notes);
  for (const n of notes) io.err(n);
  // V7 fold 1: what the auth layer computed, copied as it is (never inferred): uninstall's --delete-repos acts only on canDeleteRepos
  return { app, token: auth.token, canDeleteRepos: auth.canDeleteRepos, kind: auth.kind, g: { gh, login, clock, local: { env: io.env }, lease: undefined } };
}

const show = (s: string, n = 300): string => safeText(s, n);

/** `pipegen finish [--print] [--rotate-key]` (carry 59): prints FinishResult; 0 done (a skipped step is printed, not a failure). */
export async function finishCommand(io: CliIO, app: RepoRef, opts: FinishOpts, g: CommandGitHub, run: typeof finish = finish): Promise<number> {
  const res = await run(g.gh, app, opts, {
    out: (l) => { io.out(l); }, probe: githubFinishProbe(g.login), cosignBin: () => ensurePinnedBinary('cosign'),
    ...(g.clock === undefined ? {} : { clock: g.clock }), local: g.local ?? {}, io: io.prompt, interactive: interactiveRun(io),
    ...(g.lease === undefined ? {} : { lease: g.lease }),
  });
  for (const a of res.applied) io.out(`applied: ${show(a)}`);
  for (const s of res.skipped) io.out(`skipped: ${show(s.what)} (${show(s.why, 600)})`);
  for (const n of res.notes) io.out(show(n, 1000));
  if (opts.print === true) {
    io.out('The commands, in order:');
    for (const c of res.commands ?? []) io.out(c);
  }
  if (res.recordHash !== undefined) io.out(`install record: sha256 ${show(res.recordHash, 80)}`);
  if (res.centralPrUrl !== undefined) io.out(`central pull request: ${show(res.centralPrUrl)}`);
  return 0;
}

/** `pipegen verify` (carry 61): the drift as a table, then warnings and notes. Any drift exits 1. */
export async function verifyCommand(io: CliIO, app: RepoRef, g: CommandGitHub, run: typeof verify = verify): Promise<number> {
  const res = await run(g.gh, app, { ...(g.clock === undefined ? {} : { clock: g.clock }), local: g.local ?? {} });
  if (res.drift.length > 0) {
    io.out('Drift (what pipegen set up, and what is there now):');
    io.out('  what | expected | actual');
    for (const d of res.drift) io.out(`  ${show(d.what, 200)} | ${show(d.expected, 200)} | ${d.actual === null ? '(gone)' : show(d.actual, 200)}`);
  } else {
    io.out('No drift: everything pipegen set up is as it was recorded.');
  }
  for (const w of res.warnings) io.out(`warning: ${show(w, 600)}`);
  for (const n of res.notes) io.out(show(n, 600));
  return res.drift.length > 0 ? 1 : 0;
}

/** `pipegen update` (carry 63): the preview, the pull requests, and what pipegen did not act on. An owner-edited file is never overwritten. */
export async function updateCommand(io: CliIO, app: RepoRef, g: CommandGitHub, run: typeof update = update): Promise<number> {
  const res = await run(g.gh, app, {
    io: io.prompt, reviewed: loadReviewed(), interactive: interactiveRun(io), local: g.local ?? {}, ...(g.clock === undefined ? {} : { clock: g.clock }),
    ...(g.lease === undefined ? {} : { lease: g.lease }),
  });
  if (res.preview !== '') io.out(res.preview);
  if (res.prUrl !== undefined) io.out(`pull request: ${show(res.prUrl)}`);
  if (res.centralPrUrl !== undefined) io.out(`central pull request: ${show(res.centralPrUrl)}`);
  for (const p of res.prompts) io.out(`update prompt: issue #${p.issue} (${p.in}): ${show(p.key, 120)} ${show(p.version, 60)}`);
  for (const i of res.ignored) io.out(`ignored: issue #${i.issue} (${i.in}): ${show(i.why, 600)}`);
  for (const r of res.refused) io.out(`refused: issue #${r.issue} (${r.in}): ${show(r.why, 600)}${r.shown === undefined ? '' : `\n${show(r.shown, 4000)}`}`);
  for (const c of res.conflicts) io.out(`not changed (your edits): ${c.repo === 'central' ? 'central ' : ''}${show(c.path, 200)}: ${show(c.why, 600)}`);
  for (const n of res.notes) io.out(show(n, 1000));
  if (!res.done && res.prUrl === undefined && res.centralPrUrl === undefined) io.out('Nothing to update.');
  return 0;
}
