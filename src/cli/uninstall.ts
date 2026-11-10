// v0.2 Plan V V7 (plan Task 3, CLI part; rulings V-S3, V-S12, V-S15): `pipegen uninstall [--delete-repos]`. main.ts runs unsafeFolderStop first (G13-R0 14);
// this file then: (1) needs a terminal (typed names and the one yes are asked there, V-S13), before anything is read or sent; (2) connects as write mode
// through G13's `connect` (no token: stop before planning); (3) takes the app's lease (V9a, V8 sec M4: before the loader, which may write this machine's
// local record file) and holds it to the end; (4) loads the install record once (loadUninstallRecord: it is the one that rebuilds the record for a second
// run 2 and finishes an uninstall whose central repo is gone); (5) runs one uninstallStep with that lease. Every stop those throw is one clear message.
//
// Exit codes (V5-R1, V6-R3): 0 a run that did what it set out to (run 1 done, waiting for a merge, closed unmerged, run 2 done or waiting for the central
// pull request, or an uninstall that finished: UninstallFinished); 1 declined; 2 stopped, failed, interrupted, a step the loader or the run refused, or done
// with leftovers (a manual step, a kept item or a step not done; a note, V8 sec i6, is none). 4 (unsafe folder) comes from main.
//
// This file only imports a short list of names (test/helpers/import-scan.ts, CLI_UNINSTALL_ALLOWED): the one entry of apply.ts, the loader, and read-only
// helpers. It sends nothing to GitHub itself, and reads (never writes) the progress file to name a crash.
import { lstatSync, readFileSync } from 'node:fs';
import { localRecordPath } from '../deliver/record.js';
import { isRateStop } from '../engine/github-rate.js';
import { GitHubAccessError, hideToken } from '../github/client.js';
import type { StateDeps } from '../proof/state.js';
import { NotGitHubRepoError } from '../read/project.js';
import { holdUninstallLease, uninstallStep, type StepResult } from '../uninstall/apply.js';
import { UninstallError, UninstallFinished } from '../uninstall/errors.js';
import { MAX_PROGRESS_BYTES, uninstallProgressPath } from '../uninstall/progress.js';
import { loadUninstallRecord } from '../uninstall/record.js';
import { safeText } from '../util/safe-text.js';
import { interactiveRun, type connect } from './commands.js';
import type { CliIO } from './io.js';

/** What the command needs besides the terminal (main passes `connect` from its Commands seam; tests replace load and step). */
export interface UninstallCommandDeps {
  dir: string; allowBroad: boolean;
  /** --delete-repos (V-S3): run 2 deletes the scratch repo and, last project, the central repo (App mode), or prints the gh commands (token mode). */
  deleteRepos: boolean;
  connect: typeof connect;
  load?: typeof loadUninstallRecord; step?: typeof uninstallStep;
  /** The lease's state folder (default: the CLI's environment). */
  state?: StateDeps;
}

const LINE_MAX = 1500;

/** The exit code of a run (see the header). A kept item, a manual step or a step not done is never a clean 0. */
function exitOf(r: StepResult): number {
  switch (r.status) {
    case 'declined': return 1;
    case 'a-done': case 'b-done': return r.manual.length > 0 || r.skipped.length > 0 || r.failed.length > 0 ? 2 : 0;
    case 'waiting': case 'closed-unmerged': case 'b-waiting': return 0;
    default: return 2;   // stopped, failed, interrupted, replan, b-partial, and any other b-*
  }
}

/** A progress file that still holds a pending delete of `<owner>/pipelines` (the process died inside that request): the file only names it. */
type LocalDeps = Parameters<typeof localRecordPath>[1];
function pendingDeleteNote(app: { owner: string; repo: string }, local: LocalDeps): string | null {
  const path = uninstallProgressPath(app, local);
  let data: unknown;
  try {
    const info = lstatSync(path);
    if (!info.isFile() || info.size > MAX_PROGRESS_BYTES) return null;
    data = JSON.parse(readFileSync(path, 'utf8'));
  } catch { return null; }
  const p = data as { phase?: unknown; centralDeleteSent?: { confirmed?: unknown } | null } | null;
  if (p === null || typeof p !== 'object' || p.phase !== 'B' || p.centralDeleteSent === null || typeof p.centralDeleteSent !== 'object' || p.centralDeleteSent.confirmed !== false) return null;
  const central = `${app.owner}/pipelines`;
  return `pipegen was deleting ${central} when it stopped (${path} still holds a pending delete), so it can't tell whether GitHub carried the delete out. Look at ${central} on GitHub: if it is gone, the uninstall is finished, and you remove ${localRecordPath(app, local)} and ${path} by hand; if it is still there and pipegen can't read its install record, check what changed in ${central}.`;
}

/** `pipegen uninstall`: see the header. Expected stops are printed and returned as an exit code; anything unexpected passes to main (exit 1). */
export async function uninstallCommand(io: CliIO, deps: UninstallCommandDeps): Promise<number> {
  let token: string | null = null;
  const clean = (s: string): string => safeText(hideToken(s, token), LINE_MAX);
  const say = (s: string): void => { io.out(clean(s)); };
  const fail = (s: string): void => { io.err(clean(s)); };
  if (!interactiveRun(io)) {
    fail('pipegen uninstall needs a terminal (not CI): it shows what it will do and asks for one yes, and for names typed, before it changes anything. Nothing was changed. Run `npx pipegen uninstall` in a terminal.');
    return 2;
  }
  let stage: 'connect' | 'load' | 'step' = 'connect';
  let app: { owner: string; repo: string } | null = null;
  let localDeps: LocalDeps = { env: io.env };
  try {
    const c = await deps.connect(io, deps.dir, { allowBroad: deps.allowBroad, mode: 'write' });
    token = c.token;
    app = c.app;
    localDeps = c.g.local ?? {};
    stage = 'load';
    // Auth.canDeleteRepos as connect copied it (App login with Administration: write, write mode); anything else is token mode: print-only
    const canDeleteRepos = c.canDeleteRepos === true;
    const state = deps.state ?? { env: io.env };
    // V9a (V8 sec M4): the lease first; another pipegen on this repo is a stop before the record is read
    const held = await holdUninstallLease(c.app, state);
    try {
      // the one place the record is loaded: no preview or dry mode exists that could remove the local files through it (V6-R4)
      const loadDeps = { io: io.prompt, interactive: true, local: localDeps, ...(c.g.clock === undefined ? {} : { clock: c.g.clock }) };
      const loaded = deps.load !== undefined ? await deps.load(c.g.gh, c.app, loadDeps) : await loadUninstallRecord(c.g.gh, c.app, loadDeps);
      stage = 'step';
      const stepDeps = { out: say, interactive: true, deleteRepos: deps.deleteRepos, canDeleteRepos, local: localDeps, state, lease: held.lease, ...(c.g.clock === undefined ? {} : { clock: c.g.clock }) };
      const r = deps.step !== undefined ? await deps.step(c.g.gh, loaded, io.prompt, stepDeps) : await uninstallStep(c.g.gh, loaded, io.prompt, stepDeps);
      for (const l of r.lines) say(l);
      return exitOf(r);
    } finally {
      held.release();
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    // not a failure: the last run's delete of the central repo went through and GitHub says it is gone; the loader removed the local files
    if (e instanceof UninstallFinished) { for (const l of message.split('\n')) say(l); return 0; }
    if (e instanceof NotGitHubRepoError) { fail(`pipegen uninstall needs a GitHub repository: ${message}`); return 2; }
    if (e instanceof UninstallError || e instanceof GitHubAccessError || isRateStop(e)) {
      const lines = message.split('\n');
      fail(`pipegen uninstall stopped: ${lines[0] ?? ''}`);
      for (const l of lines.slice(1)) fail(l);
      if (stage === 'load' && app !== null) {
        const note = pendingDeleteNote(app, localDeps);
        if (note !== null) fail(note);
      }
      return 2;
    }
    throw e;
  }
}
