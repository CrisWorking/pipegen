// `pipegen cleanup` (Plan E Task 7 / E8; ruling S20): reads the repo's saved proof state and removes what a proof left in
// GitHub (the same cleanup as after a proof: src/proof/cleanup.ts). Plan G wires it into src/cli/main.ts together with
// `run` and `resume` (E8 ruling E8-R1: the command reaches the proof runner's modules, which bring libsodium and execa into
// dist/cli/main.js; the bundle's node:-only and THIRD_PARTY_NOTICES checks are settled once, for the whole runner, there).
import { isRateStop } from '../engine/github-rate.js';
import { getAuth, GitHubAccessError, hideToken, makeOctokit } from '../github/client.js';
import { cleanupLeftovers } from '../proof/cleanup.js';
import type { PollClock } from '../proof/run.js';
import { StateError, StateStore, type StateDeps } from '../proof/state.js';
import { ProofStopError } from '../proof/target.js';
import { NotGitHubRepoError, readOrigin } from '../read/project.js';
import { safeText } from '../util/safe-text.js';
import type { CliIO } from './io.js';

export interface CleanupCommandDeps extends Pick<StateDeps, 'home' | 'uid'> {
  clock?: PollClock;
  cancelWaitMs?: number;
  settleMs?: number;
}

/** `pipegen cleanup [--dir <folder>]`: reads the repo's saved proof state and removes what the proof left behind. Exit code. */
export async function cleanupCommand(dir: string, io: CliIO, opts: { allowBroad: boolean }, deps: CleanupCommandDeps = {}): Promise<number> {
  let token: string | null = null;
  const say = (s: string) => { io.out(hideToken(s, token)); };
  const fail = (s: string) => { io.err(hideToken(s, token)); };
  let owner: string;
  let repo: string;
  try {
    ({ owner, repo } = await readOrigin(dir));
  } catch (e) {
    if (!(e instanceof NotGitHubRepoError)) throw e;
    fail(`pipegen cleanup needs a GitHub repository: ${safeText(e.message, 400)}`);
    fail('Run it inside a clone of a GitHub repo, or pass --dir <folder>.');
    return 1;
  }
  let store: StateStore;
  try {
    store = await StateStore.open({ owner, repo }, { env: io.env, ...(deps.home === undefined ? {} : { home: deps.home }), ...(deps.uid === undefined ? {} : { uid: deps.uid }) });
  } catch (e) {
    if (!(e instanceof StateError)) throw e;
    fail(safeText(e.message, 600));
    return 1;
  }
  const st = store.state;
  if (st === null) {
    say(`Nothing to clean up: pipegen has no saved proof for ${owner}/${repo}.`);
    return 0;
  }
  // review M-1: the saved state must be this origin's (the folder binds them by path only); never another repo's scratch repo
  if (st.app.owner.toLowerCase() !== owner.toLowerCase() || st.app.repo.toLowerCase() !== repo.toLowerCase()) {
    fail(`The saved proof state is for ${st.app.owner}/${st.app.repo}, not ${owner}/${repo}; pipegen won't clean another repo's scratch repo from here.`);
    return 1;
  }
  // review I-5: a cleanup that already finished, with nothing left: nothing to send
  if (st.cleanupDone === true && st.leftovers.length === 0) {
    say('Nothing is left behind.');
    return 0;
  }
  const scratch = `pipegen-proof-${st.app.repo}`;
  try {
    const auth = await getAuth({ owner: st.app.owner, repos: [scratch, 'pipelines'], allowBroad: opts.allowBroad, mode: 'write' }, { env: io.env, ...(io.fetch === undefined ? {} : { fetch: io.fetch }) });
    token = auth.token;
    const gh = makeOctokit(auth.token, { ...(io.fetch === undefined ? {} : { fetch: io.fetch }), log: fail });
    say(`Cleaning up after the proof ${st.runId} of ${st.app.owner}/${st.app.repo} (the scratch repo ${st.app.owner}/${scratch}).`);
    const res = await cleanupLeftovers(gh, store, {
      canDeleteRepo: auth.canDeleteRepos, io,
      ...(deps.clock === undefined ? {} : { clock: deps.clock }), ...(deps.cancelWaitMs === undefined ? {} : { cancelWaitMs: deps.cancelWaitMs }),
      ...(deps.settleMs === undefined ? {} : { settleMs: deps.settleMs }),
    });
    say(res.repoDeleted ? `Deleted ${st.app.owner}/${scratch}.` : (res.message ?? `Emptied ${st.app.owner}/${scratch}.`));
    let left = res.leftovers;
    if (res.scratchMissing === true) {
      // review I-5: GitHub answers 404 for a scratch repo pipegen didn't delete. Only the user can say it is gone (a token that
      // lost access answers 404 too), so pipegen asks (default No) before it forgets what it left there.
      const full = `${st.app.owner}/${scratch}`;
      if (await io.prompt.confirm(`Did you delete ${full}? pipegen can't see it. If it is deleted, pipegen forgets what it left there.`, false)) {
        store.update((n) => {
          n.scratchDeleted = true;
          delete n.scratchRepoId;
          n.leftovers = n.leftovers.filter((l) => !l.includes(full));
          n.cleanupDone = n.leftovers.length === 0;
        });
        left = left.filter((l) => !l.includes(full));
      }
    }
    if (left.length === 0) {
      say('Nothing is left behind.');
      return 0;
    }
    fail(`Still left behind (${left.length}):`);
    for (const l of left) fail(`  ${l}`);
    return 1;
  } catch (e) {
    if (e instanceof GitHubAccessError || e instanceof ProofStopError || e instanceof StateError || isRateStop(e)) {
      fail(`pipegen cleanup stopped: ${safeText(e instanceof Error ? e.message : String(e), 800)}`);
      return 1;
    }
    throw e;
  }
}
