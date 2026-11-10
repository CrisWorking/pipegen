// PL-E1: split out of finish.ts (a pure move, by step); see finish.ts for the whole story.
import type { Octokit } from '@octokit/rest';
import type { RateClock } from '../engine/github-rate.js';
import { probeCapabilities } from '../github/capabilities.js';
import { readGitHubContext } from '../github/client.js';
import { CENTRAL_REPO } from '../proof/target.js';
import { parseYamlLimited } from '../read/limits.js';
import { MAX_WORKFLOWS, tagPinnedOf, WORKFLOW_FILE } from '../read/workflows.js';
import { readBlobText, readHead, readTree, type RepoRef } from './git-data.js';
import { isObj } from './settings-api.js';
import { MAX_TEXT, type FinishProbe, isStop } from './finish-base.js';

// ---------- the real re-probe (G13 wires it) ----------

/** The app's own workflows on its default branch: how many action references name a tag or branch (planLocks leaves sha pinning off then). */
export async function workflowPins(gh: Octokit, app: RepoRef, branch: string, clock: RateClock): Promise<{ tagPinned: number; unchecked: boolean }> {
  const head = await readHead(gh, app, branch, clock);
  if (head === null) return { tagPinned: 0, unchecked: true };
  const { entries } = await readTree(gh, app, head, clock);
  const wf = [...entries].filter(([p, e]) => WORKFLOW_FILE.test(p) && e.type === 'blob');
  let tagPinned = 0;
  let unchecked = wf.length > MAX_WORKFLOWS;
  for (const [, e] of wf.slice(0, MAX_WORKFLOWS)) {
    try {
      const doc = parseYamlLimited(await readBlobText(gh, app, e.sha, MAX_TEXT, clock));
      if (!isObj(doc)) { unchecked = true; continue; }
      const t = tagPinnedOf(doc);
      tagPinned += t.n;
      if (t.unchecked) unchecked = true;
    } catch (err) {
      if (isStop(err)) throw err;
      unchecked = true;
    }
  }
  return { tagPinned, unchecked };
}

/** The re-probe on GitHub: readGitHubContext (the plan), probeCapabilities of the app and of the central repo, the app's workflow pins. */
export function githubFinishProbe(login: string | null): FinishProbe {
  return async (gh, app, facts, notes, clock) => {
    const c = await readGitHubContext(gh, app.owner, app.repo, login, clock, notes);
    const caps = await probeCapabilities(gh, app.owner, app.repo, { private: c.private, plan: c.plan, ownerType: c.ownerType, defaultBranch: c.defaultBranch }, notes, clock);
    const centralCaps = await probeCapabilities(gh, app.owner, CENTRAL_REPO, { private: true, plan: c.plan, ownerType: c.ownerType, defaultBranch: facts.centralDefaultBranch }, notes, clock);
    return { plan: c.plan, caps, centralBranchProtection: centralCaps.branchProtection, workflowPins: await workflowPins(gh, app, facts.defaultBranch, clock) };
  };
}
