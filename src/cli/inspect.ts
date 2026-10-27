// `pipegen inspect` (Plan A Task 8): reads the project, then the repo's GitHub context and what GitHub allows there,
// and prints a readable summary. Read-only: no AI call (so no consent), nothing written, only GET requests to
// https://api.github.com. Works without a token on a public repo (anonymous) and says what it couldn't check.
// Every repo-derived string passes safeText, and every line passes hideToken, so no token is ever printed.
import type { Octokit } from '@octokit/rest';
import { isRateStop, newRateBudget, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { probeCapabilities, signingMode, SIGNING_ENVIRONMENT } from '../github/capabilities.js';
import { getAuth, githubTokenRejected, GitHubAccessError, hideToken, makeOctokit, permissionsTable, readGitHubContext } from '../github/client.js';
import { NotGitHubRepoError, readProject } from '../read/project.js';
import type { Auth, Capabilities, RepoProfile, Service } from '../types.js';
import { safeText } from '../util/safe-text.js';
import type { CliIO } from './io.js';

type LocalProfile = Awaited<ReturnType<typeof readProject>>;
type GitHubContext = Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'>;

const I = '  ';
const MAX_LIST = 30;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;

const t = (s: string, max = 200) => safeText(s, max);
const yesNo = (b: boolean) => (b ? 'yes' : 'no');
/** Cleaned items joined with ", ", at most MAX_LIST, or `none`. */
function list(items: readonly string[], none = 'none', max = 100): string {
  if (items.length === 0) return none;
  const shown = items.slice(0, MAX_LIST).map((s) => t(s, max));
  return items.length > MAX_LIST ? `${shown.join(', ')} and ${items.length - MAX_LIST} more` : shown.join(', ');
}

function serviceLines(s: Service): string[] {
  const deps = s.dependsOn.map((d) => `${d.kind}${d.name !== d.kind ? ` ${d.name}` : ''} (${d.evidence})`);
  return [
    `${I}${t(s.name, 100)} (${t(s.path)})`,
    `${I}${I}Language: ${s.language}`,
    `${I}${I}Package manager: ${s.packageManager ?? 'unknown'}`,
    `${I}${I}Runtime: ${s.runtimeVersion === undefined ? 'not pinned' : t(s.runtimeVersion, 60)}`,
    `${I}${I}Frameworks: ${list(s.frameworks)}`,
    ...(s.port === undefined ? [] : [`${I}${I}Port: ${s.port}`]),
    `${I}${I}Tests: ${s.hasTests ? `yes${s.testFramework === undefined ? '' : ` (${t(s.testFramework, 60)})`}` : 'none found'}`,
    `${I}${I}Scripts: ${list(s.scripts)}`,
    ...(s.dockerfile === undefined ? [] : [`${I}${I}Dockerfile: ${t(s.dockerfile)}`]),
    `${I}${I}Env var names: ${list(s.envVars)}`,
    `${I}${I}Dependencies: ${list(deps, 'none found', 200)}`,
  ];
}

function projectLines(p: LocalProfile): string[] {
  const out = [
    'Project',
    `${I}Monorepo: ${p.monorepo}`,
    `${I}Docker Compose: ${yesNo(p.hasCompose)}`,
    `${I}Terraform folders: ${list(p.terraformDirs)}`,
    `${I}Hooks: ${p.precommit ?? 'none'}`,
    '',
    `Services (${p.services.length})`,
    ...p.services.flatMap(serviceLines),
    '',
    `Workflows (${p.existingWorkflows.length})`,
  ];
  if (p.existingWorkflows.length === 0) out.push(`${I}none found`);
  for (const w of p.existingWorkflows) {
    out.push(
      `${I}${t(w.path)}`,
      `${I}${I}Triggers: ${list(w.triggers)}`,
      `${I}${I}Jobs: ${list(w.jobs)}`,
      `${I}${I}Deploys: ${yesNo(w.deploys)}`,
      `${I}${I}Secrets used: ${list(w.secretsUsed)}`,
    );
  }
  return out;
}

const ACCESS: Record<Auth['kind'], string> = {
  anonymous: 'no token (public repo, read anonymously; GitHub allows 60 requests an hour without one)',
  'fine-grained': 'fine-grained token (GITHUB_TOKEN), read-only checks',
  app: 'GitHub App user token, read-only checks',
  classic: 'classic token, allowed by --allow-broad-token (it reaches every repo you have)',
  installation: 'the Actions GITHUB_TOKEN, read-only',
};

function signingText(p: RepoProfile, caps: Capabilities): string {
  switch (signingMode(p, caps)) {
    case 'keyless': return 'keyless (Sigstore; allowed because the repo is public)';
    case 'attest': return 'GitHub artifact attestations';
    case 'key-env': return `a cosign key in the ${SIGNING_ENVIRONMENT} environment, usable from the default branch only`;
    case 'none':
      return caps.environments
        ? `decided at setup: pipegen creates the ${SIGNING_ENVIRONMENT} environment with a default-branch-only rule and reads it back before it relies on a signing key`
        : 'decided at setup: environments were not confirmed here, and without them pipegen does not sign with a key';
  }
}

function githubLines(p: RepoProfile, auth: Auth, caps: Capabilities): string[] {
  const plan = p.plan === 'unknown' ? "unknown (GitHub shows an account's plan only to that account's own token, or to an organization member)" : p.plan;
  return [
    'GitHub',
    `${I}Visibility: ${p.private ? 'private' : 'public'}`,
    `${I}Owner: ${p.ownerType === 'Organization' ? 'organization' : 'user account'}`,
    `${I}Plan: ${plan}`,
    `${I}Default branch: ${t(p.defaultBranch, 100)}`,
    `${I}Access: ${ACCESS[auth.kind]}`,
    '',
    'What GitHub allows here',
    `${I}Merge rules (rulesets): ${yesNo(caps.branchProtection)}`,
    `${I}Environments: ${yesNo(caps.environments)}`,
    `${I}Required deploy reviewers: ${yesNo(caps.envRequiredReviewers)}`,
    // public repos sign keyless and never need the rule, so the line only means something on a private repo
    ...(p.private ? [`${I}Signing environment rule proven (default branch only): ${yesNo(caps.deploymentBranchPolicies)}`] : []),
    `${I}Artifact attestations: ${yesNo(caps.attestations)}`,
    `${I}Code scanning: ${yesNo(caps.codeScanning)}`,
    `${I}Keyless signing: ${yesNo(caps.keylessSigningAllowed)}`,
    `${I}Signing: ${signingText(p, caps)}`,
  ];
}

/**
 * The token's own login (GET /user), which readGitHubContext needs to read a personal account's plan. null for
 * anonymous access and the Actions token (no user), and when GitHub won't say (with a note). A 401 means the token
 * was rejected; a rate stop is thrown.
 */
async function tokenLogin(gh: Octokit, auth: Auth, clock: RateClock, notes: string[]): Promise<string | null> {
  if (auth.kind === 'anonymous' || auth.kind === 'installation') return null;
  try {
    const login = (await withRateLimit(() => gh.rest.users.getAuthenticated(), clock)).data.login;
    return typeof login === 'string' && LOGIN_RE.test(login) ? login : null;
  } catch (e) {
    if (isRateStop(e)) throw e;
    if ((e as { status?: unknown } | null)?.status === 401) throw githubTokenRejected();
    notes.push("Couldn't read which user the token belongs to, so a personal account's plan isn't checked.");
    return null;
  }
}

/** Runs `pipegen inspect` in `dir`. 0: summary printed; 1: not a GitHub repo, or GitHub couldn't be read. */
export async function inspect(dir: string, io: CliIO, opts: { allowBroad: boolean }): Promise<number> {
  let token: string | null = null;
  const say = (s: string) => { io.out(hideToken(s, token)); };
  const fail = (s: string) => { io.err(hideToken(s, token)); };
  const notes: string[] = [];

  let local: LocalProfile;
  try {
    local = await readProject(dir, { notes });
  } catch (e) {
    if (!(e instanceof NotGitHubRepoError)) throw e;
    fail(`pipegen inspect needs a GitHub repository: ${t(e.message, 400)}`);
    fail('Run it inside a clone of a GitHub repo, or pass --dir <folder>.');
    return 1;
  }
  const { owner, repo } = local;

  const clock: RateClock = { budget: newRateBudget() };
  let github: { auth: Auth; p: RepoProfile; caps: Capabilities } | { error: string };
  try {
    const auth = await getAuth({ owner, repos: [repo], allowBroad: opts.allowBroad, mode: 'read' }, { env: io.env, fetch: io.fetch, clock, notes });
    token = auth.token;
    const gh = makeOctokit(auth.token, { fetch: io.fetch, clock, log: fail });
    const login = await tokenLogin(gh, auth, clock, notes);
    const ctx: GitHubContext = await readGitHubContext(gh, owner, repo, login, clock);
    const p: RepoProfile = { ...local, ...ctx };   // GitHub's default branch replaces the reader's 'main' stub
    const caps = await probeCapabilities(gh, owner, repo, p, notes, clock);
    if (auth.kind === 'anonymous') {
      notes.unshift('Not checked without a token: the account\'s GitHub plan, and anything GitHub answers only to a token (see the other notes). '
        + 'Set GITHUB_TOKEN to a read-only fine-grained token for this repo for a full check.');
    }
    github = { auth, p, caps };
  } catch (e) {
    if (!(e instanceof GitHubAccessError) && !isRateStop(e)) throw e;
    github = { error: e instanceof Error ? e.message : String(e) };
  }

  say(`pipegen inspect: ${t(`${owner}/${repo}`)}`);
  say('Read-only: nothing was sent to an AI, and nothing was changed.');
  say('');
  for (const line of projectLines(local)) say(line);
  say('');
  if ('error' in github) {
    say('GitHub: not read (the error is on stderr)');
    fail(`GitHub: not read: ${t(github.error, 1200)}`);
    fail('Not checked: visibility, plan, default branch, and what GitHub allows here.');
  } else {
    for (const line of githubLines(github.p, github.auth, github.caps)) say(line);
    say('');
    say('Read-only permissions pipegen needs here (for a token or its GitHub App)');
    for (const r of permissionsTable('read')) say(`${I}- ${r.permission}: ${r.why}`);
  }
  if (notes.length > 0) {
    say('');
    say('Notes');
    for (const n of notes) say(`${I}- ${t(n, 600)}`);
  }
  return 'error' in github ? 1 : 0;
}
