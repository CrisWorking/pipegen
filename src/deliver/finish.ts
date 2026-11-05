// v0.2 Plan G Task 7, finish (sub-task G11; rulings S10, S11, S13, S18, S24; rows S-7, P-7; Plan V pre-flight §5 G11 items 1-3; G8 carries;
// G10 carries and rulings G10-R1, G10-R4, G10-R5): after the setup pull request is merged, `pipegen finish` applies what must not exist
// before the merge, and records it.
//
// Inputs: ONLY the install record (read through the one trust order, trust.ts) and GitHub as it is now. finish takes the app's name and
// nothing of the run that delivered it (Review Focus 11: it may run a week later on another machine). It re-probes (the plan and
// capabilities through `probe`; who can write, the org role and the sha-pinning setting through G8's probes) and calls planLocks again:
// the requests it sends are the ones planned NOW (a weakened request planted in the record is never sent), for the items the record
// planned (what the user saw in the preview). A planned item GitHub no longer allows is skipped with a plain reason; a route in the
// record's `planned` that pipegen never makes stops finish before anything is sent. A record trusted by typing (G10-R5) carries no
// `planned`, merge time, block date or public key: finish re-derives what it can from GitHub and says what it couldn't.
//
// The order (each write read back; every refused or failed write named to the user and left out of the record, G8-R3):
//   1. the app's rulesets `pipegen` and `pipegen-reviews` (an existing one updated by id, never duplicated); classic branch protection only
//      when GitHub refuses rulesets as not offered on this repo;
//   2. the Actions setting sha_pinning_required (S10), Dependabot alerts, secret scanning and push protection (public repos only; a private
//      repo gets a paid add-on note with no public wording, P-7), the central repo's Actions access (private apps);
//   3. the org required workflow's rule, pinned to the central commit that holds <name>--required.yml (G10-R1), read back;
//   4. the planned environments (their earlier settings kept once as `previous`);
//   5. key-env: pipegen-signing re-verified by read-back (S-7; no read-back: no key, mode none, a note); a key pair only for --rotate-key
//      or when deliver stored none (S11), the private key through its own store path (G10-R1); then PIPEGEN_COSIGN_PUB;
//   6. PIPEGEN_BLOCK_FROM = the merge day + 7 (S18);
//   7. the central ruleset `pipegen` (an existing one reused): a new one is created switched off, so the record commit below can still go
//      straight to the central default branch with the ruleset's id in it;
//   8. the record (writeRecord: the central repo, the setup PR body's marker, the local record file), with the central CODEOWNERS file;
//   9. LAST: the central ruleset switched on (read back active).
// Every created object records GitHub's id and created_at; a setting pipegen turns on records the value it had, once (a re-run never
// records pipegen's own value as `previous`; a value pipegen can't know is left unrecorded, so uninstall leaves it as it is).
//
// `--print` applies nothing: it prints the exact `gh api` commands (and the cosign / `gh secret set` commands, which read values from
// files the user makes), never a secret value. A later `finish` finds what the commands made, applies nothing twice, and records it.
import type { Octokit } from '@octokit/rest';
import type { Prompter } from '../cli/io.js';
import { gitBlobSha } from '../create/guard.js';
import { COSIGN_KEY_SECRET, SecretStoreError, storeCosignKey, storeEnvSecret } from '../create/secrets.js';
import { centralWorkflowFile } from '../engine/central-path.js';
import { CODEOWNERS_BEGIN, CODEOWNERS_END } from '../engine/created-builders.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { CALLER_WORKFLOW } from '../engine/job-rules.js';
import { SIGNING_ENVIRONMENT } from '../engine/referee.js';
import { pubKeySha256 } from '../engine/signing.js';
import { probeCapabilities } from '../github/capabilities.js';
import { clockOf, GitHubAccessError, readGitHubContext } from '../github/client.js';
import { readOrgAdmin, readShaPinning, readWriters, type ShaPinningRead } from '../github/lock-probes.js';
import { signingMode } from '../github/signing-mode.js';
import { CENTRAL_RULESET, GATE_RULESET, LockError, planLocks, REVIEWS_RULESET, type ApiRequest, type LockPlan } from '../layers/locks.js';
import { CENTRAL_REPO } from '../proof/target.js';
import { parseYamlLimited } from '../read/limits.js';
import { emptyRepoFiles } from '../read/quality.js';
import { MAX_WORKFLOWS, tagPinnedOf, WORKFLOW_FILE } from '../read/workflows.js';
import { PROTECTED_PATHS_BASE, type Capabilities, type CreatedFile, type EnvSettings, type ExistingWorkflow, type InstallEdit, type InstallPlanned, type InstallRecord, type Plan, type RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { makeCosignKeyPair, type CosignExec, type CosignResolver } from './cosign-keys.js';
import { ensureSigningEnvironment, plannedOfLocks, readEnv, SETUP_BRANCH } from './deliver.js';
import { DeliverError, ISO_RE, readBlobText, readHead, readRepo, readTree, statusOf, type RepoRef, type TreeEntry } from './git-data.js';
import { centralOf, centralUpdateBranch, readLocalRecord, RecordError, writeRecord, type LocalRecordDeps } from './record.js';
import { classicPutForm, holdsWanted, PLANNED_ROUTES, refusedAsUnavailable, SettingsApi } from './settings-api.js';
import { trustedPrevious } from './trust.js';

export { FINISH_WRITE_ROUTES } from './settings-api.js';

const BLOCK_FROM_VAR = 'PIPEGEN_BLOCK_FROM';
const COSIGN_PUB_VAR = 'PIPEGEN_COSIGN_PUB';
const PASSWORD_SECRET = ['PIPEGEN_COSIGN', 'PASSWORD'].join('_');
const SIGNING_SCOPE = `env:${SIGNING_ENVIRONMENT}` as const;
const CO_PLACES: readonly string[] = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
const SHA_WHAT = 'the Actions setting that requires actions pinned by commit sha';
const DAY_MS = 86_400_000;
const MAX_TEXT = 512 * 1024;
const show = (s: string, n = 140): string => safeText(s, n);
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** finish stops: a plain reason, and nothing was applied (or, after the first write, what was is named). */
export class FinishError extends Error {
  constructor(message: string, options?: { cause?: unknown }) { super(message, options); this.name = 'FinishError'; }
}
/** One step's own refusal (a read-back that doesn't match, an answer that can't be read): reported, the step not applied. */
class StepError extends Error {}

export interface FinishOpts { print?: boolean; rotateKey?: boolean }
/** What the re-probe answers (readGitHubContext and probeCapabilities, githubFinishProbe). */
export interface FinishProbeResult {
  plan: Plan; caps: Capabilities; centralBranchProtection: boolean;
  /** The app's own workflows on its default branch: action references by tag or branch (planLocks leaves sha pinning off then). */
  workflowPins: { tagPinned: number; unchecked: boolean };
}
export type FinishProbe = (gh: Octokit, app: RepoRef, facts: { private: boolean; ownerType: 'User' | 'Organization'; defaultBranch: string; centralDefaultBranch: string }, notes: string[], clock: RateClock) => Promise<FinishProbeResult>;
export interface FinishDeps {
  /** The user's output, one line per call (never a secret value). */
  out: (line: string) => void;
  probe: FinishProbe;
  /** S24: the pinned cosign binary, resolved right before each exec (`() => ensurePinnedBinary('cosign')`); the path is never kept. */
  cosignBin: CosignResolver;
  exec?: CosignExec;
  clock?: RateClock; now?: () => Date; local?: LocalRecordDeps;
  /** The trust question (G10-R-sec6): only an interactive run (a terminal, no --yes, not CI) may ask it. */
  io?: Prompter; interactive?: boolean;
  /** Where the key pair is made (a fresh 0700 folder in it, removed after). Default: the OS temp folder. */
  tmpDir?: string;
}
export interface FinishResult {
  applied: string[]; skipped: { what: string; why: string }[]; notes: string[];
  /** --print: the commands, in order. */
  commands?: string[];
  recordHash?: string; centralPrUrl?: string;
}

type EnvEntry = InstallRecord['environments'][number];
type VarEntry = InstallRecord['variables'][number];
type SecretEntry = InstallRecord['secrets'][number];
interface CoFacts { path: string | null; text: string; isSymlink: boolean; block: string | null }
interface Ctx {
  gh: Octokit; api: SettingsApi; app: RepoRef; central: RepoRef; clock: RateClock; deps: FinishDeps; print: boolean; rotate: boolean;
  rec: InstallRecord; typed: boolean; planned: InstallPlanned; fresh: LockPlan; profile: RepoProfile; caps: Capabilities; shaRead: ShaPinningRead;
  branch: string; ownerType: 'User' | 'Organization'; private: boolean;
  centralHead: string; centralTree: Map<string, TreeEntry>; centralCo: CoFacts;
  applied: string[]; skipped: { what: string; why: string }[]; notes: string[]; commands: string[];
  rulesets: Map<'gate' | 'reviews', InstallRecord['rulesets'][number]>; classic?: InstallRecord['classicProtection']; orgRuleset?: InstallRecord['orgRuleset'];
  repoSettings: NonNullable<InstallRecord['repoSettings']>; centralRec: Partial<NonNullable<InstallRecord['central']>>;
  environments: Map<string, EnvEntry>; variables: VarEntry[]; secrets: SecretEntry[]; cosign?: { pub: string; sha: string };
  centralFiles: { path: string; content: string }[]; files: InstallRecord['files']; edits: InstallEdit[];
  activate?: { id: number; body: Record<string, unknown>; what: string };
}

// ---------- small helpers ----------

/** A stop of the whole run (rate limit, a rejected or insufficient token): passed through, never turned into one skipped step. */
const isStop = (e: unknown): boolean => isRateStop(e) || e instanceof GitHubAccessError;
function whyOf(e: unknown): string {
  if (e instanceof StepError || e instanceof DeliverError || e instanceof SecretStoreError || e instanceof RecordError || e instanceof LockError) return e.message;
  const s = statusOf(e);
  return s === undefined ? 'pipegen got no answer from GitHub.' : `GitHub refused it (HTTP ${s}).`;
}
/** Runs one step; a failure is named (not applied, not recorded) and the next step runs. Returns whether it went through. */
async function step(x: Ctx, what: string, fn: () => Promise<void>): Promise<boolean> {
  try { await fn(); return true; } catch (e) {
    if (isStop(e)) throw e;
    x.skipped.push({ what, why: whyOf(e) });
    return false;
  }
}
const noteAbout = (l: LockPlan, re: RegExp): string | undefined => l.notes.find((n) => re.test(n));
const pathOf = (route: string, params: Readonly<Record<string, unknown>>): string => route.replace(/\{([a-z_]+)\}/g, (_, k: string) => String(params[k]));
/** One `gh api` command; a JSON body goes on stdin through a quoted heredoc (no shell expansion). */
function apiCmd(method: string, route: string, params: Readonly<Record<string, unknown>>, body?: Record<string, unknown>): string {
  return `gh api --method ${method} ${pathOf(route, params)}${body === undefined ? '' : ` --input - <<'PIPEGEN_JSON'\n${JSON.stringify(body)}\nPIPEGEN_JSON`}`;
}
const appParams = (x: Ctx): { owner: string; repo: string } => ({ owner: x.app.owner, repo: x.app.repo });
const centralParams = (x: Ctx): { owner: string; repo: string } => ({ owner: x.central.owner, repo: x.central.repo });

/** pipegen's one CODEOWNERS block in `text` (exactly once), or null. */
function blockOf(text: string): string | null {
  const re = new RegExp(`(?:^|(?<=\\n))${CODEOWNERS_BEGIN}\\n[\\s\\S]*?\\n${CODEOWNERS_END}(?:\\n|$)`, 'g');
  const m = text.match(re);
  return m !== null && m.length === 1 ? m[0] as string : null;
}
/** The code owners a pipegen block names (the same on every line), in order. */
function ownersOf(block: string | null): string[] {
  if (block === null) return [];
  const out: string[] = [];
  for (const line of block.split('\n').slice(1, -1)) for (const t of line.trim().split(/\s+/).slice(1)) if (/^@[A-Za-z0-9-]+$/.test(t) && !out.includes(t)) out.push(t);
  return out;
}
async function coFacts(gh: Octokit, r: RepoRef, entries: ReadonlyMap<string, TreeEntry>, clock: RateClock): Promise<CoFacts> {
  for (const path of CO_PLACES) {
    const e = entries.get(path);
    if (e === undefined) continue;
    if (e.type !== 'blob' || e.mode === '120000') return { path, text: '', isSymlink: true, block: null };
    const text = await readBlobText(gh, r, e.sha, MAX_TEXT, clock);
    return { path, text, isSymlink: false, block: blockOf(text) };
  }
  return { path: null, text: '', isSymlink: false, block: null };
}

// ---------- rulesets ----------

type Target = { kind: 'repo'; repo: RepoRef } | { kind: 'org'; org: string };
const tParams = (t: Target): Record<string, string> => (t.kind === 'repo' ? { owner: t.repo.owner, repo: t.repo.repo } : { org: t.org });
const tRoute = (t: Target, one: boolean): string => (t.kind === 'repo' ? '/repos/{owner}/{repo}/rulesets' : '/orgs/{org}/rulesets') + (one ? '/{ruleset_id}' : '');

async function listRulesets(x: Ctx, t: Target): Promise<{ id: number; name: string }[]> {
  const d = (await x.api.read(`GET ${tRoute(t, false)}`, { ...tParams(t), per_page: 100, ...(t.kind === 'repo' ? { includes_parents: false } : {}) })).data;
  if (!Array.isArray(d)) throw new StepError('GitHub\'s list of rulesets could not be read.');
  return d.filter(isObj).filter((r) => Number.isSafeInteger(r.id) && typeof r.name === 'string').map((r) => ({ id: r.id as number, name: r.name as string }));
}
const getRuleset = async (x: Ctx, t: Target, id: number): Promise<Record<string, unknown> | null> => {
  const d = await x.api.readOr404(`GET ${tRoute(t, true)}`, { ...tParams(t), ruleset_id: id });
  return isObj(d) ? d : null;
};
interface Upserted { id: number; createdAt: string | null; wrote: 'created' | 'updated' | 'none' }
/** The ruleset `name` as `want`: an existing one (by name) kept when it already holds it, else updated by id; a new one created. Read back. */
async function upsertRuleset(x: Ctx, t: Target, name: string, want: Record<string, unknown>, existing: readonly { id: number; name: string }[]): Promise<Upserted> {
  const same = existing.filter((r) => r.name === name);
  if (same.length > 1) throw new StepError(`There is more than one ruleset named ${show(name, 100)}; remove the extra ones, then run finish again.`);
  let id: number;
  let wrote: Upserted['wrote'];
  if (same[0] !== undefined) {
    id = same[0].id;
    const cur = await getRuleset(x, t, id);
    if (cur !== null && holdsWanted(want, cur)) wrote = 'none';
    else { await x.api.write(`PUT ${tRoute(t, true)}`, { ...tParams(t), ruleset_id: id, ...want }); wrote = 'updated'; }
  } else {
    const d = await x.api.write(`POST ${tRoute(t, false)}`, { ...tParams(t), ...want });
    if (!isObj(d) || !Number.isSafeInteger(d.id) || (d.id as number) <= 0) throw new StepError(`GitHub's answer to the new ruleset ${show(name, 100)} could not be read.`);
    id = d.id as number;
    wrote = 'created';
  }
  const back = await getRuleset(x, t, id);
  if (back === null || !holdsWanted(want, back)) throw new StepError(`The ruleset ${show(name, 100)} doesn't read back as pipegen set it.`);
  return { id, createdAt: typeof back.created_at === 'string' && ISO_RE.test(back.created_at) ? back.created_at : null, wrote };
}
async function printRuleset(x: Ctx, t: Target, name: string, req: ApiRequest, existing: readonly { id: number; name: string }[]): Promise<void> {
  const ex = existing.find((r) => r.name === name);
  if (ex === undefined) { x.commands.push(apiCmd(req.method, req.route, req.params, req.body)); return; }
  const cur = await getRuleset(x, t, ex.id);
  if (cur !== null && holdsWanted(req.body, cur)) { x.commands.push(`# ruleset ${name} is already as pipegen sets it`); return; }
  x.commands.push(apiCmd('PUT', tRoute(t, true), { ...tParams(t), ruleset_id: ex.id }, req.body));
}

// ---------- 1. the app's locks ----------

async function appLocks(x: Ctx): Promise<void> {
  const P = x.planned;
  const F = x.fresh;
  if (P.rulesets === undefined && P.classic === undefined) return;
  const what = 'the merge locks (rulesets pipegen and pipegen-reviews)';
  if (F.rulesets === undefined) { x.skipped.push({ what, why: noteAbout(F, /lock merges|branch rules/) ?? 'GitHub no longer offers branch rules on this repo.' }); return; }
  const t: Target = { kind: 'repo', repo: x.app };
  let unavailable = P.rulesets === undefined;
  let existing: { id: number; name: string }[] = [];
  if (!unavailable) {
    try { existing = await listRulesets(x, t); } catch (e) {
      if (isStop(e)) throw e;
      if (refusedAsUnavailable(e)) unavailable = true;
      else { x.skipped.push({ what, why: whyOf(e) }); return; }
    }
  }
  const kinds: ['gate' | 'reviews', string, ApiRequest][] = [['gate', GATE_RULESET, F.rulesets.gate], ...(P.rulesets?.reviews === undefined ? [] : [['reviews', REVIEWS_RULESET, F.rulesets.reviews] as ['reviews', string, ApiRequest]])];
  if (!unavailable) {
    for (const [kind, name, req] of kinds) {
      if (x.print) { await printRuleset(x, t, name, req, existing); continue; }
      try {
        const r = await upsertRuleset(x, t, name, req.body, existing);
        x.applied.push(`ruleset ${name}${r.wrote === 'none' ? ' (already in place)' : ''}`);
        const prior = x.rec.rulesets.find((p) => p.kind === kind && p.id === r.id && p.githubCreatedAt === r.createdAt);
        if (r.createdAt !== null && (prior !== undefined || r.wrote !== 'updated')) x.rulesets.set(kind, { kind, id: r.id, name: name as 'pipegen' | 'pipegen-reviews', githubCreatedAt: r.createdAt });
        else x.notes.push(`The ruleset ${name} that was already on ${show(`${x.app.owner}/${x.app.repo}`)} now holds pipegen's rules, but pipegen can't show it made it, so it is not recorded (uninstall leaves it).`);
      } catch (e) {
        if (isStop(e)) throw e;
        if (refusedAsUnavailable(e)) { unavailable = true; break; }
        x.skipped.push({ what: `ruleset ${name}`, why: whyOf(e) });
      }
    }
  }
  if (x.print && F.classic !== undefined && P.classic !== undefined) {
    x.commands.push('# Only if GitHub refuses the rulesets as not offered on this repo: classic branch protection instead (the same check and review rules)');
    x.commands.push(`# ${apiCmd(F.classic.method, F.classic.route, F.classic.params, F.classic.body).replace(/\n/g, '\n# ')}`);
  }
  if (unavailable && !x.print) await classic(x);
}

/** G8 carry: classic protection, only after GitHub refused rulesets as not offered. Its PUT-form body before is recorded once (null: none). */
async function classic(x: Ctx): Promise<void> {
  const req = x.fresh.classic;
  const what = `classic branch protection on ${show(x.branch, 100)}`;
  if (req === undefined || x.planned.classic === undefined) { x.skipped.push({ what, why: 'GitHub doesn\'t offer rulesets on this repo, and no classic protection was planned.' }); return; }
  x.notes.push('GitHub doesn\'t offer rulesets on this repo, so pipegen uses classic branch protection instead: the same required check, bound to the same app, and the same review rules.');
  await step(x, what, async () => {
    const route = 'GET /repos/{owner}/{repo}/branches/{branch}/protection';
    const cur = await x.api.readOr404(route, req.params);
    const before = cur === null ? null : classicPutForm(cur);
    const prior = x.rec.classicProtection?.branch === x.branch ? x.rec.classicProtection : undefined;
    if (before !== null && holdsWanted(req.body, before)) {
      x.applied.push(`${what} (already in place)`);
      if (prior !== undefined) x.classic = prior;
      else x.notes.push(`Classic branch protection on ${show(x.branch, 100)} was already as pipegen sets it, so pipegen can't tell what it was before and doesn't record it (uninstall leaves it as it is).`);
      return;
    }
    await x.api.write(`${req.method} ${req.route}`, { ...req.params, ...req.body });
    const back = await x.api.readOr404(route, req.params);
    if (back === null || !holdsWanted(req.body, classicPutForm(back))) throw new StepError(`Classic branch protection on ${show(x.branch, 100)} doesn't read back as pipegen set it.`);
    x.classic = prior ?? { branch: x.branch, previous: before };
    x.applied.push(what);
  });
}

// ---------- 2. repo settings ----------

async function shaPinning(x: Ctx): Promise<void> {
  if (x.planned.shaPinning === undefined) return;
  const F = x.fresh.shaPinning;
  if (F === undefined || x.shaRead.state !== 'read') { x.skipped.push({ what: SHA_WHAT, why: noteAbout(x.fresh, /full-length commit SHA/) ?? 'GitHub doesn\'t offer the setting on this repo now.' }); return; }
  const prior = x.rec.repoSettings?.shaPinningRequired;
  if (x.shaRead.required) {
    if (prior !== undefined) x.repoSettings.shaPinningRequired = prior;
    x.applied.push(`${SHA_WHAT} (already on)`);
    return;
  }
  if (x.print) { x.commands.push(apiCmd(F.request.method, F.request.route, F.request.params, F.request.body)); return; }
  await step(x, SHA_WHAT, async () => {
    await x.api.write(`${F.request.method} ${F.request.route}`, { ...F.request.params, ...F.request.body });
    const back = await readShaPinning(x.gh, x.app.owner, x.app.repo, [], x.clock);
    if (back.state !== 'read' || back.required !== true) throw new StepError('The setting doesn\'t read back as on.');
    x.repoSettings.shaPinningRequired = prior ?? { previous: false };
    x.applied.push(SHA_WHAT);
  });
}

async function securitySettings(x: Ctx): Promise<void> {
  const p = appParams(x);
  const alertsOn = async (): Promise<boolean> => {
    try { return (await x.api.read('GET /repos/{owner}/{repo}/vulnerability-alerts', p)).status === 204; } catch (e) {
      if (statusOf(e) === 404) return false;
      throw e;
    }
  };
  const what = 'Dependabot alerts';
  await step(x, what, async () => {
    const prior = x.rec.repoSettings?.vulnerabilityAlerts;
    if (await alertsOn()) {
      if (prior !== undefined) x.repoSettings.vulnerabilityAlerts = prior;
      x.applied.push(`${what} (already on)`);
      return;
    }
    if (x.print) { x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/vulnerability-alerts', p)); return; }
    await x.api.write('PUT /repos/{owner}/{repo}/vulnerability-alerts', p);
    if (!await alertsOn()) throw new StepError('Dependabot alerts don\'t read back as on.');
    x.repoSettings.vulnerabilityAlerts = prior ?? { previous: false };
    x.applied.push(what);
  });
  if (x.private) {
    x.notes.push('Secret scanning and push protection on a private repo come with GitHub\'s paid Secret Protection add-on, so pipegen leaves them as they are; turn them on in the repository settings if you have the add-on.');
    return;
  }
  const what2 = 'secret scanning and push protection';
  await step(x, what2, async () => {
    const read = async (): Promise<{ ss: boolean; pp: boolean }> => {
      const d = (await x.api.read('GET /repos/{owner}/{repo}', p)).data;
      const sa = isObj(d) && isObj(d.security_and_analysis) ? d.security_and_analysis : {};
      const on = (k: string): boolean => isObj(sa[k]) && (sa[k] as { status?: unknown }).status === 'enabled';
      return { ss: on('secret_scanning'), pp: on('secret_scanning_push_protection') };
    };
    const cur = await read();
    const prior = { ss: x.rec.repoSettings?.secretScanning, pp: x.rec.repoSettings?.pushProtection };
    const keep = (): void => {
      if (prior.ss !== undefined) x.repoSettings.secretScanning = prior.ss;
      if (prior.pp !== undefined) x.repoSettings.pushProtection = prior.pp;
    };
    if (cur.ss && cur.pp) { keep(); x.applied.push(`${what2} (already on)`); return; }
    const body = { security_and_analysis: { secret_scanning: { status: 'enabled' }, secret_scanning_push_protection: { status: 'enabled' } } };
    if (x.print) { x.commands.push(apiCmd('PATCH', '/repos/{owner}/{repo}', p, body)); return; }
    await x.api.write('PATCH /repos/{owner}/{repo}', { ...p, ...body });
    const back = await read();
    if (!back.ss || !back.pp) throw new StepError('Secret scanning and push protection don\'t read back as on.');
    keep();
    if (prior.ss === undefined && !cur.ss) x.repoSettings.secretScanning = { previous: false };
    if (prior.pp === undefined && !cur.pp) x.repoSettings.pushProtection = { previous: false };
    x.applied.push(what2);
  });
}

/** The central repo's Actions access (private apps: the app's workflows call the central ones). Its earlier level recorded once. */
async function actionsAccess(x: Ctx): Promise<void> {
  if (!x.private) return;
  const level = x.ownerType === 'Organization' ? 'organization' : 'user';
  const what = `the Actions access of ${show(`${x.central.owner}/${x.central.repo}`)} (${level})`;
  const p = centralParams(x);
  await step(x, what, async () => {
    const read = async (): Promise<string | null> => {
      const d = (await x.api.read('GET /repos/{owner}/{repo}/actions/permissions/access', p)).data;
      return isObj(d) && typeof d.access_level === 'string' ? d.access_level : null;
    };
    const cur = await read();
    const prior = x.rec.central?.actionsAccess;
    if (cur === level || (level === 'organization' && cur === 'enterprise')) {
      if (prior !== undefined) x.centralRec.actionsAccess = prior;
      x.applied.push(`${what} (already set)`);
      return;
    }
    if (x.print) { x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/actions/permissions/access', p, { access_level: level })); return; }
    await x.api.write('PUT /repos/{owner}/{repo}/actions/permissions/access', { ...p, access_level: level });
    if (await read() !== level) throw new StepError('The access level doesn\'t read back as set.');
    const prev = prior ?? (cur !== null && /^[a-z_]{1,40}$/.test(cur) ? { previous: cur } : undefined);
    if (prev !== undefined) x.centralRec.actionsAccess = prev;
    x.applied.push(what);
  });
}

// ---------- 3. the org required workflow ----------

async function orgRequired(x: Ctx): Promise<void> {
  if (x.planned.orgRequiredWorkflow === undefined) return;
  const what = 'the org required workflow';
  const F = x.fresh.orgRequiredWorkflow;
  if (F === undefined) { x.skipped.push({ what, why: noteAbout(x.fresh, /org required workflow/) ?? 'It can\'t be planned on this repo now.' }); return; }
  // G10-R1: the rule runs the file at the commit it names; the file exists only from the record's commit on (it calls the pinned one)
  const e = x.centralTree.get(F.file.path);
  if (e === undefined || e.type !== 'blob' || e.mode !== '100644' || e.sha !== gitBlobSha(F.file.content)) {
    x.skipped.push({ what, why: `The central default branch of ${show(`${x.central.owner}/${x.central.repo}`)} doesn't hold ${show(F.file.path)} as pipegen wrote it, so pipegen adds no rule that would run it; run pipegen again to deliver it.` });
    return;
  }
  const body = structuredClone(F.rule.body);
  const rules = Array.isArray(body.rules) ? body.rules : [];
  const wf = (rules[0] as { parameters?: { workflows?: Record<string, unknown>[] } } | undefined)?.parameters?.workflows?.[0];
  if (wf === undefined || wf.path !== F.file.path) { x.skipped.push({ what, why: 'The planned rule doesn\'t name the required workflow.' }); return; }
  wf.sha = x.centralHead;
  const name = String(body.name);
  const t: Target = { kind: 'org', org: x.app.owner };
  await step(x, `${what} (ruleset ${show(name, 100)})`, async () => {
    const existing = await listRulesets(x, t);
    if (x.print) { await printRuleset(x, t, name, { ...F.rule, body }, existing); return; }
    const r = await upsertRuleset(x, t, name, body, existing);
    const prior = x.rec.orgRuleset;
    const own = (prior !== undefined && prior.id === r.id && prior.githubCreatedAt === r.createdAt) || r.wrote !== 'updated';
    if (own && r.createdAt !== null) x.orgRuleset = { org: x.app.owner, id: r.id, name, githubCreatedAt: r.createdAt };
    else x.notes.push(`The org ruleset ${show(name, 100)} that was already there now holds pipegen's rule, but pipegen can't show it made it, so it is not recorded (uninstall leaves it).`);
    x.applied.push(`${what} (ruleset ${show(name, 100)}, pinned to ${x.centralHead.slice(0, 12)})${r.wrote === 'none' ? ' (already in place)' : ''}`);
  });
}

// ---------- 4. environments ----------

async function environments(x: Ctx): Promise<void> {
  for (const e of x.planned.environments) {
    if (e.name === SIGNING_ENVIRONMENT) continue;
    const what = `environment ${show(e.name, 100)}`;
    if (!x.caps.environments) { x.skipped.push({ what, why: 'GitHub no longer offers environments on this repo (its plan), so pipegen leaves it.' }); continue; }
    await step(x, what, async () => {
      const ids: { type: 'User'; id: number }[] = [];
      if (e.reviewers) {
        if (!x.caps.envRequiredReviewers) x.notes.push(`GitHub doesn't offer required reviewers on this repo's environments, so ${what} gets none.`);
        else if (x.fresh.owners.app.length === 0) x.notes.push(`No code owners review changes here, so ${what} gets no required reviewers: nobody else could approve a deploy.`);
        else {
          for (const login of x.fresh.owners.app.slice(0, 6)) {
            const d = (await x.api.read('GET /users/{username}', { username: login.slice(1) })).data;
            if (!isObj(d) || !Number.isSafeInteger(d.id) || (d.id as number) <= 0) throw new StepError(`GitHub's answer about ${show(login, 40)} could not be read.`);
            ids.push({ type: 'User', id: d.id as number });
          }
        }
      }
      const cur = await readEnv(x.gh, x.app, x.clock, e.name);
      const s = cur?.settings;
      const want: Omit<EnvSettings, 'branch_policies'> = {
        wait_timer: s?.wait_timer ?? 0, prevent_self_review: ids.length > 0 ? true : s?.prevent_self_review ?? false, reviewers: ids.length > 0 ? ids : s?.reviewers ?? [],
        can_admins_bypass: s?.can_admins_bypass ?? true, deployment_branch_policy: s?.deployment_branch_policy ?? null,
      };
      const keys = Object.keys(want) as (keyof typeof want)[];
      const changed = cur === null ? [] : keys.filter((k) => JSON.stringify(want[k]) !== JSON.stringify(s?.[k]));
      let back = cur;
      if (cur === null || changed.length > 0) {
        const params = { ...appParams(x), environment_name: e.name };
        if (x.print) { x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/environments/{environment_name}', params, { ...want })); return; }
        await x.api.write('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...params, ...want });
        back = await readEnv(x.gh, x.app, x.clock, e.name);
        if (back === null || keys.some((k) => JSON.stringify(back?.settings[k]) !== JSON.stringify(want[k]))) throw new StepError(`The environment ${show(e.name, 100)} doesn't read back as pipegen set it.`);
      }
      if (x.print) return;
      const at = back?.createdAt ?? null;
      const atField = at !== null && ISO_RE.test(at) ? { githubCreatedAt: at } : { unconfirmed: true as const };
      const prior = x.rec.environments.find((p) => p.name === e.name);
      let entry: EnvEntry;
      if (prior !== undefined && prior.githubCreatedAt !== undefined && prior.githubCreatedAt === at) entry = { ...prior, changed: [...new Set([...prior.changed, ...changed])] };   // captured once
      else if (cur === null) entry = { name: e.name, created: true, ...atField, changed: [], branchPolicyIds: [] };
      else if (changed.length > 0) entry = { name: e.name, created: false, ...atField, previous: { ...cur.settings, branch_policies: cur.policies.map((p) => ({ name: p.name, type: p.type })) }, changed, branchPolicyIds: [] };
      else entry = { name: e.name, created: false, ...atField, changed: [], branchPolicyIds: [] };
      x.environments.set(e.name, entry);
      x.applied.push(`${what}${cur !== null && changed.length === 0 ? ' (already in place)' : ''}`);
    });
  }
}

// ---------- 5. signing ----------

async function secretAt(x: Ctx, name: string): Promise<string | null> {
  const d = await x.api.readOr404('GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { ...appParams(x), environment_name: SIGNING_ENVIRONMENT, secret_name: name });
  if (d === null) return null;
  return isObj(d) && typeof d.created_at === 'string' ? d.created_at : '';
}

/** A repo or environment variable set to `value` (created, or changed from what it was), read back; its record entry kept once. */
async function setVariable(x: Ctx, scope: 'repo' | `env:${string}`, name: string, value: string, what: string): Promise<void> {
  const env = scope === 'repo' ? null : scope.slice(4);
  const p = { ...appParams(x), ...(env === null ? {} : { environment_name: env }) };
  const one = env === null ? '/repos/{owner}/{repo}/actions/variables/{name}' : '/repos/{owner}/{repo}/environments/{environment_name}/variables/{name}';
  const all = env === null ? '/repos/{owner}/{repo}/actions/variables' : '/repos/{owner}/{repo}/environments/{environment_name}/variables';
  const read = async (): Promise<{ value: string; createdAt: string | null } | null> => {
    const d = await x.api.readOr404(`GET ${one}`, { ...p, name });
    if (d === null) return null;
    if (!isObj(d) || typeof d.value !== 'string') throw new StepError(`GitHub's answer about ${name} could not be read.`);
    return { value: d.value, createdAt: typeof d.created_at === 'string' && ISO_RE.test(d.created_at) ? d.created_at : null };
  };
  const cur = await read();
  if (cur !== null && cur.value !== value && cur.value.length > 10_000) throw new StepError(`${name} holds a value too long for pipegen to keep for uninstall, so pipegen leaves it; remove it, then run finish again.`);
  if (x.print) {
    if (cur?.value === value) { x.commands.push(`# ${name} is already set`); return; }
    x.commands.push(env === null ? `gh variable set ${name} --repo ${x.app.owner}/${x.app.repo} --body ${value}` : `gh variable set ${name} --env ${env} --repo ${x.app.owner}/${x.app.repo} --body '${value}'`);
    return;
  }
  if (cur === null) await x.api.write(`POST ${all}`, { ...p, name, value });
  else if (cur.value !== value) await x.api.write(`PATCH ${one}`, { ...p, name, value });
  const back = await read();
  if (back === null || back.value !== value) throw new StepError(`${name} doesn't read back as pipegen set it.`);
  const at = back.createdAt === null ? { unconfirmed: true as const } : { githubCreatedAt: back.createdAt };
  const prior = x.rec.variables.find((v) => v.name === name && v.scope === scope);
  let entry: VarEntry;
  if (prior !== undefined && prior.githubCreatedAt !== undefined && prior.githubCreatedAt === back.createdAt) entry = { ...prior };   // captured once: never pipegen's own value as previous
  else if (cur === null) entry = { name, scope, created: true, ...at };
  else if (cur.value !== value) entry = { name, scope, created: false, previous: cur.value, ...at };
  else entry = { name, scope, created: false, ...at };
  x.variables = [...x.variables.filter((v) => !(v.name === name && v.scope === scope)), entry];
  x.applied.push(cur?.value === value ? `${what} (already set)` : what);
}

async function signing(x: Ctx): Promise<void> {
  if (x.planned.signingMode !== 'key-env') return;
  const whatEnv = `the signing environment ${SIGNING_ENVIRONMENT} (default branch only)`;
  const whatKey = `the signing key (${COSIGN_KEY_SECRET}, ${PASSWORD_SECRET})`;
  const whatPub = `${COSIGN_PUB_VAR} (environment ${SIGNING_ENVIRONMENT})`;
  if (!x.caps.environments) { x.skipped.push({ what: whatEnv, why: 'GitHub no longer offers environments on this repo, so pipegen keeps no signing key there: signing is off (mode none).' }); return; }
  const needKey = x.rotate || !x.rec.secrets.some((s) => s.scope === SIGNING_SCOPE && s.name === COSIGN_KEY_SECRET);
  const repo = `${x.app.owner}/${x.app.repo}`;
  if (x.print) {
    const env = await readEnv(x.gh, x.app, x.clock);
    const ok = env !== null && env.settings.deployment_branch_policy?.protected_branches === false && env.settings.deployment_branch_policy.custom_branch_policies === true && env.policies.length === 1 && env.policies[0]?.name === x.branch && env.policies[0].type === 'branch';
    if (!ok) {
      x.commands.push(`# The environment ${SIGNING_ENVIRONMENT}, usable from the default branch only (check it reads back so before you store a key in it)`);
      x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/environments/{environment_name}', { ...appParams(x), environment_name: SIGNING_ENVIRONMENT }, { deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }));
      x.commands.push(apiCmd('POST', '/repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies', { ...appParams(x), environment_name: SIGNING_ENVIRONMENT }, { name: x.branch, type: 'branch' }));
    }
    if (needKey) {
      x.commands.push('# A new key pair, in a private folder: cosign asks for a password; save it to pipegen-signing.password (never in a command line)');
      x.commands.push('cosign generate-key-pair --output-key-prefix pipegen-signing');
      x.commands.push(`gh secret set ${COSIGN_KEY_SECRET} --env ${SIGNING_ENVIRONMENT} --repo ${repo} < pipegen-signing.key`);
      x.commands.push(`gh secret set ${PASSWORD_SECRET} --env ${SIGNING_ENVIRONMENT} --repo ${repo} < pipegen-signing.password`);
      x.commands.push(`gh variable set ${COSIGN_PUB_VAR} --env ${SIGNING_ENVIRONMENT} --repo ${repo} < pipegen-signing.pub`);
      x.commands.push('# Then delete the three files. The verify step checks the new public key\'s sha256 only after a pull request puts it in your workflow (run `npx pipegen` again).');
    } else if (x.rec.cosignPub !== undefined) await step(x, whatPub, () => setVariable(x, SIGNING_SCOPE, COSIGN_PUB_VAR, x.rec.cosignPub as string, whatPub));
    return;
  }
  // S-7: the environment and its default-branch rule, read back, before any key
  let env: EnvEntry;
  try { env = await ensureSigningEnvironment(x.gh, x.app, x.branch, x.rec.environments.find((e) => e.name === SIGNING_ENVIRONMENT), x.clock, x.notes); } catch (e) {
    if (isStop(e)) throw e;
    x.skipped.push({ what: whatKey, why: `${whyOf(e)} pipegen stores no signing key and sets no ${COSIGN_PUB_VAR}: signing is off (mode none) until it does.` });
    x.notes.push(`Signing is off (mode none): the environment ${SIGNING_ENVIRONMENT} didn't read back as usable from the default branch only. Fix it in the repository settings, then run \`npx pipegen finish\` again.`);
    return;
  }
  x.environments.set(SIGNING_ENVIRONMENT, env);
  x.applied.push(whatEnv);
  if (signingMode(x.profile, { ...x.caps, deploymentBranchPolicies: true }) !== 'key-env') {
    x.skipped.push({ what: whatKey, why: 'GitHub doesn\'t offer what key-env signing needs on this repo now, so pipegen stores no key: signing is off (mode none).' });
    return;
  }
  let pub: string;
  if (needKey) {
    let made = false;
    let fresh = '';
    await step(x, whatKey, async () => {
      const pair = await makeCosignKeyPair(x.deps.cosignBin, x.deps.exec, x.deps.tmpDir);
      const stores: [string, () => Promise<void>][] = [
        [COSIGN_KEY_SECRET, () => storeCosignKey(x.gh, x.app, SIGNING_ENVIRONMENT, pair.key, x.clock)],
        [PASSWORD_SECRET, () => storeEnvSecret(x.gh, x.app, SIGNING_ENVIRONMENT, PASSWORD_SECRET, pair.password, x.clock)],
      ];
      // deliver stored none (S11): an existing secret of the same name is not pipegen's to replace without --rotate-key
      if (!x.rotate) for (const [name] of stores) if (await secretAt(x, name) !== null) throw new StepError(`${SIGNING_ENVIRONMENT} already has ${name}, which no install record shows pipegen stored; run \`npx pipegen finish --rotate-key\` to replace the key pair.`);
      for (const [name, store] of stores) {
        const before = await secretAt(x, name);
        await store();
        const after = await secretAt(x, name).catch((e: unknown) => { if (isStop(e)) throw e; return null; });
        const at = after !== null && ISO_RE.test(after) ? { githubCreatedAt: after } : { unconfirmed: true as const };
        const prior = x.rec.secrets.find((s) => s.name === name && s.scope === SIGNING_SCOPE);
        const own = before !== null && prior?.created === true && prior.githubCreatedAt === before;
        x.secrets.push(before === null || own ? { name, scope: SIGNING_SCOPE, created: true, ...at } : { name, scope: SIGNING_SCOPE, created: false, overwritten: true, ...at });
      }
      fresh = pair.pub;
      made = true;
    });
    if (!made) return;
    pub = fresh;
    x.applied.push(whatKey);
    x.notes.push('The new signing key replaces the old one: images signed with the old key won\'t verify any more. Re-run the pipeline on the commit you deploy to sign it again with the new key.');
    x.notes.push('The verify step fails closed until a pull request puts the new public key\'s sha256 in your workflow: that literal changes only through a pull request (run `npx pipegen` again to open it). `npx pipegen verify` reports the key as changed until the central pull request with the new install record is merged.');
  } else {
    const p = x.rec.cosignPub;
    if (p === undefined || x.rec.cosignPubSha256 === undefined || pubKeySha256(p) !== x.rec.cosignPubSha256) {
      x.skipped.push({ what: whatPub, why: `pipegen couldn't re-derive the public key from the install record (${x.typed ? 'a record confirmed by typing doesn\'t carry it' : 'it holds none'}), so it sets no ${COSIGN_PUB_VAR}; run \`npx pipegen finish --rotate-key\` to make a new key pair.` });
      return;
    }
    const missing: string[] = [];
    for (const name of [COSIGN_KEY_SECRET, PASSWORD_SECRET]) if (await secretAt(x, name) === null) missing.push(name);
    if (missing.length > 0) x.skipped.push({ what: whatKey, why: `${missing.join(' and ')} ${missing.length === 1 ? 'is' : 'are'} missing from ${SIGNING_ENVIRONMENT}, so nothing can be signed; run \`npx pipegen finish --rotate-key\` to make a new key pair.` });
    pub = p;
  }
  if (await step(x, whatPub, () => setVariable(x, SIGNING_SCOPE, COSIGN_PUB_VAR, pub, whatPub))) x.cosign = { pub, sha: pubKeySha256(pub) };
  else if (needKey) x.cosign = { pub, sha: pubKeySha256(pub) };   // the key pair is stored: the record names its public key, so verify reports the variable
}

// ---------- 7. the central ruleset and CODEOWNERS ----------

async function centralRuleset(x: Ctx): Promise<void> {
  if (x.planned.centralRuleset === undefined) return;
  const what = `the central merge rule (ruleset ${CENTRAL_RULESET} on ${show(`${x.central.owner}/${x.central.repo}`)})`;
  const F = x.fresh.centralRuleset;
  if (F === undefined) { x.skipped.push({ what, why: noteAbout(x.fresh, /lock merges on the private/) ?? 'GitHub no longer offers branch rules on the central repo.' }); return; }
  const t: Target = { kind: 'repo', repo: x.central };
  await step(x, what, async () => {
    const existing = await listRulesets(x, t);
    if (x.print) { await printRuleset(x, t, CENTRAL_RULESET, F, existing); return; }
    if (existing.some((r) => r.name === CENTRAL_RULESET)) {
      // reused (another project's, or this one's from an earlier finish): never a second one
      const r = await upsertRuleset(x, t, CENTRAL_RULESET, F.body, existing);
      if (r.createdAt === null) throw new StepError('GitHub didn\'t say when it made the central ruleset, so pipegen can\'t record it.');
      x.centralRec.rulesetId = r.id;
      x.centralRec.rulesetCreatedAt = r.createdAt;
      x.applied.push(`${what} (${r.wrote === 'none' ? 'reused: already in place' : 'updated'})`);
      return;
    }
    // new: made switched off now, switched on last (after the record commit, which it would otherwise refuse)
    const off = { ...F.body, enforcement: 'disabled' };
    const r = await upsertRuleset(x, t, CENTRAL_RULESET, off, existing);
    if (r.createdAt === null) throw new StepError('GitHub didn\'t say when it made the central ruleset, so pipegen can\'t record it.');
    x.centralRec.rulesetId = r.id;
    x.centralRec.rulesetCreatedAt = r.createdAt;
    x.activate = { id: r.id, body: F.body, what };
  });
}

/** The central CODEOWNERS: an existing pipegen block is reused; else the planned file goes with the record commit (before the rule is on). */
function centralCodeowners(x: Ctx): void {
  const F = x.fresh.centralCodeowners;
  if (F === undefined || x.planned.centralRuleset === undefined) return;
  const c = x.centralCo;
  if (c.block !== null && c.path !== null) {
    const was = x.rec.central?.codeowners;
    x.centralRec.codeowners = { path: c.path, created: was?.path === c.path ? was.created : false };
    x.applied.push(`the central CODEOWNERS (${show(c.path)}, reused)`);
    return;
  }
  if (x.print) {
    x.commands.push(`# Add ${F.file.path} to ${x.central.owner}/${x.central.repo} with this text, before you switch its ruleset on:`);
    for (const line of F.file.content.replace(/\n$/, '').split('\n')) x.commands.push(`#   ${line}`);
    return;
  }
  const sha = gitBlobSha(F.file.content);
  x.centralFiles.push({ path: F.file.path, content: F.file.content });
  x.centralRec.codeowners = { path: F.file.path, created: c.path === null };
  if (c.path === null) {
    const at = x.files.findIndex((f) => f.repo === 'central' && f.path === F.file.path);
    const shas = at < 0 ? [sha] : [...(x.files[at]?.shas ?? []).filter((s) => s !== sha), sha];
    const entry = { repo: 'central' as const, path: F.file.path, part: 'codeowners' as const, shas };
    x.files = at < 0 ? [...x.files, entry] : x.files.map((f, i) => (i === at ? entry : f));
  } else {
    const original = c.text;
    const inserted = F.file.content.startsWith(original) ? F.file.content.slice(original.length) : null;
    if (inserted === null) return;
    x.edits = [...x.edits.filter((e) => !(e.repo === 'central' && e.path === F.file.path)), { repo: 'central', path: F.file.path, kind: 'codeowners', inserted, originalSha: gitBlobSha(original), writtenShas: [sha] }];
  }
}

// ---------- the record ----------

function buildRecord(x: Ctx, mergedAt: string, blockFrom: string): InstallRecord {
  const r = x.rec;
  const handled = new Set(x.rulesets.keys());
  return {
    ...r, mergedAt, blockFrom, files: x.files, edits: x.edits,
    secrets: [...r.secrets.filter((s) => !x.secrets.some((n) => n.name === s.name && n.scope === s.scope)), ...x.secrets],
    variables: [...r.variables.filter((v) => !x.variables.some((n) => n.name === v.name && n.scope === v.scope)), ...x.variables],
    environments: [...r.environments.filter((e) => !x.environments.has(e.name)), ...x.environments.values()],
    rulesets: [...r.rulesets.filter((s) => !handled.has(s.kind)), ...x.rulesets.values()],
    ...(x.classic ?? r.classicProtection) === undefined ? {} : { classicProtection: x.classic ?? r.classicProtection },
    ...(x.orgRuleset ?? r.orgRuleset) === undefined ? {} : { orgRuleset: x.orgRuleset ?? r.orgRuleset },
    ...(Object.keys({ ...r.repoSettings, ...x.repoSettings }).length === 0 ? {} : { repoSettings: { ...r.repoSettings, ...x.repoSettings } }),
    central: { ...(r.central ?? { createdByPipegen: false }), ...x.centralRec },
    planned: x.planned,
    ...(x.cosign === undefined ? {} : { cosignPubSha256: x.cosign.sha, cosignPub: x.cosign.pub }),
  };
}

// ---------- the setup pull request ----------

async function setupPr(x: { api: SettingsApi; app: RepoRef; branch: string }, local: number | undefined): Promise<{ number: number; mergedAt: string | null; state: string }> {
  let num = local;
  if (num === undefined) {
    const d = (await x.api.read('GET /repos/{owner}/{repo}/pulls', { owner: x.app.owner, repo: x.app.repo, head: `${x.app.owner}:${SETUP_BRANCH}`, state: 'all', per_page: 100 })).data;
    const list = Array.isArray(d) ? d.filter(isObj).filter((p) => isObj(p.head) && p.head.ref === SETUP_BRANCH && isObj(p.base) && p.base.ref === x.branch && Number.isSafeInteger(p.number)) : [];
    num = list.map((p) => p.number as number).sort((a, b) => b - a)[0];
    if (num === undefined) throw new FinishError(`pipegen can't find its setup pull request (branch ${SETUP_BRANCH}) in ${show(`${x.app.owner}/${x.app.repo}`)}, so it applies nothing. Run pipegen first.`);
  }
  const d = (await x.api.read('GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner: x.app.owner, repo: x.app.repo, pull_number: num })).data;
  if (!isObj(d) || !isObj(d.head) || d.head.ref !== SETUP_BRANCH) throw new FinishError(`Pull request #${num} of ${show(`${x.app.owner}/${x.app.repo}`)} is not pipegen's setup pull request, so pipegen applies nothing.`);
  const merged = typeof d.merged_at === 'string' && ISO_RE.test(d.merged_at) ? d.merged_at : null;
  return { number: num, mergedAt: merged, state: typeof d.state === 'string' ? d.state : '' };
}

/** A record's `planned` request that pipegen never makes (each slot has one route), or null. */
function plannedRouteProblem(p: InstallPlanned): string | null {
  const slots: [string, { method: string; route: string } | undefined][] = [
    [PLANNED_ROUTES.rulesets, p.rulesets?.gate], [PLANNED_ROUTES.rulesets, p.rulesets?.reviews], [PLANNED_ROUTES.classic, p.classic],
    [PLANNED_ROUTES.centralRuleset, p.centralRuleset], [PLANNED_ROUTES.orgRequiredWorkflow, p.orgRequiredWorkflow?.rule], [PLANNED_ROUTES.shaPinning, p.shaPinning?.request],
  ];
  for (const [want, r] of slots) if (r !== undefined && `${r.method} ${r.route}` !== want) return `${r.method} ${r.route}`;
  return null;
}

// ---------- finish ----------

/**
 * `pipegen finish` for the app `app` (see the header). Throws FinishError, with nothing applied, when the record can't be trusted, the
 * setup pull request isn't merged, or the locks can't be planned again.
 */
export async function finish(gh: Octokit, app: RepoRef, opts: FinishOpts, deps: FinishDeps): Promise<FinishResult> {
  const clock = deps.clock ?? clockOf(gh);
  const notes: string[] = [];
  const stop = (e: unknown): never => {
    if (isStop(e) || e instanceof FinishError) throw e;
    if (e instanceof DeliverError || e instanceof RecordError || e instanceof LockError) throw new FinishError(`${e.message} Nothing was applied.`, { cause: e });
    throw e;
  };
  const api = new SettingsApi(gh, app, clock);
  const central = centralOf(app);
  let x: Ctx;
  let pr: { number: number; mergedAt: string };
  try {
    // 1. the repos and the record (the one trust order)
    const appRepo = await readRepo(gh, app, clock);
    if (appRepo === null) throw new FinishError(`pipegen can't see ${show(`${app.owner}/${app.repo}`)}, so it applies nothing.`);
    const centralRepo = await readRepo(gh, central, clock);
    if (centralRepo === null || !centralRepo.private) throw new FinishError(`pipegen can't see the private ${show(`${central.owner}/${central.repo}`)}, where the install record is, so it applies nothing.`);
    const update = centralUpdateBranch(app.repo);
    const updateExists = await readHead(gh, central, update, clock) !== null;
    const trusted = await trustedPrevious(gh, app, central, centralRepo.defaultBranch, updateExists ? update : null, deps.local ?? {}, clock, notes, deps.io === undefined ? undefined : { io: deps.io, interactive: deps.interactive === true });
    if (trusted.record === null) {
      throw new FinishError(`${trusted.exists ? `pipegen found no install record for ${show(`${app.owner}/${app.repo}`)} that it trusts` : `There is no install record for ${show(`${app.owner}/${app.repo}`)}`}, so it applies nothing: finish reads what to apply only from the record. ${trusted.exists ? 'Run finish on the machine that set it up, or interactively to confirm the record by typing the repo name.' : 'Run pipegen first.'}${notes.length > 0 ? ` ${notes.join(' ')}` : ''}`);
    }
    const rec = trusted.record;
    const local = await readLocalRecord(app, deps.local ?? {}).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
    const typed = local?.typed === true;
    if (rec.app.repoId !== appRepo.id || rec.app.owner.toLowerCase() !== app.owner.toLowerCase() || rec.app.repo.toLowerCase() !== app.repo.toLowerCase()) throw new FinishError('The install record is not this repository\'s (another repo id or name), so pipegen applies nothing.');
    if (rec.app.private !== appRepo.private || rec.app.defaultBranch !== appRepo.defaultBranch) throw new FinishError(`${show(`${app.owner}/${app.repo}`)} changed since pipegen set it up (${rec.app.private !== appRepo.private ? `it is ${appRepo.private ? 'private' : 'public'} now` : `its default branch is ${show(appRepo.defaultBranch, 100)} now`}), so pipegen applies nothing; run pipegen again.`);
    // G10 re-review r2: a request pipegen never makes stops everything before anything is sent
    const badRoute = typed ? null : plannedRouteProblem(rec.planned);
    if (badRoute !== null) throw new FinishError(`The install record plans a request pipegen never makes (${show(badRoute, 120)}), so pipegen applies nothing. The record was changed by someone else; run pipegen again to write a new one.`);
    if (opts.rotateKey === true && !typed && rec.planned.signingMode !== 'key-env') throw new FinishError('--rotate-key works only in key-env signing mode (a cosign key kept in the pipegen-signing environment); this repo signs another way, so pipegen applies nothing.');

    // 2. the setup pull request must be merged
    const p = await setupPr({ api, app, branch: appRepo.defaultBranch }, local?.setupPr);
    if (p.mergedAt === null) {
      throw new FinishError(p.state === 'closed'
        ? `The setup pull request #${p.number} was closed without being merged, so pipegen applies nothing. Run pipegen again to open a new one.`
        : `The setup pull request #${p.number} is not merged yet, so pipegen applies nothing: the settings come after the merge, or the pull request could not merge. Merge it, then run \`npx pipegen finish\`.`);
    }
    pr = { number: p.number, mergedAt: p.mergedAt };

    // 3. re-probe (S10, G8 carry) and plan the locks again
    const probed = await deps.probe(gh, app, { private: appRepo.private, ownerType: appRepo.ownerType, defaultBranch: appRepo.defaultBranch, centralDefaultBranch: centralRepo.defaultBranch }, notes, clock);
    const writers = await readWriters(gh, app.owner, app.repo, CENTRAL_REPO, clock);
    const orgAdmin = await readOrgAdmin(gh, app.owner, appRepo.ownerType, notes, clock);
    const shaRead = await readShaPinning(gh, app.owner, app.repo, notes, clock);
    const appHead = await readHead(gh, app, appRepo.defaultBranch, clock);
    const centralHead = await readHead(gh, central, centralRepo.defaultBranch, clock);
    if (appHead === null || centralHead === null) throw new FinishError('A default branch of the app or the central repo is missing, so pipegen applies nothing.');
    const appTree = (await readTree(gh, app, appHead, clock)).entries;
    const centralTree = (await readTree(gh, central, centralHead, clock)).entries;
    const appCo = await coFacts(gh, app, appTree, clock);
    const centralCo = await coFacts(gh, central, centralTree, clock);
    const files: CreatedFile[] = [];
    for (const [repo, ref, tree, path] of [['app', app, appTree, CALLER_WORKFLOW], ['central', central, centralTree, centralWorkflowFile(app.repo, 'merge')]] as const) {
      const e = tree.get(path);
      if (e !== undefined && e.type === 'blob') files.push({ path, content: await readBlobText(gh, ref, e.sha, MAX_TEXT, clock), part: 'pipeline', reason: 'on the default branch', repo });
    }
    const pins = probed.workflowPins;
    const existingWorkflows: ExistingWorkflow[] = pins.tagPinned > 0 || pins.unchecked ? [{ path: '.github/workflows', triggers: [], deploys: false, secretsUsed: [], jobs: [], ...(pins.tagPinned > 0 ? { tagPinned: pins.tagPinned } : {}), ...(pins.unchecked ? { usesUnchecked: true as const } : {}) }] : [];
    const profile: RepoProfile = {
      owner: app.owner, repo: app.repo, defaultBranch: appRepo.defaultBranch, private: appRepo.private, ownerType: appRepo.ownerType, plan: probed.plan, monorepo: 'none',
      services: [], terraformDirs: [], hasCompose: false, existingWorkflows, precommit: null, repoFiles: { ...emptyRepoFiles(), codeowners: appCo.path },
    };
    // the inputs from the record (a typed record carries none: re-derived from the CODEOWNERS block on the default branch)
    const owners = typed ? ownersOf(appCo.block) : rec.planned.owners.app;
    const protectedPaths = rec.protectedPaths.length > 0 ? rec.protectedPaths : [...PROTECTED_PATHS_BASE];
    const coEdit = rec.edits.find((e) => e.repo === 'app' && e.kind === 'codeowners' && e.path === appCo.path) as { inserted: string } | undefined;
    const inserted = coEdit !== undefined && appCo.text.split(coEdit.inserted).length === 2 ? coEdit.inserted : appCo.block;
    const fresh = planLocks({
      profile, caps: probed.caps,
      central: { repo: `${central.owner}/${central.repo}`, sha: rec.centralSha ?? centralHead, branchProtection: probed.centralBranchProtection, codeowners: { path: centralCo.path, original: centralCo.text, isSymlink: centralCo.isSymlink, inserted: centralCo.block } },
      writers, owners, orgAdmin, shaPinning: shaRead, protectedPaths,
      appCodeowners: { original: appCo.text, isSymlink: appCo.isSymlink, inserted }, ids: { app: appRepo.id, central: centralRepo.id }, files,
    });
    let planned = rec.planned;
    if (typed) {
      const mode = rec.secrets.some((s) => s.scope === SIGNING_SCOPE && s.name === COSIGN_KEY_SECRET) ? 'key-env' : signingMode(profile, { ...probed.caps, deploymentBranchPolicies: false });
      planned = plannedOfLocks(fresh, mode, []);
      notes.push('The install record was confirmed by typing, so pipegen planned the locks again from GitHub (the code owners from the CODEOWNERS block on the default branch). pipegen couldn\'t re-derive the environments the setup planned (that record doesn\'t carry them): run pipegen again to set them up.');
    }
    if (opts.rotateKey === true && planned.signingMode !== 'key-env') throw new FinishError('--rotate-key works only in key-env signing mode (a cosign key kept in the pipegen-signing environment); this repo signs another way, so pipegen applies nothing.');
    x = {
      gh, api, app, central, clock, deps, print: opts.print === true, rotate: opts.rotateKey === true,
      rec, typed, planned, fresh, profile, caps: probed.caps, shaRead, branch: appRepo.defaultBranch, ownerType: appRepo.ownerType, private: appRepo.private,
      centralHead, centralTree, centralCo,
      applied: [], skipped: [], notes, commands: [],
      rulesets: new Map(), repoSettings: {}, centralRec: {}, environments: new Map(), variables: [], secrets: [],
      centralFiles: [], files: rec.files.map((f) => ({ ...f, shas: [...f.shas] })), edits: rec.edits.map((e) => structuredClone(e)),
    };
  } catch (e) {
    return stop(e);
  }

  const mergedAt = pr.mergedAt;
  const blockFrom = new Date(Date.parse(`${mergedAt.slice(0, 10)}T00:00:00Z`) + 7 * DAY_MS).toISOString().slice(0, 10);

  // 4. the settings, in order (each named when refused); the central ruleset last
  await appLocks(x);
  await shaPinning(x);
  await securitySettings(x);
  await actionsAccess(x);
  await orgRequired(x);
  await environments(x);
  await signing(x);
  await step(x, `${BLOCK_FROM_VAR} = ${blockFrom}`, () => setVariable(x, 'repo', BLOCK_FROM_VAR, blockFrom, `${BLOCK_FROM_VAR} = ${blockFrom} (the end of the warn period)`));
  await centralRuleset(x);
  centralCodeowners(x);

  if (x.print) {
    deps.out(`pipegen finish --print for ${x.app.owner}/${x.app.repo}: nothing is applied. Review these commands, run them yourself, then run \`npx pipegen finish\` to record what they made:`);
    for (const c of x.commands) deps.out(c);
    report(x, deps.out, false);
    return { applied: [], skipped: x.skipped, notes: x.notes, commands: x.commands };
  }

  // 5. the record (the central CODEOWNERS with it), then the central ruleset switched on, last
  const record = buildRecord(x, mergedAt, blockFrom);
  let written: Awaited<ReturnType<typeof writeRecord>>;
  try {
    // the central rule is on already (reused, or made by an earlier finish): the record goes through the central pull request; a new rule
    // is still switched off here, so the record commit goes straight to the default branch (a refused direct move falls back to the PR)
    const via = x.centralRec.rulesetId !== undefined && x.activate === undefined ? 'pr' : 'direct';
    written = await writeRecord(gh, { record, setupPr: pr.number, via, files: x.centralFiles, base: x.centralHead, clock, ...(deps.now === undefined ? {} : { now: deps.now }), ...(deps.local === undefined ? {} : { local: deps.local }) });
  } catch (e) {
    if (isRateStop(e)) throw e;
    report(x, deps.out, true);
    throw new FinishError(`pipegen applied ${x.applied.length === 0 ? 'nothing' : x.applied.join(', ')}, but couldn't write the install record (${whyOf(e)}); run \`npx pipegen finish\` again to record it.${x.activate === undefined ? '' : ' The central merge rule was made but is not switched on yet.'}`, { cause: e });
  }
  x.notes.push(...written.notes);
  if (x.centralFiles.length > 0) x.applied.push(`the central CODEOWNERS (${x.centralFiles.map((f) => f.path).join(', ')})`);
  x.applied.push(written.via === 'direct' ? `the install record on ${x.central.owner}/${x.central.repo}` : `the install record in the central pull request ${written.centralPr?.url ?? ''} (merge it)`);
  if (x.activate !== undefined) {
    const a = x.activate;
    await step(x, a.what, async () => {
      await x.api.write('PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}', { ...centralParams(x), ruleset_id: a.id, ...a.body });
      const back = await getRuleset(x, { kind: 'repo', repo: x.central }, a.id);
      if (back === null || !holdsWanted(a.body, back)) throw new StepError('The central ruleset doesn\'t read back as switched on.');
      x.applied.push(a.what);
    });
  }
  report(x, deps.out, true);
  return { applied: x.applied, skipped: x.skipped, notes: x.notes, recordHash: written.recordHash, ...(written.centralPr === undefined ? {} : { centralPrUrl: written.centralPr.url }) };
}

/** The user's summary: what was applied, what was not (each by name, with why), and the notes. */
function report(x: Ctx, out: (s: string) => void, applied: boolean): void {
  if (applied) {
    out(`pipegen finish for ${x.app.owner}/${x.app.repo}:`);
    for (const a of x.applied) out(`  done: ${a}`);
  }
  if (x.skipped.length > 0) {
    out(`These were not applied${applied ? ', and the install record doesn\'t list them' : ''}:`);
    for (const s of x.skipped) out(`  - ${s.what}: ${s.why}`);
  }
  for (const n of x.notes) out(n);
}

// ---------- the real re-probe (G13 wires it) ----------

/** The app's own workflows on its default branch: how many action references name a tag or branch (planLocks leaves sha pinning off then). */
async function workflowPins(gh: Octokit, app: RepoRef, branch: string, clock: RateClock): Promise<{ tagPinned: number; unchecked: boolean }> {
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
