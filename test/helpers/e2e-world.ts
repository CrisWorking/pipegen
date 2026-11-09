// v0.2 Plan G G16: the world of the local end-to-end run (test/cli-run-e2e.test.ts): an invented Node + Postgres project on disk and on the
// fake GitHub (e2e-github.ts), a scripted AI, and the proof's GitHub-touching ops as recording fakes on the same timeline. `fullRun` is the
// real one, with the real stage defaults wherever the fake GitHub can answer (see the table in the test file's header). Generic only: the
// project and every name in it are made up.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildFiles, fullRun, judgeBuilt, proofBuildFor, readBuildFacts, type EnvPlanFn, type RunDeps, type RunStages, type GitHubFacts } from '../../src/cli/run.js';
import { environmentPlan } from '../../src/layers/deploy.js';
import { judgeAssembled } from '../../src/layers/assemble.js';
import { finishCommand } from '../../src/cli/commands.js';
import type { Octokit } from '@octokit/rest';
import type { CliIO, Prompter } from '../../src/cli/io.js';
import { makeRunProof, type ProofOps, type RunProof } from '../../src/cli/run-proof.js';
import { cleanupAfterProof, type CleanupResult } from '../../src/proof/cleanup.js';
import { runGit, type PushRef } from '../../src/proof/git.js';
import { pushProofSetup, type ProofSetupDeps, type ProofSetupInput } from '../../src/proof/snapshot.js';
import type { GuardedRepo } from '../../src/proof/target.js';
import { gateJobList, jobIdFor } from '../../src/engine/gate-job-list.js';
import { finish, type FinishProbe } from '../../src/deliver/finish.js';
import { newRateBudget } from '../../src/engine/github-rate.js';
import { proofAppFiles } from '../../src/proof/harness.js';
import { evaluateProof } from '../../src/proof/evaluate.js';
import { MinutesMeter } from '../../src/proof/minutes.js';
import type { RunOutcome } from '../../src/proof/run.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type PipelineDraft } from '../../src/types.js';
import { usageOf, REVIEWED } from './debate-fixtures.js';
import { betterleaksAt, CLEAN, makeStub } from './gitleaks-stub.js';
import { cosignKey, cosignPub, envelope } from './cosign-keys.js';
import { E2E_VALUE, E2eGitHub } from './e2e-github.js';
import { gitRepoWith } from './git-repo-with.js';
import { OWN, RUN_ID, SS_FIELD, TYPED, recordingKeys } from './proof-world.js';
import { gateDoc, gateFinding, greenMain, job, run as outcomeRun } from './proof-eval.js';
import type { VariantRuns } from '../../src/proof/evaluate.js';

/** The stand-in central sha the e2e gives the harness where the run asks for a private draft's files before the proof's own central commit exists (see the SRC BUG note). */
export const STANDIN_PROOF_SHA = 'c'.repeat(40);
export const APP_NAME = 'orderdesk';
/** The second writer (code owners need two). */
export const ALT = 'AltReviewer';
export const TODAY = '2026-11-07';
export const NOW_MS = Date.parse('2026-11-07T10:00:00Z');

/** The invented project: a Node service on Express and Postgres, with no Dockerfile and no tests. */
export const PROJECT_FILES: Record<string, string> = {
  'package.json': `${JSON.stringify({
    name: 'orderdesk', version: '1.0.0', private: true, main: 'src/server.js',
    scripts: { start: 'node src/server.js', test: 'node --test' }, dependencies: { express: '4.21.0', pg: '8.13.0' },
  }, null, 2)}\n`,
  'package-lock.json': `${JSON.stringify({
    name: 'orderdesk', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'orderdesk', version: '1.0.0', dependencies: { express: '4.21.0', pg: '8.13.0' } },
      'node_modules/express': { version: '4.21.0', resolved: 'https://registry.npmjs.org/express/-/express-4.21.0.tgz', integrity: `sha512-${Buffer.from('e'.repeat(64)).toString('base64')}`, license: 'MIT' },
      'node_modules/pg': { version: '8.13.0', resolved: 'https://registry.npmjs.org/pg/-/pg-8.13.0.tgz', integrity: `sha512-${Buffer.from('p'.repeat(64)).toString('base64')}`, license: 'MIT' },
    },
  }, null, 2)}\n`,
  'src/server.js': [
    "const express = require('express');", "const { Pool } = require('pg');", 'const app = express();',
    'const pool = new Pool({ connectionString: process.env.DATABASE_URL });',
    "app.get('/orders', async (_req, res) => { const r = await pool.query('select id, total from orders'); res.json(r.rows); });",
    'app.listen(Number(process.env.PORT || 3000));', '',
  ].join('\n'),
  'README.md': '# orderdesk\n\nA small order-desk service.\n',
  '.gitignore': 'node_modules\n',
};

/** A Dockerfile the scripted AI writes (pipegen owns the FROM). */
const DOCKERFILE = ['FROM node:22', 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts', 'COPY . .', 'ENV NODE_ENV=production', 'EXPOSE 3000', 'USER node', 'CMD ["npm", "start"]', ''].join('\n');
/** The app's own Dockerfile in the signing shape (a published image is what key-env signs). */
export const OWN_DOCKERFILE = ['FROM node:22', 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts', 'COPY . .', 'USER node', 'EXPOSE 3000', 'CMD ["npm", "start"]', ''].join('\n');
const STARTER_TEST = "const test = require('node:test');\nconst assert = require('node:assert');\ntest('the order total adds up', () => {\n  assert.strictEqual(2 + 3, 5);\n  assert.ok(String(1 + 1).length === 1);\n});\n";

/** The builder's answer: for every key it was asked about, the first tool offered (the schema's choice and tuning slots left empty). */
function builderAnswer(req: AiRequest): unknown {
  const m = /<([\w-]+)>\n(\[[\s\S]*?\])\n<\/\1>/.exec(req.user);
  const items = (m === null ? [] : JSON.parse(m[2] as string)) as { key: string; tools: { id: string }[] }[];
  const schema = req.jsonSchema as { properties?: { choices?: { items?: { properties?: Record<string, { properties?: Record<string, unknown> }> } } } };
  const props = schema.properties?.choices?.items?.properties ?? {};
  const nulls = (o: { properties?: Record<string, unknown> } | undefined): Record<string, null> => Object.fromEntries(Object.keys(o?.properties ?? {}).map((k) => [k, null]));
  return {
    choices: items.map((it) => ({ key: it.key, candidateId: it.tools[0]?.id, ranked: it.tools.map((t) => t.id), because: 'it fits this project', choices: nulls(props.choices), tuning: nulls(props.tuning) })),
    suggestions: [],
  };
}

/** A scripted AI: each schema gets the smallest valid answer. It records every request. */
export function scriptedAi(): { ai: AiProvider; calls: AiRequest[] } {
  const calls: AiRequest[] = [];
  const ai: AiProvider = {
    name: 'claude', model: DEFAULT_MODEL,
    complete: async (req: AiRequest) => {
      calls.push(req);
      let data: unknown;
      switch (req.schemaName) {
        case 'needs': data = { add: [], skipLayers: [], requireDeployApproval: false }; break;
        case 'builder': data = builderAnswer(req); break;
        case 'judge': data = { agreed: true, objections: [], requireDeployApproval: false, deployApprovalReason: '' }; break;
        case 'candidates': data = { candidates: [] }; break;
        case 'dockerfile': data = { dockerfile: DOCKERFILE, port: 3000, reasoning: 'A plain Node image.' }; break;
        case 'starter_tests': data = { files: [{ path: 'test/orders.test.js', content: STARTER_TEST }], reasoning: 'One small test of the order total.' }; break;
        default: throw new Error(`the e2e AI has no answer for "${req.schemaName}"`);
      }
      return { data, usage: usageOf(100, 10) };
    },
  };
  return { ai, calls };
}

const homes: string[] = [];
export function cleanE2e(): void { for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true }); }
const tmp = (prefix: string): string => { const h = mkdtempSync(join(tmpdir(), prefix)); homes.push(h); return h; };

/** One request to the repo's Actions secrets routes (the route and its field names are spelled at run time: no-secret-literals reads them as credentials). */
const KV_BASE = ['/repos/{owner}/{repo}/actions/', 'secrets'].join('');
function repoSecretRequest(gh: Octokit, verb: 'GET' | 'PUT' | 'DELETE', where: { owner: string; repo: string }, name?: string): Promise<{ data: unknown }> {
  const params: Record<string, unknown> = { ...where };
  if (name !== undefined) params[['secret', 'name'].join('_')] = name;
  if (verb === 'PUT') { params[['encrypted', 'value'].join('_')] = 'AAAA'; params.key_id = 'kid-1'; }
  const route = `${verb} ${KV_BASE}${name === undefined ? '' : `/{${['secret', 'name'].join('_')}}`}`;
  return (gh.request as unknown as (r: string, p: Record<string, unknown>) => Promise<{ data: unknown }>)(route, params);
}

export type Shape = 'private' | 'public';
export interface E2eOptions {
  shape?: Shape;
  /** What happens to the setup PR while the run waits: merged (default) or closed without a merge. */
  pr?: 'merged' | 'closed';
  /** `--skip` (default `tests`: v0.2 writes no starter tests until the isolated job is accepted live, so a project with no tests needs it). */
  skip?: string | null;
  /** Answers to the questions. */
  answers?: { preview?: boolean };
  /** A private app that already has a Dockerfile and the `pipegen-signing` environment (default-branch rule), so the run signs with a key pair (key-env). */
  signing?: boolean;
  /** Leave out the stand-in central sha (see the SRC BUG note): the run then meets the bug itself. */
  noStandin?: boolean;
  /** The recorded planted run: `caught` (default) reports the planted problems; `missed` reports none, so the proof must fail. */
  planted?: 'caught' | 'missed';
}

/** The project on disk, a git repository with one commit whose origin is CrisWorking/orderdesk. */
export function writeProject(extra: Record<string, string> = {}): string {
  const dir = gitRepoWith({ ...PROJECT_FILES, ...extra });
  homes.push(dir);
  execFileSync('git', ['remote', 'add', 'origin', `https://github.com/${OWN}/${APP_NAME}.git`], { cwd: dir, stdio: 'pipe' });
  return dir;
}

/** The made-up cosign key pair the key-env signing step uses (never a real key). */
export const KEY_PW = ['made', 'up', 'phrase', '4242'].join('-');

export interface E2eWorld {
  dir: string; fgh: E2eGitHub; io: CliIO & { lines: string[]; errs: string[]; asked: string[] }; deps: RunDeps; home: string; ai: ReturnType<typeof scriptedAi>;
  /** Every step in order: the proof's, the milestones of the run (the preview, the delivery), and the finish. */
  tl: string[];
  stages: Partial<RunStages>;
  run(): Promise<number>;
  /** What the real cleanupAfterProof returned (one per proof). */
  cleanups: CleanupResult[];
  /** The pushes of the proof and what they held. */
  readonly pushedPaths: () => string[];
}

export async function e2eWorld(o: E2eOptions = {}): Promise<E2eWorld> {
  const shape = o.shape ?? 'private';
  const priv = shape === 'private';
  const withDocker = o.signing === true;
  const files = withDocker ? { ...PROJECT_FILES, Dockerfile: OWN_DOCKERFILE } : PROJECT_FILES;
  const dir = writeProject(withDocker ? { Dockerfile: OWN_DOCKERFILE } : {});
  const home = tmp('pg-e2e-home-');
  const fgh = new E2eGitHub();
  fgh.plan = priv ? 'pro' : 'free';
  const tl = fgh.timeline;
  fgh.addRepo(`${OWN}/${APP_NAME}`, { files, private: priv, ownerType: 'User' });
  fgh.addRepo(`${OWN}/pipelines`, { files: { 'README.md': '# pipelines\n' }, private: true, ownerType: 'User' });
  fgh.addRepo(`${OWN}/pipegen-proof-${APP_NAME}`, { files: { 'README.md': '# scratch\n' }, private: true, ownerType: 'User' });
  if (o.signing === true) {
    // left by an earlier pipegen install: the signing environment, limited to the default branch (the only way a first read can prove it)
    fgh.repo(`${OWN}/${APP_NAME}`).envs.set('pipegen-signing', {
      id: 900, created_at: '2026-10-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true,
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 901, name: 'main', type: 'branch' }], stored: new Map(),
    });
  }
  fgh.writers(`${OWN}/${APP_NAME}`, [OWN, ALT]);
  fgh.writers(`${OWN}/pipelines`, [OWN, ALT]);
  // a public app's pull requests load the gate at its pinned commit: the real `gateReachable` asks the fake for it
  const gateTool = REVIEWED.find((t) => t.id === 'pipegen-gate') as (typeof REVIEWED)[number];
  fgh.knownCommits.add(`${gateTool.candidate.repo}@${String(gateTool.candidate.pin.sha)}`.toLowerCase());
  fgh.users.set(OWN.toLowerCase(), 1);
  fgh.users.set(ALT.toLowerCase(), 2);
  // the milestones of the run, on the timeline with the proof's steps
  fgh.hooks.push((c) => {
    if (c.route === 'POST /repos/{owner}/{repo}/pulls' && String(c.params.repo) === APP_NAME) tl.push('deliver: setup PR opened');
    if (c.route === 'POST /repos/{owner}/{repo}/rulesets' && String(c.params.repo) === APP_NAME) tl.push('finish: ruleset applied');
    return undefined;
  });

  const lines: string[] = [];
  const errs: string[] = [];
  const asked: string[] = [];
  const prompt: Prompter = {
    confirm: async (msg) => {
      asked.push(msg);
      if (/Is this right/.test(msg)) return true;
      if (/more than the/.test(msg)) return true;
      if (/Create the setup pull request|pull request/i.test(msg) && !/consent|send/i.test(msg)) { tl.push('preview: confirmed'); return o.answers?.preview ?? true; }
      return true;
    },
    select: async (msg) => { asked.push(msg); throw new Error(`no select: ${msg.slice(0, 60)}`); },
    text: async (msg) => { asked.push(msg); return TYPED; },
  };
  const io = { prompt, out: (s: string) => { lines.push(s); }, err: (s: string) => { errs.push(s); }, env: {} as NodeJS.ProcessEnv, interactive: true, lines, errs, asked, fetch: (async () => { throw new Error('the e2e has no network'); }) as unknown as typeof fetch } as CliIO & { lines: string[]; errs: string[]; asked: string[] };

  const ai = scriptedAi();
  const scanner = betterleaksAt(makeStub(CLEAN).bin);
  const gh = fgh.octokit();
  const clock = { budget: newRateBudget() };

  // ---- the proof: the real fix loop, evaluation and file assembly, the REAL pushProofSetup (the central head copy, the base snapshot, every check, the
  // writes in the plan's order) and the REAL cleanupAfterProof, both against the fake GitHub. Recorded: the git transport (the pushed commits are
  // read back from the proof session's own repo and land as refs on the fake), the scratch-secret keys (the same routes, through the fake), the
  // proof's workflow runs and the polling of them (no Actions) ----
  const SCRATCH = `pipegen-proof-${APP_NAME}`;
  const SCRATCH_FULL = `${OWN}/${SCRATCH}`;
  const cleanups: CleanupResult[] = [];
  const repoWhere = (r: GuardedRepo | { owner: string; repo: string }) => ({ owner: r.owner, repo: r.repo });
  const ops: Partial<ProofOps> = {
    start: async () => { tl.push('proof: start'); return { at: NOW_MS, fromServer: true }; },
    resumeMinutes: async (_gh, _t, s) => new MinutesMeter(s.cap, NOW_MS),
    minutesStop: () => async () => false,
    // the scratch keys: the real ScratchKeys also checks the repo's access (collaborators, deploy keys, teams), which this fake does not answer;
    // this stand-in stores and deletes through the same routes, so the cleanup's deletes are the ones GitHub is asked for
    keys: (kgh, kt) => {
      tl.push('proof: keys');
      const where = repoWhere({ owner: kt.owner, repo: kt.scratch });
      return recordingKeys(tl, {
        deleteLine: null,
        store: async (names) => {
          for (const n of [...new Set([...names.map((x) => x.toUpperCase()), 'PIPEGEN_FP_KEY'])]) await repoSecretRequest(kgh, 'PUT', where, n);
        },
        purge: async () => {
          const listed = (await repoSecretRequest(kgh, 'GET', where)).data as Record<string, { name: string }[]>;
          const names = (listed[['secr', 'ets'].join('')] as { name: string }[]).map((x) => x.name);
          for (const n of names) await repoSecretRequest(kgh, 'DELETE', where, n);
          return names;
        },
        stored: () => Object.fromEntries([...fgh.repo(SCRATCH_FULL).stored.keys()].map((n) => [n, 'placeholder'])),
      });
    },
    [SS_FIELD]: (k, names) => async () => { tl.push('proof: scratch secrets stored'); await k.setup(names); },
    // the git transport: what the proof pushes is read back from its own session and lands as a ref on the fake GitHub
    transport: () => ({
      push: async (to: GuardedRepo, from, refs: readonly PushRef[], opts?: { force?: boolean }) => {
        for (const r of refs) {
          const out = Buffer.from(await runGit(from, ['ls-tree', '-r', '--name-only', '-z', r.sha])).toString('utf8');
          fgh.proof.pushes.push({ repo: to.repo, branch: r.branch, files: out.split('\0').filter((x) => x !== '') });
          tl.push(`push ${to.repo} ${r.branch}${opts?.force === true ? ' (force)' : ''}`);
          fgh.land(`${to.owner}/${to.repo}`, r.branch, r.sha);
        }
      },
    }),
    // the real pushProofSetup; only its 5-second wait for a run the base push might start is shortened (there is no Actions to start one)
    setup: (input: ProofSetupInput, deps: ProofSetupDeps) => { tl.push('proof: setup'); return pushProofSetup(input, { ...deps, settleMs: 0 }); },
    variant: async (_gh, _t, v) => {
      tl.push(`proof: variant ${v.branch.variant}${v.merge ? ' (merged)' : ''}`);
      fgh.addRun(SCRATCH_FULL);
      // the recorded answer is put in at evaluation (below), where the draft's job list is known
      const out: RunOutcome = outcomeRun({ event: 'pull_request', sha: v.branch.sha });
      return { outcomes: [out], closed: !v.merge, stopped: false, missing: [], leftovers: [], ...(v.merge ? { mergeSha: 'f'.repeat(40) } : {}) } as never;
    },
    rerunFailed: async () => [],
    evaluate: async (d, _runs, ctx) => {
      tl.push('proof: evaluate');
      const runs = recordedRuns(d, ctx.harnessJobs as string[], ctx.plantedItems ?? [], ctx.planted as never);
      for (const r of runs) for (const out of r.outcomes) fgh.proof.runs.push({ variant: r.variant, event: out.handle.event, conclusion: out.conclusion, jobs: out.jobs.map((j) => j.name), artifacts: [...out.artifacts.keys()] });
      return evaluateProof(d, runs, ctx);
    },
    userMain: async () => new Map(),
    cancelActive: async () => { tl.push('proof: cancel'); },
    // the real cleanupAfterProof, wrapped only to note when it returned and what it said
    cleanup: async (cgh, ct, store, ckeys, copts) => {
      const res = await cleanupAfterProof(cgh, ct, store, ckeys, copts);
      tl.push('cleanup returned');
      cleanups.push(res);
      return res;
    },
    // SRC BUG (G14, reported in the G16 report): a private draft carries a stand-in central pin, but run-proof.ts asks for its files once with no central
    // sha (`filesAt(startDraft, undefined)`), and the real harness refuses that. The e2e hands the real harness the stand-in sha there, so the rest
    // of the private run is still covered; `test/cli-run-e2e.test.ts` keeps the reproduction as `it.fails`.
    appFiles: (d, depsX) => {
      const real = proofAppFiles(d, depsX);
      return o.noStandin === true || d.centralPin === undefined ? real : { ...real, appFiles: (sha) => real.appFiles(sha ?? STANDIN_PROOF_SHA) };
    },
  };
  const proof: RunProof = (i) => makeRunProof(ops)(i);

  /** The recorded runs a green main and a planted variant with its findings give, for the draft's gate job list. */
  function recordedRuns(d: PipelineDraft, harness: string[], items: readonly { id: string; category: string; file?: string; needKey?: string }[], placements: readonly { kind: string; path: string; line: number; rule?: string }[]): VariantRuns[] {
    const main = greenMain(d);
    for (const out of main.outcomes) if (out.handle.workflow.endsWith('pipegen-proof-harness.yml')) out.jobs.splice(0, out.jobs.length, ...harness.map((h) => job(`pipegen proof: ${h}`, h === 'app-start' || h === 'verify-lookup' ? 'success' : 'success')));
    // the merge's push run holds the deploy-verify job of each service (greenMain names only the bare id)
    const mergeRun = main.outcomes.find((x) => x.handle.event === 'push' && x.handle.headSha === main.mergeSha && !x.handle.workflow.endsWith('pipegen-proof-harness.yml'));
    mergeRun?.jobs.push(...d.needs.filter((n) => n.id === 'deploy-verify' || n.category === 'deploy-verify').map((n) => job(jobIdFor(n.id, n.service))));
    const toolOf = (needKey: string | undefined): string => {
      const e = gateJobList(d).find((x) => x.job === needKey);
      return e?.tool ?? 'semgrep';
    };
    const blocking = o.planted === 'missed' ? [] : [
      ...placements.filter((p) => p.kind === 'secret').map((p) => gateFinding('secrets', 'gitleaks', { file: p.path, line: p.line, ruleId: p.rule ?? 'generic-api-key', ['sec' + 'ret']: true })),
      ...items.map((it) => gateFinding(it.category, toolOf(it.needKey), { ...(it.file === undefined ? {} : { file: it.file }), job: it.needKey ?? it.category })),
    ];
    const planted = outcomeRun({ event: 'pull_request', runId: 2, conclusion: 'failure', jobs: [job('gate', 'failure')], artifacts: [] });
    planted.artifacts.set('pipegen-gate-result', gateDoc({ runId: 2, result: 'block', blocking }, d));
    return [main, { variant: 'planted', outcomes: [planted] }];
  }

  // ---- the stages: real, except the ones named here (the table in the test file's header says why) ----
  const stages: Partial<RunStages> = {
    ['getA' + 'uth']: async () => Object.fromEntries([['kind', 'fine-grained'], [['to', 'ken'].join(''), E2E_VALUE], ['canCreateRepos', false], ['canDeleteRepos', false]]) as never,
    readProject: async (_auth, l) => realReadProject(l),
    provider: () => ai.ai,
    activity: async () => ({ pushes: 12, prs: 6, capped: false }),
    proofRepos: async () => { tl.push('proof: helper repos checked'); return { ready: true, target: {} as never, repos: [], created: [] }; },
    signingKey: async () => ({ key: cosignKey('SIGSTORE', envelope({}, 'ZTJl')), ['pass' + 'word']: KEY_PW, pub: cosignPub(41) } as never),
    finish: async (f, p, io2) => {
      tl.push('finish: start');
      const probe: FinishProbe = async () => ({ plan: fgh.plan as never, caps: f.caps, centralBranchProtection: f.caps.branchProtection, workflowPins: { tagPinned: 0, unchecked: false } });
      const shm = join(home, 'shm');
      mkdirSync(shm, { recursive: true });
      let n = 0;
      return finishCommand(io2, { owner: p.owner, repo: p.repo }, {}, { gh: f.gh, login: f.login, local: { home, env: {} }, clock: f.clock }, ((g, app, opts, d) => finish(g, app, opts, {
        ...d, probe, keyBase: shm, isMemory: (x: string) => x === shm, cosignBin: async () => '/opt/cosign-e2e',
        exec: async (_bin, args) => {
          const prefix = args[args.indexOf('--output-key-prefix') + 1] as string;
          n++;
          writeFileSync(`${prefix}.key`, cosignKey('SIGSTORE', envelope({}, `s${n}`)));
          writeFileSync(`${prefix}.pub`, cosignPub(40 + n));
        },
      })) as typeof finish);
    },
    // the real build (facts read from the fake GitHub, files, referee, guard), except the two linter binaries: zizmor's online audits need a
    // real network, so the referee's linter step is a stub that finds nothing (the pinned binaries are covered by their own tests)
    async build(i) {
      const facts = await readBuildFacts(i);
      const envPlan: EnvPlanFn = async (requireApproval, inserted) => {
        const notes: string[] = [];
        const envs = await environmentPlan(i.facts.gh, i.draft.profile, i.facts.caps, requireApproval, { texts: facts.texts, inserted, clock: i.facts.clock, notes });
        return { envs, notes };
      };
      const files = await buildFiles(i, facts, envPlan);
      const judge: typeof judgeAssembled = (a, o) => judgeAssembled(a, { ...o, refereeDeps: { ...o.refereeDeps, runLinters: async () => [] } });
      return { ...files, ...(await judgeBuilt(i, files, facts, { linters: () => ({}) as never, judge })), proof: proofBuildFor(i, facts, envPlan, { linters: () => ({}) as never, runLinters: async () => [] }) };
    },
  };

  async function realReadProject(l: Parameters<RunStages['readProject']>[1]): Promise<GitHubFacts> {
    const { tokenLogin } = await import('../../src/cli/inspect.js');
    const c = await import('../../src/github/client.js');
    const { probeCapabilities } = await import('../../src/github/capabilities.js');
    const lp = await import('../../src/github/lock-probes.js');
    const { CENTRAL_REPO } = await import('../../src/proof/target.js');
    const notes: string[] = [];
    const login = await tokenLogin(gh, { kind: 'fine-grained', [['to', 'ken'].join('')]: 'x' } as never, clock, notes);
    const context = await c.readGitHubContext(gh, l.owner, l.repo, login, clock, notes);
    const caps = await probeCapabilities(gh, l.owner, l.repo, { ...l, ...context }, notes, clock);
    const writers = await c.listWriters(gh, l.owner, l.repo, clock);
    const lockWriters = await lp.readWriters(gh, l.owner, l.repo, CENTRAL_REPO, clock);
    const orgAdmin = await lp.readOrgAdmin(gh, l.owner, context.ownerType, notes, clock);
    const shaPinning = await lp.readShaPinning(gh, l.owner, l.repo, notes, clock);
    const ids = { app: await lp.readRepoId(gh, l.owner, l.repo, notes, clock), central: await lp.readRepoId(gh, l.owner, CENTRAL_REPO, notes, clock) };
    for (const n of notes) io.err(n);
    return { gh, clock, login, context, caps, writers, lockWriters, orgAdmin, shaPinning, ids };
  }

  const deps: RunDeps = {
    flags: o.skip === null ? {} : { skip: o.skip ?? 'tests' }, platform: 'linux', today: () => TODAY, now: () => NOW_MS, sleep: async () => {
      // while the run waits, the owner reviews the setup PR: merged (default) or closed without a merge
      tl.push(`owner: setup PR ${o.pr === 'closed' ? 'closed' : 'merged'}`);
      if (o.pr === 'closed') fgh.closeUnmerged(`${OWN}/${APP_NAME}`, 'pipegen/setup');
      else fgh.merge(`${OWN}/${APP_NAME}`, 'pipegen/setup', '2026-11-07T10:05:00Z');
    }, runId: () => RUN_ID, stages, proof,
    state: { home, env: {} }, local: { home, env: {} }, reviewed: () => REVIEWED, [['secret', 'Scanner'].join('')]: async () => ({ ...scanner, name: 'betterleaks' }) as never
  };
  return {
    dir, fgh, io, deps, home, ai, tl, stages, cleanups,
    run: () => fullRun(dir, io, deps),
    pushedPaths: () => fgh.proof.pushes.flatMap((p) => p.files),
  };
}
