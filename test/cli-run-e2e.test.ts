// v0.2 Plan G G16: `pipegen run` end to end on this machine, against fakes. The driver is the real `fullRun` (src/cli/run.ts) with its real
// stage defaults wherever the fake GitHub (helpers/e2e-github.ts) can answer. No network, no real `gh`, `cosign` or `docker`, no live token.
//
// REAL here (the code under test): consent text and estimates, the project read, the capability probes, the lock-probe reads (writers, org
// admin, sha pinning, repo ids), the needs / discover / debate / creators stages (with a scripted AI), the secrets stage, the key-env signing
// plan, readBuildFacts + buildFiles + the referee and the guard (judgeBuilt), the assemble step, the fix loop and the evaluation of the proof
// (src/proof/evaluate.ts, src/cli/run-proof.ts), pushProofSetup (src/proof/snapshot.ts: the central head copy read from the fake, the base
// snapshot of the project's HEAD, every tree check, Dependabot off, the no-run check, the secret store step, the main and planted pushes, in the
// plan's order), cleanupAfterProof (src/proof/cleanup.ts: the scratch secrets first, the runs, the proof branches, the default branch reset, the
// central proof branch), the delivery (central workflows, the N4 signing environment, secrets, the git data API, the setup PR, the install
// record), `gateReachable` (public app), `trusted` (reads the central repo), `prState` (GET the pull request), the finish (rulesets, central
// merge rule, central CODEOWNERS, signing key, PIPEGEN_BLOCK_FROM) and the summary.
// FAKE: GitHub itself (an in-memory Octokit that answers the routes above); the git TRANSPORT (the pushed commits are read back from the proof
// session's own repo and land as refs on the fake); the proof's workflow RUNS and the polling of them (recorded answers: a passing `main`, the
// `planted` variant with its findings); the scratch-secret KEYS object (the real ScratchKeys also checks the scratch repo's access, collaborators,
// deploy keys and teams, which the fake does not answer; its stand-in stores and deletes through the same secret routes); the AI; the clock,
// sleep, run id; the pinned secret scanner; the two workflow linters (zizmor's online audits need a real network); the cosign key pair;
// `discover`'s search (the fake has none, so no new action is found and `resolvePin` is not reached); the helper-repo check (`proofRepos`:
// creating repos and the access settings are GitHub-side); the real `readProject` of the stage table is replayed in e2e-world.ts because it
// builds its own Octokit from the token.
// NOT covered (live only, see docs/smoke-test.md): real runner minutes, the real Actions runs and the checks they report, a real token, the
// helper repos' real creation, the real ScratchKeys access check, a real git push (the transport), GitHub's own answers to the probes, Anthropic.
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cleanE2e, e2eWorld, APP_NAME, KEY_PW, type E2eOptions, type E2eWorld } from './helpers/e2e-world.js';
import { OWN, RUN_ID } from './helpers/proof-world.js';
import { COMPAT_PREFIX, HARNESS_PATH } from './helpers/proof-eval.js';
import type { Call } from './helpers/deliver-github.js';

beforeAll(() => { vi.stubEnv('XDG_CONFIG_HOME', mkdtempSync(join(tmpdir(), 'pg-e2e-xdg-'))); });
afterAll(() => { vi.unstubAllEnvs(); cleanE2e(); });

interface Ran { w: E2eWorld; code: number }
const cache = new Map<string, Promise<Ran>>();
/** One run per scenario, shared by the tests that look at it (a run takes about 15 s). */
function scenario(name: string, o: E2eOptions): Promise<Ran> {
  let r = cache.get(name);
  if (r === undefined) { r = (async () => { const w = await e2eWorld(o); return { w, code: await w.run() }; })(); cache.set(name, r); }
  return r;
}
const PRIVATE = (): Promise<Ran> => scenario('private-signing', { signing: true });
const CLOSED = (): Promise<Ran> => scenario('private-signing-closed', { signing: true, pr: 'closed' });
const PLAIN = (): Promise<Ran> => scenario('private-plain', {});
const PUBLIC = (): Promise<Ran> => scenario('public', { shape: 'public' });
const FAILED = (): Promise<Ran> => scenario('private-planted-missed', { planted: 'missed' });

const APP = `${OWN}/${APP_NAME}`;
const SCRATCH = `pipegen-proof-${APP_NAME}`;
const CENTRAL = `${OWN}/pipelines`;
const SIGNING_ENV = 'pipegen-signing';
const isWrite = (c: Call): boolean => !c.route.startsWith('GET ');
const indexOfCall = (calls: readonly Call[], pred: (c: Call) => boolean): number => calls.findIndex(pred);
const rulesetNames = (w: E2eWorld, repo: string): string[] => [...w.fgh.repo(repo).rulesets.values()].map((r) => String(r.name)).sort();
const EVERYTHING_FINISH_APPLIES = /\/rulesets|\/actions\/permissions|\/vulnerability-alerts|\/variables|\/environments\/\{environment_name\}\/variables/;

describe('e2e', () => {
  it('e2e: private app full run against fake GitHub delivers one PR, record, and finish applies settings', async () => {
    const { w, code } = await PRIVATE();
    expect(code, w.io.errs.join('\n')).toBe(0);
    expect(w.io.lines.at(-1)).toBe('pipegen set up this repository.');
    expect(w.fgh.unrouted).toEqual([]);

    // exactly one setup PR, from pipegen/setup into the default branch
    const prs = w.fgh.calls.filter((c) => c.route === 'POST /repos/{owner}/{repo}/pulls');
    expect(prs).toHaveLength(1);
    expect(prs[0]?.params).toMatchObject({ repo: APP_NAME, head: 'pipegen/setup', base: 'main' });
    expect(w.fgh.repo(APP).pulls).toHaveLength(1);

    // exactly one install record, in the private central repo, naming this app
    const central = w.fgh.filesOn(CENTRAL, 'main') as Map<string, string>;
    expect([...central.keys()].filter((p) => p.startsWith('installs/'))).toEqual(['installs/orderdesk.json']);
    const record = JSON.parse(central.get('installs/orderdesk.json') as string) as Record<string, any>;
    expect(record.app).toMatchObject({ owner: OWN, repo: APP_NAME, private: true });
    expect(record.blockFrom).toBe('2026-11-14');
    expect(typeof record.cosignPubSha256).toBe('string');
    expect(record.environments.map((e: { name: string }) => e.name)).toEqual([SIGNING_ENV]);

    // finish applied: both rulesets of the app, the central merge rule and central CODEOWNERS, the signing environment, PIPEGEN_BLOCK_FROM
    expect(rulesetNames(w, APP)).toEqual(['pipegen', 'pipegen-reviews']);
    for (const r of w.fgh.repo(APP).rulesets.values()) expect(r.enforcement).toBe('active');
    expect(rulesetNames(w, CENTRAL)).toEqual(['pipegen']);
    expect([...w.fgh.repo(CENTRAL).rulesets.values()][0]?.enforcement).toBe('active');
    expect(central.get('.github/CODEOWNERS')).toContain('/.github/workflows/ @CrisWorking @AltReviewer');
    const env = w.fgh.repo(APP).envs.get(SIGNING_ENV);
    expect([...(env?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']);
    expect(env?.policies.map((p) => p.name)).toEqual(['main']);
    expect(w.fgh.x(APP).envVars.get(SIGNING_ENV)?.get('PIPEGEN_COSIGN_PUB')?.value).toMatch(/BEGIN PUBLIC KEY|BEGIN SIGSTORE PUBLIC KEY|^-----/);
    expect(w.fgh.x(APP).variables.get('PIPEGEN_BLOCK_FROM')?.value).toBe('2026-11-14');
    expect(w.fgh.x(APP).actions.sha_pinning_required).toBe(true);
    expect(w.fgh.repo(APP).stored.has('PIPEGEN_FP_KEY')).toBe(true);

    // settings only after the merge: no lock write comes before the PR is opened, and finish runs after the owner merged it
    const calls = w.fgh.calls;
    const prAt = indexOfCall(calls, (c) => c.route === 'POST /repos/{owner}/{repo}/pulls');
    const firstLock = indexOfCall(calls, (c) => isWrite(c) && EVERYTHING_FINISH_APPLIES.test(c.route));
    expect(prAt).toBeGreaterThanOrEqual(0);
    expect(firstLock).toBeGreaterThan(prAt);
    const order = w.tl.filter((s) => /^(deliver|owner|finish):/.test(s));
    expect(order.slice(0, 3)).toEqual(['deliver: setup PR opened', 'owner: setup PR merged', 'finish: start']);
  }, 180_000);

  it('e2e: closing the setup PR unmerged → finish applies nothing', async () => {
    const { w, code } = await CLOSED();
    expect(code, w.io.errs.join('\n')).toBe(0);
    expect(w.io.lines.join('\n')).toContain('The setup pull request was closed without merging: nothing was applied.');
    expect(w.tl).toContain('owner: setup PR closed');
    expect(w.tl).not.toContain('finish: start');
    expect(w.io.lines.join('\n')).not.toMatch(/pipegen finish for|applied:/);
    // not one lock, setting or variable was written, in either repo
    expect(w.fgh.writes().filter((c) => EVERYTHING_FINISH_APPLIES.test(c.route))).toEqual([]);
    expect(w.fgh.repo(APP).rulesets.size).toBe(0);
    expect(w.fgh.repo(CENTRAL).rulesets.size).toBe(0);
    expect(w.fgh.x(APP).variables.size).toBe(0);
    expect(w.fgh.x(APP).actions.sha_pinning_required).toBe(false);
    expect(w.fgh.x(APP).vulnAlerts).toBe(false);
    // the signing environment made before the PR (N4) stays, with its key, and the install record names it (S11)
    const env = w.fgh.repo(APP).envs.get(SIGNING_ENV);
    expect(env).toBeDefined();
    expect([...(env?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']);
    const record = JSON.parse((w.fgh.filesOn(CENTRAL, 'main') as Map<string, string>).get('installs/orderdesk.json') as string) as Record<string, any>;
    expect(record.environments.map((e: { name: string }) => e.name)).toEqual([SIGNING_ENV]);
    expect(record.blockFrom).toBeUndefined();
    // the PR itself is closed and unmerged
    expect(w.fgh.repo(APP).pulls[0]?.state).toBe('closed');
    expect(w.fgh.x(APP).merged.get(1)).toBeNull();
  }, 180_000);

  it('e2e: the cleanup is done before the preview, and delivery waits for cleaned with a passed proof', async () => {
    for (const { w, code } of [await PRIVATE(), await PUBLIC()]) {
      expect(code, w.io.errs.join('\n')).toBe(0);
      expect(w.fgh.unrouted).toEqual([]);
      const at = (s: string): number => w.tl.findIndex((x) => x === s || x.startsWith(`${s}:`));
      const lastAt = (s: string): number => w.tl.findLastIndex((x) => x === s || x.startsWith(`${s}:`));
      // the REAL pushProofSetup: dependabot updates off, the no-run check, then the scratch secrets are stored, and only then the proof branches are pushed
      expect(at('setup: dependabot updates off')).toBeGreaterThanOrEqual(0);
      expect(at('setup: no-run check')).toBeGreaterThan(at('setup: dependabot updates off'));
      expect(at('scratch secret stored')).toBeGreaterThan(at('setup: no-run check'));
      expect(at(`push ${SCRATCH} proof/${RUN_ID}/main`)).toBeGreaterThan(lastAt('scratch secret stored'));
      expect(at(`push ${SCRATCH} proof/${RUN_ID}/planted`)).toBeGreaterThan(at(`push ${SCRATCH} proof/${RUN_ID}/main`));
      expect(at(`push ${SCRATCH} main (force)`)).toBeLessThan(at('scratch secret stored'));
      // the REAL cleanupAfterProof: the scratch secrets first, then the proof branches, the runs, the default branch reset; only then the cleanup returns
      expect(at('scratch secret deleted')).toBeGreaterThan(lastAt('scratch secret stored'));
      expect(at('scratch proof branch deleted')).toBeGreaterThan(lastAt('scratch secret deleted'));
      expect(at('scratch run deleted')).toBeGreaterThan(at('scratch secret deleted'));
      expect(at('scratch default branch reset')).toBeGreaterThan(at('scratch proof branch deleted'));
      expect(at('cleanup returned')).toBeGreaterThan(at('scratch default branch reset'));
      // only after the cleanup: the preview is answered, then the PR is opened
      expect(at('preview: confirmed')).toBeGreaterThan(at('cleanup returned'));
      expect(at('deliver: setup PR opened')).toBeGreaterThan(at('preview: confirmed'));
      expect(w.io.asked.filter((q) => /Open the setup pull request with these changes\?/.test(q))).toHaveLength(1);
      // what is left on the fake: nothing of the proof
      expect(w.cleanups).toHaveLength(1);
      expect(w.cleanups[0]?.leftovers).toEqual([]);
      expect(w.fgh.repo(`${OWN}/${SCRATCH}`).stored.size).toBe(0);
      expect([...w.fgh.repo(`${OWN}/${SCRATCH}`).refs.keys()].filter((r) => r.startsWith('heads/proof/'))).toEqual([]);
      expect([...w.fgh.repo(CENTRAL).refs.keys()].filter((r) => r.startsWith('heads/proof/'))).toEqual([]);
      expect(w.fgh.actionRuns(`${OWN}/${SCRATCH}`)).toEqual([]);
      // the central proof branch exists only for a private app, and is deleted by the cleanup after the secrets
      if (w.fgh.repo(`${OWN}/${APP_NAME}`).private) {
        expect(at(`push pipelines proof/${RUN_ID}`)).toBeLessThan(at(`push ${SCRATCH} main (force)`));
        expect(at('central proof branch deleted')).toBeGreaterThan(at('scratch secret deleted'));
      } else {
        expect(at('central proof branch deleted')).toBe(-1);
      }
      // nothing was written to the app or the central repo before the proof passed and was cleaned
      const cleanedAt = at('cleanup returned');
      expect(at('deliver: setup PR opened')).toBeGreaterThan(cleanedAt);
      expect(w.fgh.writesTo(APP_NAME).length).toBeGreaterThan(0);
    }
    // a proof that does not pass delivers nothing: no PR, no write to the app, the real cleanup done, no preview
    const { w, code } = await FAILED();
    expect(code).toBe(2);
    expect(w.io.errs.join('\n')).toContain('the proof did not pass');
    expect(w.tl).toContain('cleanup returned');
    expect(w.tl.some((x) => x.startsWith('scratch secret deleted'))).toBe(true);
    expect(w.tl).not.toContain('preview: confirmed');
    expect(w.tl).not.toContain('deliver: setup PR opened');
    expect(w.cleanups).toHaveLength(1);
    expect(w.cleanups[0]?.leftovers).toEqual([]);
    expect(w.fgh.repo(`${OWN}/${SCRATCH}`).stored.size).toBe(0);
    expect(w.fgh.writesTo(APP_NAME)).toEqual([]);
    // the one write to the central repo is the cleanup deleting the proof's own branch (the central copy the proof pushed)
    expect(w.fgh.writesTo('pipelines').map((c) => `${c.route} ${String(c.params.ref)}`)).toEqual([`DELETE /repos/{owner}/{repo}/git/refs/{ref} heads/proof/${RUN_ID}`]);
    expect(w.fgh.repo(APP).pulls).toEqual([]);
    expect(w.io.asked.some((q) => /Open the setup pull request/.test(q))).toBe(false);
  }, 240_000);

  it('e2e: no planted file, harness file, compat copy or secret value reaches the setup PR', async () => {
    for (const { w, code } of [await PRIVATE(), await PLAIN(), await PUBLIC()]) {
      expect(code, w.io.errs.join('\n')).toBe(0);
      // the check is not vacuous: the proof's planted branch did hold the planted files and the harness
      const planted = w.fgh.proof.pushes.find((p) => p.branch.endsWith('/planted'));
      expect(planted?.files.some((f) => f.startsWith('pipegen-planted/'))).toBe(true);
      expect(w.fgh.proof.pushes.some((p) => p.files.includes(HARNESS_PATH))).toBe(true);
      // the pushes are the real pushProofSetup's commits (read back from its session): the base holds the project and no workflow, the main branch
      // holds the harness and no planted file, the planted branch holds both
      const base = w.fgh.proof.pushes.find((p) => p.repo === SCRATCH && p.branch === 'main');
      expect(base?.files).toContain('src/server.js');
      expect(base?.files.some((f) => f.startsWith('.github/workflows/'))).toBe(false);
      const main = w.fgh.proof.pushes.find((p) => p.branch === `proof/${RUN_ID}/main`);
      expect(main?.files).toContain(HARNESS_PATH);
      expect(main?.files.some((f) => f.startsWith('pipegen-planted/'))).toBe(false);
      // the delivered batch: the setup branch and the central repo's head
      const delivered = [w.fgh.filesOn(APP, 'pipegen/setup'), w.fgh.filesOn(CENTRAL, 'main')].filter((f): f is Map<string, string> => f !== null);
      expect(delivered).toHaveLength(2);
      for (const files of delivered) {
        for (const [path, text] of files) {
          expect(path, path).not.toMatch(/^pipegen-planted\//);
          expect(path, path).not.toMatch(/(^|\/)pipegen-c1b\//);
          expect(path, path).not.toBe(HARNESS_PATH);
          expect(path, path).not.toContain(COMPAT_PREFIX);
          expect(path, path).not.toMatch(/pipegen-proof-harness/);
          expect(text, path).not.toContain('pipegen-planted/');
          expect(text, path).not.toContain(KEY_PW);
          expect(text, path).not.toMatch(/PRIVATE KEY/);
        }
      }
      // no secret value in anything the run printed, asked, or sent to GitHub
      const everything = JSON.stringify([w.io.lines, w.io.errs, w.io.asked, w.fgh.calls.map((c) => c.params)]);
      expect(everything).not.toContain(KEY_PW);
      expect(everything).not.toMatch(/PRIVATE KEY/);
    }
  }, 240_000);

  it('e2e: public app full run delivers the local two-level layout and a records-only pipelines', async () => {
    const { w, code } = await PUBLIC();
    expect(code, w.io.errs.join('\n')).toBe(0);
    // the real gateReachable read the gate at its pinned commit (a public app loads it from the public pipegen repo)
    expect(w.fgh.calls.some((c) => c.route === 'GET /repos/{owner}/{repo}/commits/{ref}')).toBe(true);
    const app = w.fgh.filesOn(APP, 'pipegen/setup') as Map<string, string>;
    // the two-level local chain: the caller job `pipegen` calls the local merge workflow, whose job is `gate`
    const caller = app.get('.github/workflows/pipegen.yml') as string;
    expect(caller).toMatch(/^ {2}pipegen:\n {4}name: pipegen\n {4}uses: \.\/\.github\/workflows\/pipegen-merge\.yml$/m);
    expect(caller).not.toMatch(/CrisWorking\/pipelines\/\.github\/workflows/);
    const merge = app.get('.github/workflows/pipegen-merge.yml') as string;
    expect(merge).toMatch(/^ {2}gate:$/m);
    // pipelines holds records only: the install record and CODEOWNERS (and its own README), no workflow
    const central = w.fgh.filesOn(CENTRAL, 'main') as Map<string, string>;
    expect([...central.keys()].sort()).toEqual(['.github/CODEOWNERS', 'README.md', 'installs/orderdesk.json']);
    expect(w.fgh.filesOn(CENTRAL, 'main')?.has('.github/workflows/orderdesk--merge.yml')).toBe(false);
    const record = JSON.parse(central.get('installs/orderdesk.json') as string) as Record<string, any>;
    expect(record.app).toMatchObject({ private: false });
    // finish applied the app's locks; the proof never pushed central workflows for a public app
    expect(rulesetNames(w, APP)).toEqual(['pipegen', 'pipegen-reviews']);
    expect(w.fgh.proof.pushes.some((p) => p.repo === 'pipelines')).toBe(false);
    expect(w.fgh.x(APP).variables.get('PIPEGEN_BLOCK_FROM')?.value).toBe('2026-11-14');
  }, 180_000);

  it('e2e helpers: the proof fakes, the constants and the keys fake come from proof-world.ts, not a copy', () => {
    const world = readFileSync(join(import.meta.dirname, 'helpers/e2e-world.ts'), 'utf8');
    expect(world).toMatch(/from '\.\/proof-world\.js'/);
    for (const copy of [/function fakeKeys/, /export const OWN\b/, /const RUN_ID\b/, /export const TYPED\b/, /const OWN\s*=/]) expect(world).not.toMatch(copy);
  });

  // Pins the G14fix repair (run-proof.ts): a private app's proof asks the real harness for its files only for the central commit the setup pushed
  // (before it, a precheck checks the assembled workflows and the compat copies), so the run no longer stops with "The draft has a central pin,
  // but no proof central sha was given." The fixture has no test script, so the run also passes the no-test-script + `--skip tests` path.
  it('e2e: a private app run reaches the proof with the real harness (no stand-in central sha)', async () => {
    const { w, code } = await scenario('private-real-harness', {});
    expect(w.io.errs.join('\n')).not.toContain('The draft has a central pin, but no proof central sha was given.');
    expect(code).toBe(0);
  }, 120_000);

  // Ruling G-SIGN1 (G16 review F6): a private app that builds an image, with NO pipegen-signing environment before the run. The run makes
  // the environment itself after consent, reads it back with the default-branch rule, re-derives the signing mode (key-env) before assembly,
  // and the first run signs: the delivered workflows sign with the key, the key is stored, the record says pipegen made the environment.
  it('e2e: G-SIGN1 the first run on a private repo with no signing environment makes it, reads it back, and signs', async () => {
    const { w, code } = await scenario('private-signing-fresh', { signing: true, signingEnv: false });
    expect(code, w.io.errs.join('\n')).toBe(0);
    expect(w.io.lines.at(-1)).toBe('pipegen set up this repository.');
    expect(w.fgh.unrouted).toEqual([]);
    expect(w.io.errs.join('\n')).toMatch(/pipegen made the environment pipegen-signing \(default branch only\) and read it back, so this run signs/);
    expect(w.io.errs.join('\n')).not.toMatch(/Signing is off/);
    // G-SIGN1-R1: the consent screen named the write before the yes
    expect(w.io.asked.find((q) => /Go ahead\?/.test(q))).toMatch(/pipegen creates the environment pipegen-signing \(usable from the default branch only\)/);
    expect(w.io.errs.join('\n')).not.toMatch(/deleted the environment/);

    // the environment: made once (the PUT and its one rule), before any proof push and before the setup PR; read back after its rule
    const calls = w.fgh.calls;
    const envPuts = calls.filter((c) => c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}' && c.params.environment_name === SIGNING_ENV);
    expect(envPuts).toHaveLength(1);
    const putAt = calls.indexOf(envPuts[0] as Call);
    const ruleAt = indexOfCall(calls, (c) => c.route === 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies');
    const readBackAt = calls.findIndex((c, i) => i > ruleAt && c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies');
    expect(putAt).toBeGreaterThanOrEqual(0);
    expect(ruleAt).toBeGreaterThan(putAt);
    expect(readBackAt).toBeGreaterThan(ruleAt);
    const firstProofWrite = indexOfCall(calls, (c) => isWrite(c) && String(c.params.repo) === SCRATCH);
    expect(firstProofWrite).toBeGreaterThan(readBackAt);
    expect(indexOfCall(calls, (c) => c.route === 'POST /repos/{owner}/{repo}/pulls')).toBeGreaterThan(readBackAt);
    const env = w.fgh.repo(APP).envs.get(SIGNING_ENV);
    expect(env?.deployment_branch_policy).toEqual({ protected_branches: false, custom_branch_policies: true });
    expect(env?.policies.map((p) => p.name)).toEqual(['main']);
    expect([...(env?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']);
    expect(w.fgh.x(APP).envVars.get(SIGNING_ENV)?.get('PIPEGEN_COSIGN_PUB')?.value).toMatch(/^-----BEGIN/);

    // the record: key-env, the public key, and the environment as pipegen's own (uninstall deletes it), with GitHub's created_at
    const central = w.fgh.filesOn(CENTRAL, 'main') as Map<string, string>;
    const record = JSON.parse(central.get('installs/orderdesk.json') as string) as Record<string, any>;
    expect(record.planned.signingMode).toBe('key-env');
    expect(typeof record.cosignPubSha256).toBe('string');
    expect(record.environments).toEqual([expect.objectContaining({ name: SIGNING_ENV, created: true, githubCreatedAt: env?.created_at })]);
    expect(record.environments[0].previous).toBeUndefined();

    // the delivered workflows sign with the key in the environment (key-env), as the seeded run's do
    const sign = central.get('.github/workflows/orderdesk--sign.yml') as string;
    expect(sign).toMatch(/environments pipegen-signing, key-env|\(environment pipegen-signing, key-env\)/);
    expect(sign).toMatch(/^\s+environment: pipegen-signing$/m);
    expect(sign).toMatch(/cosign" sign --yes --key env:\/\/PIPEGEN_COSIGN_KEY/);
    expect(sign).toMatch(/PIPEGEN_COSIGN_KEY: "\$\{\{ secrets\.PIPEGEN_COSIGN_KEY \}\}"/);
  }, 240_000);

  // Ruling G-SIGN1-R1: a run that made its own signing environment and stops before delivery (here: "no" at the preview) deletes it again,
  // and takes it off the local leftovers file; the seeded run's consent screen has no such line (the environment is proven there)
  it('e2e: G-SIGN1-R1 a no at the preview deletes the signing environment the run made', async () => {
    const { w, code } = await scenario('private-signing-fresh-no', { signing: true, signingEnv: false, answers: { preview: false } });
    expect(code, w.io.errs.join('\n')).toBe(1);
    expect(w.fgh.calls.some((c) => c.route === 'POST /repos/{owner}/{repo}/pulls')).toBe(false);
    expect(w.fgh.repo(APP).envs.has(SIGNING_ENV)).toBe(false);
    const del = w.fgh.calls.filter((c) => c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}');
    expect(del.map((c) => c.params.environment_name)).toEqual([SIGNING_ENV]);
    expect(w.io.errs.join('\n')).toMatch(/pipegen deleted the environment pipegen-signing it made earlier in this run/);
    const seeded = await PRIVATE();
    expect(seeded.w.io.asked.find((q) => /Go ahead\?/.test(q))).not.toMatch(/pipegen creates the environment pipegen-signing/);
  }, 240_000);

  // G17-F1-R2 (sec I1): the scratch keys of the e2e world apply ScratchKeys' own name rules (placeholderName); the run's vault holds the
  // fingerprint key (run.ts generateFpKey) and the real assembled workflows read GITHUB_TOKEN and PIPEGEN_FP_KEY, so without the filter in
  // run-proof.ts the setup would throw and the run stop. Both layouts reach delivery with placeholders for stored names only
  it('e2e: G17-F1-R2 the public and the private run store scratch placeholders through the real name rules and set the repository up', async () => {
    for (const [layout, ran] of [['private', await PLAIN()], ['public', await PUBLIC()]] as const) {
      expect(ran.code, `${layout}: ${ran.w.io.errs.join('\n')}`).toBe(0);
      const setups = ran.w.tl.filter((x) => x.startsWith('keys.setup:'));
      expect(setups.length, layout).toBe(1);
      expect(setups[0], layout).not.toMatch(/GITHUB_|PIPEGEN_/);
      expect(ran.w.io.lines.at(-1), layout).toBe('pipegen set up this repository.');
    }
  }, 480_000);

  // G17-F1 (sec M1): `--skip deploy` signs nothing (assembly drops the signing plan), so the run makes no signing environment, says
  // nothing about signing with a key pair, asks no consent for it, makes no key pair, and needs no memory folder
  it('e2e: G17-F1 --skip deploy on a first private run makes no signing environment, prints no "this run signs" note and asks no consent for it', async () => {
    const w = await e2eWorld({ signing: true, signingEnv: false, skip: 'tests,deploy' });
    let keys = 0;
    const key = w.stages.signingKey as NonNullable<typeof w.stages.signingKey>;
    w.stages.signingKey = async () => { keys++; return key(); };
    const code = await w.run();
    expect(code, w.io.errs.join('\n')).toBe(0);
    const envWrites = w.fgh.calls.filter((c) => isWrite(c) && c.route.includes('/environments/'));
    expect(envWrites.map((c) => c.route)).toEqual([]);
    expect(w.fgh.repo(APP).envs.has(SIGNING_ENV)).toBe(false);
    const errs = w.io.errs.join('\n');
    expect(errs).not.toMatch(/pipegen made the environment pipegen-signing/);
    expect(errs).not.toMatch(/deleted the environment pipegen-signing/);
    expect(errs).not.toMatch(/Signing is off/);
    expect(w.io.asked.find((q) => /Go ahead\?/.test(q))).not.toMatch(/pipegen creates the environment pipegen-signing/);
    expect(keys).toBe(0);
  }, 240_000);

  it('e2e: G17-F1 --skip deploy on a repo with a proven signing environment and no memory folder is not stopped for the memory folder', async () => {
    const w = await e2eWorld({ signing: true, skip: 'tests,deploy' });
    w.deps.isMemory = () => false;
    let keys = 0;
    const key = w.stages.signingKey as NonNullable<typeof w.stages.signingKey>;
    w.stages.signingKey = async () => { keys++; return key(); };
    const code = await w.run();
    expect(w.io.errs.join('\n')).not.toMatch(/no such folder/);
    expect(code, w.io.errs.join('\n')).toBe(0);
    expect(keys).toBe(0);
  }, 240_000);
});
