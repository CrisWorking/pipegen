// C9 Part 0 (final-review-r1.md), written first (strict test-first):
// - r1-1: an INPUT_<name> variable is refused at every env level (the step's, the job's and the workflow's): the gate action reads every
//   INPUT_* variable it finds as an input, so a job- or workflow-level INPUT_SKIPPED could hand the gate a `skipped` the draft never gave.
// - r1-3: licence coverage says "not covered" for an npm package-lock.json with lockfileVersion 1 (Trivy reads licences from the lockfile only
//   from v2) and for the lockfile of a second language in the same service (a requirements.txt beside a package.json).
import { afterEach, describe, expect, it } from 'vitest';
import { licenceLockfilesOf } from '../src/engine/gate-inputs.js';
import { isDangerousName } from '../src/engine/job-rules.js';
import { licenceReadFor } from '../src/engine/licence-lockfiles.js';
import { readProject } from '../src/read/project.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { PipelineDraft, Service } from '../src/types.js';
import { draftOf, jobsOf, run, show, workflow, type Job } from './helpers/gate-pipeline.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { execFileSync } from 'node:child_process';
import { profile, service } from './helpers/render.js';

afterEach(cleanupRepos);

describe('r1-1: INPUT_<name> is a dangerous env name at every level', () => {
  it('isDangerousName: every INPUT_ name (any case of the prefix), and not a name that only contains INPUT', () => {
    for (const n of ['INPUT_SKIPPED', 'INPUT_MODE', 'INPUT_JOB-LIST', 'INPUT_', 'input_skipped', 'Input_Policy']) expect(isDangerousName(n), n).toBe(true);
    for (const n of ['MY_INPUT_SKIPPED', 'INPUTS', 'STRIPE_KEY']) expect(isDangerousName(n), n).toBe(false);
  });

  it('the referee: the honest pipeline passes; INPUT_SKIPPED as a job-level env of the gate job, or a workflow-level env, is refused', async () => {
    const d = draftOf();
    const honest = jobsOf(d);
    expect(show(await run([workflow(honest)], d))).toBe('');
    const jobLevel = { ...honest, gate: { ...(honest.gate as Job), env: { INPUT_SKIPPED: '["unit-tests"]' } } };
    const r1 = await run([workflow(jobLevel)], d);
    expect(r1.ok, show(r1)).toBe(false);
    expect(show(r1)).toMatch(/INPUT_SKIPPED/);
    const r2 = await run([workflow(honest, { env: { INPUT_SKIPPED: '["unit-tests"]' } })], d);
    expect(r2.ok, show(r2)).toBe(false);
    expect(show(r2)).toMatch(/INPUT_SKIPPED/);
    // any other job, and the lower-case spelling, too
    const other = { ...honest, 'base-scan': { ...(honest['base-scan'] as Job), env: { input_policy: '{}' } } };
    const r3 = await run([workflow(other)], d);
    expect(r3.ok, show(r3)).toBe(false);
    expect(show(r3)).toMatch(/input_policy/);
  });
});

describe('r1-3: licence coverage of an npm v1 lockfile and of a second language\'s lockfile', () => {
  const svc = (over: Partial<Service>): Service => service({ name: 'app', path: '.', language: 'node', packageManager: 'npm', ...over });
  const lic = (services: Service[]): PipelineDraft => draftOf({ profile: { ...profile(services), repoFiles: emptyRepoFiles() } });

  it('licenceReadFor: npm is read only with a proven lockfileVersion of 2 or more; every other kind as the table says', () => {
    expect(licenceReadFor('npm', svc({ npmLockfileVersion: 3 }))).toBe(true);
    expect(licenceReadFor('npm', svc({ npmLockfileVersion: 2 }))).toBe(true);
    expect(licenceReadFor('npm', svc({ npmLockfileVersion: 1 }))).toBe(false);
    expect(licenceReadFor('npm', svc({}))).toBe(false);   // not known: never read as covered
    for (const k of ['pip', 'yarn', 'go', 'uv'] as const) expect(licenceReadFor(k, svc({ npmLockfileVersion: 3 })), k).toBe(false);
  });

  it('licenceLockfilesOf: an npm v1 lockfile is not read; a node service with a requirements.txt also lists pip (not read); go stays', () => {
    expect(licenceLockfilesOf(lic([svc({ npmLockfileVersion: 1 })]))).toEqual([{ service: 'app', lockfiles: [{ kind: 'npm', read: false }] }]);
    expect(licenceLockfilesOf(lic([svc({ npmLockfileVersion: 3 })]))).toEqual([{ service: 'app', lockfiles: [{ kind: 'npm', read: true }] }]);
    expect(licenceLockfilesOf(lic([svc({ npmLockfileVersion: 3, alsoLanguages: ['python', 'go'], alsoPackageManagers: ['pip'] })])))
      .toEqual([{ service: 'app', lockfiles: [{ kind: 'npm', read: true }, { kind: 'pip', read: false }, { kind: 'go', read: false }] }]);
    // a kind is listed once, whatever names it twice
    expect(licenceLockfilesOf(lic([svc({ npmLockfileVersion: 3, alsoPackageManagers: ['npm', 'poetry', 'poetry'] })])))
      .toEqual([{ service: 'app', lockfiles: [{ kind: 'npm', read: true }, { kind: 'poetry', read: false }] }]);
  });

  const repoWith = (files: Record<string, string>): string => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    execFileSync('git', ['init', '-q'], { cwd: dir, stdio: 'pipe' });
    execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/o/r.git'], { cwd: dir, stdio: 'pipe' });
    return dir;
  };

  it('readProject records the npm lockfileVersion (pretty or compact JSON; none when the file names none) and a second language\'s package manager', async () => {
    const v1 = await readProject(repoWith({ 'package.json': '{"name":"a"}', 'package-lock.json': '{\n  "name": "a",\n  "version": "1.0.0",\n  "lockfileVersion": 1,\n  "requires": true,\n  "dependencies": {}\n}\n' }));
    expect(v1.services[0]?.npmLockfileVersion).toBe(1);
    const v3 = await readProject(repoWith({ 'package.json': '{"name":"a"}', 'package-lock.json': '{ "lockfileVersion": 3 }' }));
    expect(v3.services[0]?.npmLockfileVersion).toBe(3);
    const none = await readProject(repoWith({ 'package.json': '{"name":"a"}', 'package-lock.json': '{ "name": "a" }' }));
    expect(none.services[0]?.npmLockfileVersion).toBeUndefined();
    const mixed = await readProject(repoWith({ 'package.json': '{"name":"a"}', 'package-lock.json': '{ "lockfileVersion": 3 }', 'requirements.txt': 'flask==3.0.0\n' }));
    expect(mixed.services[0]).toMatchObject({ language: 'node', packageManager: 'npm', alsoLanguages: ['python'], alsoPackageManagers: ['pip'] });
    const poetry = await readProject(repoWith({ 'package.json': '{"name":"a"}', 'pyproject.toml': '[project]\nname = "a"\n', 'poetry.lock': '# x\n' }));
    expect(poetry.services[0]?.alsoPackageManagers).toEqual(['poetry']);
    // a pnpm service has no npm lockfile version, and a service with no second language no list
    const pnpm = await readProject(repoWith({ 'package.json': '{"name":"a"}', 'pnpm-lock.yaml': 'lockfileVersion: 9.0\n' }));
    expect(pnpm.services[0]?.npmLockfileVersion).toBeUndefined();
    expect(pnpm.services[0]?.alsoPackageManagers).toBeUndefined();
  });
});
