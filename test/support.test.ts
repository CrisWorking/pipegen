import { afterEach, describe, expect, it } from 'vitest';
import { readProject } from '../src/read/project.js';
import { supportLevel } from '../src/read/support.js';
import { cleanupRepos, makeRepo } from './helpers/make-repo.js';

const GH = 'https://github.com/o/r.git';
const profile = (fixture: string) => readProject(makeRepo(fixture, GH));

afterEach(() => cleanupRepos());

describe('support', () => {
  it('single node service → full', async () => {
    const r = supportLevel(await profile('node-npm'), 'v0.2');
    expect(r).toEqual({ level: 'full', reasons: [] });
  });

  it('pnpm workspaces → audit-only with monorepo reason', async () => {
    const r = supportLevel(await profile('node-pnpm-workspaces'), 'v0.2');
    expect(r.level).toBe('audit-only');
    expect(r.reasons).toEqual([
      'Monorepos and repos with several services arrive in v0.4. You can run `pipegen audit` today.',
    ]);
  });

  it('python → audit-only with v0.4 reason', async () => {
    const r = supportLevel(await profile('python-poetry'), 'v0.2');
    expect(r.level).toBe('audit-only');
    expect(r.reasons).toEqual(['Python support arrives in v0.4. You can run `pipegen audit` today.']);
  });

  it('no service found → audit-only with a no-service reason', async () => {
    const p = await profile('node-npm');
    const r = supportLevel({ ...p, services: [] }, 'v0.2');
    expect(r.level).toBe('audit-only');
    expect(r.reasons).toEqual([
      'The repo has no service pipegen can run yet. You can run `pipegen audit` today.',
    ]);
  });

  it('v0.4 accepts python and monorepos', async () => {
    expect(supportLevel(await profile('python-poetry'), 'v0.4')).toEqual({ level: 'full', reasons: [] });
    expect(supportLevel(await profile('node-pnpm-workspaces'), 'v0.4')).toEqual({ level: 'full', reasons: [] });
  });
});
