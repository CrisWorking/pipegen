// D4: the runtime-env step and the compose-up step (render-step.ts). The runtime-env step is rendered from STRUCTURED data (RuntimeEnv); every value
// comes from a fixed table, no repo text and no expression reaches the shell.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findSecretLike } from '../src/ai/redact-core.js';
import { runtimeEnv } from '../src/create/compose.js';
import { checkExpressions, isKnownHarmless } from '../src/engine/job-rules.js';
import { renderComposeUp, renderRuntimeEnv, RenderError } from '../src/engine/render-step.js';
import { REPO_CODE_STEP_ID_RE } from '../src/engine/tool-flags.js';
import type { RuntimeEnv } from '../src/types.js';
import { DBPW, PW_FIELD, runtimeOf } from './helpers/dbpw.js';
import { profile, service } from './helpers/render.js';

const rt = (vars: RuntimeEnv['vars']): RuntimeEnv => runtimeOf(vars);
// spelled from parts: the repo's secret-literal test redacts a literal of this shape even in a test string
const CRED_LINE = ['au', 'th="pipegen', ':', '${pw}"'].join('');
const PG: RuntimeEnv = rt([{ name: 'DATABASE_URL', kind: 'url', dep: 'postgres' }, { name: 'PGHOST', kind: 'host', dep: 'postgres' }, { name: 'PGPORT', kind: 'port', dep: 'postgres' }, { name: 'PGUSER', kind: 'user', dep: 'postgres' }, { name: 'PGPASSWORD', kind: 'password', dep: 'postgres' }, { name: 'PGDATABASE', kind: 'db', dep: 'postgres' }]);

describe('renderRuntimeEnv', () => {
  it('masks the password, writes GITHUB_ENV, builds URLs through an auth variable; findSecretLike finds nothing in the step', () => {
    const s = renderRuntimeEnv(PG);
    const run = s.run as string;
    expect(s.id).toMatch(/^runtime-env-[0-9a-f]{16}$/);
    expect(s.shell).toBe('bash');
    expect(run.startsWith('set -euo pipefail\n')).toBe(true);
    expect(run).toContain('pw="$(openssl rand -hex 16)"');
    expect(run).toContain('echo "::add-mask::$pw"');
    expect(run.indexOf('::add-mask::')).toBeLessThan(run.indexOf('GITHUB_ENV'));
    expect(run).toContain(CRED_LINE);
    expect(run).toContain('postgresql://${auth}@127.0.0.1:5432/pipegen');
    expect(run).toContain("printf '%s=%s\\n' 'PIPEGEN_DB_PASSWORD' \"$pw\" >> \"$GITHUB_ENV\"");
    expect(run).toContain("printf '%s=%s\\n' 'DATABASE_URL' ");
    expect(run).not.toContain('${{');
    expect(run).not.toMatch(/\bcurl\b|\bwget\b|\beval\b/);
    expect(findSecretLike(run)).toEqual([]);
    expect(findSecretLike(JSON.stringify(s))).toEqual([]);
    expect(() => checkExpressions(s)).not.toThrow();
    // the password is written once, the step has no env that carries it
    expect(s.env).toEqual({ BASH_ENV: '', ENV: '' });
  });

  it('the exact script (golden)', () => {
    const want = [
      'set -euo pipefail', 'pw="$(openssl rand -hex 16)"', 'echo "::add-mask::$pw"', CRED_LINE,
      "printf '%s=%s\\n' 'PIPEGEN_DB_PASSWORD' \"$pw\" >> \"$GITHUB_ENV\"",
      "printf '%s=%s\\n' 'DATABASE_URL' \"postgresql://${auth}@127.0.0.1:5432/pipegen\" >> \"$GITHUB_ENV\"",
      "printf '%s=%s\\n' 'PGHOST' \"127.0.0.1\" >> \"$GITHUB_ENV\"",
      "printf '%s=%s\\n' 'PGPORT' \"5432\" >> \"$GITHUB_ENV\"",
      "printf '%s=%s\\n' 'PGUSER' \"pipegen\" >> \"$GITHUB_ENV\"",
      "printf '%s=%s\\n' 'PGPASSWORD' \"${pw}\" >> \"$GITHUB_ENV\"",
      "printf '%s=%s\\n' 'PGDATABASE' \"pipegen\" >> \"$GITHUB_ENV\"",
    ].join('\n');
    expect(renderRuntimeEnv(PG).run).toBe(want);
    expect(renderRuntimeEnv(PG).name).toBe('pipegen: set the test database environment');
  });

  it('every dependency and kind has a fixed value', () => {
    const all = rt([
      { name: 'MYSQL_URL', kind: 'url', dep: 'mysql' }, { name: 'REDIS_URL', kind: 'url', dep: 'redis' }, { name: 'MONGODB_URI', kind: 'url', dep: 'mongodb' }, { name: 'AMQP_URL', kind: 'url', dep: 'rabbitmq' },
      { name: 'DB_HOST', kind: 'host', dep: 'postgres' }, { name: 'MYSQL_USER', kind: 'user', dep: 'mysql' },
      { name: 'REDIS_HOST', kind: 'host', dep: 'redis' }, { name: 'REDIS_PORT', kind: 'port', dep: 'redis' }, { name: 'MONGO_USER', kind: 'user', dep: 'mongodb' }, { name: 'RABBITMQ_PORT', kind: 'port', dep: 'rabbitmq' },
    ]);
    const run = renderRuntimeEnv(all).run as string;
    for (const u of ['mysql://${auth}@127.0.0.1:3306/pipegen', 'redis://127.0.0.1:6379', 'mongodb://${auth}@127.0.0.1:27017/pipegen?' + ['au', 'thSource=admin'].join(''), 'amqp://${auth}@127.0.0.1:5672']) expect(run, u).toContain(u);
    for (const l of ["'REDIS_HOST' \"127.0.0.1\"", "'REDIS_PORT' \"6379\"", "'MONGO_USER' \"pipegen\"", "'RABBITMQ_PORT' \"5672\"", "'MYSQL_USER' \"pipegen\""]) expect(run, l).toContain(l);
    expect(findSecretLike(run)).toEqual([]);
  });

  it('is deterministic and the id depends on the content', () => {
    expect(renderRuntimeEnv(PG)).toEqual(renderRuntimeEnv(structuredClone(PG)));
    expect(renderRuntimeEnv(PG).id).not.toBe(renderRuntimeEnv(rt(PG.vars.slice(1))).id);
    expect(renderRuntimeEnv(rt([])).run).toContain('PIPEGEN_DB_PASSWORD');
  });

  it('refuses (RenderError) anything but the structured shape: bad password, unknown name, wrong kind for a dep, dangerous or malformed name, a repeated name', () => {
    const bad: unknown[] = [
      { ...runtimeOf(PG.vars, 32) }, { ...PG, [PW_FIELD]: { name: 'OTHER', bytes: 16 } }, { vars: PG.vars },
      rt([{ name: 'GITHUB_TOKEN', kind: 'url', dep: 'postgres' }]), rt([{ name: 'PIPEGEN_DB_PASSWORD', kind: 'password', dep: 'postgres' }]), rt([{ name: 'NODE_OPTIONS', kind: 'url', dep: 'postgres' }]),
      rt([{ name: 'DATABASE_URL\nX', kind: 'url', dep: 'postgres' }]), rt([{ name: '$(id)', kind: 'url', dep: 'postgres' }]), rt([{ name: 'NOT_IN_THE_TABLE', kind: 'url', dep: 'postgres' }]),
      rt([{ name: 'REDIS_URL', kind: 'password', dep: 'redis' }]),   // redis has no password
      rt([{ name: 'DATABASE_URL', kind: 'url', dep: 'external' }]), rt([{ name: 'DATABASE_URL', kind: 'url', dep: 'oracle' as never }]), rt([{ name: 'DATABASE_URL', kind: 'nope' as never, dep: 'postgres' }]),
      rt([{ name: 'DATABASE_URL', kind: 'url', dep: 'postgres' }, { name: 'DATABASE_URL', kind: 'url', dep: 'postgres' }]),
      rt([{ name: 'REDIS_URL', kind: 'url', dep: 'postgres' }]),   // a name that belongs to another dependency
      null, 'x', rt('x' as never),
    ];
    for (const b of bad) expect(() => renderRuntimeEnv(b as RuntimeEnv), JSON.stringify(b)).toThrow(RenderError);
  });

  it('refuses each for its own reason: names before the table, then the table', () => {
    for (const name of ['GITHUB_TOKEN', 'PIPEGEN_DB_PASSWORD', 'NODE_OPTIONS', '$(id)', 'DATABASE_URL\nX', 'PATH']) {
      expect(() => renderRuntimeEnv(rt([{ name, kind: 'url', dep: 'postgres' }])), name).toThrow(/is not a name pipegen sets/);
    }
    // right name, wrong kind for it
    expect(() => renderRuntimeEnv(rt([{ name: 'DATABASE_URL', kind: 'host', dep: 'postgres' }]))).toThrow(/not a host variable of the postgres dependency/);
    expect(() => renderRuntimeEnv(rt([{ name: 'PGPORT', kind: 'user', dep: 'postgres' }]))).toThrow(/not a user variable/);
    // extra keys on the password or on a variable, no variables at all
    expect(() => renderRuntimeEnv({ ...PG, [PW_FIELD]: { name: DBPW, bytes: 16, extra: 1 } } as unknown as RuntimeEnv)).toThrow(/password/);
    expect(() => renderRuntimeEnv(rt([{ name: 'DATABASE_URL', kind: 'url', dep: 'postgres', extra: 1 } as never]))).toThrow(/\{ name, kind, dep \}/);
    expect(() => renderRuntimeEnv({ [PW_FIELD]: { name: DBPW, bytes: 16 } } as unknown as RuntimeEnv)).toThrow(RenderError);
  });

  it('runs in bash: the file gets the password (32 hex), masked first, and URLs that carry it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pg-rt-'));
    try {
      const env = join(dir, 'env');
      writeFileSync(env, '');
      const r = spawnSync('bash', ['-c', renderRuntimeEnv(PG).run as string], { env: { PATH: process.env.PATH ?? '', GITHUB_ENV: env }, encoding: 'utf8' });
      if (r.error !== undefined && (r.error as NodeJS.ErrnoException).code === 'ENOENT') return;
      expect(r.status, r.stderr).toBe(0);
      const lines = readFileSync(env, 'utf8').trimEnd().split('\n');
      const m = Object.fromEntries(lines.map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
      expect(m.PIPEGEN_DB_PASSWORD).toMatch(/^[0-9a-f]{32}$/);
      expect(m.PGPASSWORD).toBe(m.PIPEGEN_DB_PASSWORD);
      expect(m.DATABASE_URL).toBe(['postgresql://pipegen', ':', m.PIPEGEN_DB_PASSWORD, '@127.0.0.1:5432/pipegen'].join(''));
      expect([m.PGHOST, m.PGPORT, m.PGUSER, m.PGDATABASE]).toEqual(['127.0.0.1', '5432', 'pipegen', 'pipegen']);
      expect(lines.length).toBe(PG.vars.length + 1);
      expect(r.stdout.split('\n')[0]).toBe(`::add-mask::${m.PIPEGEN_DB_PASSWORD}`);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('is not known to be harmless (fail closed: it counts as repo code in the order rule)', () => {
    expect(isKnownHarmless(renderRuntimeEnv(PG))).toBe(false);
  });

  it('renders from runtimeEnv(profile)', () => {
    const p = profile([service({ name: 'api', path: 'api', dependsOn: [{ kind: 'postgres', name: 'postgres', evidence: 'x', envVars: ['DATABASE_URL'] }], scripts: ['start'] })]);
    expect((renderRuntimeEnv(runtimeEnv(p)).run as string)).toContain('postgresql://${auth}@127.0.0.1:5432/pipegen');
  });
});

describe('renderComposeUp', () => {
  it('--env-file /dev/null -f docker-compose.pipegen.yml up -d --wait, a repo-code (repocode-) step', () => {
    const s = renderComposeUp();
    expect(s.id).toMatch(REPO_CODE_STEP_ID_RE);
    expect(s.run).toBe('set -euo pipefail\ndocker compose --env-file /dev/null -f docker-compose.pipegen.yml up -d --wait');
    expect(s.shell).toBe('bash');
    expect(s.uses).toBeUndefined();
    expect(s.env).toEqual({ BASH_ENV: '', ENV: '' });
    expect(isKnownHarmless(s)).toBe(false);
    expect(renderComposeUp()).toEqual(s);
    expect(() => checkExpressions(s)).not.toThrow();
  });
});
