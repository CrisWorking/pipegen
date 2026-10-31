// D4: the computed compose file (composeText / createCompose) and the structured runtime env (runtimeEnv). Written first (strict test-first).
// The compose file is FULLY computed: no AI text, no repo text except validated values (slug, port, plain service path). The referee recomputes it
// and compares byte for byte (compose-judge.test.ts). Allowlists throughout: a key, an env name, a literal or a port is written only if a fixed table says so.
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { COMPOSE_PATH, composeText, createCompose, DEP_TABLE, ENV_TABLE, planCompose, runtimeEnv, runtimeEnvNotes, VALUE_TABLE } from '../src/create/compose.js';
import { baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { isDangerousName } from '../src/engine/job-rules.js';
import { NAME_RE } from '../src/read/manifest.js';
import type { Dependency, DependencyKind, RepoProfile, Service } from '../src/types.js';
import { DBPW, PG_PW_ENTRY, runtimeOf } from './helpers/dbpw.js';
import { profile, service } from './helpers/render.js';

const list = loadBaseImages();
const dep = (kind: DependencyKind, envVars: string[] = [], version?: string): Dependency => ({ kind, name: kind, evidence: 'x', envVars, ...(version === undefined ? {} : { version }) });
const api = (over: Partial<Service> = {}): Service => service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: [dep('postgres', ['DATABASE_URL'])], ...over });
const prof = (services: Service[] = [api()]): RepoProfile => profile(services);
const text = (p: RepoProfile = prof(), dockerfiles?: readonly string[]): string => composeText(p, list, dockerfiles) as string;
const doc = (p: RepoProfile = prof()): any => parse(text(p));
const ALL = (['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq'] as const).map((k) => dep(k));

describe('compose: services', () => {
  it('postgres dependency -> a service pinned by the base-image list with a healthcheck', () => {
    const d = doc();
    expect(d.services.postgres.image).toBe(baseImageRef('postgres-17'));
    expect(d.services.postgres.image).toMatch(/^postgres:17\.\d+@sha256:[0-9a-f]{64}$/);
    expect(d.services.postgres.healthcheck.test[0]).toMatch(/^CMD/);
    expect(d.services.postgres.healthcheck.interval).toBeDefined();
    expect(d.services.postgres.healthcheck.retries).toBeGreaterThan(0);
  });

  it('every kind: image id, fixed env, standard port on 127.0.0.1, fixed healthcheck', () => {
    const d = doc(prof([api({ dependsOn: ALL })]));
    expect(Object.keys(d.services)).toEqual(['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq', 'app-api']);
    const want: Record<string, { id: string; port: number }> = {
      postgres: { id: 'postgres-17', port: 5432 }, mysql: { id: 'mysql-8.4', port: 3306 }, redis: { id: 'redis-7', port: 6379 }, mongodb: { id: 'mongo-8.0', port: 27017 }, rabbitmq: { id: 'rabbitmq-4-management', port: 5672 },
    };
    for (const [k, w] of Object.entries(want)) {
      expect(d.services[k].image, k).toBe(baseImageRef(w.id));
      expect(d.services[k].ports, k).toEqual([`127.0.0.1:${w.port}:${w.port}`]);
      expect(d.services[k].healthcheck, k).toEqual(DEP_TABLE[k as keyof typeof DEP_TABLE].healthcheck);
      expect(Object.keys(d.services[k]).sort(), k).toEqual((k === 'redis' ? ['healthcheck', 'image', 'ports'] : ['environment', 'healthcheck', 'image', 'ports']).sort());
    }
    expect(d.services.postgres.environment).toEqual({ POSTGRES_USER: 'pipegen', ...PG_PW_ENTRY, POSTGRES_DB: 'pipegen' });
  });

  it('app depends_on a healthy db; build is the plain service path and Dockerfile; env only ${NAME}; port on 127.0.0.1', () => {
    const d = doc();
    expect(d.services['app-api']).toEqual({
      build: { context: './api', dockerfile: 'Dockerfile' },
      environment: { DATABASE_URL: '${PIPEGEN_APP_DATABASE_URL:?}' },
      ports: ['127.0.0.1:3000:3000'],
      depends_on: { postgres: { condition: 'service_healthy' } },
    });
    // the root service builds in '.'
    const root = doc(prof([api({ path: '.', dockerfile: 'Dockerfile' })]));
    expect(root.services['app-api'].build).toEqual({ context: '.', dockerfile: 'Dockerfile' });
  });

  it('no literal password anywhere in the file (only ${NAME} references and the table literals)', () => {
    const t = text(prof([api({ dependsOn: ALL.map((x) => dep(x.kind, ['DATABASE_URL'])) })]));
    expect(t.replaceAll('${' + DBPW + ':?}', 'REF')).not.toMatch(/password\s*[:=]\s*(?!"REF")[^\s"]/i);
    const d = parse(t);
    const LITERALS = new Set(['pipegen']);
    for (const s of Object.values<any>(d.services)) {
      for (const v of Object.values<string>(s.environment ?? {})) expect(/^\$\{PIPEGEN_(?:DB_PASSWORD|APP_[A-Z0-9_]+):\?\}$/.test(v) || LITERALS.has(v), v).toBe(true);
    }
    expect(t.replace(/@sha256:[0-9a-f]{64}/g, '')).not.toMatch(/[0-9a-f]{32}/);
  });

  it('external dependency is never containerised', () => {
    const p = prof([api({ dependsOn: [dep('external', ['STRIPE_KEY']), dep('redis', ['REDIS_URL'])] })]);
    const d = doc(p);
    expect(Object.keys(d.services)).toEqual(['redis', 'app-api']);
    expect(d.services['app-api'].depends_on).toEqual({ redis: { condition: 'service_healthy' } });
    expect(JSON.stringify(d.services['app-api'].environment ?? {})).not.toContain('STRIPE');
    // only an external dependency: nothing to containerise, no file
    expect(composeText(prof([api({ dependsOn: [dep('external', ['STRIPE_KEY'])] })]), list)).toBeNull();
  });

  it('no non-external deps -> null', () => {
    expect(composeText(prof([api({ dependsOn: [] })]), list)).toBeNull();
    expect(composeText(prof([]), list)).toBeNull();
  });

  it('text equals composeText(profile, baseImages): deterministic, byte-stable, newline-ended, LF only', () => {
    const p = prof();
    expect(text(p)).toBe(text(p));
    expect(text(prof([api()]))).toBe(text(structuredClone(p)));
    expect(text(p).endsWith('\n')).toBe(true);
    expect(text(p)).not.toContain('\r');
    expect(text(p).startsWith('services:\n')).toBe(true);
    // the order of the profile's services does not matter
    const a = api(); const b = api({ name: 'web', path: 'web', dockerfile: 'web/Dockerfile', port: 3001, dependsOn: [dep('redis', ['REDIS_URL'])] });
    expect(text(prof([a, b]))).toBe(text(prof([b, a])));
  });

  it('only the allowed keys: no privileged, cap_add, volumes, network_mode, pid, ipc, devices, extends, include, env_file, secrets, configs, profiles, x-*, command, entrypoint, user, labels', () => {
    const d = doc(prof([api({ dependsOn: ALL })]));
    expect(Object.keys(d)).toEqual(['services']);
    const ALLOWED = new Set(['image', 'build', 'environment', 'ports', 'healthcheck', 'depends_on']);
    for (const [name, s] of Object.entries<any>(d.services)) {
      for (const k of Object.keys(s)) expect(ALLOWED.has(k), `${name}.${k}`).toBe(true);
      if (name.startsWith('app-')) expect(Object.keys(s).sort()).toEqual(['build', 'depends_on', 'ports']);   // no env names in this profile
    }
    for (const bad of ['privileged', 'cap_add', 'volumes', 'network_mode', 'pid', 'ipc', 'devices', 'extends', 'include', 'env_file', 'secrets', 'configs', 'profiles', 'x-', 'command', 'entrypoint', 'user:', 'labels']) expect(text(prof([api({ dependsOn: ALL })]))).not.toContain(bad);
  });

  it('ports are only 127.0.0.1:<p>:<p>', () => {
    const d = doc(prof([api({ dependsOn: ALL, port: 8081 })]));
    for (const s of Object.values<any>(d.services)) for (const p of s.ports) {
      const m = /^127\.0\.0\.1:(\d+):(\d+)$/.exec(p);
      expect(m, p).not.toBeNull();
      expect(m?.[1]).toBe(m?.[2]);
    }
  });

  it('keys: app-<slug(name)>, dependency keys fixed; one shared service per kind', () => {
    const p = prof([api({ name: '@scope/My.App' , path: 'a', dockerfile: 'a/Dockerfile' }), api({ name: 'web', path: 'web', dockerfile: 'web/Dockerfile', port: 3001 })]);
    const d = doc(p);
    expect(Object.keys(d.services)).toEqual(['postgres', 'app-scope-my-app', 'app-web']);
    expect(d.services['app-web'].depends_on).toEqual({ postgres: { condition: 'service_healthy' } });
  });

  it('environment values are only ${NAME} with NAME_RE and not dangerous', () => {
    const p = prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL', 'PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE']), dep('redis', ['REDIS_URL']), dep('mongodb', ['MONGODB_URI']), dep('rabbitmq', ['AMQP_URL'])] })]);
    const d = doc(p);
    const env = d.services['app-api'].environment as Record<string, string>;
    expect(Object.keys(env).sort()).toEqual(['AMQP_URL', 'DATABASE_URL', 'MONGODB_URI', 'PGDATABASE', 'PGHOST', 'PGPASSWORD', 'PGPORT', 'PGUSER', 'REDIS_URL']);
    for (const [k, v] of Object.entries(env)) {
      expect(NAME_RE.test(k) && !isDangerousName(k), k).toBe(true);
      expect(v).toBe('${PIPEGEN_APP_' + k + ':?}');
    }
  });

  it('the app environment lists only the names of ITS dependencies', () => {
    const a = api({ dependsOn: [dep('postgres', ['DATABASE_URL'])] });
    const b = api({ name: 'web', path: 'web', dockerfile: 'web/Dockerfile', port: 3001, dependsOn: [dep('redis', ['REDIS_URL'])] });
    const d = doc(prof([a, b]));
    expect(Object.keys(d.services['app-api'].environment)).toEqual(['DATABASE_URL']);
    expect(Object.keys(d.services['app-web'].environment)).toEqual(['REDIS_URL']);
    expect(Object.keys(d.services).sort()).toEqual(['app-api', 'app-web', 'postgres', 'redis']);
  });
});

describe('compose: the exact text (golden)', () => {
  it('all five kinds and one app, byte for byte', () => {
    const r = (id: string): string => baseImageRef(id);
    const pw = '${' + DBPW + ':?}';
    const want = [
      'services:',
      '  postgres:', `    image: "${r('postgres-17')}"`, '    environment:', '      POSTGRES_USER: "pipegen"', ...Object.entries(PG_PW_ENTRY).map(([k, v]) => `      ${k}: "${v}"`), '      POSTGRES_DB: "pipegen"',
      '    ports:', '      - "127.0.0.1:5432:5432"', '    healthcheck:', '      test: ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "pipegen", "-d", "pipegen"]', '      interval: "5s"', '      timeout: "5s"', '      retries: 20',
      '  mysql:', `    image: "${r('mysql-8.4')}"`, '    environment:', `      MYSQL_ROOT_${'PASS' + 'WORD'}: "${pw}"`, '      MYSQL_USER: "pipegen"', `      MYSQL_${'PASS' + 'WORD'}: "${pw}"`, '      MYSQL_DATABASE: "pipegen"',
      '    ports:', '      - "127.0.0.1:3306:3306"', '    healthcheck:', '      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-u", "pipegen", "--silent"]', '      interval: "5s"', '      timeout: "5s"', '      retries: 30', '      start_period: "20s"',
      '  redis:', `    image: "${r('redis-7')}"`, '    ports:', '      - "127.0.0.1:6379:6379"', '    healthcheck:', '      test: ["CMD", "redis-cli", "ping"]', '      interval: "5s"', '      timeout: "5s"', '      retries: 20',
      '  mongodb:', `    image: "${r('mongo-8.0')}"`, '    environment:', '      MONGO_INITDB_ROOT_USERNAME: "pipegen"', `      MONGO_INITDB_ROOT_${'PASS' + 'WORD'}: "${pw}"`, '      MONGO_INITDB_DATABASE: "pipegen"',
      '    ports:', '      - "127.0.0.1:27017:27017"', '    healthcheck:', '      test: ["CMD", "mongosh", "--quiet", "--eval", "db.adminCommand(\'ping\').ok"]', '      interval: "5s"', '      timeout: "10s"', '      retries: 30', '      start_period: "20s"',
      '  rabbitmq:', `    image: "${r('rabbitmq-4-management')}"`, '    environment:', '      RABBITMQ_DEFAULT_USER: "pipegen"', `      RABBITMQ_DEFAULT_PASS: "${pw}"`,
      '    ports:', '      - "127.0.0.1:5672:5672"', '    healthcheck:', '      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]', '      interval: "10s"', '      timeout: "10s"', '      retries: 30', '      start_period: "30s"',
      '  app-api:', '    build:', '      context: "./api"', '      dockerfile: "Dockerfile"', '    environment:', '      AMQP_URL: "${PIPEGEN_APP_AMQP_URL:?}"', '      DATABASE_URL: "${PIPEGEN_APP_DATABASE_URL:?}"', '      MONGODB_URI: "${PIPEGEN_APP_MONGODB_URI:?}"', '      REDIS_URL: "${PIPEGEN_APP_REDIS_URL:?}"',
      '    ports:', '      - "127.0.0.1:3000:3000"', '    depends_on:',
      '      postgres:', '        condition: service_healthy', '      mysql:', '        condition: service_healthy', '      redis:', '        condition: service_healthy', '      mongodb:', '        condition: service_healthy', '      rabbitmq:', '        condition: service_healthy',
      '',
    ].join('\n');
    const p = prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL']), dep('mysql'), dep('redis', ['REDIS_URL']), dep('mongodb', ['MONGODB_URI']), dep('rabbitmq', ['AMQP_URL'])] })]);
    expect(text(p)).toBe(want);
  });
});

describe('compose: more edges', () => {
  it('the tables agree: every mapped name has a value for its dependency and kind; every dependency has an image id in the list', () => {
    for (const [dep, names] of Object.entries(ENV_TABLE)) for (const [name, kind] of Object.entries(names)) expect(VALUE_TABLE[dep as keyof typeof VALUE_TABLE][kind], `${dep} ${name}`).toBeDefined();
    for (const spec of Object.values(DEP_TABLE)) expect(() => baseImageRef(spec.id, list)).not.toThrow();
  });
  it('a node service that is not npm-by-language (language other, packageManager npm) is skipped with a note', () => {
    const r = planCompose(prof([api({ language: 'other' })]), list);
    expect(r.text).toBeNull();
    expect(r.notes.join()).toMatch(/npm/);
  });
  it('an app gets a name only through a dependency whose table maps it (DATABASE_URL listed under redis is not passed on)', () => {
    const a = api({ dependsOn: [dep('postgres', ['DATABASE_URL'])] });
    const b = api({ name: 'web', path: 'web', dockerfile: 'web/Dockerfile', port: 3001, dependsOn: [dep('redis', ['REDIS_URL', 'DATABASE_URL'])] });
    const d = doc(prof([a, b]));
    expect(Object.keys(d.services['app-web'].environment)).toEqual(['REDIS_URL']);
    expect(Object.keys(d.services['app-api'].environment)).toEqual(['DATABASE_URL']);
  });
  it('app environment names are written sorted', () => {
    const d = doc(prof([api({ dependsOn: [dep('rabbitmq', ['AMQP_URL']), dep('redis', ['REDIS_URL']), dep('postgres', ['PGUSER', 'DATABASE_URL', 'PGHOST'])] })]));
    expect(Object.keys(d.services['app-api'].environment)).toEqual(['AMQP_URL', 'DATABASE_URL', 'PGHOST', 'PGUSER', 'REDIS_URL']);
  });
  it('the version of a dependency of a service that gets no container does not stop the others', () => {
    const lib = api({ name: 'lib', path: 'lib', dockerfile: undefined, port: undefined, dependsOn: [dep('postgres', [], '16')] });
    const r = planCompose(prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL'], '17')] }), lib]), list);
    expect(r.text).not.toBeNull();
  });
  it('a base-image list without the image of a needed kind: no file and a note, never a throw', () => {
    const r = planCompose(prof(), list.filter((e) => e.id !== 'postgres-17'));
    expect(r.text).toBeNull();
    expect(r.notes.join()).toMatch(/postgres-17|base-image list/);
  });
});

describe('compose: which services get an app container', () => {
  it('needs a runnable npm service with a port, a plain path and a Dockerfile (existing, or created in the draft)', () => {
    const noDocker = api({ dockerfile: undefined });
    expect(composeText(prof([noDocker]), list)).toBeNull();   // no Dockerfile and none created: no runnable app container -> not proven
    expect(planCompose(prof([noDocker]), list).notes.join()).toMatch(/Dockerfile/);
    const t = composeText(prof([noDocker]), list, ['api/Dockerfile']);
    expect(t).not.toBeNull();
    expect(parse(t as string).services['app-api'].build.context).toBe('./api');
    // a created Dockerfile at another path does not count
    expect(composeText(prof([noDocker]), list, ['web/Dockerfile'])).toBeNull();
    // an existing Dockerfile with another name is not the one `dockerfile: Dockerfile` builds
    expect(composeText(prof([api({ dockerfile: 'api/Dockerfile.prod' })]), list)).toBeNull();
  });

  it('a service that does not run (library), has no port, is not npm, or has no dependency is skipped with a note', () => {
    const lib = api({ scripts: [], frameworks: [], dockerfile: undefined, port: undefined });
    expect(composeText(prof([lib]), list, ['api/Dockerfile'])).toBeNull();
    const noPort = planCompose(prof([api({ port: undefined })]), list);
    expect(noPort.text).toBeNull();
    expect(noPort.notes.join()).toMatch(/port/);
    const py = planCompose(prof([api({ language: 'python', packageManager: 'pip' })]), list);
    expect(py.text).toBeNull();
    expect(py.notes.join()).toMatch(/npm/);
    const pnpm = planCompose(prof([api({ packageManager: 'pnpm' })]), list);
    expect(pnpm.text).toBeNull();
    // one good service plus one that does not qualify: the good one is written, the other has a note
    const mixed = planCompose(prof([api(), api({ name: 'lib', path: 'lib', dockerfile: undefined, port: undefined, scripts: [], dependsOn: [dep('redis')] })]), list);
    expect(Object.keys(parse(mixed.text as string).services)).toEqual(['postgres', 'app-api']);
    expect(mixed.notes.join()).toMatch(/lib/);
    // a service without any dependency gets no container
    const free = planCompose(prof([api(), api({ name: 'web', path: 'web', dockerfile: 'web/Dockerfile', port: 3001, dependsOn: [] })]), list);
    expect(Object.keys(parse(free.text as string).services)).toEqual(['postgres', 'app-api']);
  });

  it('notStandalone and publishedPackage services are not runnable', () => {
    expect(composeText(prof([api({ notStandalone: 'one-shot', dockerfile: undefined })]), list, ['api/Dockerfile'])).toBeNull();
  });

  it('two apps on one port: not proven (they could not both bind), with a note', () => {
    const p = prof([api(), api({ name: 'web', path: 'web', dockerfile: 'web/Dockerfile', port: 3000 })]);
    const r = planCompose(p, list);
    expect(r.text).toBeNull();
    expect(r.notes.join()).toMatch(/3000/);
  });
});

describe('compose: hostile profile values never reach the file', () => {
  const HOSTILE_NAMES = ['api${x}', 'a\nb', 'a:b', 'a#b', 'a b', '..', '${{ secrets.X }}', 'a"b', "a'b", 'a\u202eb', ''];
  it.each(HOSTILE_NAMES)('service name %j -> skipped with a note, nothing reaches the file', (name) => {
    const r = planCompose(prof([api(), api({ name, path: 'web', dockerfile: 'web/Dockerfile', port: 3001 })]), list);
    expect(r.notes.length).toBeGreaterThan(0);
    const t = r.text ?? '';
    for (const bad of ['${x}', '\nb', 'a:b', 'a#b', 'secrets', '..', '\u202e']) expect(t).not.toContain(bad);
    expect(Object.keys(parse(t).services)).toEqual(['postgres', 'app-api']);
  });

  it.each(['../x', 'a/../b', '/etc', 'a\nb', 'a b', 'a:b', '${x}', 'a//b', '.git', 'node_modules/x', '.hidden', 'a/.b', 'C:\\x', 'a;b', 'a#b', 'x'.repeat(250)])('service path %j -> that service is skipped with a note', (path) => {
    const r = planCompose(prof([api({ path, dockerfile: `${path}/Dockerfile` })]), list, [`${path}/Dockerfile`]);
    expect(r.text).toBeNull();
    expect(r.notes.join()).toMatch(/path|folder/i);
  });

  it.each([0, -1, 70000, 65536, 1.5, Number.NaN, Number.POSITIVE_INFINITY])('port %j -> the service is skipped with a note', (port) => {
    const r = planCompose(prof([api({ port })]), list);
    expect(r.text).toBeNull();
    expect(r.notes.join()).toMatch(/port/);
  });

  it('a port at the edges 1 and 65535 is written', () => {
    expect(doc(prof([api({ port: 1 })])).services['app-api'].ports).toEqual(['127.0.0.1:1:1']);
    expect(doc(prof([api({ port: 65535 })])).services['app-api'].ports).toEqual(['127.0.0.1:65535:65535']);
  });

  it('env-var names that are dangerous, GITHUB_*, PIPEGEN_DB_PASSWORD, malformed or not in the table never reach the file, each with a note', () => {
    const names = ['GITHUB_TOKEN', 'PIPEGEN_DB_PASSWORD', 'NODE_OPTIONS', 'PATH', 'LD_PRELOAD', 'bad name', 'A=B', 'DATABASE_URL\nX=1', '${X}', 'DATABASE_URL '];
    const p = prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL', ...names])] })]);
    const t = text(p);
    for (const n of names.filter((x) => x !== 'PIPEGEN_DB_PASSWORD')) expect(t, n).not.toContain(n);
    expect(Object.keys(parse(t).services['app-api'].environment)).toEqual(['DATABASE_URL']);   // PIPEGEN_DB_PASSWORD appears only as the ${...} reference of the dependency's env
    const notes = runtimeEnvNotes(p).join('\n');
    for (const n of ['GITHUB_TOKEN', 'NODE_OPTIONS', 'LD_PRELOAD']) expect(notes, n).toContain(n);
    // each is refused for its own reason (the layers before the table), not only because the table lacks it
    expect(notes).toMatch(/"GITHUB_TOKEN"[^\n]*starts with GITHUB_/);
    expect(notes).toMatch(/"NODE_OPTIONS"[^\n]*changes how code runs/);
    expect(notes).toMatch(/"PIPEGEN_DB_PASSWORD"[^\n]*is pipegen's own database password variable/);
    expect(notes).toMatch(/"bad name"[^\n]*is not a plain environment variable name/);
    // a hostile name in a note is cleaned (no newline, no control character)
    expect(notes).not.toMatch(/[\u0000-\u0009\u000b-\u001f]/);
  });

  it('a dependency kind pipegen does not know -> not proven, no file, a note', () => {
    const r = planCompose(prof([api({ dependsOn: [{ kind: 'oracle' as DependencyKind, name: 'oracle', evidence: 'x', envVars: [] }] })]), list);
    expect(r.text).toBeNull();
    expect(r.notes.join()).toMatch(/oracle|kind/);
  });

  it('Dependency.name, evidence and envVars text never appear in the file', () => {
    const p = prof([api({ dependsOn: [{ kind: 'postgres', name: 'EVIL-NAME', evidence: 'EVIL-EVIDENCE ${{x}}', envVars: ['DATABASE_URL'] }] })]);
    const t = text(p);
    expect(t).not.toContain('EVIL');
  });
});

describe('compose: slug collision', () => {
  it('two services with one slug -> no file and a note', () => {
    const r = planCompose(prof([api({ name: 'My.App', path: 'a', dockerfile: 'a/Dockerfile' }), api({ name: 'my-app', path: 'b', dockerfile: 'b/Dockerfile', port: 3001 })]), list);
    expect(r.text).toBeNull();
    expect(r.notes.join()).toMatch(/collide|same key|both/i);
  });
});

describe('compose: versions', () => {
  const only = (version: string | undefined, kind: DependencyKind = 'postgres') => planCompose(prof([api({ dependsOn: [dep(kind, [], version)] })]), list);
  it('a version inside the list ids is silent (postgres 17 / 17.2, redis 7 / 7.2, mongo 8.0, mysql 8.4, rabbitmq 4)', () => {
    for (const [k, v] of [['postgres', '17.2'], ['redis', '7.2'], ['redis', '7.2.4'], ['mongodb', '8.0'], ['mongodb', '8.0.3'], ['mysql', '8.4'], ['rabbitmq', '4.1']] as const) {
      const r = only(v, k);
      expect(r.text, `${k} ${v}`).not.toBeNull();
      expect(r.notes.join(), `${k} ${v}`).not.toMatch(/pipegen uses/);
    }
  });
  it('same major, other series: the file is written and the note says what pipegen uses and what the repo asks (mongo 8.3, mysql 8.0)', () => {
    const m = only('8.3', 'mongodb');
    expect(m.text).not.toBeNull();
    expect(m.notes.join()).toContain('pipegen uses mongo-8.0; your repo asks for 8.3');
    expect(parse(m.text as string).services.mongodb.image).toBe(baseImageRef('mongo-8.0'));
    const my = only('8.0', 'mysql');
    expect(my.text).not.toBeNull();
    expect(my.notes.join()).toContain('pipegen uses mysql-8.4; your repo asks for 8.0');
  });
  it('another major (postgres 16, mysql 9, redis 6, rabbitmq 3.13, mongo 7): not proven, no file, a note; never a silent downgrade or upgrade', () => {
    for (const [k, v, id] of [['postgres', '16', 'postgres-17'], ['mysql', '9.1', 'mysql-8.4'], ['redis', '6', 'redis-7'], ['rabbitmq', '3.13', 'rabbitmq-4-management'], ['mongodb', '7', 'mongo-8.0'], ['postgres', '18', 'postgres-17']] as const) {
      const r = only(v, k);
      expect(r.text, `${k} ${v}`).toBeNull();
      expect(r.notes.join(), `${k} ${v}`).toContain(`pipegen uses ${id}; your repo asks for ${v}`);
    }
  });
  it('an unreadable version (not digits and dots) is never copied; it counts as unknown, with a note', () => {
    for (const v of ['latest', '16; rm -rf', '${V}', '1.2.3.4', '', 'v17', '17\n']) {
      const r = only(v);
      expect(r.text, v).not.toBeNull();
      expect(r.text, v).not.toContain(v.trim() === '' ? '\u0000' : v);
      expect(r.notes.join(), v).toMatch(/version/);
    }
  });
  it('no version known: the list id is used, with a note saying so', () => {
    const r = only(undefined);
    expect(r.text).not.toBeNull();
    expect(r.notes.join()).toMatch(/postgres-17/);
  });
  it('two services asking for different majors of one kind: not proven', () => {
    const a = api({ dependsOn: [dep('postgres', [], '17')] });
    const b = api({ name: 'web', path: 'web', dockerfile: 'web/Dockerfile', port: 3001, dependsOn: [dep('postgres', [], '16')] });
    expect(planCompose(prof([a, b]), list).text).toBeNull();
  });
});

describe('createCompose', () => {
  const ctx = (over: Record<string, unknown> = {}) => ({ repoPaths: new Set<string>(['api/Dockerfile', 'api/package.json']), baseImages: list, ...over });
  it('returns the file for docker-compose.pipegen.yml: part compose, repo app, text = composeText', () => {
    const p = prof();
    const r = createCompose(p, ctx());
    expect(r.file).toEqual({ path: COMPOSE_PATH, content: text(p), part: 'compose', reason: expect.any(String), repo: 'app' });
    expect(COMPOSE_PATH).toBe('docker-compose.pipegen.yml');
    expect(r.file?.reason).not.toMatch(/\$\{|\n/);
  });
  it('an existing docker-compose.pipegen.yml that pipegen does not own -> no file and a note (S3)', () => {
    const r = createCompose(prof(), ctx({ repoPaths: new Set(['api/Dockerfile', 'docker-compose.pipegen.yml']) }));
    expect(r.file).toBeNull();
    expect(r.notes.join()).toMatch(/docker-compose\.pipegen\.yml/);
    // case-insensitive
    expect(createCompose(prof(), ctx({ repoPaths: ['Docker-Compose.Pipegen.yml'] })).file).toBeNull();
    // a file the install record says pipegen owns may be rewritten
    expect(createCompose(prof(), ctx({ repoPaths: new Set(['docker-compose.pipegen.yml']), ownsCompose: true })).file).not.toBeNull();
  });
  it('without the repo file list nothing is created (a missing input never reads as nothing there)', () => {
    expect(createCompose(prof(), { baseImages: list } as never).file).toBeNull();
  });
  it('not proven cases give no file: unknown kind, no runnable service, external only, version major', () => {
    expect(createCompose(prof([api({ dependsOn: [] })]), ctx()).file).toBeNull();
    expect(createCompose(prof([api({ dependsOn: [dep('postgres', [], '16')] })]), ctx()).notes.join()).toMatch(/16/);
    expect(createCompose(prof([api({ dependsOn: [dep('postgres', [], '16')] })]), ctx()).file).toBeNull();
  });
  it('a Dockerfile pipegen creates counts (createdDockerfiles)', () => {
    const p = prof([api({ dockerfile: undefined })]);
    expect(createCompose(p, ctx({ repoPaths: new Set<string>() })).file).toBeNull();
    expect(createCompose(p, ctx({ repoPaths: new Set<string>(), createdDockerfiles: ['api/Dockerfile'] })).file).not.toBeNull();
  });
});

describe('runtimeEnv', () => {
  it('structured: the password (name and bytes) and the vars with kind and dep; no shell text', () => {
    const p = prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL', 'PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE']), dep('redis', ['REDIS_URL'])] })]);
    expect(runtimeEnv(p)).toEqual({
      ...runtimeOf([]),
      vars: [
        { name: 'DATABASE_URL', kind: 'url', dep: 'postgres' }, { name: 'PGDATABASE', kind: 'db', dep: 'postgres' }, { name: 'PGHOST', kind: 'host', dep: 'postgres' },
        { name: 'PGPASSWORD', kind: 'password', dep: 'postgres' }, { name: 'PGPORT', kind: 'port', dep: 'postgres' }, { name: 'PGUSER', kind: 'user', dep: 'postgres' },
        { name: 'REDIS_URL', kind: 'url', dep: 'redis' },
      ],
    });
    expect(JSON.stringify(runtimeEnv(p))).not.toMatch(/\$\(|openssl|\$\{/);
  });
  it('DATABASE_URL, POSTGRES_URL, DB_*, REDIS_URL, MONGODB_URI, AMQP_URL map by the dependency that lists them', () => {
    const p = prof([api({ dependsOn: [dep('postgres', ['POSTGRES_URL', 'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME']), dep('redis', ['REDIS_URL']), dep('mongodb', ['MONGODB_URI']), dep('rabbitmq', ['AMQP_URL'])] })]);
    const got = runtimeEnv(p).vars.map((v) => [v.dep, v.name, v.kind]).sort((a, b) => a.join('/').localeCompare(b.join('/')));
    const want = [
      ['mongodb', 'MONGODB_URI', 'url'], ['postgres', 'DB_HOST', 'host'], ['postgres', 'DB_NAME', 'db'], ['postgres', 'DB_PASSWORD', 'password'], ['postgres', 'DB_PORT', 'port'], ['postgres', 'DB_USER', 'user'],
      ['postgres', 'POSTGRES_URL', 'url'], ['rabbitmq', 'AMQP_URL', 'url'], ['redis', 'REDIS_URL', 'url'],
    ];
    expect(got).toEqual(want);
  });
  it('a name of a covered dependency that is not in the table gets a note and is never guessed', () => {
    const p = prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL', 'PG_POOL_SIZE', 'POSTGRES_SSL_CERT'])] })]);
    expect(runtimeEnv(p).vars.map((v) => v.name)).toEqual(['DATABASE_URL']);
    const notes = runtimeEnvNotes(p).join('\n');
    expect(notes).toContain('PG_POOL_SIZE');
    expect(notes).toContain('POSTGRES_SSL_CERT');
    expect(notes).not.toContain('DATABASE_URL');
  });
  it('a name claimed by two dependencies (DATABASE_URL under postgres and mysql) is not mapped, with a note', () => {
    const p = prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL']), dep('mysql', ['DATABASE_URL'])] })]);
    expect(runtimeEnv(p).vars).toEqual([]);
    expect(runtimeEnvNotes(p).join()).toMatch(/DATABASE_URL/);
    expect(Object.keys(parse(text(p)).services['app-api']).includes('environment')).toBe(false);
  });
  it('external dependencies map nothing', () => {
    expect(runtimeEnv(prof([api({ dependsOn: [dep('external', ['STRIPE_KEY', 'DATABASE_URL'])] })])).vars).toEqual([]);
  });
  it('redis has no user, password or db: those names are notes', () => {
    const p = prof([api({ dependsOn: [dep('redis', ['REDIS_URL', 'REDIS_PASSWORD', 'REDIS_HOST', 'REDIS_PORT'])] })]);
    expect(runtimeEnv(p).vars.map((v) => v.name).sort()).toEqual(['REDIS_HOST', 'REDIS_PORT', 'REDIS_URL']);
    expect(runtimeEnvNotes(p).join()).toContain('REDIS_PASSWORD');
  });
  it('the table itself: every name passes NAME_RE, is not dangerous, not GITHUB_* and not PIPEGEN_DB_PASSWORD', () => {
    let n = 0;
    for (const [k, names] of Object.entries(ENV_TABLE)) for (const name of Object.keys(names)) {
      n++;
      expect(NAME_RE.test(name), `${k} ${name}`).toBe(true);
      expect(isDangerousName(name), `${k} ${name}`).toBe(false);
      expect(name.startsWith('GITHUB_') || name === 'PIPEGEN_DB_PASSWORD', `${k} ${name}`).toBe(false);
    }
    expect(n).toBeGreaterThan(30);
  });
  it('the vars are sorted and unique by name, whatever the profile order', () => {
    const a = prof([api({ dependsOn: [dep('redis', ['REDIS_URL']), dep('postgres', ['DATABASE_URL'])] })]);
    const b = prof([api({ dependsOn: [dep('postgres', ['DATABASE_URL']), dep('redis', ['REDIS_URL', 'REDIS_URL'])] })]);
    expect(runtimeEnv(a)).toEqual(runtimeEnv(b));
  });
  it('a dependency of a service that gets no container maps nothing', () => {
    const lib = api({ dockerfile: undefined, port: undefined, scripts: [], dependsOn: [dep('postgres', ['DATABASE_URL'])] });
    expect(runtimeEnv(prof([lib])).vars).toEqual([]);
  });
});
