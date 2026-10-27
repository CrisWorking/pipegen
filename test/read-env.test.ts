import { join } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { afterEach, describe, expect, it } from 'vitest';
import { readEnv as readEnvOwned } from '../src/read/env.js';
import { IGNORED_DIRS, listFiles, readTextLimited } from '../src/read/limits.js';
import { REQUIREMENTS_FILE_RE, asObj, baseOf, dirOf, inDir, pythonNames, readPyproject, requirementLines, type Manifests } from '../src/read/manifest.js';
import { readProject } from '../src/read/project.js';
import type { Service } from '../src/types.js';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';
import { emptyServiceQuality } from '../src/read/quality.js';

afterEach(cleanupRepos);

/** The service's manifests, read and parsed the way readProject does before it calls readEnv. */
async function manifests(dir: string, base: string, owned: string[]): Promise<Manifests> {
  const parsed = async (rel: string, parse: (t: string) => unknown) => {
    const text = await readTextLimited(join(dir, rel));
    try { return text === null ? null : asObj(parse(text)); } catch { return null; }
  };
  const requirements: Manifests['requirements'] = [];
  for (const file of owned.filter((f) => dirOf(f) === base && REQUIREMENTS_FILE_RE.test(baseOf(f)))) {
    const text = await readTextLimited(join(dir, file));
    if (text !== null) requirements.push({ file, names: pythonNames(requirementLines(text)) });
  }
  return { pkg: await parsed(inDir(base, 'package.json'), JSON.parse), py: readPyproject(await parsed(inDir(base, 'pyproject.toml'), parseToml)), requirements };
}

/** Lists the repo like readProject does, then keeps only the files this service owns (not a deeper service's). */
async function readEnv(dir: string, service: Service, deeper: string[] = []) {
  const all = (await listFiles(dir, ['**/*'], IGNORED_DIRS.map((d) => `**/${d}/**`))).files;
  const owned = all.filter((f) => !deeper.some((d) => f.startsWith(`${d}/`)));
  return readEnvOwned(dir, service, owned, await manifests(dir, service.path, owned));
}

const svc = (path = '.', name = 'app'): Service => ({ name, path, language: 'node', hasTests: false, envVars: [], dependsOn: [], scripts: [], frameworks: [], quality: emptyServiceQuality() });
const pkg = (deps: Record<string, string>) => JSON.stringify({ name: 'app', dependencies: deps });

describe('readEnv', () => {
  it('env: names from .env.example and code references', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.env.example', '# comment\nAPI_URL=http://localhost\nexport LOG_LEVEL=info\nEMPTY=\n');
    writeIn(dir, '.env.sample', 'SAMPLE_ONLY=1\n');
    writeIn(dir, 'src/a.ts', "const a = process.env.PORT_A; const b = process.env['BRACKET_B']; const c = import.meta.env.VITE_C;\n");
    writeIn(dir, 'node_modules/x/index.js', 'process.env.IGNORED_ONE');
    const out = await readEnv(dir, svc());
    expect(out.envVars).toEqual(['API_URL', 'BRACKET_B', 'EMPTY', 'LOG_LEVEL', 'PORT_A', 'SAMPLE_ONLY', 'VITE_C']);
    expect(out.dependsOn).toEqual([]);
  });

  it('env: names from .env, values never kept', async () => {
    const dir = makeTempDir();
    const stripeVal = 'sk_' + 'test_' + 'abc123XYZ';
    const ghVal = 'ghp_' + 'tok' + 'en9876';
    const pgUrl = 'postgres' + '://user:pw' + 'hunter2@db/app';
    writeIn(dir, '.env', ['STRIPE_SECRET_KEY' + '=' + stripeVal, 'API_TOKEN' + '="' + ghVal + '"', 'DATABASE_URL=' + pgUrl].join('\n') + '\n');
    writeIn(dir, 'docker-compose.yml', `services:\n  app:\n    build: .\n    environment:\n      - COMPOSE_KEY=${'cv_' + 'val77'}\n`);
    const out = await readEnv(dir, svc());
    const json = JSON.stringify(out);
    for (const v of [stripeVal, ghVal, pgUrl, 'hunter2', 'cv_' + 'val77', 'user:pw']) expect(json).not.toContain(v);
    expect(out.envVars).toEqual(['API_TOKEN', 'COMPOSE_KEY', 'DATABASE_URL', 'STRIPE_SECRET_KEY']);
    // the only thing derived from a value is a yes/no: DATABASE_URL points at postgres
    const pg = out.dependsOn.find((d) => d.kind === 'postgres');
    expect(pg?.envVars).toEqual(['DATABASE_URL']);
    expect(pg?.evidence).toBe('.env: DATABASE_URL');
  });

  it('env: DATABASE_URL that is not postgres makes no postgres dependency', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.env', 'DATABASE_URL=sqlite:///local.db\n');
    expect((await readEnv(dir, svc())).dependsOn).toEqual([]);
  });

  it('env: prisma postgresql → postgres dependency with DATABASE_URL', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', pkg({ '@prisma/client': '5.0.0' }));
    writeIn(dir, 'prisma/schema.prisma', 'generator client {\n  provider = "prisma-client-js"\n}\ndatasource db {\n  provider = "postgresql"\n  url = env("DATABASE_URL")\n}\n');
    writeIn(dir, 'src/db.ts', 'const u = process.env.DATABASE_URL;\n');
    const out = await readEnv(dir, svc());
    expect(out.dependsOn).toEqual([{ kind: 'postgres', name: 'postgres', evidence: 'prisma/schema.prisma: datasource provider postgresql', envVars: ['DATABASE_URL'] }]);
  });

  it('env: prisma provider outside a datasource block is ignored', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'prisma/schema.prisma', 'generator client {\n  provider = "postgresql"\n}\n');
    expect((await readEnv(dir, svc())).dependsOn).toEqual([]);
  });

  it('env: stripe package → external dependency with STRIPE_* vars', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', pkg({ stripe: '^14.0.0' }));
    writeIn(dir, '.env.example', ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'OTHER'].map((k) => k + '=').join('\n') + '\n');
    const out = await readEnv(dir, svc());
    expect(out.dependsOn).toEqual([{ kind: 'external', name: 'stripe', evidence: 'package.json: stripe', envVars: ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'] }]);
  });

  it('env: python os.getenv detected', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'requirements.txt', 'flask==3.0\npsycopg2-binary==2.9\nredis>=5\n');
    writeIn(dir, 'app/main.py', "import os\na = os.getenv('PY_ONE')\nb = os.environ['PY_TWO']\nc = os.environ.get(\"PY_THREE\", 'x')\nREDIS_URL = os.getenv('REDIS_URL')\nPGHOST = os.getenv('PGHOST')\n");
    const out = await readEnv(dir, svc());
    expect(out.envVars).toEqual(['PGHOST', 'PY_ONE', 'PY_THREE', 'PY_TWO', 'REDIS_URL']);
    expect(out.dependsOn.map((d) => [d.kind, d.evidence, d.envVars])).toEqual([
      ['postgres', 'requirements.txt: psycopg2-binary', ['PGHOST']],
      ['redis', 'requirements.txt: redis', ['REDIS_URL']],
    ]);
  });

  it('env: pyproject dependencies and other kinds are detected', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'pyproject.toml', '[project]\nname = "x"\ndependencies = ["pymysql", "pymongo", "pika", "boto3"]\n');
    const kinds = (await readEnv(dir, svc())).dependsOn.map((d) => `${d.kind}:${d.name}`);
    expect(kinds.sort()).toEqual(['external:aws', 'mongodb:mongodb', 'mysql:mysql', 'rabbitmq:rabbitmq']);
  });

  it('env: node packages map to kinds once each, aws family is one entry', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', JSON.stringify({ dependencies: { pg: '1', ioredis: '1', '@aws-sdk/client-s3': '1', '@aws-sdk/client-sqs': '1', '@anthropic-ai/sdk': '1', '@sendgrid/mail': '1' }, devDependencies: { mongoose: '1', amqplib: '1' } }));
    writeIn(dir, '.env.example', 'AWS_REGION=\nANTHROPIC_API_KEY' + '=\nSENDGRID_API_KEY' + '=\nMONGO_URI=\nRABBIT_URL=\nREDIS_HOST=\n');
    const out = await readEnv(dir, svc());
    const byName = Object.fromEntries(out.dependsOn.map((d) => [`${d.kind}:${d.name}`, d.envVars]));
    expect(byName).toEqual({
      'postgres:postgres': [], 'redis:redis': ['REDIS_HOST'], 'mongodb:mongodb': ['MONGO_URI'], 'rabbitmq:rabbitmq': ['RABBIT_URL'],
      'external:aws': ['AWS_REGION'], 'external:@anthropic-ai/sdk': ['ANTHROPIC_API_KEY'], 'external:sendgrid': ['SENDGRID_API_KEY'],
    });
  });

  it('env: names that are not valid variable names are dropped', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.env.example', 'GOOD_ONE=1\n1BAD=1\nBAD-NAME=1\nBAD NAME=1\n' + 'L'.repeat(129) + '=1\n');
    writeIn(dir, 'a.js', "process.env['has space']; process.env['A;rm -rf']; process.env.OK_TWO;\n");
    expect((await readEnv(dir, svc())).envVars).toEqual(['GOOD_ONE', 'OK_TWO']);
  });

  it('env: lines over 4 KB are ignored by the regexes', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'a.js', `process.env.SHORT_ONE;\nprocess.env.LONG_ONE; // ${'x'.repeat(5000)}\n`);
    expect((await readEnv(dir, svc())).envVars).toEqual(['SHORT_ONE']);
  });

  it('env: compose environment keys are read in list and map form', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'compose.yml', 'services:\n  app:\n    build: .\n    environment:\n      - LIST_ONE=a\n      - LIST_TWO\n  other:\n    image: x\n    environment:\n      NOT_MINE: "1"\n');
    writeIn(dir, 'services/api/docker-compose.yml', 'services:\n  api:\n    build: .\n    environment:\n      MAP_ONE: a\n      MAP_TWO:\n');
    expect((await readEnv(dir, svc('.', 'app'))).envVars).toEqual(['LIST_ONE', 'LIST_TWO']);
    expect((await readEnv(dir, svc('services/api', 'api'))).envVars).toEqual(['MAP_ONE', 'MAP_TWO']);
  });

  it('env: compose in the repo root matches a service by build context', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'compose.yaml', 'services:\n  web:\n    build:\n      context: ./apps/site\n    environment:\n      - CTX_VAR=1\n');
    expect((await readEnv(dir, svc('apps/site', 'site'))).envVars).toEqual(['CTX_VAR']);
  });

  it('env: a broken compose file or alias bomb yields no names and no error', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'compose.yml', 'services: [unclosed\n');
    expect(await readEnv(dir, svc())).toEqual({ envVars: [], dependsOn: [] });
  });

  it('env: multi-line quoted values (PEM key, JSON) never become names', async () => {
    const dir = makeTempDir();
    const pem = ['-----BEGIN ' + 'PRIVATE KEY-----', 'ABC=' + 'frag1', 'secret' + 'part=' + 'frag2', 'MIIE' + 'frag3==', '-----END ' + 'PRIVATE KEY-----'];
    const json = ['{', '  "ABC_JSON": "' + 'frag4' + '",', '  "k": "x"', "}'"];
    const eq = '=';
    writeIn(dir, '.env', `FIRST=1\nPRIVATE_KEY${eq}"${pem.join('\n')}"\nJSON_CONF='${json.join('\n')}\nLAST_ONE=2\n`);
    writeIn(dir, '.env.example', `TICK=\`line1\nINSIDE=${'frag5'}\n\`\nAFTER=1\nOPEN_END="never closed\nLOST=1\n`);
    const out = await readEnv(dir, svc());
    expect(out.envVars).toEqual(['AFTER', 'FIRST', 'JSON_CONF', 'LAST_ONE', 'OPEN_END', 'PRIVATE_KEY', 'TICK']);
    const text = JSON.stringify(out);
    for (const f of ['frag1', 'frag2', 'frag3', 'frag4', 'frag5']) expect(text).not.toContain(f);
  });

  it('env: a line over 4 KB inside an open quote stays inside the quote', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.env', `A="start\n${'x'.repeat(5000)}\nHIDDEN=1\n"\nB=2\n`);
    expect((await readEnv(dir, svc())).envVars).toEqual(['A', 'B']);
  });

  it('env: over-4KB line that opens a quote does not leak its continuation lines', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.env', `BEFORE=1\nLONG_ONE='${'y'.repeat(5000)}\n  "x":1,\nABC=${'frag'}'\nREAL_AFTER=2\n`);
    const out = await readEnv(dir, svc());
    expect(out.envVars).toEqual(['BEFORE', 'REAL_AFTER']);
    expect(JSON.stringify(out)).not.toContain('frag');
  });

  it('env: backslash-quote inside single quotes keeps the value open (safe side)', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.env', "P='C:\\dir\\'\nLEAK=" + 'pa' + "rt\n'\nNEXT=1\n");
    const out = await readEnv(dir, svc());
    expect(out.envVars).toEqual(['NEXT', 'P']);
    expect(JSON.stringify(out)).not.toContain('LEAK');
  });

  it('env: package names over 4 KB are skipped', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', pkg({ ['pg' + 'x'.repeat(5000)]: '1', stripe: '1' }));
    expect((await readEnv(dir, svc())).dependsOn.map((d) => d.name)).toEqual(['stripe']);
  });

  it('env: root service does not inherit a nested service\'s env vars or dependencies', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'Dockerfile', 'FROM node\n');
    writeIn(dir, 'worker/Dockerfile', 'FROM node\n');
    writeIn(dir, 'worker/index.js', 'process.env.WORKER_ONLY;\n');
    writeIn(dir, 'worker/prisma/schema.prisma', 'datasource db {\n  provider = "postgresql"\n}\n');
    const root = await readEnv(dir, svc('.', 'root'), ['worker']);
    expect(root).toEqual({ envVars: [], dependsOn: [] });
    const worker = await readEnv(dir, svc('worker', 'worker'));
    expect(worker.envVars).toEqual(['WORKER_ONLY']);
    expect(worker.dependsOn.map((d) => d.kind)).toEqual(['postgres']);
  });

  it('env: compose service builds another folder → its env keys are not ours, even with the same name', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'compose.yml', 'services:\n  api:\n    build: ./other\n    environment:\n      - OTHER_KEY=1\n  web:\n    image: x\n    environment:\n      - NO_BUILD_WEB=1\n');
    writeIn(dir, 'api/index.js', '1;\n');
    expect((await readEnv(dir, svc('api', 'api'))).envVars).toEqual([]);
    expect((await readEnv(dir, svc('other', 'other'))).envVars).toEqual(['OTHER_KEY']);
    // no build at all: falls back to the name
    expect((await readEnv(dir, svc('web', 'web'))).envVars).toEqual(['NO_BUILD_WEB']);
  });

  it('env: compose build contexts that leave the repo or are absolute/URLs never match', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'compose.yml', 'services:\n  a:\n    build: ../x\n    environment: [ESC_A=1]\n  b:\n    build:\n      context: /abs\n    environment: [ABS_B=1]\n  c:\n    build: https://example.com/r.git\n    environment: [URL_C=1]\n');
    for (const p of ['x', 'abs', '..', '.']) expect((await readEnv(dir, svc(p, 'zz'))).envVars, p).toEqual([]);
  });

  it('env: names used only in test files are not collected', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', 'process.env.REAL_ONE;\n');
    writeIn(dir, 'src/a.test.ts', 'process.env.ONLY_IN_TEST;\n');
    writeIn(dir, 'tests/helper.py', "import os\nos.getenv('PY_TEST_ONLY')\n");
    writeIn(dir, 'test_x.py', "import os\nos.getenv('PY_TEST_X')\n");
    writeIn(dir, '__tests__/b.js', 'process.env.UNDERSCORE_TEST;\n');
    expect((await readEnv(dir, svc())).envVars).toEqual(['REAL_ONE']);
  });

  it('env: single-line prisma datasource with postgresql is detected', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'schema.prisma', 'datasource db { provider = "postgresql" url = env("DATABASE_URL") }\n');
    expect((await readEnv(dir, svc())).dependsOn.map((d) => [d.kind, d.evidence])).toEqual([['postgres', 'schema.prisma: datasource provider postgresql']]);
  });

  it('readProject: parent service does not inherit a nested service\'s names or dependencies', async () => {
    const dir = makeRepo('node-express', 'https://github.com/o/r.git');
    writeIn(dir, 'Dockerfile', 'FROM node\n');
    writeIn(dir, 'worker/Dockerfile', 'FROM node\n');
    writeIn(dir, 'worker/index.js', 'process.env.WORKER_ONLY;\n');
    writeIn(dir, 'worker/prisma/schema.prisma', 'datasource db {\n  provider = "postgresql"\n}\n');
    const p = await readProject(dir);
    const root = p.services.find((s) => s.path === '.');
    const worker = p.services.find((s) => s.path === 'worker');
    expect(root?.envVars).not.toContain('WORKER_ONLY');
    expect(root?.dependsOn.map((d) => d.kind)).not.toContain('postgres');
    expect(worker?.envVars).toEqual(['WORKER_ONLY']);
    expect(worker?.dependsOn.map((d) => d.kind)).toEqual(['postgres']);
  });

  it('readProject fills envVars and dependsOn', async () => {
    const dir = makeRepo('node-express', 'https://github.com/o/r.git');
    writeIn(dir, '.env.example', 'FROM_PROJECT=1\n');
    const p = await readProject(dir);
    expect(p.services[0]?.envVars).toContain('FROM_PROJECT');
  });
});
