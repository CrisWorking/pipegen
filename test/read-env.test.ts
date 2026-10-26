import { afterEach, describe, expect, it } from 'vitest';
import { readEnv } from '../src/read/env.js';
import { readProject } from '../src/read/project.js';
import type { Service } from '../src/types.js';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const svc = (path = '.', name = 'app'): Service => ({ name, path, language: 'node', hasTests: false, envVars: [], dependsOn: [], scripts: [], frameworks: [] });
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
    const secret = 'sk_' + 'test_' + 'abc123XYZ';
    const token = 'ghp_' + 'tok' + 'en9876';
    const pgUrl = 'postgres' + '://user:pw' + 'hunter2@db/app';
    writeIn(dir, '.env', `STRIPE_SECRET_KEY=${secret}\nAPI_TOKEN="${token}"\nDATABASE_URL=${pgUrl}\n`);
    writeIn(dir, 'docker-compose.yml', `services:\n  app:\n    build: .\n    environment:\n      - COMPOSE_KEY=${'cv_' + 'val77'}\n`);
    const out = await readEnv(dir, svc());
    const json = JSON.stringify(out);
    for (const v of [secret, token, pgUrl, 'hunter2', 'cv_' + 'val77', 'user:pw']) expect(json).not.toContain(v);
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
    writeIn(dir, '.env.example', 'STRIPE_SECRET_KEY=\nSTRIPE_WEBHOOK_SECRET=\nOTHER=\n');
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
    writeIn(dir, '.env.example', 'AWS_REGION=\nANTHROPIC_API_KEY=\nSENDGRID_API_KEY=\nMONGO_URI=\nRABBIT_URL=\nREDIS_HOST=\n');
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

  it('readProject fills envVars and dependsOn', async () => {
    const dir = makeRepo('node-express', 'https://github.com/o/r.git');
    writeIn(dir, '.env.example', 'FROM_PROJECT=1\n');
    const p = await readProject(dir);
    expect(p.services[0]?.envVars).toContain('FROM_PROJECT');
  });
});
