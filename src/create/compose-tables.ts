// The fixed tables of the compose file and the runtime-env step (v0.2 Plan D, D4; preflight B6 and S7). A leaf: it imports nothing.
// Every key, literal, port, command and name that compose.ts writes into docker-compose.pipegen.yml, and every value render-step.ts writes into
// the runtime-env step, comes from here. The profile chooses WHICH rows are used; it never supplies a character of a row.

/** The dependency kinds pipegen starts. `external` (a SaaS) is never containerised. */
export const DEP_KEYS = ['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq'] as const;
export type DepKey = typeof DEP_KEYS[number];
export const isDepKey = (k: unknown): k is DepKey => typeof k === 'string' && (DEP_KEYS as readonly string[]).includes(k);

/** The generated database password: one per run, 16 random bytes in hex, referenced in the compose file as ${PIPEGEN_DB_PASSWORD}. */
export const DB_PASSWORD_NAME = 'PIPEGEN_DB_PASSWORD';
export const DB_PASSWORD_BYTES = 16;
/** The one non-secret literal of the dependency environments (user and database name). Anything else must be a ${NAME} reference. */
export const DB_USER = 'pipegen';
export const DB_NAME = 'pipegen';
export const LOCAL_HOST = '127.0.0.1';
/** `:?` makes Compose stop with an error instead of starting a container with an empty password when the runtime-env step did not run. */
const PASSWORD_REF = '${PIPEGEN_DB_PASSWORD:?}';
/** The prefix of the container-network copy of each runtime variable (written by the runtime-env step, read by the app service in the compose file). */
export const APP_PREFIX = 'PIPEGEN_APP_';

export interface Healthcheck { test: readonly string[]; interval: string; timeout: string; retries: number; start_period?: string }
export interface DepSpec {
  /** the id in data/base-images.yml */
  id: string;
  /** the release series the id stands for ('17', '8.4', '8.0'): a repo asking for another series gets a note, another major no file */
  series: string;
  port: number;
  /** the dependency's own environment, in the order written: name, then a literal from this file or a ${NAME} reference */
  env: readonly (readonly [string, string])[];
  healthcheck: Healthcheck;
}

export const DEP_TABLE: Readonly<Record<DepKey, DepSpec>> = Object.freeze({
  postgres: {
    id: 'postgres-17', series: '17', port: 5432,
    env: [['POSTGRES_USER', DB_USER], ['POSTGRES_PASSWORD', PASSWORD_REF], ['POSTGRES_DB', DB_NAME]],
    healthcheck: { test: ['CMD', 'pg_isready', '-h', LOCAL_HOST, '-U', DB_USER, '-d', DB_NAME], interval: '5s', timeout: '5s', retries: 20 },
  },
  mysql: {
    id: 'mysql-8.4', series: '8.4', port: 3306,
    env: [['MYSQL_ROOT_PASSWORD', PASSWORD_REF], ['MYSQL_USER', DB_USER], ['MYSQL_PASSWORD', PASSWORD_REF], ['MYSQL_DATABASE', DB_NAME]],
    healthcheck: { test: ['CMD', 'mysqladmin', 'ping', '-h', LOCAL_HOST, '-u', DB_USER, '--silent'], interval: '5s', timeout: '5s', retries: 30, start_period: '20s' },
  },
  redis: {
    id: 'redis-7', series: '7', port: 6379,
    env: [],
    healthcheck: { test: ['CMD', 'redis-cli', 'ping'], interval: '5s', timeout: '5s', retries: 20 },
  },
  mongodb: {
    id: 'mongo-8.0', series: '8.0', port: 27017,
    env: [['MONGO_INITDB_ROOT_USERNAME', DB_USER], ['MONGO_INITDB_ROOT_PASSWORD', PASSWORD_REF], ['MONGO_INITDB_DATABASE', DB_NAME]],
    healthcheck: { test: ['CMD', 'mongosh', '--quiet', '--eval', "db.adminCommand('ping').ok"], interval: '5s', timeout: '10s', retries: 30, start_period: '20s' },
  },
  rabbitmq: {
    id: 'rabbitmq-4-management', series: '4', port: 5672,
    env: [['RABBITMQ_DEFAULT_USER', DB_USER], ['RABBITMQ_DEFAULT_PASS', PASSWORD_REF]],
    healthcheck: { test: ['CMD', 'rabbitmq-diagnostics', '-q', 'ping'], interval: '10s', timeout: '10s', retries: 30, start_period: '30s' },
  },
});

/** What an env var of a dependency holds. */
export type VarKind = 'url' | 'host' | 'port' | 'user' | 'password' | 'db';
export const VAR_KINDS: readonly VarKind[] = ['url', 'host', 'port', 'user', 'password', 'db'];

/**
 * The value of each (dependency, kind), as the text inside the double quotes of the runtime-env step's shell: `${auth}` is the variable
 * `auth="pipegen:${pw}"` the step sets, `${pw}` the generated password. A pair with no row (redis has no user, password or database) can not be mapped.
 */
export const VALUE_TABLE: Readonly<Record<DepKey, Readonly<Partial<Record<VarKind, string>>>>> = Object.freeze({
  postgres: { url: `postgresql://\${auth}@${LOCAL_HOST}:5432/${DB_NAME}`, host: LOCAL_HOST, port: '5432', user: DB_USER, password: '${pw}', db: DB_NAME },
  mysql: { url: `mysql://\${auth}@${LOCAL_HOST}:3306/${DB_NAME}`, host: LOCAL_HOST, port: '3306', user: DB_USER, password: '${pw}', db: DB_NAME },
  redis: { url: `redis://${LOCAL_HOST}:6379`, host: LOCAL_HOST, port: '6379' },
  mongodb: { url: `mongodb://\${auth}@${LOCAL_HOST}:27017/${DB_NAME}?authSource=admin`, host: LOCAL_HOST, port: '27017', user: DB_USER, password: '${pw}', db: DB_NAME },
  rabbitmq: { url: `amqp://\${auth}@${LOCAL_HOST}:5672`, host: LOCAL_HOST, port: '5672', user: DB_USER, password: '${pw}' },
});

/**
 * The value the APP container sees (P6): the runner values reach a container as its own localhost, so the host of a url or a host var is the
 * dependency's compose key (`postgres`, `redis`, ...), which resolves on the compose network at the same port. Port, user, password and db are
 * the runner values. One rule for every kind, from the same table, so nothing runner-side reaches a container.
 */
export function containerValue(dep: DepKey, kind: VarKind): string | undefined {
  const v = VALUE_TABLE[dep][kind];
  return v === undefined ? undefined : kind === 'url' || kind === 'host' ? v.replace(LOCAL_HOST, dep) : v;
}

const DB_GENERIC: Readonly<Record<string, VarKind>> = { DB_HOST: 'host', DB_PORT: 'port', DB_USER: 'user', DB_PASSWORD: 'password', DB_NAME: 'db' };

/**
 * The env var names pipegen can fill, per dependency, with what each holds (B6). A name of a covered dependency that is not here is never
 * guessed: it gets a note. A name two dependencies both list (DATABASE_URL under postgres and mysql) is not mapped either.
 */
export const ENV_TABLE: Readonly<Record<DepKey, Readonly<Record<string, VarKind>>>> = Object.freeze({
  postgres: {
    DATABASE_URL: 'url', POSTGRES_URL: 'url', PGHOST: 'host', PGPORT: 'port', PGUSER: 'user', PGPASSWORD: 'password', PGDATABASE: 'db',
    POSTGRES_HOST: 'host', POSTGRES_PORT: 'port', POSTGRES_USER: 'user', POSTGRES_PASSWORD: 'password', POSTGRES_DB: 'db', ...DB_GENERIC,
  },
  mysql: {
    DATABASE_URL: 'url', MYSQL_URL: 'url', MYSQL_HOST: 'host', MYSQL_PORT: 'port', MYSQL_USER: 'user', MYSQL_PASSWORD: 'password', MYSQL_DATABASE: 'db', ...DB_GENERIC,
  },
  redis: { REDIS_URL: 'url', REDIS_HOST: 'host', REDIS_PORT: 'port' },
  mongodb: { MONGODB_URI: 'url', MONGODB_URL: 'url', MONGO_URL: 'url', MONGO_URI: 'url', MONGO_HOST: 'host', MONGO_PORT: 'port', MONGO_USER: 'user', MONGO_PASSWORD: 'password', MONGO_DB: 'db' },
  rabbitmq: { AMQP_URL: 'url', RABBITMQ_URL: 'url', RABBITMQ_HOST: 'host', RABBITMQ_PORT: 'port', RABBITMQ_USER: 'user', RABBITMQ_PASSWORD: 'password' },
});
