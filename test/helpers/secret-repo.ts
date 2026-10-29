import { makeTempDir, writeIn } from './make-repo.js';

// Every secret-like string here is joined from pieces at runtime, so no scanner (pipegen's own
// gitleaks job, GitHub push protection) ever sees a real-looking secret in the committed source.
const KEY_KIND = 'RSA PRIV' + 'ATE KEY';

export const fake = {
  githubClassic: () => 'gh' + 'p_' + 'a'.repeat(36),
  githubPat: () => 'github' + '_pat_' + 'B'.repeat(30),
  stripeKey: () => 'sk' + '_live_' + 'c'.repeat(24),
  openaiKey: () => 'sk' + '-' + 'D'.repeat(30),
  awsKey: () => 'AK' + 'IA' + 'E'.repeat(16),
  slackBot: () => 'xo' + 'xb-' + '1234-' + 'f'.repeat(20),
  jwt: () => ['ey' + 'J' + 'hbGciOiJIUzI1NiJ9', 'ey' + 'J' + 'zdWIiOiIxIn0', 'g'.repeat(24)].join('.'),
  slackWebhook: () => 'https://hooks.' + 'slack.com/' + 'services/' + 'T0000/B0000/' + 'h'.repeat(24),
  googleKey: () => 'AI' + 'za' + 'j'.repeat(35),
  npmPublish: () => 'np' + 'm_' + 'k'.repeat(36),
  keyBegin: () => '-----' + 'BEGIN ' + KEY_KIND + '-----',
  keyEnd: () => '-----' + 'END ' + KEY_KIND + '-----',
  keyBody: () => 'MIIEo' + 'w'.repeat(59),
  /** `name=value` with a word the generic redact rule looks for. */
  assign: (name: string, value: string, sep = '=') => name + sep + value,
};

export interface SecretRepo {
  dir: string;
  /** Every secret value written into the repo; none may ever appear in a bundle. */
  values: string[];
}

/** A fresh temp repo full of secret-like files and strings, all built at runtime. */
export function makeSecretRepo(): SecretRepo {
  const dir = makeTempDir();
  const gh = fake.githubClassic();
  const jwt = fake.jwt();
  const hook = fake.slackWebhook();
  const npm = fake.npmPublish();
  const body = fake.keyBody();
  const envPass = 'env' + 'pass' + 'value1';
  const tfstate = 'tfstate' + 'value2';
  const tfvars = 'tfvars' + 'value3';
  const kube = 'kube' + 'value4';
  const p12 = 'p12' + 'value5';

  writeIn(dir, '.env', fake.assign('PASS' + 'WORD', 'x') + '\n' + fake.assign('DB_PASS', envPass) + '\n');
  writeIn(dir, '.env.example', 'DB_HOST=\nDB_PORT=\n');
  writeIn(dir, 'package.json', JSON.stringify({ name: 'app', scripts: { release: `GH_PUBLISH=${gh} npm publish`, start: 'node src/app.ts' } }, null, 2) + '\n');
  writeIn(dir, 'config/dev.pem', `${fake.keyBegin()}\n${body}\n${body}\n${fake.keyEnd()}\n`);
  writeIn(dir, 'infra/prod.tfstate', JSON.stringify({ outputs: { db: { value: tfstate } } }) + '\n');
  writeIn(dir, 'infra/prod.tfvars', `db_value = "${tfvars}"\n`);
  writeIn(dir, 'infra/main.tf', 'resource "null_resource" "x" {}\n');
  writeIn(dir, '.npmrc', '//registry.npmjs.org/:_auth' + 'Tok' + 'en=' + npm + '\n');
  writeIn(dir, 'certs/app.p12', `${p12}\n`);
  writeIn(dir, '.kube/config', `users:\n- name: dev\n  user:\n    client-data: ${kube}\n`);
  writeIn(dir, 'src/config.ts', `export const session = '${jwt}';\nexport const hook = '${hook}';\n`);
  writeIn(dir, 'src/app.ts', "import { hook } from './config';\nconsole.log('hello', typeof hook);\n");
  return { dir, values: [gh, jwt, hook, npm, body, envPass, tfstate, tfvars, kube, p12] };
}
