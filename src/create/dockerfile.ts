// The Dockerfile creator (v0.2 Plan D, D3; preflight S4, S5, S6, S13). When an npm service has no Dockerfile, pipegen creates `<service>/Dockerfile`
// and `<service>/.dockerignore`. The AI drafts the Dockerfile; pipegen then
//   - owns every FROM: the image is the list id chosen from the repo's Node version (nodeBaseImageId), written as the reviewed
//     `<image>:<tag>@sha256:<digest>`. The prompt shows the AI the exact FROM lines, and pipegen rewrites any FROM that is not an earlier stage
//     alias, so the AI's tag text is ignored;
//   - judges the text with the rules leaf (dockerfile-rules.ts), the same function the referee's judge calls; on violations it asks once more
//     with the list, and if the second answer is still refused it throws a DockerfileError (Plan E makes the part failed);
//   - writes the fixed .dockerignore (dockerignoreText) and takes the AI's `reasoning` only into notes (through safeText), never into a file.
// Not proven (no file, one note): an existing Dockerfile (never edited; reviewExisting words its weaknesses), a package manager other than npm,
// no lock file of the service's own, an existing .dockerignore or Dockerfile.dockerignore (BuildKit reads the second first; pipegen won't edit either),
// a workspace monorepo (the build context would be outside the service), a Node version the list does not offer, or a folder path that is not plain.
import { z } from 'zod';
import { DOCKERFILE_SYSTEM, dockerfileInstructions } from '../ai/prompts/dockerfile.js';
import { completeValidated, formatAiText } from '../ai/provider.js';
import { bundleText, type CodeBundle } from '../ai/redact.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { baseImageRef, BaseImageError, loadBaseImages, nodeBaseImageId } from '../engine/base-images.js';
import { createdPathProblem } from '../engine/job-rules.js';
import type { AiProvider, AiRequest, AiUsage, CreatedFile, RepoProfile, Service } from '../types.js';
import { activeSafeText as safeText } from '../util/known-values.js';
import { buildsInsideOf, dockerfileProblems, dockerignoreText, envPairs, parseDockerfile, SECRET_NAME_RE, userIsRoot, type DockerfileCtx } from './dockerfile-rules.js';

const TIMEOUT_MS = 180_000;
const MAX_OUTPUT_TOKENS = 8_000;

/** What the creator can not know from the profile: the repo's file list (the reader's `fileSet`), to prove a file absent. Without it nothing is created. */
export interface DockerfileFacts { repoPaths: ReadonlySet<string> | readonly string[] }
export interface DockerfileResult { files: CreatedFile[]; notes: string[]; usage?: AiUsage }
/**
 * Plan E S10 (the fix loop, E7): `baseId` is a Node image id of pipegen's reviewed base-image list to build from instead of the one the
 * service's Node version gives (the docker part failed on its base image's CVEs and the AI chose another id from an enum). pipegen still
 * writes every FROM; any other id (another image, an id not in the list) creates nothing and asks the AI nothing.
 */
export interface DockerfileOptions { baseId?: string }
/** The ids `baseId` may name: the list's Node images. */
const NODE_ID_RE = /^node-\d+-bookworm-slim$/;

/** The second answer was refused too. Plan E makes the docker part failed. `usage` is the AI cost of both attempts. */
export class DockerfileError extends Error {
  constructor(message: string, readonly problems: readonly string[], readonly usage?: AiUsage) {
    super(safeText(message, 1200));
    this.name = 'DockerfileError';
  }
}

type AiDockerfile = { dockerfile: string; port: number; reasoning: string };
export const dockerfileSchema: AiSchema<AiDockerfile> = aiSchema<AiDockerfile>(z.strictObject({
  dockerfile: z.string().max(40_000), port: z.number().int(), reasoning: z.string().max(4_000),
}));

// ---------- paths ----------

const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
const validPort = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n >= 1 && n <= 65535;
/** A service folder the registry claims: plain path, no hidden or node_modules segment. */
const plainFolder = (dir: string): boolean => createdPathProblem(dir === '' ? 'Dockerfile' : `${dir}/Dockerfile`) === null && !dir.split('/').some((s) => s.startsWith('.') || s === 'node_modules');
const WORKSPACES: readonly string[] = ['npm-workspaces', 'pnpm-workspaces', 'yarn-workspaces', 'turbo', 'nx'];

// ---------- existing Dockerfiles (S15) ----------

export type ExistingCode = 'root-user' | 'unpinned-base' | 'add-url' | 'secret-arg';
export interface ExistingNote { code: ExistingCode; line: number }

/** Weaknesses of an existing Dockerfile as codes with the line (the first line of the instruction); Plan G words them. Never throws, never edits. */
export function reviewExistingCodes(text: string): ExistingNote[] {
  const out: ExistingNote[] = [];
  try {
    const { instructions } = parseDockerfile(text);
    const aliases = new Map<string, number>();
    const stages: { parent?: number; users: { value: string; line: number }[]; line: number }[] = [];
    for (const ins of instructions) {
      if (ins.kw === 'FROM') {
        const w = ins.args.replace(/^(?:--\S+\s+)+/, '').split(/\s+/).filter((x) => x !== '');
        const image = w[0] ?? '';
        const parent = aliases.get(image);
        if (parent === undefined && image.toLowerCase() !== 'scratch' && !/@sha256:[0-9a-f]{64}$/.test(image)) out.push({ code: 'unpinned-base', line: ins.line });
        stages.push({ ...(parent === undefined ? {} : { parent }), users: [], line: ins.line });
        if (w[1]?.toLowerCase() === 'as' && w[2] !== undefined) aliases.set(w[2], stages.length - 1);
      } else if (ins.kw === 'USER' && stages.length > 0) {
        (stages[stages.length - 1] as { users: { value: string; line: number }[] }).users.push({ value: ins.args.trim(), line: ins.line });
      } else if (ins.kw === 'ADD' && /(?:^|\s)(?:https?:\/\/|git(?:@|:\/\/|\+)|ssh:\/\/)/i.test(ins.args)) {
        out.push({ code: 'add-url', line: ins.line });
      } else if (ins.kw === 'ARG' || ins.kw === 'ENV') {
        const pairs = envPairs(ins.kw, ins.args) ?? [];
        if (pairs.some((p) => SECRET_NAME_RE.test(p.name) && p.value !== undefined && p.value !== '')) out.push({ code: 'secret-arg', line: ins.line });
      }
    }
    if (stages.length > 0) {
      let user: { value: string; line: number } | undefined;
      for (let s: number | undefined = stages.length - 1; s !== undefined && user === undefined; s = stages[s]?.parent) user = stages[s]?.users.at(-1);
      if (user === undefined || userIsRoot(user.value)) out.push({ code: 'root-user', line: user?.line ?? (stages[stages.length - 1] as { line: number }).line });
    }
  } catch { /* hostile text: no notes */ }
  return out.sort((a, b) => a.line - b.line || a.code.localeCompare(b.code));
}

const WORDS: Readonly<Record<ExistingCode, string>> = {
  'root-user': 'the container runs as root (no USER, or the last USER is root); add a USER with a non-root account',
  'unpinned-base': 'a base image is not pinned by digest (FROM image:tag@sha256:...); a tag can move',
  'add-url': 'ADD fetches a URL or a git repository at build time; use COPY, or fetch with a pinned and checked download',
  'secret-arg': 'an ARG or ENV with a secret-like name has a value, which ends up in the image and its history',
};

/** Notes for an existing Dockerfile (never edited): one per weakness, with the line. */
export function reviewExisting(text: string, svc: Pick<Service, 'name'>): string[] {
  return reviewExistingCodes(text).map((n) => `The existing Dockerfile of "${safeText(svc.name, 80)}" (line ${n.line}): ${WORDS[n.code]}. pipegen doesn't edit an existing Dockerfile.`);
}

// ---------- FROM ownership ----------

/** The text with every FROM that does not start from an earlier stage alias rewritten to `FROM <ref>` (and ` AS <name>` when the stage is named). */
export function ownFromLines(text: string, ref: string): string {
  const lines = text.split('\n');
  const { instructions } = parseDockerfile(text);
  const aliases = new Set<string>();
  const edits: { from: number; to: number; line: string | null }[] = [];
  for (const ins of instructions) {
    if (ins.kw !== 'FROM') continue;
    const w = ins.args.replace(/^(?:--\S+\s+)+/, '').split(/\s+/).filter((x) => x !== '');
    const image = w[0] ?? '';
    const named = w.length === 3 && w[1]?.toLowerCase() === 'as' ? (w[2] as string) : undefined;
    const fine = w.length === 1 || named !== undefined;
    const isAlias = aliases.has(image);
    if (named !== undefined) aliases.add(named);
    if (isAlias || !fine || (named !== undefined && !/^[a-z][a-z0-9_.-]{0,63}$/.test(named))) continue;   // left as written: the rules judge it
    edits.push({ from: ins.line - 1, to: ins.end - 1, line: `FROM ${ref}${named === undefined ? '' : ` AS ${named}`}` });
  }
  for (const e of edits.reverse()) lines.splice(e.from, e.to - e.from + 1, e.line as string);
  return lines.join('\n');
}

// ---------- the creator ----------

const notProven = (message: string): DockerfileResult => ({ files: [], notes: [message] });
const show = (s: Service): string => `"${safeText(s.name, 80)}"`;

/**
 * Creates `<service>/Dockerfile` and `<service>/.dockerignore` for an npm service, or says why not. See the file header for the rules.
 * `facts.repoPaths` is the repo's file list; without it every file is unproven absent and nothing is created.
 */
export async function createDockerfile(svc: Service, _profile: RepoProfile, bundle: CodeBundle, ai: AiProvider, facts?: DockerfileFacts, opts: DockerfileOptions = {}): Promise<DockerfileResult> {
  const code = bundleText(bundle);   // first: throws SecretScanRequiredError before anything else happens
  const dir = rootPrefix(svc.path);
  const at = (name: string): string => (dir === '' ? name : `${dir}/${name}`);

  if (svc.dockerfile !== undefined && svc.dockerfile !== '') {
    const entry = bundle.files.find((f) => f.path === svc.dockerfile);
    if (entry === undefined) return notProven(`${show(svc)} already has a Dockerfile, which pipegen doesn't edit; it could not read it to review it.`);
    const notes = reviewExisting(entry.content, svc);
    return { files: [], notes: notes.length > 0 ? notes : [`${show(svc)} already has a Dockerfile, which pipegen doesn't edit; it found nothing to flag.`] };
  }
  if (svc.language !== 'node' || svc.packageManager !== 'npm') {
    return notProven(`pipegen creates a Dockerfile only for npm services in this version; ${show(svc)} uses ${safeText(svc.packageManager ?? 'no recognised package manager', 20)}, so no Dockerfile was created.`);
  }
  if (!plainFolder(dir)) return notProven(`The folder of ${show(svc)} is not a plain path that pipegen can write into, so no Dockerfile was created.`);
  if (facts === undefined) return notProven(`pipegen could not list the files of ${show(svc)}, so it can't prove there is no Dockerfile, lock file or .dockerignore, and created none.`);
  const paths = new Set([...facts.repoPaths]);
  const inDir = [...paths].filter((p) => (dir === '' ? !p.includes('/') : p.startsWith(`${dir}/`) && !p.slice(dir.length + 1).includes('/'))).map((p) => p.slice(dir === '' ? 0 : dir.length + 1));
  if (inDir.some((n) => n.toLowerCase() === 'dockerfile')) return notProven(`${show(svc)} has a Dockerfile pipegen did not read as one, so it created none and edits none.`);
  if (!paths.has(at('package-lock.json'))) return notProven(`${show(svc)} has no package-lock.json of its own, so pipegen can't build a reproducible image (npm ci needs it) and created no Dockerfile.`);
  if (inDir.some((n) => ['.dockerignore', 'dockerfile.dockerignore'].includes(n.toLowerCase()))) {
    return notProven(`${show(svc)} has a .dockerignore (or Dockerfile.dockerignore), and pipegen won't edit your .dockerignore, so it created no Dockerfile.`);
  }
  if (WORKSPACES.includes(_profile.monorepo) && dir !== '') {
    return notProven(`${show(svc)} is in a workspace monorepo (${_profile.monorepo}), where the build context would be outside the service folder; pipegen created no Dockerfile.`);
  }

  let nodeId: string;
  if (opts.baseId !== undefined) {
    const id: unknown = opts.baseId;
    let known = false;
    try {
      known = typeof id === 'string' && NODE_ID_RE.test(id) && loadBaseImages().some((e) => e.id === id);
    } catch (e) {
      if (!(e instanceof BaseImageError)) throw e;
    }
    if (!known) return notProven(`No Dockerfile for ${show(svc)}: "${safeText(String(id), 60)}" is not a Node image id of pipegen's reviewed base-image list.`);
    nodeId = id as string;
  } else {
    try {
      const m = nodeBaseImageId(svc.runtimeVersion);
      if (m.note !== undefined) return notProven(`No Dockerfile for ${show(svc)}: ${safeText(m.note, 300)}`);
      nodeId = m.id;
    } catch (e) {
      if (!(e instanceof BaseImageError)) throw e;
      return notProven(`No Dockerfile for ${show(svc)}: pipegen's base-image list has no Node image it can use.`);
    }
  }
  const list = loadBaseImages();
  const ref = baseImageRef(nodeId, list);
  const builds = buildsInsideOf(svc);
  const knownPort = validPort(svc.port) ? svc.port : null;
  const fromLines = builds ? [`FROM ${ref} AS build`, `FROM ${ref}`] : [`FROM ${ref}`];
  const factsBlock = `<service-facts>\n${JSON.stringify({
    packageManager: 'npm', buildsInside: builds, hasStartScript: svc.scripts.includes('start'), port: knownPort, nodeBaseId: nodeId,
  }, null, 1)}\n</service-facts>`;
  const req: AiRequest = {
    system: DOCKERFILE_SYSTEM,
    user: `${code}\n${factsBlock}\n\n${dockerfileInstructions({ fromLines, buildsInside: builds, port: knownPort, hasStartScript: svc.scripts.includes('start') })}`,
    schemaName: 'dockerfile', jsonSchema: dockerfileSchema.jsonSchema, timeoutMs: TIMEOUT_MS, maxOutputTokens: MAX_OUTPUT_TOKENS,
  };

  const usage: AiUsage = { inputTokens: 0, outputTokens: 0 };
  const addUsage = (u: AiUsage): void => {
    usage.inputTokens += u.inputTokens; usage.outputTokens += u.outputTokens;
    if (u.cacheReadTokens !== undefined) usage.cacheReadTokens = (usage.cacheReadTokens ?? 0) + u.cacheReadTokens;
    if (u.cacheWriteTokens !== undefined) usage.cacheWriteTokens = (usage.cacheWriteTokens ?? 0) + u.cacheWriteTokens;
  };
  const attempt = async (request: AiRequest): Promise<{ answer: AiDockerfile; text: string; port: number; problems: string[] }> => {
    const { data, usage: u } = await completeValidated(ai, request, dockerfileSchema.zod);
    addUsage(u);
    const port = knownPort ?? data.port;
    const body = data.dockerfile.replace(/\r\n/g, '\n');
    const text = ownFromLines(body.endsWith('\n') ? body : `${body}\n`, ref);
    const ctx: DockerfileCtx = { port, baseImages: list, buildsInside: builds, scripts: svc.scripts };
    return { answer: data, text, port, problems: dockerfileProblems(text, svc, ctx) };
  };
  const tell = (e: unknown): never => { if (e instanceof Error && 'usage' in e) addUsage((e as { usage?: AiUsage }).usage ?? { inputTokens: 0, outputTokens: 0 }); throw e; };

  let got = await attempt(req).catch(tell);
  if (got.problems.length > 0) {
    const list1 = got.problems.slice(0, 20).map((p) => `- ${p}`).join('\n');
    got = await attempt({ ...req, user: `${req.user}\n\nThe Dockerfile you wrote was refused for these reasons:\n${list1}\nWrite the whole Dockerfile again so that none of these applies, and answer with JSON that matches the schema.` }).catch(tell);
    if (got.problems.length > 0) throw new DockerfileError(`The Dockerfile for ${show(svc)} was refused twice: ${got.problems.slice(0, 5).join('; ')}`, got.problems, usage);
  }

  const notes = [`The AI explained the Dockerfile for ${show(svc)}: ${formatAiText(got.answer.reasoning, 300)}`];
  if (knownPort === null) notes.push(`pipegen did not find the port of ${show(svc)} in the code, so the Dockerfile exposes port ${got.port}, which the AI chose; check that it is right.`);
  const files: CreatedFile[] = [
    { path: at('Dockerfile'), content: got.text, part: 'docker', repo: 'app', reason: `The service ${show(svc)} has no Dockerfile. This one builds from pipegen's reviewed base image, installs with npm ci --ignore-scripts --git=/usr/bin/git and runs as a non-root user.` },
    { path: at('.dockerignore'), content: dockerignoreText(svc, builds), part: 'docker', repo: 'app', reason: 'Keeps .git, .env files, keys, .npmrc and node_modules out of the image build context.' },
  ];
  return { files, notes, usage };
}
