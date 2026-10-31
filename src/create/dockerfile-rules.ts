// The Dockerfile rules leaf (v0.2 Plan D, D3; preflight S5 and S6). No AI, no filesystem: text in, reasons out. The creator (dockerfile.ts)
// and the referee's judge (created-judges/dockerfile.ts) call the SAME function, so what pipegen writes and what pipegen accepts can not drift.
//
// A Dockerfile is code that runs in CI with the repo's secrets nearby, and the AI's text is hostile until proven otherwise. So:
//   - the text is PARSED the way Docker parses it (continuation lines, comments inside a continuation, case-insensitive instructions,
//     JSON and shell form, leading blanks), and an instruction the parser can not classify is a problem, never a pass;
//   - default deny: only FROM WORKDIR COPY RUN ENV ARG USER EXPOSE CMD ENTRYPOINT HEALTHCHECK LABEL (ADD, ONBUILD, SHELL, VOLUME, STOPSIGNAL
//     and every unknown word are refused);
//   - the only text is printable ASCII, tab and LF, so no look-alike letters, no CR, no zero-width or bidi trick;
//   - every FROM is an exact reference of pipegen's reviewed base-image list (or an earlier stage alias), so no image, tag or `# syntax=`
//     frontend the AI names ever runs; `COPY --from=` names only an earlier alias;
//   - RUN, CMD, ENTRYPOINT and HEALTHCHECK are a strict ALLOWLIST (fix round 1, ruling R1), not a denylist: RUN is only ` && `-joined plain words
//     from a short list of commands (npm ci --ignore-scripts, npm run <script of the service>, npm prune --omit=dev, npm cache clean --force,
//     mkdir -p, chown node:node), CMD is one of three exec forms, ENTRYPOINT and HEALTHCHECK are refused. So a download, an interpreter, a pipe,
//     a variable or a substitution can not be written at all, and --ignore-scripts is mandatory (there is no retry without it);
//   - every USER is node, node:node, 1000 or 1000:1000 (R2), and the final stage has one; no secret-named ARG/ENV with a value, no secret-shaped
//     text (findSecretLike);
//   - EXPOSE is the one port, and a build step means more than one stage.
// Messages hold line numbers, instruction words from the allow list and short cleaned fragments, so they can be sent back to the AI as feedback.
import { findSecretLike } from '../ai/redact-core.js';
import { baseImageRef, type BaseImage } from '../engine/base-images.js';
import type { Service } from '../types.js';
import { safeText } from '../util/safe-text.js';

export interface DockerfileCtx {
  /** The one port the service listens on (1..65535). */
  port: number;
  /** pipegen's reviewed list: every FROM must be the exact reference of one entry (or an earlier stage alias). */
  baseImages: readonly BaseImage[];
  /** The service has a build step (a `build` script), so the Dockerfile must build in an earlier stage and `dist` is not copied from the context. */
  buildsInside: boolean;
  /** The service's script names (trusted: from the draft's service, like `buildsInside`): the only `npm run <name>` and `CMD ["npm","run","<name>"]` allowed. */
  scripts: readonly string[];
}

/** Whether the service's image builds inside the Dockerfile (a `build` script exists): one definition for the creator, the judge and the .dockerignore text. */
export const buildsInsideOf = (svc: Pick<Service, 'scripts'>): boolean => Array.isArray(svc.scripts) && svc.scripts.includes('build');

// ---------- .dockerignore (S6) ----------

/** The build-context root is the service folder; `**\/` also matches below it (Docker's `.env*` alone matches only the root). */
export const DOCKERIGNORE_LINES: readonly string[] = Object.freeze([
  '.git', '.env*', '**/.env*', '**/*.pem', '**/*.key', '**/.npmrc', '**/.netrc', '**/*.tfstate', '**/*.tfvars', '**/id_rsa*', '**/node_modules', '.venv',
  // fix round 1 (S6 amendment, m2): nested .git, ssh/cloud/docker credentials, more key and keystore files, tfstate backups
  '**/.git', '**/.ssh', '**/.aws', '**/.docker', '**/.git-credentials', '**/id_ed25519*', '**/id_ecdsa*', '**/id_dsa*', '**/*.p12', '**/*.pfx', '**/*.jks', '**/*.tfstate.backup', '**/*.tfvars.json',
]);

/** The fixed .dockerignore text: no `!` line, no comment, no repo text; `dist` only when the Dockerfile builds inside. */
export function dockerignoreText(_svc: Pick<Service, 'name'>, buildsInside: boolean): string {
  return `${[...DOCKERIGNORE_LINES, ...(buildsInside ? ['dist'] : [])].join('\n')}\n`;
}

// ---------- the parser ----------

export interface Instruction {
  /** The keyword in upper case (`ADD`), or the word as written when it is not letters. */
  kw: string;
  /** Everything after the keyword, joined across continuation lines the way Docker joins them, trimmed. */
  args: string;
  /** 1-based number of the first physical line. */
  line: number;
  /** 1-based number of the last physical line the instruction took (the continuation lines and the comments inside them included). */
  end: number;
  /** The first word of each continuation line, as written (Docker reads these lines as part of this instruction). */
  contWords: string[];
}
export interface ParsedDockerfile {
  instructions: Instruction[];
  /** Line numbers of comments shaped like a parser directive (`# word=value`). */
  directives: number[];
}

const DIRECTIVE_RE = /^#\s*[A-Za-z][A-Za-z0-9]*\s*=\s*\S/;
const CONTINUES_RE = /\\[ \t]*$/;

/**
 * Splits the text into instructions as Docker does, with the default escape character `\` (a directive that changes it is refused elsewhere).
 * A line ending in `\` goes on; comment and empty lines inside a continuation are dropped; the next line is appended with nothing between, so
 * `AD\` + `D x y` is the instruction ADD. Never throws.
 */
export function parseDockerfile(text: string): ParsedDockerfile {
  const lines = text.split('\n');
  const instructions: Instruction[] = [];
  const directives: number[] = [];
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i] as string;
    const t = raw.trim();
    if (t === '') { i++; continue; }
    if (t.startsWith('#')) { if (DIRECTIVE_RE.test(t)) directives.push(i + 1); i++; continue; }
    const start = i;
    let logical = '';
    const contWords: string[] = [];
    let cur = raw;
    for (;;) {
      const m = CONTINUES_RE.exec(cur);
      if (m === null) { logical += cur; i++; break; }
      logical += cur.slice(0, m.index);
      i++;
      while (i < lines.length && ((lines[i] as string).trim() === '' || (lines[i] as string).trim().startsWith('#'))) i++;
      if (i >= lines.length) break;
      cur = lines[i] as string;
      contWords.push(cur.trim().split(/[ \t]+/)[0] ?? '');
    }
    const body = logical.replace(/^[ \t]+/, '');
    const cut = body.search(/[ \t]/);
    const word = cut === -1 ? body : body.slice(0, cut);
    const rest = cut === -1 ? '' : body.slice(cut).trim();
    instructions.push({ kw: /^[A-Za-z]+$/.test(word) ? word.toUpperCase() : word, args: rest, line: start + 1, end: Math.min(i, lines.length), contWords });
  }
  return { instructions, directives };
}

// ---------- small helpers ----------

const MAX_BYTES = 64 * 1024;
const MAX_LINE = 4000;       // findSecretLike skips lines over 4 KB, so a longer line could hide a secret
const MAX_INSTRUCTIONS = 500;
const ALLOWED = new Set(['FROM', 'WORKDIR', 'COPY', 'RUN', 'ENV', 'ARG', 'USER', 'EXPOSE', 'CMD', 'ENTRYPOINT', 'HEALTHCHECK', 'LABEL']);
/** The refused words that matter if one is hidden at the start of a continuation line. */
const HIDDEN_KEYWORDS = new Set(['ADD', 'ONBUILD', 'FROM', 'USER', 'SHELL', 'VOLUME', 'STOPSIGNAL']);
/** ARG/ENV names that hold a secret (S5). */
export const SECRET_NAME_RE = /(KEY|SECRET|TOKEN|PASS|PWD|CREDENTIAL|AUTH|PRIVATE|DSN|DATABASE_URL)/i;
/** ARG/ENV names that change where packages or code come from, or how the tools load code or check TLS. */
const RISKY_NAME_RE = /^(?:NPM_CONFIG_.*|LD_.*|BASH_ENV|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|(?:HTTP|HTTPS|ALL|NO)_PROXY)$/i;
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ALIAS_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
const q = (s: string): string => safeText(s, 60);

/** Words split on blanks with quotes removed (`'` and `"`), a backslash escaping the next character outside single quotes. Null for an open quote. */
function shellWords(s: string): string[] | null {
  const out: string[] = [];
  let cur = '';
  let has = false;
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (quote === "'") { if (c === "'") quote = null; else cur += c; continue; }
    if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === '\\' && i + 1 < s.length) cur += s[++i];
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; has = true; continue; }
    if (c === '\\' && i + 1 < s.length) { cur += s[++i]; has = true; continue; }
    if (c === ' ' || c === '\t') { if (has || cur !== '') { out.push(cur); cur = ''; has = false; } continue; }
    cur += c;
  }
  if (quote !== null) return null;
  if (has || cur !== '') out.push(cur);
  return out;
}

/** The elements of a JSON-form argument (`["a", "b"]`), or null when it is shell form (Docker's rule: valid JSON, an array of strings). */
function execForm(args: string): string[] | null {
  const t = args.trim();
  if (!t.startsWith('[')) return null;
  try {
    const j: unknown = JSON.parse(t);
    return Array.isArray(j) && j.every((x) => typeof x === 'string') ? (j as string[]) : null;
  } catch { return null; }
}

/** Leading `--flag` or `--flag=value` words, and the rest of the argument text. */
function takeFlags(args: string): { flags: string[]; rest: string } {
  const flags: string[] = [];
  let rest = args.trim();
  for (;;) {
    const m = /^(--[^\s]*)(?:[ \t]+|$)/.exec(rest);
    if (m === null) return { flags, rest };
    flags.push(m[1] as string);
    rest = rest.slice(m[0].length);
  }
}

/** The only USER values pipegen writes (the official Node image's `node` user, by name or by id). */
const ALLOWED_USERS: ReadonlySet<string> = new Set(['node', 'node:node', '1000', '1000:1000']);

/** For an EXISTING Dockerfile (notes only): whether a USER value is root, or can not be shown not to be (a variable, a name with a blank, an empty value). */
export function userIsRoot(value: string): boolean {
  const v = value.trim();
  if (v === '' || /[\s$]/.test(v)) return true;
  const [user = '', group] = v.split(':') as [string, string?];
  const zero = (s: string): boolean => /^root$/i.test(s) || (/^[+-]?\d+$/.test(s) && Number(s) === 0);
  if (!/^[A-Za-z0-9._+-]+$/.test(user) || (group !== undefined && !/^[A-Za-z0-9._+-]+$/.test(group))) return true;
  return zero(user) || (group !== undefined && zero(group));
}

/** ENV/ARG pairs of an instruction's argument: name and value (undefined: a name alone); null when the argument is malformed. */
export function envPairs(kw: 'ENV' | 'ARG', args: string): { name: string; value?: string }[] | null {
  if (args.trim() === '') return null;
  const first = args.trim().split(/[ \t]+/)[0] as string;
  if (kw === 'ENV' && !first.includes('=')) {   // the old form: ENV name some value
    return [{ name: first, value: args.trim().slice(first.length).trim() }];
  }
  const words = shellWords(args);
  if (words === null) return null;
  const out: { name: string; value?: string }[] = [];
  for (const w of words) {
    const eq = w.indexOf('=');
    if (eq === -1) { if (kw === 'ENV') return null; out.push({ name: w }); } else out.push({ name: w.slice(0, eq), value: w.slice(eq + 1) });
  }
  return out.length > 0 ? out : null;
}

// ---------- RUN and CMD: the allowlist ----------

const WORD_RE = /^[A-Za-z0-9._/@=:,+-]+$/;
const PATH_RE = /^[A-Za-z0-9._/-]+$/;
const SCRIPT_RE = /^[A-Za-z0-9:._-]+$/;
const NPM_CI_FLAGS = new Set(['--ignore-scripts', '--omit=dev', '--omit=optional', '--no-audit', '--no-fund']);
/** A plain path: no `..` segment, no leading dash. */
const plainPath = (p: string): boolean => PATH_RE.test(p) && !p.startsWith('-') && !p.split('/').includes('..');

/** The words of a RUN command: the elements of the JSON form (each one plain word), or the shell text with blanks collapsed. Null when it is neither. */
function runWords(rest: string): string[] | null {
  const e = execForm(rest);
  if (e !== null) return e.length > 0 && e.every((w) => w === '&&' || WORD_RE.test(w)) ? e : null;
  const text = rest.trim().replace(/[ \t]+/g, ' ');
  return text === '' ? null : text.split(' ');
}

/** Why a RUN command is not allowed ('' when it is); `npmCi` counts the `npm ci` commands seen. */
function runCommandProblem(words: readonly string[], ctx: DockerfileCtx, counts: { npmCi: number }): string {
  if (words.some((w) => w !== '&&' && !WORD_RE.test(w))) return 'a word of the command is not plain (only letters, digits and . / _ @ = : , + -; no quote, variable, pipe, redirect or substitution)';
  const cmds: string[][] = [[]];
  for (const w of words) { if (w === '&&') cmds.push([]); else (cmds[cmds.length - 1] as string[]).push(w); }
  for (const c of cmds) {
    const [a, b, ...more] = c as [string, string?, ...string[]];
    if (c.length === 0) return 'an empty command (&& must join two commands)';
    if (a === 'npm' && b === 'ci') {
      const seen = new Set<string>();
      for (const f of more) { if (!NPM_CI_FLAGS.has(f) || seen.has(f)) return `npm ci may only have --ignore-scripts and, once each, --omit=dev, --omit=optional, --no-audit, --no-fund (not ${q(f)})`; seen.add(f); }
      if (!seen.has('--ignore-scripts')) return 'npm ci needs --ignore-scripts (install scripts of the dependencies would run in CI)';
      counts.npmCi++;
    } else if (a === 'npm' && b === 'run') {
      if (more.length !== 1 || !SCRIPT_RE.test(more[0] as string) || !ctx.scripts.includes(more[0] as string)) return `npm run needs exactly one script name that is a script of this service (not ${q(more.join(' '))})`;
    } else if (a === 'npm' && b === 'prune' && more.join(' ') === '--omit=dev') { /* allowed */ } else if (a === 'npm' && b === 'cache' && more.join(' ') === 'clean --force') { /* allowed */ } else if (a === 'mkdir' && b === '-p' && more.length === 1 && plainPath(more[0] as string)) { /* allowed */ } else if (a === 'chown') {
      const args = [b, ...more].filter((x): x is string => x !== undefined);
      const rest = args[0] === '-R' ? args.slice(1) : args;
      if (!(rest.length === 2 && rest[0] === 'node:node' && plainPath(rest[1] as string))) return 'chown is only allowed as chown [-R] node:node <plain path>';
    } else return `${q(c.join(' '))} is not one of the commands pipegen allows (npm ci --ignore-scripts, npm run <script>, npm prune --omit=dev, npm cache clean --force, mkdir -p <path>, chown [-R] node:node <path>)`;
  }
  return '';
}

/** Why a CMD is not allowed ('' when it is): exec form only, `["node","<plain .js/.mjs/.cjs path>"]`, `["npm","start"]` or `["npm","run","<script>"]`. */
function cmdProblem(args: string, ctx: DockerfileCtx): string {
  const e = execForm(args);
  if (e === null || e.length === 0) return 'CMD must be in exec form (a JSON list)';
  if (e.length === 2 && e[0] === 'node' && /^[A-Za-z0-9._/-]+\.(?:js|mjs|cjs)$/.test(e[1] as string) && !(e[1] as string).startsWith('/') && plainPath(e[1] as string)) return '';
  if (e.length === 2 && e[0] === 'npm' && e[1] === 'start') return '';
  if (e.length === 3 && e[0] === 'npm' && e[1] === 'run' && SCRIPT_RE.test(e[2] as string) && ctx.scripts.includes(e[2] as string)) return '';
  return 'CMD must be ["node", "<plain relative .js, .mjs or .cjs path>"], ["npm", "start"] or ["npm", "run", "<a script of this service>"]';
}

// ---------- the rules ----------

/**
 * The reasons a Dockerfile is not acceptable (empty: it is). `svc` must be an npm service; `ctx.port` is the one port; `ctx.baseImages` the list
 * the FROM lines must come from. Never throws, for any input.
 */
export function dockerfileProblems(text: string, svc: Pick<Service, 'language' | 'packageManager'>, ctx: DockerfileCtx): string[] {
  try {
    return rules(text, svc, ctx);
  } catch {
    return ['the Dockerfile could not be checked, so it is refused'];
  }
}

function rules(text: string, svc: Pick<Service, 'language' | 'packageManager'>, ctx: DockerfileCtx): string[] {
  const out: string[] = [];
  const add = (m: string): void => { if (!out.includes(m)) out.push(m); };
  if (typeof text !== 'string') return ['the Dockerfile is not text'];
  if (svc.language !== 'node' || svc.packageManager !== 'npm') add('pipegen writes a Dockerfile only for a Node.js service that uses npm (v0.2)');
  if (!Number.isInteger(ctx.port) || ctx.port < 1 || ctx.port > 65535) add('the port is not a whole number from 1 to 65535');
  if (text.length > MAX_BYTES) return [...out, `the Dockerfile is too large (over ${MAX_BYTES} bytes)`];
  if (/[^\t\n\x20-\x7e]/.test(text)) return [...out, 'the Dockerfile has a character other than printable ASCII, tab and newline (a carriage return, control, invisible or non-ASCII character)'];
  if (text.split('\n').some((l) => l.length > MAX_LINE)) add(`a line of the Dockerfile is too long (over ${MAX_LINE} characters; the secret scan does not read such lines)`);

  const parsed = parseDockerfile(text);
  for (const n of parsed.directives) add(`line ${n} is a parser directive (a comment of the form # name=value, such as # syntax= or # escape=); pipegen allows none`);
  if (parsed.instructions.length > MAX_INSTRUCTIONS) return [...out, 'the Dockerfile has too many instructions'];
  if (text.includes('<<')) add('the Dockerfile has a heredoc (<<); pipegen allows none');

  for (const hit of findSecretLike(text)) add(`the Dockerfile has text that looks like a secret (${hit})`);
  for (const ins of parsed.instructions) for (const hit of findSecretLike(`${ins.kw} ${ins.args}`)) add(`line ${ins.line} holds text that looks like a secret (${hit})`);

  const refs = new Set(ctx.baseImages.map((e) => baseImageRef(e.id, ctx.baseImages)));
  const aliasStage = new Map<string, number>();   // alias (exact case, lower case only) -> index of its stage
  const stages: { alias?: string; parent?: number; users: string[]; expose: number; cmds: number }[] = [];
  const counts = { npmCi: 0 };
  let stage = -1;

  for (const ins of parsed.instructions) {
    const where = `${ins.kw} on line ${ins.line}`;
    if (ins.kw === 'ONBUILD') { add(`${where}: ONBUILD is not allowed`); continue; }
    if (!ALLOWED.has(ins.kw)) {
      add(ins.kw === 'ADD' ? `line ${ins.line}: ADD is not allowed (use COPY)` : `line ${ins.line}: ${q(ins.kw)} isn't an instruction pipegen allows (only FROM, WORKDIR, COPY, RUN, ENV, ARG, USER, EXPOSE, CMD, ENTRYPOINT, HEALTHCHECK and LABEL)`);
      continue;
    }
    for (const w of ins.contWords) if (HIDDEN_KEYWORDS.has(w.toUpperCase()) && /^[A-Za-z]+$/.test(w)) add(`line ${ins.line}: a continuation line starts with ${w.toUpperCase()}; pipegen refuses an instruction word hidden behind a continuation`);
    if (ins.kw !== 'FROM' && stage === -1) { add(`${where} comes before the first FROM`); continue; }

    switch (ins.kw) {
      case 'FROM': {
        const { flags, rest } = takeFlags(ins.args);
        for (const f of flags) if (!/^--platform=linux\/(?:amd64|arm64|arm\/v7)$/.test(f)) add(`${where}: the flag ${q(f)} is not allowed (only a literal --platform=linux/amd64 or linux/arm64)`);
        if (ins.args.includes('$')) add(`${where}: FROM may not use a variable`);
        const w = rest.split(/[ \t]+/).filter((x) => x !== '');
        const image = w[0] ?? '';
        let alias: string | undefined;
        if (w.length === 3 && w[1]?.toLowerCase() === 'as') alias = w[2] as string;
        else if (w.length !== 1) add(`${where}: FROM needs one image, and optionally AS and a stage name`);
        if (alias !== undefined) {
          if (!ALIAS_RE.test(alias) || alias === 'scratch') add(`${where}: the stage name ${q(alias)} is not allowed`);
          else if (aliasStage.has(alias)) add(`${where}: the stage name ${q(alias)} is used twice (a duplicate alias)`);
        }
        let parent: number | undefined;
        if (refs.has(image)) parent = undefined;
        else if (aliasStage.has(image)) parent = aliasStage.get(image);
        else add(`${where}: FROM ${q(image)} is not a reference from pipegen's reviewed base-image list or an earlier stage name`);
        stage++;
        stages.push({ ...(alias !== undefined && ALIAS_RE.test(alias) ? { alias } : {}), ...(parent === undefined ? {} : { parent }), users: [], expose: 0, cmds: 0 });
        if (alias !== undefined && ALIAS_RE.test(alias) && alias !== 'scratch' && !aliasStage.has(alias)) aliasStage.set(alias, stage);
        break;
      }
      case 'COPY': {
        const { flags, rest } = takeFlags(ins.args);
        const seen = new Set<string>();
        for (const f of flags) {
          const name = f.replace(/=.*$/, '');
          if (seen.has(name)) { add(`${where}: the flag ${name} is given twice`); continue; }
          seen.add(name);
          if (f === '--link') continue;
          if (/^--chmod=0?[0-7]{3}$/.test(f) || /^--chown=(?:node:node|1000:1000)$/.test(f)) continue;
          const from = /^--from=(.*)$/.exec(f)?.[1];
          if (from !== undefined) {
            const idx = aliasStage.get(from);
            if (idx === undefined || idx >= stage) add(`${where}: --from=${q(from)} is not an earlier stage name, written in the same letter case (COPY --from may not name an image, a number or a variable)`);
          } else add(`${where}: the flag ${q(f)} is not allowed (COPY takes --from=<earlier stage>, --link, --chmod=<3 octal digits>, --chown=node:node or 1000:1000)`);
        }
        const parts = execForm(rest) ?? shellWords(rest);
        if (parts === null || parts.length < 2) add(`${where}: COPY needs sources and a destination`);
        break;
      }
      case 'RUN': {
        const { flags, rest } = takeFlags(ins.args);
        if (flags.length > 2 || new Set(flags).size !== flags.length || flags.some((f) => f !== '--mount=type=cache,target=/root/.npm' && f !== '--network=none')) add(`${where}: the only RUN flags allowed are --mount=type=cache,target=/root/.npm and --network=none, once each`);
        const words = runWords(rest);
        if (words === null) { add(`${where}: RUN needs a command made of plain words (a JSON list of plain words is fine)`); break; }
        const why = runCommandProblem(words, ctx, counts);
        if (why !== '') add(`${where}: ${why}`);
        break;
      }
      case 'CMD': {
        const why = cmdProblem(ins.args, ctx);
        if (why !== '') add(`${where}: ${why}`);
        if (++(stages[stage] as { cmds: number }).cmds > 1) add(`${where}: a stage has more than one CMD`);
        break;
      }
      case 'ENTRYPOINT': add(`${where}: ENTRYPOINT is not allowed (pipegen starts the service with CMD)`); break;
      case 'HEALTHCHECK': add(`${where}: HEALTHCHECK is not allowed (the health of the service is checked by the compose file)`); break;
      case 'WORKDIR': {
        const w = shellWords(ins.args);
        if (w === null || w.length !== 1 || !/^[A-Za-z0-9._/-]+$/.test(w[0] as string)) add(`${where} needs one plain path (letters, digits, . _ - and /; no variable)`);
        break;
      }
      case 'LABEL': {
        if (ins.args.trim() === '' || shellWords(ins.args) === null) add(`${where} is malformed`);
        break;
      }
      case 'USER': {
        const value = ins.args.trim();
        if (!ALLOWED_USERS.has(value)) add(`${where}: USER must be exactly node, node:node, 1000 or 1000:1000 (not ${q(value)})`);
        (stages[stage] as { users: string[] }).users.push(value);
        break;
      }
      case 'EXPOSE': {
        const w = ins.args.split(/[ \t]+/).filter((x) => x !== '');
        if (w.length === 0) add(`${where} needs a port`);
        for (const p of w) {
          const m = /^(\d{1,5})(?:\/tcp)?$/i.exec(p);
          if (m === null) add(`${where}: ${q(p)} is not a TCP port (a whole number, optionally with /tcp)`);   // ctx.port is checked to be 1..65535 above, so equality below also bounds the range
          else if (Number(m[1]) !== ctx.port) add(`${where}: EXPOSE ${m[1]} is not the service's port (${ctx.port})`);
        }
        (stages[stage] as { expose: number }).expose++;
        break;
      }
      case 'ENV': case 'ARG': {
        const pairs = envPairs(ins.kw, ins.args);
        if (pairs === null) { add(`${where} is malformed`); break; }
        for (const p of pairs) {
          if (!NAME_RE.test(p.name)) { add(`${where}: ${q(p.name)} is not a valid name`); continue; }
          if (RISKY_NAME_RE.test(p.name)) add(`${where}: ${p.name} changes where packages come from or how code is loaded, and is not allowed`);
          if (SECRET_NAME_RE.test(p.name) && p.value !== undefined && p.value !== '') add(`${where}: ${p.name} looks like a secret and has a value (the value would be in the image and its history)`);
        }
        break;
      }
      default: break;
    }
  }

  if (stage === -1) { add('the Dockerfile has no FROM'); return out; }
  if (stages.length < 2 && ctx.buildsInside) add('the service has a build step, so the Dockerfile must be multi-stage (build in one stage, run from a clean one)');
  const finalStage = stages[stage] as { parent?: number; users: string[]; expose: number };
  if (finalStage.expose === 0) add('the final stage has no EXPOSE of the service port');
  // the user of the final stage: its last USER, else the one it inherits from the stage it starts from
  let user: string | undefined;
  for (let s: number | undefined = stage; s !== undefined && user === undefined; s = stages[s]?.parent) user = stages[s]?.users.at(-1);
  if (user === undefined) add('the final stage has no USER (the container would run as root)');
  if (ctx.buildsInside && finalStage.parent !== undefined) add('the service has a build step, so the final stage must start from a reviewed base image (a FROM with a list reference), not from the build stage');
  if (counts.npmCi === 0) add('there is no npm ci (dependencies are installed with npm ci --ignore-scripts from package-lock.json)');
  return out;
}
