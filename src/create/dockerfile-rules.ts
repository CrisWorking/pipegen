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
//   - no download is run (curl/wget...), nothing is piped into a shell, no heredoc, no ONBUILD;
//   - only `npm ci` installs, with --ignore-scripts, from the lock file; no other package manager, no npx;
//   - the last user is not root; the final stage has a USER; no secret-named ARG/ENV with a value, no secret-shaped text (findSecretLike);
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
  /** Plan E may allow install scripts for one retry when the build needs them; the rule then stops asking for --ignore-scripts. */
  allowInstallScripts?: boolean;
}

/** Whether the service's image builds inside the Dockerfile (a `build` script exists): one definition for the creator, the judge and the .dockerignore text. */
export const buildsInsideOf = (svc: Pick<Service, 'scripts'>): boolean => Array.isArray(svc.scripts) && svc.scripts.includes('build');

// ---------- .dockerignore (S6) ----------

/** The build-context root is the service folder; `**\/` also matches below it (Docker's `.env*` alone matches only the root). */
export const DOCKERIGNORE_LINES: readonly string[] = Object.freeze([
  '.git', '.env*', '**/.env*', '**/*.pem', '**/*.key', '**/.npmrc', '**/.netrc', '**/*.tfstate', '**/*.tfvars', '**/id_rsa*', '**/node_modules', '.venv',
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

/** Whether a USER value is root, or can not be shown not to be (a variable, a name with a blank, an empty value). */
export function userIsRoot(value: string): boolean {
  const v = value.trim();
  if (v === '' || /[\s$]/.test(v)) return true;
  const [user = '', group] = v.split(':') as [string, string?];
  const zero = (s: string): boolean => /^root$/i.test(s) || (/^\d+$/.test(s) && Number(s) === 0);
  if (!/^[A-Za-z0-9._-]+$/.test(user) || (group !== undefined && !/^[A-Za-z0-9._-]+$/.test(group))) return true;
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

// ---------- shell text ----------

interface Seg { words: string[]; cmd: string; sep: string; pipeline: number; sub: boolean }
const WRAPPERS = new Set(['sudo', 'doas', 'env', 'exec', 'time', 'nohup', 'command', 'nice', 'ionice', 'xargs', 'then', 'do', 'else', 'elif', 'if', 'while', 'until', 'timeout', 'stdbuf', 'setsid', '!']);
export const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ash', 'ksh', 'csh', 'tcsh', 'fish', 'busybox']);
const INTERPRETERS = new Set(['python', 'python2', 'python3', 'perl', 'ruby', 'node', 'php', 'lua', 'tclsh', 'awk', 'eval', 'source', '.']);
const DOWNLOADERS = new Set(['curl', 'wget', 'aria2c', 'lwp-download', 'ftp', 'tftp', 'nc', 'ncat', 'netcat', 'socat', 'telnet']);
const INSTALLERS = new Set(['apt-get', 'apt', 'apk', 'dpkg', 'yum', 'dnf', 'microdnf', 'zypper', 'pacman']);
const OTHER_MANAGERS = new Set(['yarn', 'yarnpkg', 'pnpm', 'pnpx', 'bun', 'bunx', 'corepack', 'npx']);
const NPM_ALLOWED = new Set(['ci', 'clean-install', 'run', 'run-script', 'start', 'test', 'prune', 'cache']);

/** A word as the shell would run it: quotes and backslashes inside it removed (`c\url`, `cu""rl`), the path dropped, lower case. */
const bare = (w: string): string => w.replace(/['"\\`]/g, '').replace(/^[\s$({]+|[\s;)}\]]+$/g, '').replace(/^.*\//, '').toLowerCase();

/** The commands of a piece of shell text, found by splitting at `; && || | & ( ) { } backtick` and newlines; quotes are ignored on purpose (text in quotes is read too). */
function segments(text: string): Seg[] {
  const segs: Seg[] = [];
  const stack: boolean[] = [];   // for each open `(`: whether it is a substitution ($( <( >()
  let tick = false;
  let sep = '';
  let cur = '';
  let pipeline = 0;
  const flush = (next: string): void => {
    const words = cur.split(/[ \t]+/).filter((w) => w !== '');
    if (words.length > 0) {
      let k = 0;
      for (; k < words.length; k++) {
        const w = words[k] as string;
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w) || w.startsWith('-') || /^\d+$/.test(w)) continue;
        if (!WRAPPERS.has(bare(w))) break;
      }
      segs.push({ words, cmd: bare(words[k] ?? ''), sep, pipeline, sub: tick || stack.includes(true) });
    }
    if (next !== '|') pipeline++;
    sep = next;
    cur = '';
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    const two = text.slice(i, i + 2);
    if (two === '&&' || two === '||') { flush(two); i++; continue; }
    if (c === '|') { flush('|'); continue; }
    if (c === ';' || c === '&' || c === '\n' || c === '{' || c === '}') { flush(c); continue; }
    if (c === '`') { flush('`'); tick = !tick; continue; }
    if (c === '(') {
      const prev = cur.slice(-1);
      const sub = prev === '$' || prev === '<' || prev === '>';
      if (sub) cur = cur.slice(0, -1);
      flush('(');
      stack.push(sub);
      continue;
    }
    if (c === ')') { flush(')'); stack.pop(); continue; }
    cur += c;
  }
  flush('');
  return segs;
}

interface RunSummary { problems: string[]; npmCi: number }

/** What is wrong with the shell text of one RUN, CMD, ENTRYPOINT or HEALTHCHECK command. `isRun`: the downloads ban applies. */
function shellProblems(text: string, where: string, isRun: boolean, allowScripts: boolean): RunSummary {
  const problems: string[] = [];
  let npmCi = 0;
  const segs = segments(text);
  const downloadsIn = (s: Seg): string | undefined => (INSTALLERS.has(s.cmd) ? undefined : s.words.map(bare).find((w) => DOWNLOADERS.has(w)));
  for (const s of segs) {
    const dl = downloadsIn(s);
    if (s.sep === '|' && (SHELLS.has(s.cmd) || INTERPRETERS.has(s.cmd))) {
      const fromDownload = segs.some((o) => o.pipeline === s.pipeline && o !== s && downloadsIn(o) !== undefined);
      if (fromDownload) problems.push(`${where} pipes a download into a shell`);
      else if (SHELLS.has(s.cmd)) problems.push(`${where} pipes data into a shell`);
    }
    if (dl !== undefined) {
      if (s.sub) problems.push(`${where} runs a download (${dl}) inside a command or process substitution`);
      if (isRun) problems.push(`${where} downloads with ${dl}; pipegen's Dockerfile installs only with npm ci from the lock file`);
    }
    if (s.cmd === 'eval') problems.push(`${where} uses eval`);
    for (const raw of s.words) {
      const w = raw.replace(/['"\\`]/g, '');
      if (/^(?:npm_config_|NPM_CONFIG_)/i.test(w)) problems.push(`${where} sets an npm config value in the environment (${q(w.split('=')[0] ?? '')})`);
      if (w.includes('.npmrc')) problems.push(`${where} touches an .npmrc file`);
      if (/^(?:base64|xxd|uudecode)$/.test(bare(raw)) && !INSTALLERS.has(s.cmd)) problems.push(`${where} uses ${bare(raw)}, which can decode a hidden command`);
    }
    if (INSTALLERS.has(s.cmd)) continue;   // `apt-get install yarn` names a package, it does not run it
    for (let k = 0; k < s.words.length; k++) {
      const w = bare(s.words[k] as string);
      if (OTHER_MANAGERS.has(w)) problems.push(w === 'npx' || w === 'pnpx' || w === 'bunx' ? `${where} runs ${w}, which downloads and runs a package` : `${where} uses ${w}; only npm is supported (npm ci from package-lock.json)`);
      if (w !== 'npm') continue;
      const args = s.words.slice(k + 1).map((a) => a.replace(/^['"]+|['"]+$/g, ''));
      const sub = args.find((a) => !a.startsWith('-'));
      if (args.some((a) => /^--(?:[^=]*:)?registry(?:=|$)|^--(?:user|global)config(?:=|$)/.test(a))) problems.push(`${where} sets an npm registry or config file (${q(args.join(' '))})`);
      if (sub === undefined || !NPM_ALLOWED.has(sub)) { problems.push(`${where} runs npm ${q(sub ?? '')}; only npm ci, npm run, npm start, npm test, npm prune and npm cache are allowed (npm install, npm exec and the rest are not)`); continue; }
      if (sub === 'ci' || sub === 'clean-install') {
        npmCi++;
        const flag = [...args].reverse().find((a) => /^--(?:no-)?ignore-scripts(?:=|$)/.test(a));
        const on = flag === '--ignore-scripts' || flag === '--ignore-scripts=true';
        if (!on && !allowScripts) problems.push(`${where} runs npm ci without --ignore-scripts (install scripts of the dependencies would run in CI)`);
      }
    }
  }
  return { problems, npmCi };
}

/** The shell text of a RUN/CMD/ENTRYPOINT command: the elements of the JSON form joined by blanks, or the text itself. */
const commandText = (args: string): string => { const e = execForm(args); return e !== null ? e.join(' ') : args; };

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
  const aliasStage = new Map<string, number>();   // lower-case alias -> index of its stage
  const stages: { alias?: string; parent?: number; users: string[]; expose: number; froms: number }[] = [];
  let npmCi = 0;
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
        if (w.length === 3 && w[1]?.toLowerCase() === 'as') alias = (w[2] as string).toLowerCase();
        else if (w.length !== 1) add(`${where}: FROM needs one image, and optionally AS and a stage name`);
        if (alias !== undefined) {
          if (!ALIAS_RE.test(alias) || alias === 'scratch') add(`${where}: the stage name ${q(alias)} is not allowed`);
          else if (aliasStage.has(alias)) add(`${where}: the stage name ${q(alias)} is used twice (a duplicate alias)`);
        }
        let parent: number | undefined;
        if (refs.has(image)) parent = undefined;
        else if (aliasStage.has(image.toLowerCase()) && !image.includes(':') && !image.includes('@')) parent = aliasStage.get(image.toLowerCase());
        else add(`${where}: FROM ${q(image)} is not a reference from pipegen's reviewed base-image list or an earlier stage name`);
        stage++;
        stages.push({ ...(alias !== undefined && ALIAS_RE.test(alias) ? { alias } : {}), ...(parent === undefined ? {} : { parent }), users: [], expose: 0, froms: 1 });
        if (alias !== undefined && ALIAS_RE.test(alias) && alias !== 'scratch' && !aliasStage.has(alias)) aliasStage.set(alias, stage);
        break;
      }
      case 'COPY': {
        const { flags, rest } = takeFlags(ins.args);
        for (const f of flags) {
          const m = /^--([a-z-]+)(?:=(.*))?$/.exec(f);
          if (m === null || !['from', 'chown', 'chmod', 'link'].includes(m[1] as string)) { add(`${where}: the flag ${q(f)} is not allowed`); continue; }
          if (m[1] === 'from') {
            const from = (m[2] ?? '').toLowerCase();
            const idx = aliasStage.get(from);
            if (idx === undefined || idx >= stage || !ALIAS_RE.test(from)) add(`${where}: --from=${q(m[2] ?? '')} is not an earlier stage name (COPY --from may not name an image, a number or a variable)`);
          }
        }
        const parts = execForm(rest) ?? shellWords(rest);
        if (parts === null || parts.length < 2) add(`${where}: COPY needs sources and a destination`);
        break;
      }
      case 'RUN': {
        const { flags, rest } = takeFlags(ins.args);
        for (const f of flags) runFlagProblem(f, where, add);
        if (rest.trim() === '') { add(`${where}: RUN needs a command`); break; }
        const r = shellProblems(commandText(rest), where, true, ctx.allowInstallScripts === true);
        r.problems.forEach(add);
        npmCi += r.npmCi;
        break;
      }
      case 'CMD': case 'ENTRYPOINT': {
        if (ins.args.trim() === '') { add(`${where} needs a command`); break; }
        shellProblems(commandText(ins.args), where, false, true).problems.forEach(add);
        break;
      }
      case 'HEALTHCHECK': {
        const { flags, rest } = takeFlags(ins.args);
        for (const f of flags) if (!/^--(?:interval|timeout|start-period|start-interval|retries)=[0-9a-z.]+$/.test(f)) add(`${where}: the flag ${q(f)} is not allowed`);
        if (/^none$/i.test(rest) && flags.length === 0) break;
        const m = /^cmd(?:[ \t]+([\s\S]+))?$/i.exec(rest);
        if (m === null || (m[1] ?? '').trim() === '') { add(`${where} must be NONE or CMD with a command`); break; }
        shellProblems(commandText(m[1] as string), where, false, true).problems.forEach(add);
        break;
      }
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
        const w = shellWords(ins.args);
        if (w === null || w.length !== 1) { add(`${where} needs exactly one user`); (stages[stage] as { users: string[] }).users.push('root'); break; }
        (stages[stage] as { users: string[] }).users.push(w[0] as string);
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
  else if (userIsRoot(user)) add('the last USER is root (or 0, or not shown to be a plain non-root user)');
  if (npmCi === 0) add('there is no npm ci (dependencies are installed with npm ci --ignore-scripts from package-lock.json)');
  return out;
}

const MOUNT_KEYS = new Set(['type', 'target', 'id', 'sharing', 'mode', 'uid', 'gid']);

/** RUN flags: a cache mount, no network or the default, the default sandbox; nothing that pulls an image, a secret or the host in. */
function runFlagProblem(flag: string, where: string, add: (m: string) => void): void {
  const m = /^--([a-z-]+)(?:=(.*))?$/.exec(flag);
  const v = m?.[2] ?? '';
  if (m?.[1] === 'mount') {
    const pairs = v.split(',').map((p) => p.split('='));
    const ok = pairs.every(([k, val]) => MOUNT_KEYS.has(k as string) && val !== undefined && /^[A-Za-z0-9_./-]+$/.test(val)) && pairs.some(([k, val]) => k === 'type' && val === 'cache');
    if (!ok) add(`${where}: only --mount=type=cache (with target, id, sharing, mode, uid, gid) is allowed`);
  } else if (m?.[1] === 'network') { if (v !== 'none' && v !== 'default') add(`${where}: --network=${q(v)} is not allowed`); } else if (m?.[1] === 'security') { if (v !== 'sandbox') add(`${where}: --security=${q(v)} is not allowed`); } else add(`${where}: the flag ${q(flag)} is not allowed`);
}
