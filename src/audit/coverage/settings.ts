// Coverage mapper (see ../coverage.ts for the rules): step and job settings that lower a run: `if:` conditions, soft-fail
// flags and `with:` inputs, the action version (`actionRef`), and the env gate (TOX…, NOX…, SKIP, NPM_CONFIG_DRY_RUN).
import { parseArgv } from '../../engine/argv.js';
import { TRIVY_GRAMMAR } from '../../engine/tool-grammar.js';
import { regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { MAX_FLAG_WORDS, MAX_INPUT_KEYS, MAX_SPELLINGS } from './bounds.js';
import { PRE_COMMIT_ID, type ToolSignature } from './signatures.js';
import { tokenize } from './tokenize.js';
import type { Found, JobEnv, Obj, Reason } from './types.js';

/**
 * Reasons that say the tool may not run at all (not just "can't block"): they make even a need that doesn't block
 * partial. Task 5 fix round 1 adds the pre-commit ones (hook-repo, files, stage) and SKIP; the Plan U final review (I2)
 * adds a TOX… or NOX… variable that picks what tox or nox runs; Plan P Task 3 adds an action this repo can't use, one
 * not set up for the check, egress control missing from some release jobs, a scan target pipegen can't place, a config
 * file or env var that can turn the check off, and an egress step on a runner it can't guard. (Here, not in decide.ts,
 * so the env gate can read it without an import cycle.)
 */
export const MAY_NOT_RUN: ReadonlySet<Reason> = new Set<Reason>(['condition', 'script-condition', 'hook-repo', 'files', 'stage', 'skip', 'ref', 'tox-env', 'nox-env',
  'unavailable', 'needs-inputs', 'some-jobs', 'target', 'config', 'runner', 'never-listed']);

// ---------- if: conditions (review I3) ----------

type Cond = 'none' | 'never' | 'partial';
export interface RepoId { owner: string; repo: string }
/** Conditions that hold on every normal run: always(), success(), !cancelled(). */
const STATUS_RUNS = /^(?:always|success)\(\s*\)$|^!\s*cancelled\(\s*\)$/;
/** A condition that never holds. */
const STATUS_NEVER = /^!\s*always\(\s*\)$/;
const REPO_GUARD = /^github\.repository(_owner)?\s*(==|!=)\s*(?:'([^']*)'|"([^"]*)")$/;

/** Trims spaces and outer parentheses with a loop (no regex backtracking on long runs of parentheses). */
function stripParens(s: string): string {
  let a = 0;
  let b = s.length;
  for (;;) {
    while (a < b && /\s/.test(s[a] as string)) a++;
    while (b > a && /\s/.test(s[b - 1] as string)) b--;
    if (a < b && s[a] === '(' && s[b - 1] === ')') {
      a++;
      b--;
    } else return s.slice(a, b);
  }
}

function atomCond(a: string, self: RepoId): Cond {
  if (a === 'true' || STATUS_RUNS.test(a)) return 'none';
  if (a === 'false' || STATUS_NEVER.test(a)) return 'never';
  const m = REPO_GUARD.exec(a);
  if (m) {
    // A guard naming this repo (or its owner) holds here; one naming another repo never does.
    const want = m[1] === undefined ? `${self.owner}/${self.repo}` : self.owner;
    const same = (m[3] ?? m[4] ?? '').toLowerCase() === want.toLowerCase();
    return same === (m[2] === '==') ? 'none' : 'never';
  }
  return 'partial'; // cancelled(), !success(), failure(), github.event_name == …, anything else
}

/**
 * A job or step `if:`: 'never' drops the run, 'none' ignores the condition, 'partial' means it may not run on every
 * event. `a && b` holds only if both do; `a || b` is treated as 'none' only when every side is, 'never' when every side is.
 */
export function condition(v: unknown, self: RepoId): Cond {
  if (v === undefined || v === null || v === true) return 'none';
  if (v === false || v === 0) return 'never';
  if (typeof v !== 'string' || !regexSafe(v)) return 'partial';
  let s = v.trim();
  if (s.startsWith('${{') && s.endsWith('}}') && s.indexOf('${{', 3) < 0) s = s.slice(3, -2).trim();
  if (s === '') return 'none';
  const ors = s.split('||').map((side) => {
    const ands = side.split('&&').map((x) => atomCond(stripParens(x), self));
    return ands.includes('never') ? 'never' : ands.every((x) => x === 'none') ? 'none' : 'partial';
  });
  return ors.every((x) => x === 'none') ? 'none' : ors.every((x) => x === 'never') ? 'never' : 'partial';
}

// ---------- soft-fail settings (review I1) ----------

/**
 * Fix round 1: an exit code the shell sees as non-zero: 1–255 written plainly. Everything else counts as zero: the
 * tools parse with base prefixes (pflag `ParseInt(s, 0, 64)`, https://github.com/spf13/pflag/blob/master/int.go; the
 * trivy action through cast, `ParseInt(trimDecimal(s), 0, 0)`), so 00, 0x0, +0 and 0o0 are 0, and 256 exits 0.
 */
export const nonZeroExit = (v: string) => /^[1-9][0-9]{0,2}$/.test(v) && Number(v) % 256 !== 0;

/**
 * "--fail" matches --fail and --fail=x; "--exit-code=0" matches --exit-code=0 and --exit-code 0. Fix round 1: a spec
 * whose value is 0 is an exit code, so it matches any value that isn't a plain non-zero one (nonZeroExit).
 */
export function flagGiven(spec: string, words: readonly string[]): boolean {
  const eq = spec.indexOf('=');
  if (eq < 0) return words.some((w) => w === spec || w.startsWith(`${spec}=`));
  const name = spec.slice(0, eq);
  const value = spec.slice(eq + 1);
  if (value === '0') {
    return words.some((w, i) => (w.startsWith(`${name}=`) && !nonZeroExit(w.slice(name.length + 1)))
      || (w === name && i + 1 < words.length && !nonZeroExit(words[i + 1] as string)));
  }
  return words.some((w, i) => w === spec || (w === name && words[i + 1] === value));
}

/**
 * Fix round 1: TypeScript reads option names in any letter case and with one or two dashes
 * (https://github.com/microsoft/TypeScript/blob/main/src/compiler/commandLineParser.ts: names are looked up lowercased,
 * and `-x` and `--x` are the same). A flag word becomes `--` + its lowercased name; other words stay.
 */
const anyCaseFlag = (w: string) => (w.startsWith('-') && w.length > 1 ? `--${w.replace(/^-+/, '').toLowerCase()}` : w);
/** The words and a spec normaliser for a tool: as they are, or any-case for flagsAnyCase tools. */
function flagView(tool: ToolSignature, words: readonly string[]): { ws: readonly string[]; spec: (f: string) => string } {
  return tool.flagsAnyCase === true ? { ws: words.map(anyCaseFlag), spec: anyCaseFlag } : { ws: words, spec: (f) => f };
}

/** Plan P Task 4 (PB4 b): a plain decimal above 0 ("80", "79.5"); "0", "0.0", "-5", "abc" and "" are not. */
const positiveNumber = (v: string) => /^\d{1,6}(\.\d{1,6})?$/.test(v) && Number(v) > 0;
/** jest's --coverageThreshold takes JSON; a number above 0 anywhere in it (depth and size bounded) is a minimum. */
function jsonHoldsPositive(v: string): boolean {
  if (v.length > 4096) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(v);
  } catch {
    return false;
  }
  const stack: unknown[] = [parsed];
  for (let n = 0; stack.length > 0 && n < 1000; n++) {
    const x = stack.pop();
    if (typeof x === 'number') {
      if (Number.isFinite(x) && x > 0) return true;
    } else if (x !== null && typeof x === 'object') stack.push(...Object.values(x as object));
  }
  return false;
}
const THRESHOLD_FLAGS = ['--lines', '--functions', '--branches', '--statements'];
/** Flags of the wrapper tools (c8, nyc, coverage) that take the next word as their value. */
const WRAPPER_VALUE_FLAGS: ReadonlySet<string> = new Set([...THRESHOLD_FLAGS, '--reporter', '-r', '--include', '-n', '--exclude', '-x', '--temp-directory', '--report-dir', '--reports-dir', '--src', '--rcfile', '--data-file', '--cwd', '--branch-limit']);
/**
 * The words before the wrapped command: stops at the first word that is not an option or an option's value. A word
 * after a flag pipegen doesn't know could be its value or the command, so it counts as the command (the rest is not read).
 */
function leadingWords(words: readonly string[]): readonly string[] {
  if (words[0] === 'run') return []; // `coverage run` takes no minimum; what follows is the wrapped command
  let i = words[0] === 'report' ? 1 : 0; // `coverage report` / `c8 report`: the subcommand is not the wrapped command
  while (i < words.length) {
    const w = words[i] as string;
    if (!w.startsWith('-')) break;
    i += !w.includes('=') && WRAPPER_VALUE_FLAGS.has(w) ? 2 : 1;
  }
  return words.slice(0, i);
}
/**
 * Plan P Task 4 (PB4 b): what the command line says about a coverage minimum. 'set': a number above 0 from a minimum
 * flag (or --check-coverage with a threshold flag above 0); 'off': a minimum flag given with 0, an empty object or a value
 * that isn't a number (the flag wins over any config file, so the minimum is off); 'none': nothing about it.
 */
export function minimumState(tool: ToolSignature, all: readonly string[]): 'set' | 'off' | 'none' {
  const words = tool.minimumLeading === true ? leadingWords(all) : all;
  let off = false;
  for (const f of tool.minimumFlags ?? []) {
    const v = lastFlagValue(f, words);
    if (v === undefined) continue;
    if (typeof v === 'string' && (positiveNumber(v) || jsonHoldsPositive(v))) return 'set';
    off = true;
  }
  if ((tool.minimumSwitches ?? []).some((f) => onlyFlagGiven(f, words))) {
    if (THRESHOLD_FLAGS.some((f) => { const v = lastFlagValue(f, words); return typeof v === 'string' && positiveNumber(v); })) return 'set';
  }
  return off ? 'off' : 'none';
}

export function commandReason(tool: ToolSignature, words: readonly string[]): Reason | null {
  const { ws, spec } = flagView(tool, words);
  if ((tool.softFlags ?? []).some((f) => flagGiven(spec(f), ws))) return 'soft';
  if (filteredByFlag(tool, ws, spec)) return 'needs-inputs';
  if (tool.commandFails === 'never') {
    const m = minimumState(tool, ws);
    return m === 'set' ? null : m === 'off' ? 'soft' : 'never';
  }
  // fix round 1: a fail flag set to a false value (--fail-on-violation=false, --fail=false) doesn't make it fail
  if (tool.commandFails === 'flag' && !(tool.failFlags ?? []).some((f) => onlyFlagGiven(spec(f), ws))) return 'no-fail';
  return null;
}

/** A `with:` value as lowercase text, or null when it isn't a scalar. */
function inputText(v: unknown): string | null {
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  return typeof v === 'string' && regexSafe(v) ? v.trim().toLowerCase() : null;
}

/**
 * Inputs a step sets, by lowercase name. GitHub reads input names case-insensitively and keeps the last spelling; pipegen
 * keeps up to MAX_SPELLINGS spellings, and a soft value in any of them counts (a failing value must hold in all of them).
 * A name with more spellings is `crowded` (it counts as soft for a tool that reads it); a step with more than
 * MAX_INPUT_KEYS keys is `unread` past them (every tool the step runs is partial). One pass, appending in place.
 */
export interface Inputs { byName: Map<string, unknown[]>; crowded: Set<string>; unread: boolean }
export function lowerInputs(w: Obj): Inputs {
  const out: Inputs = { byName: new Map(), crowded: new Set(), unread: false };
  const keys = Object.keys(w);
  if (keys.length > MAX_INPUT_KEYS) out.unread = true;
  for (const k of keys.slice(0, MAX_INPUT_KEYS)) {
    const name = k.toLowerCase();
    const all = out.byName.get(name);
    if (all === undefined) out.byName.set(name, [w[k]]);
    else if (all.length < MAX_SPELLINGS) all.push(w[k]);
    else out.crowded.add(name);
  }
  return out;
}

/** Whether one value is a listed value (`*` = any non-empty); an expression counts only when `exprCounts`. */
function valueListed(v: unknown, values: string[], exprCounts: boolean): boolean {
  const s = inputText(v);
  if (s === null) return false;
  if (s.includes('${{')) return exprCounts;
  // fix round 2 (R4): `+` reads the raw value, as trivy does: cast.ToInt doesn't trim, so ' 1' is a parse error, which is 0
  const raw = typeof v === 'string' ? v : String(v);
  return values.includes(s) || (values.includes('*') && s !== '') || (values.includes('+') && nonZeroExit(raw));
}

/** Soft check: some spelling of a listed input has a listed value (an expression counts: errs to "can't block"). */
function softInputGiven(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => (w.byName.get(name.toLowerCase()) ?? []).some((v) => valueListed(v, values, true)));
}

/** Fail check: a listed input is set, and every spelling of it has a listed value (an expression doesn't count). */
function failInputGiven(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => {
    const all = w.byName.get(name.toLowerCase()) ?? [];
    return all.length > 0 && all.every((v) => valueListed(v, values, false));
  });
}

/** Whether some spelling of an input is set (non-empty) to anything but the listed values; an expression counts. */
function inputSetOtherwise(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => (w.byName.get(name.toLowerCase()) ?? []).some((v) => {
    const s = inputText(v);
    return s !== null && s !== '' && (s.includes('${{') || !values.includes(s));
  }));
}

/**
 * Every string value of an input, split into words, worked out once per step's inputs (a step can match several
 * signatures: trivy-action has five), with whether there were more than MAX_FLAG_WORDS of them.
 */
const wordsMemo = new WeakMap<Inputs, Map<string, { words: string[]; capped: boolean }>>();
function inputWordsOf(w: Inputs, name: string): { words: string[]; capped: boolean } {
  let byName = wordsMemo.get(w);
  if (byName === undefined) wordsMemo.set(w, (byName = new Map()));
  let r = byName.get(name);
  if (r === undefined) {
    const all = (w.byName.get(name) ?? []).flatMap((v) => (typeof v === 'string' && regexSafe(v) ? tokenize(v).filter((t) => t.op === null).map((t) => t.w) : []));
    byName.set(name, (r = { words: all.slice(0, MAX_FLAG_WORDS), capped: all.length > MAX_FLAG_WORDS }));
  }
  return r;
}
/** Every string value of an input, split into words (bounded). */
export const inputWords = (w: Inputs, name: string) => inputWordsOf(w, name).words;
/** Plan P Task 3: an input with more words than pipegen reads (a soft flag past them would go unseen). */
export const inputWordsCapped = (w: Inputs, name: string) => inputWordsOf(w, name).capped;

/** Inputs many actions pass straight to the tool's command line; read for the tool's soft flags. */
const ARGS_INPUTS = ['args', 'cmd_options', 'options'];

/** Whether an input the tool is read by (its listed inputs, or `names`) has more spellings than pipegen keeps. */
export function inputsCrowded(tool: ToolSignature, w: Inputs, names: readonly string[]): boolean {
  if (w.crowded.size === 0) return false;
  const listed = [tool.softInputs, tool.softUnless, tool.failInputs, tool.skipInputs, tool.skipUnless, tool.onlyWithInputs, tool.requireInputs?.all, tool.requireInputs?.any]
    .flatMap((spec) => Object.keys(spec ?? {}));
  if (tool.requireInputs?.unset !== undefined) listed.push(...tool.requireInputs.unset);
  if (tool.onlyWithFlagValue?.input !== undefined) listed.push(tool.onlyWithFlagValue.input);
  return [...listed, ...names].some((name) => w.crowded.has(name.toLowerCase()));
}

export function actionReason(tool: ToolSignature, w: Inputs): Reason | null {
  if (inputsCrowded(tool, w, ARGS_INPUTS) || ARGS_INPUTS.some((name) => inputWordsCapped(w, name))) return 'inputs';
  const args = ARGS_INPUTS.flatMap((name) => inputWords(w, name));
  if (softInputGiven(tool.softInputs, w) || inputSetOtherwise(tool.softUnless, w) || (tool.softFlags ?? []).some((f) => flagGiven(f, args))) return 'soft';
  if (filteredByInput(tool, w) || filteredByFlag(tool, args, (f) => f)) return 'needs-inputs';
  if (tool.actionFails === 'never') return 'never';
  if (tool.actionFails === 'input' && !failInputGiven(tool.failInputs, w)) return 'no-fail';
  return null;
}

/**
 * Task 5: the step's inputs mean the action doesn't do this check at all (pypi-publish with a password: no attestation).
 * Plan P Task 3: also when an onlyWithInputs input isn't set to a listed value, or the onlyWithFlagValue input doesn't
 * hold the word (trivy-action `scanners`).
 */
export function actionSkipped(tool: ToolSignature, w: Inputs): boolean {
  if (tool.onlyWithInputs !== undefined) {
    if (Object.keys(tool.onlyWithInputs).some((name) => w.crowded.has(name.toLowerCase()))) return true;
    if (!failInputGiven(tool.onlyWithInputs, w)) return true;
  }
  const rule = tool.onlyWithFlagValue;
  if (rule?.input !== undefined) {
    const name = rule.input.toLowerCase();
    if (w.crowded.has(name)) return true;
    // every spelling must hold the word (GitHub keeps one of them); an empty value is the action's default
    const given = (w.byName.get(name) ?? []).filter((v) => !(v === null || v === undefined || inputText(v) === ''));
    const holds = given.length === 0 ? flagValueAllows(rule, undefined, true) : given.every((v) => flagValueAllows(rule, inputText(v), true));
    if (!holds) return true;
  }
  if (tool.skipInputs === undefined && tool.skipUnless === undefined) return false;
  const names = [tool.skipInputs, tool.skipUnless].flatMap((spec) => Object.keys(spec ?? {}));
  if (names.some((name) => w.crowded.has(name.toLowerCase()))) return true; // can't tell: it doesn't count
  return softInputGiven(tool.skipInputs, w) || inputSetOtherwise(tool.skipUnless, w);
}

/**
 * Plan P Task 3 (ruling PB5): whether the step's inputs meet the signature's requireInputs. `all`: each input set, in
 * every spelling, to a listed value; `any`: at least one such input; `unset`: none of these set to anything but
 * "false". An expression never meets a rule.
 */
export function requiredInputsHeld(tool: ToolSignature, w: Inputs): boolean {
  const r = tool.requireInputs;
  if (r === undefined) return true;
  const holds = (name: string, values: string[]) => {
    const all = w.byName.get(name.toLowerCase()) ?? [];
    return !w.crowded.has(name.toLowerCase()) && all.length > 0 && all.every((v) => valueListed(v, values, false));
  };
  if (r.all !== undefined && !Object.entries(r.all).every(([name, values]) => holds(name, values))) return false;
  if (r.any !== undefined && !Object.entries(r.any).some(([name, values]) => holds(name, values))) return false;
  // ifSet: a set (non-empty) spelling must be a listed value; an expression never is
  if (r.ifSet !== undefined && Object.entries(r.ifSet).some(([name, values]) => w.crowded.has(name.toLowerCase())
    || (w.byName.get(name.toLowerCase()) ?? []).some((v) => {
      const t = inputText(v);
      if (t === null) return v !== null && v !== undefined;
      return t !== '' && !valueListed(v, values, false);
    }))) return false;
  if (r.unset !== undefined && r.unset.some((name) => w.crowded.has(name.toLowerCase())
    || (w.byName.get(name.toLowerCase()) ?? []).some((v) => {
      const t = inputText(v);
      return t === null ? v !== null && v !== undefined : t !== '' && t !== 'false';
    }))) return false;
  return true;
}

/** Pseudo-category prefix for runs of a version known not to do the check (actionRef, Task 5 fix round 1). */
export const OLD_PREFIX = '\u0000old:';
/** Pseudo-category prefix for runs pipegen couldn't follow to the end (more scripts than MAX_SCRIPTS; fix round 3). */
export const UNKNOWN_PREFIX = '\u0000unknown:';
/**
 * Where an action's `uses:` ref stands against the signature's actionRef: 'ok' (it does the check), 'old' (a version
 * known not to), 'unknown' (pipegen can't place it). A signature without actionRef is always 'ok'.
 */
export function refVerdict(tool: ToolSignature, uses: string): 'ok' | 'old' | 'unknown' {
  const rule = tool.actionRef;
  if (rule === undefined) return 'ok';
  const at = uses.indexOf('@');
  if (at < 0) return 'unknown';
  const ref = uses.slice(at + 1);
  if (rule.moving.includes(ref)) return 'ok';
  if (/^[0-9a-f]{40}$/.test(ref)) return rule.shas.includes(ref) ? 'ok' : 'unknown';
  const m = /^(v|release\/v)(\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?$/.exec(ref);
  if (!m || (m[1] === 'release/v' && m[4] !== undefined)) return 'unknown';
  const [x, y] = [Number(m[2]), Number(m[3])];
  const [mx, my] = rule.minVersion;
  if (x < mx || (x === mx && y < my)) return 'old';
  return x === mx ? 'ok' : 'unknown'; // a later major version: not checked upstream, so not counted as covered
}

/** Plan P Task 3 (PS12): a flag value that a CLI reads as off (npm's nopt: false, null, any number equal to 0). */
// fix round 2 (R7): Go's strconv.ParseBool also reads f and F as false
const FALSE_WORDS: ReadonlySet<string> = new Set(['false', 'f', 'null', 'no', 'off', '']);
const readsFalse = (v: string) => FALSE_WORDS.has(v.trim().toLowerCase()) || (v.trim() !== '' && Number(v) === 0);

/**
 * Plan P Task 3 (PS12): an onlyWithFlags spec is given. Matched like flagGiven (`--cov` also matches `--cov=pkg`), but
 * for a spec without a value, a word `--x=v` whose value reads as false never counts.
 */
function onlyFlagGiven(spec: string, words: readonly string[]): boolean {
  if (spec.includes('=')) return flagGiven(spec, words); // the data names the value (pinact's --fix=false)
  return words.some((w) => w === spec || (w.startsWith(`${spec}=`) && !readsFalse(w.slice(spec.length + 1))));
}

/**
 * Plan P Task 3: the value the last `flag` occurrence gives (`--f v` or `--f=v`): undefined when the flag isn't given,
 * null when it has no value word after it.
 */
function lastFlagValue(flag: string, words: readonly string[]): string | null | undefined {
  let out: string | null | undefined;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (w === flag) out = i + 1 < words.length ? (words[i + 1] as string) : null;
    else if (w.startsWith(`${flag}=`)) out = w.slice(flag.length + 1);
  }
  return out;
}

/** Plan P Task 3: whether a value (undefined = not given) passes an onlyWithFlagValue rule. */
function flagValueAllows(rule: NonNullable<ToolSignature['onlyWithFlagValue']>, value: string | null | undefined, complete: boolean): boolean {
  if (value === undefined) return rule.ifGiven === true && complete;
  if (value === null || value.trim() === '' || value.includes('${{') || value.startsWith('-')) return false;
  if (rule.contains === undefined) return true;
  return value.toLowerCase().split(',').some((x) => x.trim() === rule.contains);
}

/**
 * Task 5: a command signature that counts only with (onlyWithFlags) or without (notWithFlags) some flags. Plan P Task 3:
 * and with onlyWithFlagValue; `complete` = every word of the command line was read (an ifGiven rule needs that).
 */
export function flagsAllow(tool: ToolSignature, args: readonly string[], complete = true): boolean {
  const { ws, spec } = flagView(tool, args);
  return (tool.onlyWithFlags === undefined || tool.onlyWithFlags.some((f) => onlyFlagGiven(spec(f), ws)))
    && !(tool.notWithFlags ?? []).some((f) => flagGiven(spec(f), ws))
    && (tool.onlyWithFlagValue?.flag === undefined || flagValueAllows(tool.onlyWithFlagValue, lastFlagValue(spec(tool.onlyWithFlagValue.flag), ws), complete));
}

/** DoD G11 / P50 I2: a partialWithFlagValue value that leaves a needed word out (or can't be read: null, a variable, an expression). */
function filteredValue(rule: NonNullable<ToolSignature['partialWithFlagValue']>, v: string | null): boolean {
  if (v === null || /[$`]/.test(v)) return true;
  const words = new Set(v.toLowerCase().split(',').map((x) => x.trim()));
  return !rule.needsAll.every((x) => words.has(x));
}

/** Every value `flag` is given in `ws` (`--f v`, `--f=v`); null for one without a value word. */
function allFlagValues(flag: string, ws: readonly string[]): (string | null)[] {
  const out: (string | null)[] = [];
  for (let i = 0; i < ws.length; i++) {
    const w = ws[i] as string;
    if (w === flag) out.push(i + 1 < ws.length ? (ws[i + 1] as string) : null);
    else if (w.startsWith(`${flag}=`)) out.push(w.slice(flag.length + 1));
  }
  return out;
}

/**
 * DoD G11 / P50 I2: partialWithFlagValue's flags are given (any time) with a value that filters the check. With
 * `grammar: trivy` the words (after `trivy`: the subcommand first) are read with Trivy's own grammar, so glued
 * `-sVALUE` and `-s=VALUE` count; a command line that grammar can't read counts as filtering.
 */
function filteredByFlag(tool: ToolSignature, ws: readonly string[], spec: (f: string) => string): boolean {
  const rule = tool.partialWithFlagValue;
  if (rule?.flags === undefined) return false;
  if (rule.grammar === 'trivy') {
    const sub = ws.find((w) => !w.startsWith('-'));
    const parsed = parseArgv(ws, TRIVY_GRAMMAR[sub === 'image' || sub === 'i' ? 'image' : 'fs'], 'pflag');
    if (parsed.errors.length > 0) return true;
    const names = new Set(rule.flags.filter((f) => f.startsWith('--')).map((f) => f.slice(2)));
    return parsed.flags.some((f) => names.has(f.name) && filteredValue(rule, f.value === '' ? null : f.value));
  }
  return rule.flags.some((f) => allFlagValues(spec(f), ws).some((v) => filteredValue(rule, v)));
}

/** DoD G11: the action's partialWithFlagValue input is set (any spelling, crowded, or an expression) to a filtering value. */
function filteredByInput(tool: ToolSignature, w: Inputs): boolean {
  const rule = tool.partialWithFlagValue;
  if (rule?.input === undefined) return false;
  const name = rule.input.toLowerCase();
  if (w.crowded.has(name)) return true;
  return (w.byName.get(name) ?? []).some((v) => {
    if (v === null || v === undefined) return false;
    const t = inputText(v);
    return t === null ? true : t !== '' && filteredValue(rule, t);
  });
}

export const foundOf = (tool: ToolSignature, dir: string | null, reason: Reason | null, configOff = false): Found => ({
  categories: tool.categories, by: tool.id, subject: `The ${tool.id} check`, dir, reason,
  ...(reason === 'needs-inputs' && tool.partialWithFlagValue !== undefined ? { partialWhy: tool.partialWithFlagValue.why }
    : tool.partialWhy === undefined ? {} : { partialWhy: tool.partialWhy }),
  ...(tool.softEnv === undefined ? {} : { softEnv: tool.softEnv }),
  ...(tool.configFiles === undefined || configOff ? {} : { configFiles: tool.configFiles }),
});

/** Fix round 1 (P8): a command line that turns the tool's config file loading off (`trivy --config ''`). */
export function configTurnedOff(tool: ToolSignature, args: readonly string[]): boolean {
  const flag = tool.configFlag;
  if (flag === undefined) return false;
  return lastFlagValue(flag, args) === '';
}

// ---------- env gate (Task 5) ----------

/**
 * Task 5: environment variables that change what a run does, seen anywhere in the job (the workflow's, the job's or a
 * step's `env:` keys, any letter case, or any step's run text, where `echo X=… >> $GITHUB_ENV` would set one): TOX… and
 * NOX… pick envs or sessions (tox 4 reads TOX_<option>; TOXENV; NOXSESSION), SKIP skips pre-commit hooks
 * (https://pre-commit.com/#temporarily-disabling-hooks). An action that sets one through GITHUB_ENV isn't seen.
 */
export interface EnvGate { tox: boolean; nox: boolean; skip: boolean; npm: boolean; env: JobEnv }
const NO_ENV: JobEnv = { all: false, names: new Set(), files: new Set() };
export const NO_GATE: EnvGate = { tox: false, nox: false, skip: false, npm: false, env: NO_ENV };
export const ALL_GATE: EnvGate = { tox: true, nox: true, skip: true, npm: true, env: { all: true, names: new Set(), files: new Set() } };
/**
 * Fix round 2 (ruling P9): a job with a step pipegen can't see into (an action from the owner's own account, a
 * `docker://` step, a local action that isn't composite) may set any variable through GITHUB_ENV: every softEnv name and
 * SKIP count as set.
 */
export const OPAQUE_GATE: EnvGate = { tox: false, nox: false, skip: true, npm: false, env: { all: true, names: new Set(), files: new Set() } };
const emptyEnv = (e: JobEnv) => !e.all && e.names.size === 0 && e.files.size === 0;
const orEnv = (a: JobEnv, b: JobEnv): JobEnv =>
  (emptyEnv(b) ? a : emptyEnv(a) ? b : { all: a.all || b.all, names: new Set([...a.names, ...b.names]), files: new Set([...a.files, ...b.files]) });
export const orGate = (a: EnvGate, b: EnvGate): EnvGate =>
  ({ tox: a.tox || b.tox, nox: a.nox || b.nox, skip: a.skip || b.skip, npm: a.npm || b.npm, env: orEnv(a.env, b.env) });
/**
 * Fix round 1 (P8): `softNames` (every signature's softEnv) are looked for too: as an `env:` key (any letter case) or
 * in the run text. Fix round 2 (N1b, N1c): the bare name, as SKIP is, so a GITHUB_ENV heredoc (`NAME<<EOF`) or a
 * quote-split `"NAME"=x` counts. `configNames` (every signature's configFiles) named in the run text, in any letter case,
 * mean an earlier step may write that file (N2c, N2d).
 */
export function gateOf(texts: readonly string[], envs: readonly unknown[], base: EnvGate = NO_GATE, softNames: readonly string[] = [],
  configNames: readonly string[] = []): EnvGate {
  // an `env:` given as one expression could set anything
  if (envs.some((e) => e !== undefined && e !== null && (typeof e !== 'object' || Array.isArray(e)))) return ALL_GATE;
  const keys = envs.flatMap((e) => Object.keys(asObj(e)).slice(0, MAX_INPUT_KEYS)).map((k) => k.toUpperCase());
  const inText = (needle: string) => texts.some((t) => t.includes(needle));
  const names = softNames.filter((n) => keys.includes(n) || inText(n));
  const lower = configNames.length === 0 ? [] : texts.map((t) => t.toLowerCase());
  const files = configNames.filter((f) => lower.some((t) => t.includes(f.toLowerCase())));
  return {
    tox: base.tox || keys.some((k) => k.startsWith('TOX')) || inText('TOX'),
    nox: base.nox || keys.some((k) => k.startsWith('NOX')) || inText('NOX'),
    skip: base.skip || keys.includes('SKIP') || inText('SKIP'),
    // npm reads npm_config_* in any letter case
    npm: base.npm || keys.includes('NPM_CONFIG_DRY_RUN') || texts.some((t) => t.toLowerCase().includes('npm_config_dry_run')),
    env: names.length === 0 && files.length === 0 ? base.env : orEnv(base.env, { all: false, names: new Set(names), files: new Set(files) }),
  };
}

/** Fix round 1 (P8): the softEnv name this job sets for a run, '*' when an `env:` expression could set any, or null. */
export function softEnvSet(softEnv: readonly string[] | undefined, env: JobEnv | undefined): string | null {
  if (softEnv === undefined || env === undefined) return null;
  if (env.all) return '*';
  return softEnv.find((n) => env.names.has(n)) ?? null;
}
/** Fix round 2 (N2c, N2d): a config file the tool loads that the job's run text names (an earlier step may write it). */
export function configFileNamed(configFiles: readonly string[] | undefined, env: JobEnv | undefined): string | null {
  if (configFiles === undefined || env === undefined) return null;
  return configFiles.find((f) => env.files.has(f)) ?? null;
}
/** pipegen's own why for a run whose softEnv name or config file is set (the name and file come from pipegen's data). */
export const configWhy = (subject: string, what: string) => (what === '*'
  ? `${subject} runs, but an env: given as an expression could set a variable that turns it off, and pipegen can't tell.`
  : `${subject} runs, but ${what} is set here, which can turn its check or its failure off, and pipegen doesn't follow it.`);
/**
 * Applies the job's env gate. A tox / nox run whose envs or sessions a TOX… / NOX… variable may pick is kept as
 * partial (Plan U final review I2: pipegen can't tell what it runs, so it is never covered, and never missing either);
 * that reason comes first, since it says the tests may not run at all. An npm publish NPM_CONFIG_DRY_RUN makes a dry
 * run is dropped (it publishes nothing, so no attestation). With SKIP set (fix round 1, I3), `pre-commit run` itself is
 * partial (some hooks don't run) and its hooks' tools aren't carried over.
 */
export const gated = (found: Found[], g: EnvGate): Found[] => found
  .filter((f) => !(f.envGate === 'npm' && g.npm))
  .map((f) => {
    if (f.envGate === 'tox' && g.tox) return { ...f, reason: 'tox-env' as const };
    if (f.envGate === 'nox' && g.nox) return { ...f, reason: 'nox-env' as const };
    if (g.skip && f.by === PRE_COMMIT_ID) return { ...f, hookRun: false, reason: f.reason ?? 'skip' };
    // fix round 1 (P8): a softEnv name set in the job; a CI pre-commit run keeps the job env for the hooks it carries
    const set = softEnvSet(f.softEnv, g.env);
    const file = configFileNamed(f.configFiles, g.env);
    const what = set ?? (file === null ? null : `a ${file} file written in this job`);
    if (what !== null && (f.reason === null || !MAY_NOT_RUN.has(f.reason))) return { ...f, reason: 'config' as const, partialWhy: configWhy(f.subject, what) };
    if (f.hookRun === true && !emptyEnv(g.env)) return { ...f, jobEnv: g.env };
    return f;
  });
