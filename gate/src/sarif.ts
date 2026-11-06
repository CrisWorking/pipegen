// Plan C Task C1a: SARIF parsing for the gate (preflight-scan B8, S7, S8, S10 uri part). See parse-common.ts for the
// hostile-input rules. The one rule that matters most: a result that reads "clean" when the scan covered less is a false
// pass. So `toolError` is set (and no finding is returned) when any of these holds:
//   - a `toolExecutionNotifications` entry exists, of any level and any id (the allowlist of benign ids starts empty and
//     grows only from a fixture plus a code-reviewed change): that is how semgrep says it timed out on a file while
//     exiting 0 with `executionSuccessful: true`;
//   - an error-level `toolConfigurationNotifications` entry exists;
//   - `executionSuccessful` is false (see SARIF_TOOLS for the two tools whose own output makes that mean something else);
//   - `runs` is empty, or a run has no `results` list;
//   - the version is not 2.1.0, or the driver name is not the one expected for the tool;
//   - a cap is hit (raw size, results per run, runs), or a field the parser reads has the wrong type (also how deep
//     nesting in a read field fails: a read field is never walked, it must be what the tool writes).
// What SARIF cannot tell the gate: gitleaks and betterleaks write no `invocations` at all, so a scan that covered less
// (gitleaks 8.30.1 logs a git error as non-fatal, scans 1 of 3 commits, exits 0) reads as a clean SARIF. That is a
// property of those tools, recorded in the C1a report, not something this parser can detect.
import type { Severity } from '../../src/types.js';
import { safeText } from '../../src/util/safe-text.js';
import {
  cutText, fail, getOwn, guarded, isObj, lineOf, limitsFrom, MAX_ID_CHARS, MAX_MESSAGE_CHARS, MAX_RAW_BYTES, MAX_RESULTS_PER_RUN, MAX_RUNS, MAX_URI_CHARS,
  optList, optObj, optStr, optStrList, readJson, shown, uriIdOf,
  type Obj, type ParseLimits, type ParsedFinding, type ParseResult,
} from './parse-common.js';

export { MAX_RAW_BYTES, MAX_RESULTS_PER_RUN, MAX_RUNS };
export type { ParseLimits, ParsedFinding, ParseResult };

export interface ParseOptions {
  /** GITHUB_WORKSPACE: the absolute path the tools scanned, stripped from a uri. Without it an absolute uri is unmapped. */
  workspace?: string;
  /** Redundant for the secrets tools (the table says it), and never able to turn the secret handling off. */
  secretsTool?: boolean;
  /**
   * C1c, a staged scan: the only uris that map, exactly as written (no prefix stripped, no `.` folded, no decoding): the neutral names
   * of the stage step. Any other uri is unmapped (and the staged scrub makes that a tool error).
   */
  exactNames?: RegExp;
  /**
   * C9, the commit-range scan (a `git` mode SARIF): every result must carry the commit it was found in, `partialFingerprints.commitSha`, 40 hex
   * digits (a result without one is a tool error); it is kept as `commit`. Nothing else of the tool's fingerprints is ever read.
   */
  commits?: true;
  limits?: Partial<ParseLimits>;
}

/** Where a tool's severity comes from (S8). */
export type SeveritySource = 'secret' | 'security-severity' | 'level' | 'issue-severity' | 'tag-word';
export interface SarifToolInfo {
  /** The exact `tool.driver.name` the reviewed binary writes. */
  readonly driver: string;
  readonly severity: SeveritySource;
  readonly secrets: boolean;
  /** 'none': the finding is not about a repository file (an image layer, a web target): `file` is never set. */
  readonly fileMode: 'repo' | 'none';
  /**
   * What `executionSuccessful: false` means for this tool (measured on the pinned binaries, test/fixtures/sarif):
   * 'error' (default): the tool says it did not complete. 'findings': kube-linter writes false exactly when it found
   * something, so false with results is fine and false without any is an error. 'ignored': nuclei writes false on every
   * run it reports; its notifications still count.
   */
  readonly executionSuccessfulFalse: 'error' | 'findings' | 'ignored';
  /**
   * Rule ids the tool writes, as ordinary results, for a target it could not read (measured on the pinned binaries, C1a
   * review): any such result makes the whole file a tool error, because the tool also skipped its other checks on that
   * target. Left out they would read as findings, with one fingerprint every run, so a base that already has an unreadable
   * file would hide what a PR adds to it.
   */
  readonly errorRules: readonly string[];
  /** trivy writes security-severity 0.0 for a severity it does not know (UNKNOWN): no value, so high. Not for licences (S9: info, a human decides). */
  readonly zeroScoreIsUnknown: boolean;
  /**
   * G15a round 3 (PF-3): the exact uri the tool writes for a finding about no file (Scorecard v5.6.0 writes `no file associated with this
   * alert` under %SRCROOT% at line 1; measured in the real fixtures test/fixtures/sarif/scorecard-*.sarif). Such a result has no file and no
   * line, and it is not an unmapped uri. Only this exact string, under %SRCROOT% or no base: any other uri maps as usual.
   */
  readonly noFileUri?: string;
  /** A note put on every result of this tool (what its SARIF cannot prove). */
  readonly note?: string;
  /**
   * How the tool writes `artifactLocation.uri` (C1b fix round 1, review C2): 'raw' = the path as is, a `%` is a literal
   * character (measured: betterleaks 1.9.0 and gitleaks 8.30.1 with a file named `src/%61pp.js`); 'percent' = RFC 3986
   * percent-encoded, decoded once; 'unmeasured' = not measured yet, so a uri with a `%` is unmapped (fail closed: a
   * keyless secret in an unmapped file stays new). Decoding a raw path would file a new file's finding under another file.
   */
  readonly uriEncoding: UriEncoding;
  /**
   * Where the finding's message comes from: 'result' (the result's own message.text, masked later) or 'rule-template' (the
   * rule's uninterpolated `fullDescription.text`: semgrep puts metavariable values, even the value of a secret, into the
   * result message, and writes the template with `$VALUE` in the rules list).
   */
  readonly messageFrom: 'result' | 'rule-template';
}
export type UriEncoding = 'raw' | 'percent' | 'unmeasured';
const tool = (driver: string, severity: SeveritySource, over: Partial<SarifToolInfo> = {}): SarifToolInfo =>
  ({ driver, severity, secrets: false, fileMode: 'repo', executionSuccessfulFalse: 'error', errorRules: [], zeroScoreIsUnknown: false, uriEncoding: 'unmeasured', messageFrom: 'result', ...over });

/**
 * The reviewed tools that write SARIF and that the gate reads, by reviewed-list id. A null-prototype table: an id from
 * a file or an argument can never find an inherited property. scorecard-action is here for its scrub only: it is reported
 * weekly and never gated (a scheduled category, never on the gate's job list).
 */
export const SARIF_TOOLS: Readonly<Record<string, SarifToolInfo>> = Object.freeze(Object.assign(Object.create(null) as Record<string, SarifToolInfo>, {
  betterleaks: tool('betterleaks', 'secret', { secrets: true, uriEncoding: 'raw' }),
  gitleaks: tool('gitleaks', 'secret', { secrets: true, uriEncoding: 'raw', note: 'completeness not provable (gitleaks)' }),
  semgrep: tool('Semgrep OSS', 'level', { messageFrom: 'rule-template' }),
  'osv-scanner': tool('osv-scanner', 'security-severity'),
  'trivy-config': tool('Trivy', 'security-severity', { zeroScoreIsUnknown: true }),
  'trivy-image': tool('Trivy', 'security-severity', { fileMode: 'none', zeroScoreIsUnknown: true }),
  'trivy-licence': tool('Trivy', 'security-severity'),
  hadolint: tool('Hadolint', 'level', { errorRules: ['DL1000'] }),
  'kube-linter': tool('kube-linter', 'level', { executionSuccessfulFalse: 'findings', errorRules: ['failed-to-load-object'] }),
  nuclei: tool('Nuclei', 'security-severity', { fileMode: 'none', executionSuccessfulFalse: 'ignored' }),
  ruff: tool('ruff', 'level', { errorRules: ['invalid-syntax', 'E999', 'E902', 'panic'] }),
  gosec: tool('gosec', 'tag-word'),
  bandit: tool('Bandit', 'issue-severity'),
  // G15a round 3 (PF-3): reported weekly, never gated (a scheduled category: never on the gate's job list); read only to scrub it
  'scorecard-action': tool('Scorecard', 'security-severity', { noFileUri: 'no file associated with this alert' }),
}));

// ---------- E9 (carry E5-R3): fix information of an image finding ----------

/** trivy's SARIF message for a vulnerability (pkg/report/sarif.go, test/fixtures/sarif/trivy-image.sarif), anchored at the start. */
const TRIVY_VULN_MESSAGE = /^Package: [^\n]*\nInstalled Version: [^\n]*\nVulnerability [^\n]*\nSeverity: [^\n]*\nFixed Version: ([^\n]*)(?:\n|$)/;
/**
 * Whether trivy names a fixed version for a vulnerability finding: true for a non-blank `Fixed Version:`, false for a blank one,
 * undefined (unknown) for a message in any other shape or with the line more than once (a package name with its own line breaks
 * can not pose as the field). Only a report: the gate decides nothing on it.
 */
export function trivyFixable(message: string): boolean | undefined {
  if (typeof message !== 'string' || message.split('\nFixed Version: ').length !== 2) return undefined;
  const m = TRIVY_VULN_MESSAGE.exec(message);
  return m === null ? undefined : (m[1] as string).trim() !== '';
}

// ---------- uri ----------

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
const CONTROL = /[\u0000-\u001f\u007f]/;

function decodeOnce(s: string): string | undefined {
  try {
    return decodeURIComponent(s);
  } catch {
    return undefined;
  }
}

/**
 * A scanner's uri as a repository-relative POSIX path, or undefined ("unmapped") when it cannot be made one. Strips
 * `file://` (empty authority only), the workspace and `/src/` prefixes (the whole prefix up to a `/`), folds `//` and `.`
 * segments, and reads a `%` by the tool's `encoding` (SarifToolInfo.uriEncoding): 'raw' leaves it alone, 'percent' decodes
 * once, and 'unmeasured' (also the default, when no encoding is given) refuses any uri that holds one. Unmapped, never a
 * path: any `..` segment, an absolute path, a backslash, a control character, another scheme or a drive letter, a host, an
 * a U+FFFD (the lossy mark of a name that is not valid UTF-8), an invalid or double-encoded percent sequence (percent only, so `%2e%2e` in any case and under any encoding layer cannot get
 * through), an empty result, or a uri longer than 4096.
 */
export function normaliseUri(uri: unknown, opts: { workspace?: string; encoding?: UriEncoding } = {}): string | undefined {
  if (typeof uri !== 'string' || uri.trim() === '' || uri.length > MAX_URI_CHARS) return undefined;
  const encoding = opts.encoding ?? 'unmeasured';
  // U+FFFD is what Go's JSON writes for every byte that is not valid UTF-8: the name of a file with such a byte is the same string as the
  // name of another, valid file (review R1-C2). No tool can say which bytes it stands for.
  if (uri.includes('\uFFFD')) return undefined;
  let p = uri;
  if (/^file:\/\//i.test(p)) {
    p = p.slice(7);
    if (!p.startsWith('/')) return undefined;   // file://host/...: a host, not this machine
  } else if (SCHEME.test(p)) {
    return undefined;
  }
  const ws = opts.workspace === undefined ? '' : opts.workspace.replace(/\/+$/, '');
  if (ws.startsWith('/') && p.startsWith(`${ws}/`)) p = p.slice(ws.length + 1);
  else if (p.startsWith('/src/')) p = p.slice(5);
  else if (p.startsWith('/zap/wrk/')) p = p.slice(9);
  let once = p;
  if (encoding === 'unmeasured') {
    if (p.includes('%')) return undefined;
  } else if (encoding === 'percent') {
    const decoded = decodeOnce(p);
    if (decoded === undefined || decoded.includes('\uFFFD')) return undefined;
    once = decoded;
    const twice = decodeOnce(once);
    if (twice !== once) return undefined;           // double-encoded (or an unreadable second layer)
  }
  if (CONTROL.test(once) || once.includes('\\') || once.startsWith('/') || SCHEME.test(once)) return undefined;
  const kept: string[] = [];
  for (const segment of once.split('/')) {
    if (segment === '..') return undefined;
    if (segment !== '' && segment !== '.') kept.push(segment);
  }
  return kept.length === 0 ? undefined : kept.join('/');
}

// ---------- severity ----------

const LEVELS: Readonly<Record<string, Severity>> = Object.freeze(Object.assign(Object.create(null) as Record<string, Severity>, { error: 'high', warning: 'medium', note: 'low', none: 'info' }));
const WORDS: Readonly<Record<string, Severity>> = Object.freeze(Object.assign(Object.create(null) as Record<string, Severity>, { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }));
const RANK: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** `security-severity` is a CVSS-style number from 0 to 10 (a string or a number): >= 9 critical, >= 7 high, >= 4 medium, > 0 low, 0 info. */
function fromScore(v: unknown): Severity | undefined {
  const n = typeof v === 'number' ? v : typeof v === 'string' && /^\s*\d+(\.\d+)?\s*$/.test(v) ? Number(v) : NaN;
  if (!Number.isFinite(n) || n < 0 || n > 10) return undefined;
  return n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : n > 0 ? 'low' : 'info';
}
function fromLevel(v: string | undefined): Severity | undefined {
  return v === undefined ? undefined : LEVELS[v];
}

// ---------- the reader ----------

const MAX_TAGS = 256;
/** C2 fix round 1 (review-C2 I3): at most this many advisory ids and aliases per finding; more is a tool error. */
export const MAX_ADVISORY_IDS = 64;
const SAME = (a: Rule, b: Rule): boolean => a.level === b.level && String(a.score) === String(b.score) && a.tags.join('\0') === b.tags.join('\0') && a.template === b.template && a.aliases.join('\0') === b.aliases.join('\0');

interface Rule { id: string; level?: string; score?: unknown; tags: string[]; secret: boolean; word?: Severity; template?: string; aliases: string[] }

/**
 * The advisory ids and aliases a rule or a result carries (C2 fix round 1, review-C2 I3): SARIF's `deprecatedIds` on a rule
 * (osv-scanner lists a group's aliases there and shows one of them as the rule id) and an `aliases` list in the properties. A list
 * of the wrong type, an id over the id cap, or more than MAX_ADVISORY_IDS is a tool error, never a silent drop: the gate blocks on
 * a MAL- id wherever it stands.
 */
function readAliases(lists: readonly (string[] | undefined)[], where: string): string[] {
  const out: string[] = [];
  for (const list of lists) {
    for (const id of list ?? []) {
      if (id.length > MAX_ID_CHARS) fail(`${where}: an advisory id is longer than ${MAX_ID_CHARS}`);
      if (!out.includes(id)) out.push(id);
      if (out.length > MAX_ADVISORY_IDS) fail(`${where}: more than ${MAX_ADVISORY_IDS} advisory ids and aliases`);
    }
  }
  return out;
}

/** The tag facts of a rule or a result, computed once: a secret tag, and the highest severity word (gosec). */
function tagFacts(tags: readonly string[]): { secret: boolean; word?: Severity } {
  let secret = false;
  let word: Severity | undefined;
  for (const t of tags) {
    if (t.toLowerCase() === 'secret') secret = true;
    const w = WORDS[t];
    if (w !== undefined && (word === undefined || RANK.indexOf(w) < RANK.indexOf(word))) word = w;
  }
  return { secret, word };
}
function readTags(o: Obj, where: string): string[] {
  const tags = optStrList(o, 'tags', where) ?? [];
  if (tags.length > MAX_TAGS) fail(`${where}: more than ${MAX_TAGS} tags`);
  return tags;
}

function readRules(driver: Obj, where: string): { list: Rule[]; byId: Map<string, Rule> } {
  const list: Rule[] = [];
  const byId = new Map<string, Rule>();
  const raw = optList(driver, 'rules', where);
  for (const [i, r] of (raw ?? []).entries()) {
    const at = `${where} rule ${i}`;
    if (!isObj(r)) fail(`${at} is not an object`);
    const id = getOwn(r, 'id');
    if (typeof id !== 'string') fail(`${at} has no id`);
    const level = optStr(optObj(r, 'defaultConfiguration', at) ?? {}, 'level', `${at} defaultConfiguration`);
    const props = optObj(r, 'properties', at) ?? {};
    const score = getOwn(props, 'security-severity');
    if (score !== undefined && typeof score !== 'string' && typeof score !== 'number') fail(`${at}: security-severity is not a string or a number`);
    const tags = readTags(props, `${at} properties`);
    const template = optStr(optObj(r, 'fullDescription', at) ?? {}, 'text', `${at} fullDescription`);
    const aliases = readAliases([optStrList(r, 'deprecatedIds', at), optStrList(props, 'aliases', `${at} properties`)], at);
    const rule: Rule = { id, level, score, tags, ...tagFacts(tags), ...(template === undefined ? {} : { template }), aliases };
    list.push(rule);
    const same = byId.get(id);
    if (same === undefined) byId.set(id, rule);
    else if (!SAME(same, rule)) fail(`${at}: two rules have the same id (${shown(id)}) and different severity data`);
  }
  return { list, byId };
}

function readInvocations(run: Obj, info: SarifToolInfo, where: string): { executionFailed: boolean } {
  let executionFailed = false;
  for (const [i, inv] of (optList(run, 'invocations', where) ?? []).entries()) {
    const at = `${where} invocation ${i}`;
    if (!isObj(inv)) fail(`${at} is not an object`);
    const exec = getOwn(inv, 'executionSuccessful');
    if (typeof exec !== 'boolean') fail(`${at}: executionSuccessful is missing or not a boolean (SARIF requires it)`);
    if (exec === false && info.executionSuccessfulFalse !== 'ignored') executionFailed = true;
    const notes = optList(inv, 'toolExecutionNotifications', at);
    if (notes !== undefined && notes.length > 0) {
      const first = notes[0];
      const descriptor = isObj(first) ? getOwn(first, 'descriptor') : undefined;
      const id = isObj(descriptor) ? getOwn(descriptor, 'id') : undefined;
      fail(`${at}: the tool reported ${notes.length} execution notification(s) (toolExecutionNotifications), first: ${typeof id === 'string' ? safeText(id, 40) : 'no id'}; the scan may have covered less than it should`);
    }
    for (const [j, n] of (optList(inv, 'toolConfigurationNotifications', at) ?? []).entries()) {
      if (!isObj(n)) fail(`${at}: configuration notification ${j} is not an object`);
      const level = getOwn(n, 'level');
      if (level !== undefined && (typeof level !== 'string' || !['none', 'note', 'warning', 'error'].includes(level))) fail(`${at}: configuration notification ${j} has a level that is not a SARIF level`);
      if (level === 'error') fail(`${at}: toolConfigurationNotifications has an error-level entry`);
    }
  }
  return { executionFailed };
}

/** The message of a finding of a 'rule-template' tool: the rule's uninterpolated text, or a fixed sentence. The result's own message is never read for it. */
function templateMessage(rule: Rule | undefined, ruleId: string): string {
  return rule?.template !== undefined && rule.template !== '' ? cutText(rule.template, MAX_MESSAGE_CHARS) : cutText(`finding of rule ${ruleId}`, MAX_MESSAGE_CHARS);
}

function secretMessage(ruleId: string): string {
  return cutText(`secret detected by rule ${ruleId}`);
}

/** The folder (relative to the workspace, '' for the workspace itself) a uriBaseId names, or undefined when it is outside the workspace or unknown. */
function baseFolder(baseId: string, run: Obj, workspace: string | undefined, encoding: UriEncoding, where: string): string | undefined {
  const table = optObj(run, 'originalUriBaseIds', where);
  const entry = table === undefined ? undefined : getOwn(table, baseId);
  if (entry === undefined) return baseId === '%SRCROOT%' ? '' : undefined;   // semgrep's base names no uri: the root of what was scanned
  if (!isObj(entry)) fail(`${where}: originalUriBaseIds entry ${shown(baseId)} is not an object`);
  const uri = optStr(entry, 'uri', `${where} originalUriBaseIds entry`);
  const ws = workspace === undefined ? '' : workspace.replace(/\/+$/, '');
  if (uri === undefined || !ws.startsWith('/') || !/^file:\/\/\//i.test(uri)) return undefined;
  const path = uri.slice(7).replace(/\/+$/, '');
  if (path === ws) return '';
  return path.startsWith(`${ws}/`) ? normaliseUri(path.slice(ws.length + 1), { encoding }) : undefined;
}

/** A result's uri as a workspace-relative path, with its uriBaseId (when it has one and the uri is relative) resolved inside the workspace. */
function mapUri(uri: string, baseId: string | undefined, run: Obj, bases: Map<string, string | undefined>, workspace: string | undefined, encoding: UriEncoding, where: string): string | undefined {
  const own = normaliseUri(uri, { workspace, encoding });
  if (baseId === undefined || uri.startsWith('/') || SCHEME.test(uri)) return own;
  if (!bases.has(baseId)) bases.set(baseId, baseFolder(baseId, run, workspace, encoding, where));
  const base = bases.get(baseId);
  if (base === undefined || own === undefined) return undefined;
  return base === '' ? own : `${base}/${own}`;
}

function readRun(run: unknown, index: number, toolId: string, info: SarifToolInfo, opts: ParseOptions, limits: ParseLimits, notes: string[]): ParsedFinding[] {
  const where = `run ${index}`;
  if (!isObj(run)) fail(`${where} is not an object`);
  const driver = getOwn(optObj(run, 'tool', where) ?? {}, 'driver');
  const name = isObj(driver) ? getOwn(driver, 'name') : undefined;
  if (!isObj(driver) || name !== info.driver) fail(`${where}: the driver name is ${shown(name)}, not the "${info.driver}" expected for ${toolId}`);

  const { executionFailed } = readInvocations(run, info, where);
  const results = getOwn(run, 'results');
  if (!Array.isArray(results)) fail(`${where} has no results list`);
  if (results.length > limits.maxResults) fail(`${where} has more than ${limits.maxResults} results`);
  if (executionFailed && !(info.executionSuccessfulFalse === 'findings' && results.length > 0)) fail(`${where}: executionSuccessful is false`);
  const { list: rules, byId } = readRules(driver, where);

  const secretsTool = info.secrets || opts.secretsTool === true;
  const findings: ParsedFinding[] = [];
  let noSeverity = 0;
  let unmapped = 0;
  const unreadable = new Map<string, number>();   // errorRules seen, by id
  const bases = new Map<string, string | undefined>();   // uriBaseId -> the folder under the workspace it names ('' = the workspace), undefined = outside or unknown
  for (const [i, r] of results.entries()) {
    const at = `${where} result ${i}`;
    if (!isObj(r)) fail(`${at} is not an object`);
    const ref = optObj(r, 'rule', at);
    const rawId = getOwn(r, 'ruleId') ?? (ref === undefined ? undefined : getOwn(ref, 'id'));
    if (typeof rawId !== 'string' || rawId === '') fail(`${at} has no ruleId`);
    if (rawId.length > MAX_ID_CHARS) fail(`${at}: the ruleId is longer than ${MAX_ID_CHARS}`);
    const idx = getOwn(r, 'ruleIndex');
    if (idx !== undefined && typeof idx !== 'number') fail(`${at}: ruleIndex is not a number`);
    const indexed = typeof idx === 'number' && Number.isInteger(idx) && idx >= 0 && idx < rules.length && rules[idx].id === rawId ? rules[idx] : undefined;
    const rule = indexed ?? byId.get(rawId);   // a ruleIndex that points at another rule is not trusted

    const msg = optObj(r, 'message', at);
    const text = msg === undefined ? undefined : optStr(msg, 'text', `${at} message`);
    const level = optStr(r, 'level', at);
    const props = optObj(r, 'properties', at) ?? {};
    const resultTags = readTags(props, `${at} properties`);
    const score = getOwn(props, 'security-severity');
    if (score !== undefined && typeof score !== 'string' && typeof score !== 'number') fail(`${at}: security-severity is not a string or a number`);
    const issue = getOwn(props, 'issue_severity');
    if (issue !== undefined && typeof issue !== 'string') fail(`${at}: issue_severity is not a string`);
    const resultAliases = optStrList(props, 'aliases', `${at} properties`);
    let commit: string | undefined;
    if (opts.commits === true) {
      const pf = optObj(r, 'partialFingerprints', at);
      const c = pf === undefined ? undefined : getOwn(pf, 'commitSha');
      if (typeof c !== 'string' || !/^[0-9a-f]{40}$/.test(c)) fail(`${at} has no commit (partialFingerprints.commitSha of 40 hex digits), so its place in the commit range is not known`);
      commit = c;
    }

    // location: the first one, read along fixed paths
    let uri: string | undefined;
    let baseId: string | undefined;
    let line: number | undefined;
    let startColumn: number | undefined;
    let endLine: number | undefined;
    let endColumn: number | undefined;
    const locations = optList(r, 'locations', at);
    if (locations !== undefined && locations.length > 0) {
      const loc = locations[0];
      if (!isObj(loc)) fail(`${at}: the first location is not an object`);
      const physical = optObj(loc, 'physicalLocation', `${at} location`);
      if (physical !== undefined) {
        const artifact = optObj(physical, 'artifactLocation', `${at} location`) ?? {};
        uri = optStr(artifact, 'uri', `${at} artifactLocation`);
        baseId = optStr(artifact, 'uriBaseId', `${at} artifactLocation`);
        const region = optObj(physical, 'region', `${at} location`);
        if (region !== undefined) {
          line = lineOf(getOwn(region, 'startLine'), `${at} region`);
          startColumn = lineOf(getOwn(region, 'startColumn'), `${at} region`);
          endLine = lineOf(getOwn(region, 'endLine'), `${at} region`);
          endColumn = lineOf(getOwn(region, 'endColumn'), `${at} region`);
        }
      }
    }
    let file: string | undefined;
    let uriUnmapped = false;
    const noFile = uri !== undefined && info.noFileUri !== undefined && uri === info.noFileUri && (baseId === undefined || baseId === '%SRCROOT%');
    if (noFile) { line = undefined; startColumn = undefined; endLine = undefined; endColumn = undefined; }
    if (uri !== undefined && !noFile) {
      if (info.fileMode === 'none') {
        uriUnmapped = true;
      } else {
        // a secrets tool's uri with "!" is an archive member path (outer.zip!in/s.txt) or a made-up one: the bytes the scanner matched are not a
        // workspace file's, so it is unmapped (fail closed); archives are not opened at all by the reviewed command (--max-archive-depth 0), this is the belt
        file = opts.exactNames !== undefined ? (baseId === undefined && opts.exactNames.test(uri) ? uri : undefined)
          : info.secrets && uri.includes('!') ? undefined : mapUri(uri, baseId, run, bases, opts.workspace, info.uriEncoding, at);
        uriUnmapped = file === undefined;
        if (uriUnmapped) unmapped++;
      }
    }

    if (info.errorRules.includes(rawId)) unreadable.set(rawId, (unreadable.get(rawId) ?? 0) + 1);
    const fromResult = tagFacts(resultTags);
    const isSecret = secretsTool || rule?.secret === true || fromResult.secret;
    let severity: Severity | undefined;
    if (isSecret) {
      severity = 'critical';
    } else {
      switch (info.severity) {
        case 'security-severity':
          severity = fromScore(score !== undefined ? score : rule?.score);
          if (severity === 'info' && info.zeroScoreIsUnknown) severity = undefined;   // trivy's 0.0 is UNKNOWN: no value
          break;
        case 'level': severity = fromLevel(level ?? rule?.level); break;
        case 'issue-severity': severity = typeof issue === 'string' ? WORDS[issue] : undefined; break;
        case 'tag-word': severity = RANK.find((s) => s === rule?.word || s === fromResult.word); break;
        case 'secret': severity = 'critical'; break;
      }
    }
    if (severity === undefined) {
      severity = 'high';
      noSeverity++;
    }
    // every advisory id and alias of a non-secret finding, its own rule id first (a secrets tool's rules carry none worth keeping)
    const advisoryIds = isSecret ? [] : readAliases([[rawId], rule?.aliases, resultAliases], at);
    findings.push({
      tool: toolId,
      ruleId: isSecret ? `secret:${rawId}` : rawId,
      severity,
      file,
      line,
      message: isSecret ? secretMessage(rawId) : info.messageFrom === 'rule-template' ? templateMessage(rule, rawId) : cutText(text ?? '', MAX_MESSAGE_CHARS),
      uriUnmapped,
      secret: isSecret,
      ...(startColumn === undefined ? {} : { startColumn }),
      ...(endLine === undefined ? {} : { endLine }),
      ...(endColumn === undefined ? {} : { endColumn }),
      ...(uriUnmapped && uri !== undefined ? { uriId: uriIdOf(uri) } : {}),
      ...(advisoryIds.length > 1 ? { advisoryIds } : {}),
      ...(commit === undefined ? {} : { commit }),
    });
  }
  if (unreadable.size > 0) {
    const total = [...unreadable.values()].reduce((a, b) => a + b, 0);
    fail(`${where}: ${toolId} could not read ${total} target(s) (${[...unreadable.keys()].map((k) => safeText(k, 40)).join(', ')}); the scan covered less than it should`);
  }
  if (noSeverity > 0) notes.push(`${where}: ${noSeverity} finding(s) had no severity value at ${toolId}'s own source and are counted as high`);
  if (unmapped > 0) notes.push(`${where}: ${unmapped} finding(s) had a path that could not be mapped to a repository file`);
  return findings;
}

/**
 * nuclei writes no SARIF file when nothing matched (exit 0, measured). The render step then writes this marked empty
 * result, and only then (never over a file nuclei wrote). It is not a nuclei run: its driver name is not `Nuclei`, and
 * the parser accepts exactly this shape, for nuclei only, as "nothing reported", never as proof of coverage.
 */
export const NOTHING_REPORTED_NUCLEI = 'nothing reported (nuclei run with no result)';
export const SYNTHESIZED_NUCLEI = Object.freeze({ driver: 'pipegen-empty-nuclei', mark: 'nuclei-no-file' });
function isSynthesizedNuclei(json: Obj): boolean {
  const keys = (o: Obj): string => Object.keys(o).sort().join(',');
  const runs = getOwn(json, 'runs');
  if (getOwn(json, 'version') !== '2.1.0' || keys(json) !== 'runs,version' || !Array.isArray(runs) || runs.length !== 1) return false;
  const run = runs[0] as unknown;
  if (!isObj(run) || keys(run) !== 'properties,results,tool') return false;
  const results = getOwn(run, 'results');
  const props = getOwn(run, 'properties');
  const tool = getOwn(run, 'tool');
  const driver = isObj(tool) && keys(tool) === 'driver' ? getOwn(tool, 'driver') : undefined;
  return Array.isArray(results) && results.length === 0 && isObj(props) && keys(props) === 'pipegenSynthesized' && getOwn(props, 'pipegenSynthesized') === SYNTHESIZED_NUCLEI.mark
    && isObj(driver) && keys(driver) === 'name' && getOwn(driver, 'name') === SYNTHESIZED_NUCLEI.driver;
}

/** Reads one parsed SARIF document written by the reviewed tool `toolId` (a SARIF_TOOLS key). Never throws. */
export function parseSarif(json: unknown, toolId: string, opts: ParseOptions = {}): ParseResult {
  return guarded((notes) => {
    const info = Object.hasOwn(SARIF_TOOLS, toolId) ? SARIF_TOOLS[toolId] : undefined;
    if (info === undefined) fail(`${JSON.stringify(safeText(toolId, 60))} is not a tool whose SARIF the gate reads`);
    if (!isObj(json)) fail('the result is not a SARIF document (the top level is not an object)');
    if (toolId === 'nuclei' && isSynthesizedNuclei(json)) {
      notes.push('nothing reported (synthesized empty result)');
      return [];
    }
    const version = getOwn(json, 'version');
    if (version !== '2.1.0') fail(`the SARIF version is ${shown(version, 20)}, not 2.1.0`);
    const runs = getOwn(json, 'runs');
    if (!Array.isArray(runs)) fail('the result has no runs list');
    if (runs.length === 0) fail('the result has no runs');
    const limits = limitsFrom(opts.limits);
    if (runs.length > limits.maxRuns) fail(`the result has more than ${limits.maxRuns} runs`);
    const findings = runs.flatMap((run, i) => readRun(run, i, toolId, info, opts, limits, notes));
    // nuclei writes no file when nothing matched (so a file with no result is not what it writes: the app under test could have written it): accepted, but only as "nothing reported", never as coverage
    if (toolId === 'nuclei' && findings.length === 0) notes.push(NOTHING_REPORTED_NUCLEI);
    // a staged scan (exactNames) proves its coverage by the canaries, so gitleaks' completeness note is only for an unstaged run (C1c fix round 1, m3)
    if (info.note !== undefined && opts.exactNames === undefined) notes.push(info.note);
    return findings;
  });
}

/** Reads the bytes of a result file: size cap, strict UTF-8, one JSON.parse, then parseSarif. Never throws. */
export function parseSarifText(input: string | Uint8Array, toolId: string, opts: ParseOptions = {}): ParseResult {
  const read = readJson(input, limitsFrom(opts.limits).maxBytes);
  return read.toolError === undefined ? parseSarif(read.json, toolId, opts) : { findings: [], toolError: read.toolError, notes: [] };
}
