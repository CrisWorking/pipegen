// v0.2 Plan G (G11-2): the licence scan's result, Trivy's own JSON (`trivy fs --scanners license --format json --list-all-pkgs`, the
// pinned v0.76.0; tool-flags.ts TRIVY_LICENCE_RESULT). Trivy's SARIF lists only the licences it found, so a package whose lockfile entry
// has no licence was never seen. This reader gives the same findings the SARIF gave (one per licence of a package, rule
// `<package>:<licence>`, Trivy's severity) and one more per package with no licence data (rule `<package>:no-licence-data`, severity
// info): the licences rule of the gate makes an info finding a warning a person must look at ("counted as Unknown"), never a pass in
// silence. Same hostile-input rules as sarif.ts (parse-common.ts): own properties only, size cap, strict UTF-8, one JSON.parse, every
// text cut, a path that is not a repository path is unmapped. Shape (measured on the pinned trivy, test/fixtures/trivy-licence-json):
// { SchemaVersion: 2, ArtifactType: "filesystem", Results?: [{ Target, Class: "lang-pkgs", Packages: [{ Name, Licenses?: [string] }] },
//   { Target, Class: "license", Licenses: [{ Severity, Category, PkgName, FilePath, Name }] }] }.
import {
  cutText, fail, getOwn, guarded, isObj, limitsFrom, MAX_ID_CHARS, MAX_MESSAGE_CHARS, readJson, shown, uriIdOf,
  type Obj, type ParseLimits, type ParsedFinding, type ParseResult,
} from './parse-common.js';
import { normaliseUri } from './sarif.js';
import type { Severity } from '../../src/types.js';
import { TRIVY_LICENCE_RESULT } from '../../src/engine/tool-flags.js';
import { safeText } from '../../src/util/safe-text.js';

/** The tool whose raw result this reader reads (the scrub routes it here). */
export const TRIVY_LICENCE_TOOL: string = TRIVY_LICENCE_RESULT.tool;
/** The rule id of a package with no licence data ends with this (`<package>:no-licence-data`). */
export const NO_LICENCE_RULE_SUFFIX = ':no-licence-data';
/** Trivy's severities of a licence (pkg/licensing: forbidden CRITICAL, restricted HIGH, reciprocal MEDIUM, notice and others LOW, unknown UNKNOWN). */
const SEVERITY: Readonly<Record<string, Severity>> = Object.freeze(Object.assign(Object.create(null) as Record<string, Severity>, {
  CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', UNKNOWN: 'info',
}));
const PACKAGE_CLASSES: ReadonlySet<string> = new Set(['lang-pkgs', 'os-pkgs']);
const LICENCE_CLASSES: ReadonlySet<string> = new Set(['license', 'license-file']);
const MAX_RESULTS = 100_000;

export interface TrivyLicenceOptions { limits?: Partial<ParseLimits> }

function str(o: Obj, key: string, where: string, required: boolean): string {
  const v = getOwn(o, key);
  if (v === undefined && !required) return '';
  if (typeof v !== 'string' || (required && v === '')) fail(`${where}: ${key} is not a non-empty string (${shown(v)})`);
  if (v.length > MAX_ID_CHARS) fail(`${where}: ${key} is longer than ${MAX_ID_CHARS}`);
  return v;
}
function list(o: Obj, key: string, where: string): unknown[] {
  const v = getOwn(o, key);
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) fail(`${where}: ${key} is not a list`);
  return v;
}

/** Reads one parsed Trivy licence JSON report. Never throws. */
export function parseTrivyLicenceJson(json: unknown, toolId: string, opts: TrivyLicenceOptions = {}): ParseResult {
  return guarded((notes) => {
    if (toolId !== TRIVY_LICENCE_TOOL) fail(`${JSON.stringify(safeText(toolId, 60))} is not a tool whose Trivy licence JSON the gate reads`);
    if (!isObj(json)) fail('the result is not a Trivy JSON report (the top level is not an object)');
    if (getOwn(json, 'SchemaVersion') !== 2) fail(`the report's SchemaVersion is ${shown(getOwn(json, 'SchemaVersion'))}, not 2 (the pinned trivy's)`);
    if (getOwn(json, 'ArtifactType') !== 'filesystem') fail('the report is not of a filesystem scan (ArtifactType)');
    const limits = limitsFrom(opts.limits);
    const results = list(json, 'Results', 'the report');
    if (results.length > MAX_RESULTS) fail(`the report has more than ${MAX_RESULTS} results`);
    const findings: ParsedFinding[] = [];
    let unknownSeverity = 0;
    let unmapped = 0;
    const push = (ruleId: string, severity: Severity, path: string, message: string): void => {
      if (findings.length >= limits.maxResults) fail(`the report has more than ${limits.maxResults} findings`);
      const file = normaliseUri(path, { encoding: 'raw' });
      if (file === undefined) unmapped++;
      findings.push({
        tool: toolId, ruleId: cutText(ruleId, MAX_ID_CHARS), severity, file, line: 1, message: cutText(message, MAX_MESSAGE_CHARS),
        uriUnmapped: file === undefined, secret: false, ...(file === undefined ? { uriId: uriIdOf(path) } : {}),
      });
    };
    for (const [n, r] of results.entries()) {
      const at = `result ${n}`;
      if (!isObj(r)) fail(`${at} is not an object`);
      const target = str(r, 'Target', at, true);
      const cls = str(r, 'Class', at, true);
      if (PACKAGE_CLASSES.has(cls)) {
        for (const [k, p] of list(r, 'Packages', at).entries()) {
          const where = `${at} package ${k}`;
          if (!isObj(p)) fail(`${where} is not an object`);
          const name = str(p, 'Name', where, true);
          const lics = list(p, 'Licenses', where);
          for (const l of lics) if (typeof l !== 'string') fail(`${where}: Licenses holds a value that is not a string`);
          if (lics.length > 0) continue;   // its licences are in the result of class license
          push(`${name}${NO_LICENCE_RULE_SUFFIX}`, 'info', target,
            `Artifact: ${target}\nPkgName: ${name}\n No licence data: the package names no licence, so it counts as Unknown (a person checks it)`);
        }
      } else if (LICENCE_CLASSES.has(cls)) {
        for (const [k, l] of list(r, 'Licenses', at).entries()) {
          const where = `${at} licence ${k}`;
          if (!isObj(l)) fail(`${where} is not an object`);
          const name = str(l, 'Name', where, true);
          const pkg = str(l, 'PkgName', where, false);
          const path = str(l, 'FilePath', where, false) || target;
          const category = str(l, 'Category', where, false);
          const word = str(l, 'Severity', where, false);
          let severity = Object.hasOwn(SEVERITY, word) ? SEVERITY[word] : undefined;
          if (severity === undefined) { severity = 'high'; unknownSeverity++; }
          push(pkg === '' ? name : `${pkg}:${name}`, severity, path,
            `Artifact: ${target}\nLicense ${name}\nPkgName: ${pkg}\n Classification: ${category}\n Path: ${path}`);
        }
      } else {
        fail(`${at} is of class ${shown(cls)}, which the licence reader does not know`);
      }
    }
    if (unknownSeverity > 0) notes.push(`${unknownSeverity} licence(s) had an unknown severity and are counted as high`);
    if (unmapped > 0) notes.push(`${unmapped} finding(s) had a path that could not be mapped to a repository file`);
    return findings;
  });
}

/** Reads the bytes of the report: size cap, strict UTF-8, one JSON.parse, then parseTrivyLicenceJson. Never throws. */
export function parseTrivyLicenceJsonText(input: string | Uint8Array, toolId: string, opts: TrivyLicenceOptions = {}): ParseResult {
  const read = readJson(input, limitsFrom(opts.limits).maxBytes);
  return read.toolError === undefined ? parseTrivyLicenceJson(read.json, toolId, opts) : { findings: [], toolError: read.toolError, notes: [] };
}
