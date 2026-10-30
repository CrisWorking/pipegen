// Plan C Task C1b: the gate's scrub mode: the step between a scanner and its upload, and the last thing that touches raw scanner
// output. It reads the raw result (never through a link, never over the cap), parses it with the hostile-input parsers of C1a,
// gives every finding its fingerprint (fingerprint.ts), and REBUILDS the result from allowlisted fields only. Nothing of the raw
// file is copied, so nothing it holds that is not on the list can survive:
//
// SARIF out (one run): version, runs[0].tool.driver.name (from the reviewed table, not from the file),
//   runs[0].properties {pipegenScrubbed, pipegenTool, pipegenKeyId (only when a key made a fingerprint), pipegenNotes},
//   per result: ruleId, level (from the severity), message.text, locations[0].physicalLocation {artifactLocation.uri (a
//   workspace-relative path, only when mapped), region {startLine, endLine}}, partialFingerprints.pipegenFingerprint,
//   properties {pipegenSeverity, pipegenSecret, pipegenUnmapped, pipegenFpBy}.
// ZAP out: pipegenScrubbed, tool, notes, alerts[] {pluginid, name, severity, fingerprint, unmapped, method, path}.
// Never written: snippet, contextRegion, evidence, attack, param, markdown, the tool's own fingerprints, any other property,
// artifacts, rules, invocations, the raw uri of an unmapped finding, and the message of a secrets tool (the parser already
// replaced it by "secret detected by rule <id>"). The message of any other tool has the known secret shapes masked, and the
// messages of the rules that quote the matched string (bandit B105 to B107) are withheld.
//
// A path or url path that looks like a secret (redact-core: secretShapedName) is withheld: no uri or path is written and the finding is
// marked unmapped and `pathWithheld`; its fingerprint is still the one computed over the real path. It is not masked in place: a masked
// path would look mapped, and C2's added-line lookup would miss it (review m1).
//
// The key (`fp-key`): `mask` (core.setSecret in C5) is called with it before anything else. It is never in an output, an error
// text or a log (this module logs nothing); a last check refuses an output that holds the key or the bytes of a secret region.
// "Fork" is read from the event payload only (S11), never from an input.
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readSync, unlinkSync, writeSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';
import { secretShapedName } from '../../src/ai/redact-core.js';
import type { Severity } from '../../src/types.js';
import { safeText } from '../../src/util/safe-text.js';
import { CONTENT_FORMS, fingerprintAll, isQuotingFinding, keyId, keyProblem, maskSecretShapes, POSITION_FORMS, type FpBy, type FingerprintedFinding } from './fingerprint.js';
import { fail, getOwn, isObj, MAX_RAW_BYTES, ReadError, readJson, type ParsedFinding, type ParseResult } from './parse-common.js';
import { SARIF_TOOLS, parseSarifText } from './sarif.js';
import { applyStage, readStage, StageError, STAGED_NAME_RE, type Stage, type StagedFindings } from './stage.js';
import { ZAP_TOOL, parseZapJsonText } from './zap.js';

export type ScrubFormat = 'sarif' | 'zap-json';
export interface ScrubOptions {
  /** The reviewed-list id of the tool that wrote the result (C0a validated it). */
  tool: string;
  format: ScrubFormat;
  /** PIPEGEN_FP_KEY, from the `fp-key` input. */
  fpKey?: string;
  /** The text of the event payload (GITHUB_EVENT_PATH): the only source of "this is a fork". */
  eventText?: string;
  /** GITHUB_WORKSPACE exactly as the scanners saw it (also the base of the secret regions). */
  workspace?: string;
  /** core.setSecret: called with a non-empty key first. */
  mask?: (secret: string) => void;
  /** The raw size cap in bytes (default 64 MiB). */
  maxBytes?: number;
  /**
   * C1c: the stage folder of a secrets scan (`$RUNNER_TEMP/pipegen-stage/<artifact>`, gate/src/stage.ts). The scanner ran on its
   * neutral names; the scrub checks the folder against its manifest, proves coverage by the canaries and maps every finding back to
   * the original path and line, reading each region from the staged copy. Only for the secrets tools.
   */
  stage?: string;
}
export type ScrubOutcome =
  | { status: 'ok'; bytes: Buffer; sha256: string; findings: number; keyId?: string; notes: string[]; fpBy: Record<FpBy, number> }
  | { status: 'tool-error'; error: string };

const MAX_ERROR_CHARS = 300;
const MAX_NOTES = 50;
const MAX_NOTE_CHARS = 300;
const MAX_FIELD = 1024;
const sha256 = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const LEVEL: Readonly<Record<Severity, string>> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SEVERITIES: readonly string[] = ['critical', 'high', 'medium', 'low', 'info'];
const FP_BYS: readonly string[] = [...CONTENT_FORMS, ...POSITION_FORMS];

/** The pull request comes from another repository: `pull_request.head.repo.id` and `repository.id` are both numbers and differ. Anything else (no payload, a push, odd shapes) is "not a fork": the stricter rule. */
export function forkFromEvent(eventText: string | undefined): boolean {
  if (eventText === undefined || eventText === '') return false;
  let json: unknown;
  try {
    json = JSON.parse(eventText);
  } catch {
    return false;
  }
  if (!isObj(json)) return false;
  const pr = getOwn(json, 'pull_request');
  const head = isObj(pr) ? getOwn(pr, 'head') : undefined;
  const headRepo = isObj(head) ? getOwn(head, 'repo') : undefined;
  const repo = getOwn(json, 'repository');
  const headId = isObj(headRepo) ? getOwn(headRepo, 'id') : undefined;
  const id = isObj(repo) ? getOwn(repo, 'id') : undefined;
  return typeof headId === 'number' && typeof id === 'number' && headId !== id;
}

const clip = (s: string, max = MAX_FIELD): string => (s.length <= max ? s : s.slice(0, max));
/** A text for an output field: shapes of secrets masked, cut. Never the key (see `withoutKey`). */
const outText = (s: string): string => clip(maskSecretShapes(s));
/** A rule id as written: the `secret:` prefix the parser adds is kept (the masking core would read `secret:<rule>` as an assignment), the rest masked. */
const SECRET_PREFIX = 'sec' + 'ret:';
const ruleIdText = (id: string): string => (id.startsWith(SECRET_PREFIX) ? SECRET_PREFIX + outText(id.slice(SECRET_PREFIX.length)) : outText(id));
const withoutKey = (text: string, key: string): string => (key === '' ? text : text.split(key).join('[key]'));
/** An error text: cut, the key taken out, then everything secret-shaped masked (a text may echo a string of the tool, such as its driver name). */
const toolError = (error: string, key: string): ScrubOutcome => ({ status: 'tool-error', error: clip(maskSecretShapes(withoutKey(safeText(error, MAX_ERROR_CHARS), key)), MAX_ERROR_CHARS) });

/** What the scrub writes for a message: the rules that quote the matched string are withheld, the rest has secret shapes masked. */
function writtenMessage(f: ParsedFinding): string {
  if (isQuotingFinding(f)) return `${f.ruleId}: message withheld (the tool quotes the string it matched)`;
  return outText(f.message);
}

/** True for a path that must not be written (see the header); the answer is kept per path. */
function withholder(): (file: string | undefined) => boolean {
  const known = new Map<string, boolean>();
  return (file) => {
    if (file === undefined) return false;
    let v = known.get(file);
    if (v === undefined) { v = secretShapedName(file); known.set(file, v); }
    return v;
  };
}

function sarifOut(tool: string, findings: readonly FingerprintedFinding[], notes: readonly string[], key: string | undefined): string {
  const info = SARIF_TOOLS[tool];
  const withheld = withholder();
  const results = findings.map((f) => {
    const hide = withheld(f.file);
    const loc: Record<string, unknown> = {};
    if (f.file !== undefined && !hide) loc.artifactLocation = { uri: clip(f.file, 4096) };
    if (f.line !== undefined) loc.region = { startLine: f.line, endLine: f.endLine ?? f.line };
    return {
      ruleId: ruleIdText(f.ruleId),
      level: LEVEL[f.severity],
      message: { text: writtenMessage(f) },
      ...(Object.keys(loc).length === 0 ? {} : { locations: [{ physicalLocation: loc }] }),
      partialFingerprints: { pipegenFingerprint: f.fingerprint },
      properties: {
        pipegenSeverity: f.severity, pipegenSecret: f.secret, pipegenUnmapped: f.uriUnmapped || hide, pipegenPathWithheld: hide, pipegenFpBy: f.fpBy,
        // C1c fix round 1: the display form of a staged name with no lossless text (withheld like a path when it looks like a secret)
        ...(f.file === undefined && f.displayPath !== undefined && !withheld(f.displayPath) ? { pipegenDisplayPath: clip(f.displayPath, 4096) } : {}),
      },
    };
  });
  return JSON.stringify({
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: info.driver } },
      properties: { pipegenScrubbed: true, pipegenTool: tool, ...(key === undefined ? {} : { pipegenKeyId: keyId(key) }), pipegenNotes: [...notes] },
      results,
    }],
  });
}

function zapOut(findings: readonly FingerprintedFinding[], notes: readonly string[]): string {
  const withheld = withholder();
  return JSON.stringify({
    pipegenScrubbed: true,
    tool: ZAP_TOOL,
    notes: [...notes],
    alerts: findings.map((f) => {
      const hide = withheld(f.file);
      return {
        pluginid: outText(f.ruleId), name: outText(f.message), severity: f.severity, fingerprint: f.fingerprint, unmapped: f.uriUnmapped || hide, pathWithheld: hide,
        ...(f.method === undefined ? {} : { method: f.method }), ...(f.file === undefined || hide ? {} : { path: clip(f.file, 4096) }),
      };
    }),
  });
}

/** One note per reason the line form was used, with its count, so a result says that and why its fingerprints are weaker. */
function lineNotes(findings: readonly FingerprintedFinding[]): string[] {
  const counts = new Map<string, number>();
  for (const f of findings) if (f.fpBy === 'line' && f.fpNote !== undefined) counts.set(f.fpNote, (counts.get(f.fpNote) ?? 0) + 1);
  return [...counts].map(([note, n]) => `${n} secret finding(s), ${note}`);
}

/**
 * Scrubs the bytes of one raw result. Pure apart from the region reads of fingerprint.ts (read-only, bounded, no links).
 * Never throws; anything it cannot do is a tool error, and a tool error never counts as clean.
 */
export function scrubBytes(raw: Uint8Array, opts: ScrubOptions): ScrubOutcome {
  const key = typeof opts.fpKey === 'string' ? opts.fpKey : '';
  try {
    if (key !== '') opts.mask?.(key);   // first: before anything can fail, log or throw
  } catch {
    return toolError('the key could not be masked in the logs, so the scrub did not run', key);
  }
  try {
    const maxBytes = opts.maxBytes ?? MAX_RAW_BYTES;
    let parsed: ParseResult;
    let secretsTool = false;
    let stage: Stage | undefined;
    if (opts.format === 'sarif') {
      if (!Object.hasOwn(SARIF_TOOLS, opts.tool)) return toolError(`${JSON.stringify(safeText(opts.tool, 60))} is not a tool whose SARIF the gate reads`, key);
      secretsTool = SARIF_TOOLS[opts.tool].secrets;
      if (opts.stage !== undefined) {
        if (!secretsTool) return toolError('a stage folder is only for the secrets tools', key);
        try {
          stage = readStage(opts.stage);
        } catch (e) {
          return toolError(e instanceof StageError ? e.message : 'the stage folder could not be read', key);
        }
      }
      parsed = stage === undefined
        ? parseSarifText(raw, opts.tool, { workspace: opts.workspace, limits: { maxBytes } })
        : parseSarifText(raw, opts.tool, { workspace: stage.files, exactNames: STAGED_NAME_RE, limits: { maxBytes } });
    } else if (opts.format === 'zap-json') {
      if (opts.stage !== undefined) return toolError('a stage folder is only for the secrets tools', key);
      if (opts.tool !== ZAP_TOOL) return toolError(`${JSON.stringify(safeText(opts.tool, 60))} is not a tool whose ZAP report the gate reads`, key);
      parsed = parseZapJsonText(raw, opts.tool, { limits: { maxBytes } });
    } else {
      return toolError('the result format is not one the gate reads', key);
    }
    if (parsed.toolError !== undefined) return toolError(parsed.toolError, key);
    let staged: StagedFindings | undefined;
    if (stage !== undefined) {
      try {
        staged = applyStage(parsed.findings, stage, opts.tool);
      } catch (e) {
        return toolError(e instanceof StageError ? e.message : 'the staged findings could not be mapped back', key);
      }
      parsed = { findings: staged.findings, notes: [...parsed.notes, ...staged.notes] };
    }

    const needsKey = secretsTool || parsed.findings.some((f) => f.secret || isQuotingFinding(f));
    const problem = keyProblem(key, forkFromEvent(opts.eventText), needsKey);
    if (problem !== undefined) return toolError(problem, key);
    const usedKey = needsKey && key !== '' ? key : undefined;

    const regions: Buffer[] = [];
    const findings = fingerprintAll(parsed.findings, {
      fpKey: usedKey, workspace: opts.workspace, onRegion: (b) => { regions.push(b); },
      ...(staged === undefined ? {} : { regionOf: staged.regionOf, fileHashOf: staged.fileHashOf }),
    });
    const notes = [...parsed.notes, ...lineNotes(findings)].slice(0, MAX_NOTES).map((n) => clip(maskSecretShapes(n), MAX_NOTE_CHARS));
    const bytes = Buffer.from(opts.format === 'sarif' ? sarifOut(opts.tool, findings, notes, usedKey) : zapOut(findings, notes), 'utf8');

    // the last check: nothing secret may have reached an allowlisted field (a file name, a rule id)
    // as written and as JSON writes it (a quote, a backslash or a newline in the text is escaped in the file)
    const written = bytes.toString('utf8');
    const holds = (text: string): boolean => bytes.includes(text) || written.includes(JSON.stringify(text).slice(1, -1));
    if (usedKey !== undefined && holds(usedKey)) return toolError('the output would hold the key, so it was not written', key);
    for (const region of regions) {
      if (region.length >= 8 && (bytes.includes(region) || written.includes(JSON.stringify(region.toString('utf8')).slice(1, -1)))) return toolError('the output would hold the text of a secret region, so it was not written', key);
    }
    const fpBy: Record<FpBy, number> = { hash: 0, region: 0, quoted: 0, file: 0, line: 0, nokey: 0, 'quoted-nokey': 0 };
    for (const f of findings) fpBy[f.fpBy]++;
    return { status: 'ok', bytes, sha256: sha256(bytes), findings: findings.length, ...(usedKey === undefined ? {} : { keyId: keyId(usedKey) }), notes, fpBy };
  } catch {
    return toolError('the scrub failed unexpectedly', key);
  }
}

// ---------- reading a scrubbed result back (C2 and C5 read what the scrub wrote) ----------

export interface ScrubbedFinding {
  tool: string; ruleId: string; severity: Severity; file?: string; line?: number; endLine?: number; message: string; fingerprint: string;
  secret: boolean; fpBy: FpBy; uriUnmapped: boolean;
  /** The path looked like a secret and was not written (`file` is then absent and `uriUnmapped` is true). */
  pathWithheld: boolean;
  /** C1c fix round 1: for a staged file whose name has no lossless text, a display form of its bytes (people only; never a match key). */
  displayPath?: string;
  method?: string;
}
export interface ScrubbedResult { findings: ScrubbedFinding[]; keyId?: string; notes: string[]; toolError?: string }

const str = (o: Record<string, unknown>, k: string, where: string): string => {
  const v = getOwn(o, k);
  if (typeof v !== 'string') fail(`${where}: ${k} is not a string`);
  return v;
};
const bool = (o: Record<string, unknown>, k: string, where: string): boolean => {
  const v = getOwn(o, k);
  if (typeof v !== 'boolean') fail(`${where}: ${k} is not a boolean`);
  return v;
};
/** A boolean that may be absent (then false): files written before the field existed. */
const optBool = (o: Record<string, unknown>, k: string, where: string): boolean => {
  const v = getOwn(o, k);
  if (v === undefined) return false;
  if (typeof v !== 'boolean') fail(`${where}: ${k} is not a boolean`);
  return v;
};
const lineNo = (v: unknown, where: string): number | undefined => {
  if (v === undefined) return undefined;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1) fail(`${where}: a line is not a whole number`);
  return v;
};
function readNotes(v: unknown, where: string): string[] {
  if (!Array.isArray(v)) fail(`${where}: notes is not a list`);
  return v.map((n) => { if (typeof n !== 'string') fail(`${where}: a note is not a string`); return n; });
}

/** Reads a file the scrub wrote (strictly: any other shape is a tool error). The fingerprints and severities are the scrub's own; nothing is recomputed. */
export function readScrubbed(input: string | Uint8Array, format: ScrubFormat, maxBytes = MAX_RAW_BYTES): ScrubbedResult {
  const read = readJson(input, maxBytes);
  if (read.toolError !== undefined) return { findings: [], notes: [], toolError: read.toolError };
  try {
    const doc = read.json;
    if (!isObj(doc)) fail('the scrubbed result is not an object');
    if (format === 'sarif') {
      if (getOwn(doc, 'version') !== '2.1.0') fail('the scrubbed result is not SARIF 2.1.0');
      const runs = getOwn(doc, 'runs');
      if (!Array.isArray(runs) || runs.length !== 1 || !isObj(runs[0])) fail('the scrubbed result has not exactly one run');
      const run = runs[0];
      const props = getOwn(run, 'properties');
      if (!isObj(props) || getOwn(props, 'pipegenScrubbed') !== true) fail('the result was not written by the scrub');
      const tool = str(props, 'pipegenTool', 'properties');
      const id = getOwn(props, 'pipegenKeyId');
      if (id !== undefined && (typeof id !== 'string' || !/^[0-9a-f]{16}$/.test(id))) fail('the key id is not 16 hex characters');
      const results = getOwn(run, 'results');
      if (!Array.isArray(results)) fail('the scrubbed result has no results list');
      const findings = results.map((r, i): ScrubbedFinding => {
        const at = `result ${i}`;
        if (!isObj(r)) fail(`${at} is not an object`);
        const p = getOwn(r, 'properties');
        const fp = getOwn(r, 'partialFingerprints');
        const msg = getOwn(r, 'message');
        if (!isObj(p) || !isObj(fp) || !isObj(msg)) fail(`${at} is missing a part`);
        const severity = str(p, 'pipegenSeverity', at);
        const fpBy = str(p, 'pipegenFpBy', at);
        if (!SEVERITIES.includes(severity) || !FP_BYS.includes(fpBy)) fail(`${at}: an unknown severity or fingerprint form`);
        const fingerprint = str(fp, 'pipegenFingerprint', at);
        if (!/^(?:secret:|secret-nokey:|quoted:|quoted-nokey:)?[0-9a-f]{64}$/.test(fingerprint)) fail(`${at}: the fingerprint is not a hash`);
        let file: string | undefined;
        let line: number | undefined;
        let endLine: number | undefined;
        const locs = getOwn(r, 'locations');
        if (locs !== undefined) {
          const phys = Array.isArray(locs) && isObj(locs[0]) ? getOwn(locs[0], 'physicalLocation') : undefined;
          if (!isObj(phys)) fail(`${at}: the location is not readable`);
          const art = getOwn(phys, 'artifactLocation');
          if (art !== undefined) file = isObj(art) ? str(art, 'uri', at) : fail(`${at}: the artifact location is not an object`);
          const region = getOwn(phys, 'region');
          if (region !== undefined) {
            if (!isObj(region)) fail(`${at}: the region is not an object`);
            line = lineNo(getOwn(region, 'startLine'), at);
            endLine = lineNo(getOwn(region, 'endLine'), at);
          }
        }
        return {
          tool, ruleId: str(r, 'ruleId', at), severity: severity as Severity, ...(file === undefined ? {} : { file }), ...(line === undefined ? {} : { line }), ...(endLine === undefined ? {} : { endLine }),
          message: str(msg, 'text', at), fingerprint, secret: bool(p, 'pipegenSecret', at), fpBy: fpBy as FpBy, uriUnmapped: bool(p, 'pipegenUnmapped', at), pathWithheld: optBool(p, 'pipegenPathWithheld', at),
          ...(getOwn(p, 'pipegenDisplayPath') === undefined ? {} : { displayPath: str(p, 'pipegenDisplayPath', at) }),
        };
      });
      return { findings, ...(typeof id === 'string' ? { keyId: id } : {}), notes: readNotes(getOwn(props, 'pipegenNotes'), 'properties') };
    }
    if (getOwn(doc, 'pipegenScrubbed') !== true || getOwn(doc, 'tool') !== ZAP_TOOL) fail('the result was not written by the scrub for ZAP');
    const alerts = getOwn(doc, 'alerts');
    if (!Array.isArray(alerts)) fail('the scrubbed ZAP result has no alerts list');
    const findings = alerts.map((a, i): ScrubbedFinding => {
      const at = `alert ${i}`;
      if (!isObj(a)) fail(`${at} is not an object`);
      const severity = str(a, 'severity', at);
      const fingerprint = str(a, 'fingerprint', at);
      if (!SEVERITIES.includes(severity) || !/^[0-9a-f]{64}$/.test(fingerprint)) fail(`${at}: an unknown severity or a fingerprint that is not a hash`);
      const method = getOwn(a, 'method');
      const path = getOwn(a, 'path');
      if ((method !== undefined && typeof method !== 'string') || (path !== undefined && typeof path !== 'string')) fail(`${at}: a method or path is not a string`);
      return {
        tool: ZAP_TOOL, ruleId: str(a, 'pluginid', at), severity: severity as Severity, ...(path === undefined ? {} : { file: path }), message: str(a, 'name', at), fingerprint,
        secret: false, fpBy: 'hash', uriUnmapped: bool(a, 'unmapped', at), pathWithheld: optBool(a, 'pathWithheld', at), ...(method === undefined ? {} : { method }),
      };
    });
    return { findings, notes: readNotes(getOwn(doc, 'notes'), 'report') };
  } catch (e) {
    return { findings: [], notes: [], toolError: e instanceof ReadError ? e.message : 'the scrubbed result could not be read' };
  }
}

// ---------- files ----------

export class ScrubFileError extends Error {}
const ARTIFACT_RE = /^[a-z0-9][a-z0-9-]{0,120}$/;
const FILE_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;

function ensureFolder(path: string, what: string): void {
  let made = false;
  try {
    const st = lstatSync(path);
    if (st.isSymbolicLink()) throw new ScrubFileError(`${what} is a link, so the scrub will not write there`);
    if (!st.isDirectory()) throw new ScrubFileError(`${what} is not a folder`);
  } catch (e) {
    if (e instanceof ScrubFileError) throw e;
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw new ScrubFileError(`${what} cannot be checked`);
    try {
      mkdirSync(path, { mode: 0o755 });
      made = true;
    } catch {
      throw new ScrubFileError(`${what} cannot be created`);
    }
  }
  if (made) {
    const st = lstatSync(path);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new ScrubFileError(`${what} is not the folder that was just made`);
  }
}

/**
 * The folder rule of C0a/C0b for C5 to wire: `out` must be `<base>/pipegen-out/<artifact>/<file>` (absolute, the artifact being
 * exactly the one the step names). The scrub makes `pipegen-out` and `pipegen-out/<artifact>` itself, and refuses a link or a
 * non-folder at either (nothing is written through a link). Returns `out`. Throws ScrubFileError.
 */
export function prepareOutFolder(out: string, artifact: string): string {
  if (!ARTIFACT_RE.test(artifact)) throw new ScrubFileError('the artifact name is not a plain artifact name');
  if (!isAbsolute(out)) throw new ScrubFileError('the out path must be absolute');
  const parts = out.split(sep);
  const file = parts[parts.length - 1];
  if (parts.length < 4 || parts[parts.length - 2] !== artifact || parts[parts.length - 3] !== 'pipegen-out' || !FILE_RE.test(file)) {
    throw new ScrubFileError('the out path is not <base>/pipegen-out/<artifact>/<file> for the artifact named');
  }
  const outDir = dirname(dirname(out));
  ensureFolder(outDir, 'the pipegen-out folder');
  ensureFolder(join(outDir, artifact), 'the artifact folder in pipegen-out');
  return out;
}

export interface ScrubFileOptions extends ScrubOptions {
  artifact: string;
  /** `${{ runner.temp }}/pipegen-raw/<artifact>/<file>` */
  raw: string;
  /** `${{ runner.temp }}/pipegen-out/<artifact>/<file>` */
  out: string;
  /** Alternative to `eventText`: the path of the event payload (GITHUB_EVENT_PATH). */
  eventPath?: string;
}
export interface ScrubFileResult { status: 'ok' | 'tool-error'; sha256?: string; error?: string; findings?: number; keyId?: string; notes?: string[] }

/** Reads a file without following a link, as a regular file, never blocking, at most `max` bytes (a bigger one is refused, not cut). */
function readPlainFile(path: string, max: number, what: string): Buffer {
  let st;
  try {
    st = lstatSync(path);
  } catch (e) {
    throw new ScrubFileError((e as NodeJS.ErrnoException).code === 'ENOENT' ? `the tool left no result file (${what} is missing)` : `${what} cannot be checked`);
  }
  if (st.isSymbolicLink()) throw new ScrubFileError(`${what} is a link, so it is not read`);
  if (!st.isFile()) throw new ScrubFileError(`${what} is not a regular file`);
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== st.dev || opened.ino !== st.ino) throw new ScrubFileError(`${what} changed while it was opened`);
    if (opened.size > max) throw new ScrubFileError(`${what} is over the size cap (${max} bytes)`);
    const buf = Buffer.alloc(opened.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    return got === buf.length ? buf : buf.subarray(0, got);
  } catch (e) {
    if (e instanceof ScrubFileError) throw e;
    throw new ScrubFileError(`${what} cannot be read`);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
  }
}

/**
 * The scrub step for one result: raw file in, scrubbed file out, and the three values the step outputs. A missing, empty or
 * unreadable raw file, a key problem or any failure is `status: 'tool-error'` with a short error and NO output file (and no
 * folder: the folder is made only when there is something to write). Never throws.
 */
export function scrubFile(opts: ScrubFileOptions): ScrubFileResult {
  const key = typeof opts.fpKey === 'string' ? opts.fpKey : '';
  const fail1 = (error: string): ScrubFileResult => {
    const r = toolError(error, key);
    return { status: 'tool-error', error: r.status === 'tool-error' ? r.error : error };
  };
  try {
    if (key !== '') opts.mask?.(key);
  } catch {
    return fail1('the key could not be masked in the logs, so the scrub did not run');
  }
  // C1c: a secrets scan always runs on the stage folder; without it its coverage can not be proven, so it is never read as clean
  if (Object.hasOwn(SARIF_TOOLS, opts.tool) && SARIF_TOOLS[opts.tool].secrets && opts.stage === undefined) {
    return fail1('the secrets scan has no stage folder (the stage input): pipegen stages the checkout under neutral names before every secrets scan, and without it the scan\'s coverage can not be proven');
  }
  let raw: Buffer;
  try {
    raw = readPlainFile(opts.raw, opts.maxBytes ?? MAX_RAW_BYTES, 'the raw result');
  } catch (e) {
    return fail1(e instanceof ScrubFileError ? e.message : 'the raw result cannot be read');
  }
  let eventText = opts.eventText;
  if (eventText === undefined && opts.eventPath !== undefined) {
    try {
      eventText = readPlainFile(opts.eventPath, 16 * 1024 * 1024, 'the event payload').toString('utf8');
    } catch {
      eventText = undefined;   // unreadable: not a fork (the stricter rule)
    }
  }
  const scrubbed = scrubBytes(raw, { tool: opts.tool, format: opts.format, fpKey: opts.fpKey, eventText, workspace: opts.workspace, maxBytes: opts.maxBytes, ...(opts.stage === undefined ? {} : { stage: opts.stage }) });
  if (scrubbed.status !== 'ok') return { status: 'tool-error', error: scrubbed.error };
  // The result is written to a temporary file of its own in the artifact folder and published whole (a hard link that cannot replace
  // a file, then the temporary name removed): a failed write leaves no partial result for the upload step to pick up (review m5).
  let fd: number | undefined;
  let tmp: string | undefined;
  try {
    const path = prepareOutFolder(opts.out, opts.artifact);
    tmp = join(dirname(path), `.${basename(path)}.${randomBytes(8).toString('hex')}.tmp`);
    try {
      fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    } catch {
      tmp = undefined;
      throw new ScrubFileError('the scrubbed result file cannot be created');
    }
    let at = 0;
    while (at < scrubbed.bytes.length) at += writeSync(fd, scrubbed.bytes, at, scrubbed.bytes.length - at);
    closeSync(fd);
    fd = undefined;
    try {
      linkSync(tmp, path);
    } catch (e) {
      throw new ScrubFileError((e as NodeJS.ErrnoException).code === 'EEXIST' ? 'the scrubbed result file already exists, so it is not overwritten' : 'the scrubbed result file cannot be created');
    }
  } catch (e) {
    return fail1(e instanceof ScrubFileError ? e.message : 'the scrubbed result could not be written');
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
    if (tmp !== undefined) try { unlinkSync(tmp); } catch { /* nothing left to do */ }
  }
  return { status: 'ok', sha256: scrubbed.sha256, findings: scrubbed.findings, ...(scrubbed.keyId === undefined ? {} : { keyId: scrubbed.keyId }), notes: scrubbed.notes };
}

/** The step outputs of C0a: `<artifact>-sha256`, `<artifact>-status`, `<artifact>-error` (empty strings when not set). */
export function scrubOutputs(artifact: string, r: ScrubFileResult): Record<string, string> {
  return { [`${artifact}-sha256`]: r.sha256 ?? '', [`${artifact}-status`]: r.status, [`${artifact}-error`]: r.error ?? '' };
}
