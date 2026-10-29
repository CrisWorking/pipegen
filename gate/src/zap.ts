// Plan C Task C1a: zap-json parsing for the gate (the `-J` traditional-json report of zap-baseline.py). Same hostile-input
// rules as sarif.ts (parse-common.ts). The report's URLs and texts come from the scanned application:
// - query, fragment, user info, host and port are dropped: the identity of a ZAP finding is pluginid + method + URL
//   path (S10), and the path is the only part kept (`file`, a URL path, not a repository file);
// - `evidence`, `attack`, `param`, `otherinfo`, `desc`, `solution`, `reference` and every other free text are never read;
// - riskcode 3 → high, 2 → medium, 1 → low, 0 → info; anything else → high with a note;
// - one finding per instance; an alert with no instance is still one finding; an alert is never dropped.
import {
  cutText, fail, getOwn, guarded, isObj, limitsFrom, MAX_MESSAGE_CHARS, optList, readJson, shown,
  type Obj, type ParseLimits, type ParsedFinding, type ParseResult,
} from './parse-common.js';
import type { Severity } from '../../src/types.js';
import { safeText } from '../../src/util/safe-text.js';

export const ZAP_TOOL = 'zap-baseline';
const MAX_PLUGIN_ID = 256;
const MAX_URL_PATH = 2048;
const MAX_SITES = 1000;
const METHOD = /^[A-Za-z]{1,16}$/;

export interface ZapOptions { limits?: Partial<ParseLimits> }

function severityOf(v: unknown): Severity | undefined {
  const n = typeof v === 'number' ? v : typeof v === 'string' && /^\d$/.test(v) ? Number(v) : NaN;
  return n === 3 ? 'high' : n === 2 ? 'medium' : n === 1 ? 'low' : n === 0 ? 'info' : undefined;
}

/** The path of an http(s) URL (dot segments resolved by the URL rules), or undefined: no host, port, query, fragment or user info is kept. */
function urlPath(uri: string): string | undefined {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
  return url.pathname.length > MAX_URL_PATH ? undefined : url.pathname;
}

function optString(o: Obj, key: string, where: string, nullOk = false): string | undefined {
  const v = getOwn(o, key);
  if (v === undefined || (nullOk && v === null)) return undefined;
  if (typeof v !== 'string') fail(`${where}: ${key} is not a string`);
  return v;
}

/** Reads one parsed ZAP traditional-json report. Never throws. */
export function parseZapJson(json: unknown, toolId: string, opts: ZapOptions = {}): ParseResult {
  return guarded((notes) => {
    if (toolId !== ZAP_TOOL) fail(`${JSON.stringify(safeText(toolId, 60))} is not a tool whose ZAP report the gate reads`);
    if (!isObj(json)) fail('the result is not a ZAP report (the top level is not an object)');
    if (getOwn(json, '@programName') !== 'ZAP') fail('the report is not from ZAP (@programName)');
    const limits = limitsFrom(opts.limits);
    const sites = getOwn(json, 'site');
    if (!Array.isArray(sites)) fail('the report has no site list');
    if (sites.length === 0) fail('the report lists no site, so nothing was scanned');
    if (sites.length > MAX_SITES) fail(`the report lists more than ${MAX_SITES} sites`);

    const findings: ParsedFinding[] = [];
    let unknownRisk = 0;
    for (const [s, site] of sites.entries()) {
      const at = `site ${s}`;
      if (!isObj(site)) fail(`${at} is not an object`);
      const alerts = getOwn(site, 'alerts');
      if (!Array.isArray(alerts)) fail(`${at} has no alerts list`);
      for (const [a, alert] of alerts.entries()) {
        const where = `${at} alert ${a}`;
        if (!isObj(alert)) fail(`${where} is not an object`);
        const pluginid = getOwn(alert, 'pluginid');
        if (typeof pluginid !== 'string' || pluginid === '' || pluginid.length > MAX_PLUGIN_ID) fail(`${where} has no usable pluginid (${shown(pluginid)})`);
        const name = optString(alert, 'name', where);
        const title = optString(alert, 'alert', where);
        const risk = getOwn(alert, 'riskcode');
        if (risk !== undefined && typeof risk !== 'string' && typeof risk !== 'number') fail(`${where}: riskcode is not a string or a number`);
        let severity = severityOf(risk);
        if (severity === undefined) {
          severity = 'high';
          unknownRisk++;
        }
        const message = cutText(name ?? title ?? '', MAX_MESSAGE_CHARS);
        const instances = optList(alert, 'instances', where) ?? [];
        const make = (file: string | undefined, method: string | undefined, uriUnmapped: boolean): void => {
          if (findings.length >= limits.maxResults) fail(`the report has more than ${limits.maxResults} findings`);
          findings.push({ tool: toolId, ruleId: pluginid, severity, file, message, method, uriUnmapped });
        };
        if (instances.length === 0) make(undefined, undefined, false);
        for (const [n, inst] of instances.entries()) {
          const w = `${where} instance ${n}`;
          if (!isObj(inst)) fail(`${w} is not an object`);
          const uri = optString(inst, 'uri', w, true);
          const method = optString(inst, 'method', w, true);
          const file = uri === undefined ? undefined : urlPath(uri);
          make(file, method !== undefined && METHOD.test(method) ? method.toUpperCase() : undefined, file === undefined);
        }
      }
    }
    if (unknownRisk > 0) notes.push(`${unknownRisk} alert(s) had an unknown riskcode and are counted as high`);
    return findings;
  });
}

/** Reads the bytes of a ZAP report file: size cap, strict UTF-8, one JSON.parse, then parseZapJson. Never throws. */
export function parseZapJsonText(input: string | Uint8Array, toolId: string, opts: ZapOptions = {}): ParseResult {
  const read = readJson(input, limitsFrom(opts.limits).maxBytes);
  return read.toolError === undefined ? parseZapJson(read.json, toolId, opts) : { findings: [], toolError: read.toolError, notes: [] };
}
