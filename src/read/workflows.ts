import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import type { ExistingWorkflow, RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { listFiles, parseYamlLimited, readTextLimitedWithReason, regexLines, regexSafe } from './limits.js';
import { asObj } from './manifest.js';

// Only names are kept: event names, job ids and secret NAMES. No step, command or secret value leaves this file.

const MAX_WORKFLOWS = 200;
const WORKFLOW_FILE = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const DEPLOY_RE = /(deploy|vercel|netlify|fly(ctl)?|heroku|aws (ecs|s3|lambda)|kubectl|helm|gcloud (run|app)|az (webapp|containerapp)|docker push|npm publish|twine upload)/i;
const NAME_OR_FILE_RE = /deploy|release|publish/i;
const EXPRESSION_RE = /\$\{\{([^}]*)\}\}/g;
const SECRET_REF_RE = /\bsecrets(?:\.([A-Za-z_][A-Za-z0-9_]*)(?![\w-])|\[\s*['"]([^'"]*)['"]\s*\])/g;

const strings = (v: unknown): string[] => (typeof v === 'string' ? [v] : []);

/** True when the repo-derived text matches the deploy rule; multi-line text is tested line by line, over-long lines are skipped. */
function looksLikeDeploy(text: string, re: RegExp): boolean {
  return regexLines(text).some((line) => re.test(line));
}

function triggersOf(on: unknown): string[] {
  const names = typeof on === 'string' ? [on] : Array.isArray(on) ? on.flatMap(strings) : Object.keys(asObj(on));
  return [...new Set(names.map((n) => safeText(n, 60)))];
}

function secretsOf(text: string): string[] {
  const found = new Set<string>();
  for (const line of regexLines(text)) {
    for (const expr of line.matchAll(EXPRESSION_RE)) {
      for (const ref of (expr[1] ?? '').matchAll(SECRET_REF_RE)) {
        const name = ref[1] ?? ref[2];
        if (name !== undefined && NAME_RE.test(name)) found.add(name);
      }
    }
  }
  return [...found].sort();
}

function deploysOf(doc: Record<string, unknown>, path: string): boolean {
  if (regexSafe(path) && NAME_OR_FILE_RE.test(path)) return true;
  if (typeof doc.name === 'string' && looksLikeDeploy(doc.name, NAME_OR_FILE_RE)) return true;
  for (const job of Object.values(asObj(doc.jobs))) {
    const j = asObj(job);
    if ('environment' in j && j.environment !== null && j.environment !== undefined) return true;
    if (strings(j.uses).some((u) => looksLikeDeploy(u, DEPLOY_RE))) return true; // reusable workflow call
    for (const step of Array.isArray(j.steps) ? j.steps : []) {
      const s = asObj(step);
      if ([...strings(s.uses), ...strings(s.run)].some((t) => looksLikeDeploy(t, DEPLOY_RE))) return true;
    }
  }
  return false;
}

/**
 * Reads .github/workflows/*.yml and *.yaml (top level only).
 * `files` is the repo's file list when the caller already walked the repo; otherwise this lists the folder itself.
 * A file that cannot be read or parsed is skipped and, when `notes` is given, mentioned there.
 */
export async function readWorkflows(dir: string, files?: string[], notes: string[] = []): Promise<ExistingWorkflow[]> {
  const listed = files ?? (await listFiles(dir, ['.github/workflows/*.{yml,yaml}'], [])).files;
  const all = listed.filter((f) => WORKFLOW_FILE.test(f)).sort();
  if (all.length > MAX_WORKFLOWS) notes.push(`Only the first ${MAX_WORKFLOWS} workflow files were read.`);
  const out: ExistingWorkflow[] = [];
  for (const path of all.slice(0, MAX_WORKFLOWS)) {
    const read = await readTextLimitedWithReason(join(dir, path));
    if (!('text' in read)) {
      notes.push(`Skipped ${safeText(path)}: it could not be read (${read.skipped}).`);
      continue;
    }
    let doc: Record<string, unknown>;
    try {
      doc = asObj(parseYamlLimited(read.text));
    } catch {
      notes.push(`Skipped ${safeText(path)}: it could not be parsed.`);
      continue;
    }
    out.push({
      path,
      triggers: triggersOf(doc.on ?? doc.true),
      deploys: deploysOf(doc, path),
      secretsUsed: secretsOf(read.text),
      jobs: Object.keys(asObj(doc.jobs)).map((j) => safeText(j, 100)),
    });
  }
  return out;
}

const isRealFile = (p: string) => lstatSync(p, { throwIfNoEntry: false })?.isFile() === true;
const isRealDir = (p: string) => lstatSync(p, { throwIfNoEntry: false })?.isDirectory() === true;

/** Which hook manager the repo uses. A symbolic link never counts. Priority: pre-commit, husky, lefthook. */
export function readPrecommit(dir: string): RepoProfile['precommit'] {
  if (isRealFile(join(dir, '.pre-commit-config.yaml'))) return 'pre-commit';
  if (isRealDir(join(dir, '.husky'))) return 'husky';
  if (isRealFile(join(dir, 'lefthook.yml')) || isRealFile(join(dir, 'lefthook.yaml'))) return 'lefthook';
  return null;
}
