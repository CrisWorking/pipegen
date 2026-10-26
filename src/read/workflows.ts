import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import type { ExistingWorkflow, RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { SKIP_REASON, listFiles, parseYamlLimited, readTextLimitedWithReason, regexLines, regexSafe } from './limits.js';
import { NAME_RE, asObj } from './manifest.js';

// Only names are kept: event names, job ids and secret NAMES. No step, command or secret value leaves this file.
// Every kept name is raw but validated (see src/types.ts): a name that fails its pattern is dropped, never cleaned.

const MAX_WORKFLOWS = 200;
const WORKFLOW_FILE = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const JOB_ID_RE = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const TRIGGER_RE = /^[a-z_]+$/;
// Plan regex with whole-word guards: a leading guard on every token and a trailing guard on the short ones, so
// "butterfly" and "overwhelm" do not count while "deployment.sh" and "npm_deploy" still do. (helmfile is a known miss.)
const DEPLOY_RE = /(?<![A-Za-z])(deploy|vercel|netlify|fly(?:ctl)?(?![A-Za-z])|heroku|aws (?:ecs|s3|lambda)|kubectl|helm(?![A-Za-z])|gcloud (?:run|app)|az (?:webapp|containerapp)|docker push|npm publish|twine upload)/i;
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
  return [...new Set(names.filter((n) => regexSafe(n) && TRIGGER_RE.test(n)))];
}

// Scans line by line, so a secret inside a multi-line ${{ }} expression is missed (a safe miss), and a name
// mentioned inside a YAML comment on a line with ${{ }} is counted.
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
  const note = (line: string) => {
    if (!notes.includes(line)) notes.push(line);
  };
  // A symlinked .github or .github/workflows would lead outside the repo; list and read nothing from it.
  if (isLink(join(dir, '.github')) || isLink(join(dir, '.github/workflows'))) {
    note('Skipped .github/workflows: it is reached through a symbolic link.');
    return [];
  }
  const listed = files ?? (await listFiles(dir, ['.github/workflows/*.{yml,yaml}'], [])).files;
  const all = listed.filter((f) => WORKFLOW_FILE.test(f)).sort();
  if (all.length > MAX_WORKFLOWS) note(`Only the first ${MAX_WORKFLOWS} workflow files were read.`);
  const out: ExistingWorkflow[] = [];
  for (const path of all.slice(0, MAX_WORKFLOWS)) {
    if (safeText(path) !== path) {
      note(`Skipped ${safeText(path)}: its file name has control or invisible characters, or is too long.`);
      continue;
    }
    const read = await readTextLimitedWithReason(join(dir, path));
    if (!('text' in read)) {
      note(`Skipped ${safeText(path)}: ${SKIP_REASON[read.skipped]}.`);
      continue;
    }
    let doc: Record<string, unknown>;
    try {
      doc = asObj(parseYamlLimited(read.text));
    } catch {
      note(`Skipped ${safeText(path)}: it could not be parsed.`);
      continue;
    }
    out.push({
      path,
      triggers: triggersOf(doc.on ?? doc.true),
      deploys: deploysOf(doc, path),
      secretsUsed: secretsOf(read.text),
      jobs: Object.keys(asObj(doc.jobs)).filter((j) => regexSafe(j) && JOB_ID_RE.test(j)),
    });
  }
  return out;
}

const info = (p: string) => {
  try {
    return lstatSync(p, { throwIfNoEntry: false });
  } catch {
    return undefined; // permission errors and the like count as absent
  }
};
const isLink = (p: string) => info(p)?.isSymbolicLink() === true;
const isRealFile = (p: string) => info(p)?.isFile() === true;
const isRealDir = (p: string) => info(p)?.isDirectory() === true;

/** Which hook manager the repo uses. A symbolic link never counts. Priority: pre-commit, husky, lefthook. */
export function readPrecommit(dir: string): RepoProfile['precommit'] {
  if (isRealFile(join(dir, '.pre-commit-config.yaml'))) return 'pre-commit';
  if (isRealDir(join(dir, '.husky'))) return 'husky';
  if (isRealFile(join(dir, 'lefthook.yml')) || isRealFile(join(dir, 'lefthook.yaml'))) return 'lefthook';
  return null;
}
