import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import type { ExistingWorkflow, RepoProfile } from '../types.js';
import { PATH_SHOWN_MAX, safeText } from '../util/safe-text.js';
import { SKIP_REASON, listFiles, parseYamlLimited, readTextLimitedWithReason, regexLines, regexSafe } from './limits.js';
import { NAME_RE, asObj } from './manifest.js';

// Only names are kept: event names, job ids and secret NAMES. No step, command or secret value leaves this file.
// Every kept name is raw but validated (see src/types.ts): a name that fails its pattern is dropped, never cleaned.

// Exported for the audit's coverage mapper (src/audit/coverage.ts), which re-reads these workflows with the same rules.
export const MAX_WORKFLOWS = 200;
export const WORKFLOW_FILE = /^\.github\/workflows\/[^/]+\.ya?ml$/;
export const JOB_ID_RE = /^[A-Za-z_][A-Za-z0-9_-]*$/;
export const TRIGGER_RE = /^[a-z_]+$/;
// Plan regex with whole-word guards: a leading guard on every token and a trailing guard on the short ones, so
// "butterfly" and "overwhelm" do not count while "deployment.sh" and "npm_deploy" still do. (helmfile is a known miss.)
const DEPLOY_RE = /(?<![A-Za-z])(deploy|vercel|netlify|fly(?:ctl)?(?![A-Za-z])|heroku|aws (?:ecs|s3|lambda)|kubectl|helm(?![A-Za-z])|gcloud (?:run|app)|az (?:webapp|containerapp)|docker push|npm publish|twine upload)/i;
const NAME_OR_FILE_RE = /deploy|release|publish/i;
/**
 * Plan U Task 5: a run line that STARTS with a command publishing to npm or PyPI (after optional spaces), so an
 * echo, a comment or a quoted mention never counts. Linear; lines over 4 KB are skipped by regexLines.
 */
const NPM_PUBLISH_LINE = /^\s*(?:npx\s+)?(?:npm(?:\s+stage)?|pnpm|bun|yarn(?:\s+npm)?)\s+publish(?:\s|$)/;
const PYPI_PUBLISH_LINE = /^\s*(?:(?:python3?\s+-m\s+)?twine\s+upload|(?:uv|poetry|flit|hatch|pdm)\s+publish)(?:\s|$)/;
/** The PyPI publish action (any ref): https://github.com/pypa/gh-action-pypi-publish */
const PYPI_ACTION = /^pypa\/gh-action-pypi-publish(?:@|$)/i;
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
 * Registries a workflow's steps publish to (top-level job steps only; a called workflow or action isn't looked into).
 * Fix round 1 (I5): it counts only real publishing, since "published package" removes the image and running-app
 * checks: never a workflow that runs only on pull requests, never a line with --dry-run, and no npm publish where an
 * `env:` sets NPM_CONFIG_DRY_RUN (any letter case, or an `env:` given as one expression) or the step's text names it.
 */
const publishesField = (p: ('npm' | 'pypi')[]) => (p.length > 0 ? { publishes: p } : {});
const tagPinnedField = (t: { n: number; unchecked: boolean }) => ({ ...(t.n > 0 ? { tagPinned: t.n } : {}), ...(t.unchecked ? { usesUnchecked: true as const } : {}) });
const PR_ONLY = new Set(['pull_request', 'pull_request_target']);
const DRY_RUN_WORD = /(?:^|\s)--dry-run(?:[=\s]|$)/;
const dryRunEnv = (env: unknown) => env !== undefined && env !== null
  && (typeof env !== 'object' || Array.isArray(env) || Object.keys(asObj(env)).some((k) => k.toUpperCase() === 'NPM_CONFIG_DRY_RUN'));

function publishesOf(doc: Record<string, unknown>): ('npm' | 'pypi')[] {
  const triggers = triggersOf(doc.on ?? doc.true);
  if (triggers.length > 0 && triggers.every((t) => PR_ONLY.has(t))) return [];
  const out = new Set<'npm' | 'pypi'>();
  for (const job of Object.values(asObj(doc.jobs))) {
    for (const step of Array.isArray(asObj(job).steps) ? asObj(job).steps as unknown[] : []) {
      const s = asObj(step);
      const npmDry = [doc.env, asObj(job).env, s.env].some(dryRunEnv);
      for (const u of strings(s.uses)) if (regexSafe(u) && PYPI_ACTION.test(u.trim())) out.add('pypi');
      for (const r of strings(s.run)) {
        const lines = regexLines(r).filter((l) => !DRY_RUN_WORD.test(l));
        if (!npmDry && !r.toLowerCase().includes('npm_config_dry_run') && lines.some((l) => NPM_PUBLISH_LINE.test(l))) out.add('npm');
        if (lines.some((l) => PYPI_PUBLISH_LINE.test(l))) out.add('pypi');
      }
    }
  }
  return [...out].sort();
}

/**
 * Task 9 (PS36): how many `uses:` lines (a step's, or a job calling a reusable workflow) name an action or workflow by
 * a tag or branch instead of a 40-character commit. A local path (./...) and a docker:// image aren't counted; the
 * count covers only the file's own top-level jobs. Only a number leaves this file.
 */
const COMMIT_REF = /^[0-9a-f]{40}$/i;
function tagPinnedOf(doc: Record<string, unknown>): { n: number; unchecked: boolean } {
  let n = 0;
  let unchecked = false;
  const check = (u: string) => {
    if (!regexSafe(u)) {
      unchecked = true; // not counted: the report must not claim "none"
      return;
    }
    const t = u.trim();
    if (t.startsWith('./') || t.startsWith('docker://')) return;
    const at = t.lastIndexOf('@');
    if (at < 0 || !COMMIT_REF.test(t.slice(at + 1))) n++;
  };
  for (const job of Object.values(asObj(doc.jobs))) {
    const j = asObj(job);
    for (const u of strings(j.uses)) check(u);
    for (const step of Array.isArray(j.steps) ? j.steps : []) for (const u of strings(asObj(step).uses)) check(u);
  }
  return { n, unchecked };
}

const LINKED_NOTE = 'Skipped .github/workflows: it is reached through a symbolic link.';
const OVER_CAP_NOTE = `Only the first ${MAX_WORKFLOWS} workflow files were read.`;
const SKIPPED_PREFIX = 'Skipped .github/workflows/';

/**
 * How many workflow files readWorkflows skipped, counted from its notes (the audit passes this to mapCoverage, so a
 * check in a skipped file is never reported as missing). A per-file skip counts once; a symbolic-linked workflows
 * folder and the over-the-cap note count as one each (the exact number isn't known, only that some were skipped).
 * Another reader's note about a file under .github/workflows/ also counts, which only ever makes rows unknown.
 */
export function skippedWorkflowCount(notes: readonly string[]): number {
  return notes.filter((n) => n.startsWith(SKIPPED_PREFIX) || n === LINKED_NOTE || n === OVER_CAP_NOTE).length;
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
    note(LINKED_NOTE);
    return [];
  }
  const listed = files ?? (await listFiles(dir, ['.github/workflows/*.{yml,yaml}'], [])).files;
  const all = listed.filter((f) => WORKFLOW_FILE.test(f)).sort();
  if (all.length > MAX_WORKFLOWS) note(OVER_CAP_NOTE);
  const out: ExistingWorkflow[] = [];
  for (const path of all.slice(0, MAX_WORKFLOWS)) {
    if (safeText(path) !== path) {
      note(`Skipped ${safeText(path, PATH_SHOWN_MAX)}: its file name has control or invisible characters, or is too long.`);
      continue;
    }
    const read = await readTextLimitedWithReason(join(dir, path), dir);
    if (!('text' in read)) {
      note(`Skipped ${safeText(path, PATH_SHOWN_MAX)}: ${SKIP_REASON[read.skipped]}.`);
      continue;
    }
    let doc: Record<string, unknown>;
    try {
      doc = asObj(parseYamlLimited(read.text));
    } catch {
      note(`Skipped ${safeText(path, PATH_SHOWN_MAX)}: it could not be parsed.`);
      continue;
    }
    out.push({
      path,
      triggers: triggersOf(doc.on ?? doc.true),
      deploys: deploysOf(doc, path),
      secretsUsed: secretsOf(read.text),
      jobs: Object.keys(asObj(doc.jobs)).filter((j) => regexSafe(j) && JOB_ID_RE.test(j)),
      ...publishesField(publishesOf(doc)),
      ...tagPinnedField(tagPinnedOf(doc)),
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

/** Every config name lefthook 2.2.2 reads (main and -local; checked against the real binary in the 6d review), at the root or in .config/. */
const LEFTHOOK_FILES: readonly string[] = ['', '.config/'].flatMap((dir) => ['', '.'].flatMap((dot) => ['lefthook', 'lefthook-local'].flatMap((base) => ['yml', 'yaml', 'toml', 'json', 'jsonc'].map((ext) => `${dir}${dir === '' ? dot : ''}${base}.${ext}`))));

/** Which hook manager the repo uses. A symbolic link never counts. Priority: pre-commit, husky, lefthook. */
export function readPrecommit(dir: string): RepoProfile['precommit'] {
  if (isRealFile(join(dir, '.pre-commit-config.yaml'))) return 'pre-commit';
  if (isRealDir(join(dir, '.husky'))) return 'husky';
  if (LEFTHOOK_FILES.some((f) => isRealFile(join(dir, f)))) return 'lefthook';
  return null;
}
