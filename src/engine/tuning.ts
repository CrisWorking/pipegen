// Per-repo tool tuning (Plan B Task 6d; DECISIONS #84, narrowed by Cristiano's ruling #108). This file is REVIEWED POLICY, not
// data anyone else writes: every tuning option of every tool is listed here, with its kind, the enum its values come from, and
// the one way it renders. The AI (Plan F) only picks from enums built per call from the RepoProfile (`StepSpec.choices.tuning`);
// it never writes a config key, a flag or a path. Values reach the step the way every run-time value does: in a step env
// variable, quoted in the script (render-cli.ts), never in the shell text.
//
// DECISIONS #108 (binding): tuning only ADDS coverage. Secret, dependency and image scans are never narrowed by pipegen: no skip
// path, no ignore-unfixed, no severity above the floor, no ZAP alert moved to warn. Lint and SAST may skip only folders pipegen
// itself detected as vendored or generated (RepoProfile.generatedDirs). So there are two kinds, and no third:
//   - `adds`: more coverage (more Semgrep rule folders, hooks from the repo's own lint scripts, the app's
//     own start script for a web scan);
//   - `scope-lint`: a folder skip, offered only on tools of the lint, SAST, duplication and dead-code classes (the test walks
//     this model and fails if a skip option sits on a secret, dependency, image, IaC, licence, SBOM or DAST tool).
// Tools covered, and why each option fits #108:
//   semgrep (sast)        extra-rules   adds        more rule folders of the verified rules tree for the languages and files the service has
//   semgrep (sast)        skip-generated scope-lint --exclude of a folder the profile marks vendored or generated (SAST class)
//   eslint, eslint-typescript, oxlint-typeaware (lint)   skip-generated  scope-lint  --ignore-pattern of such a folder
//   jscpd (duplication)   skip-generated scope-lint --ignore of such a folder
//   zap-baseline, nuclei (dast)  start-script  adds   the service's own start or serve script, for Plan G to start the app
//   lefthook (hooks-ci)   hooks         adds        hooks from the repo's own lint and format-check scripts, only when the repo has no hook manager at all
// NOT built, on purpose: OSV --lockfile (dropped in 6d fix round 1: measured with osv-scanner 2.7.0 it adds nothing next to --recursive . and exits 127 on bun.lockb), gitleaks/betterleaks extra rules (no reviewed rule list exists; no skip path ever), trivy (no skip dir,
// no ignore-unfixed, no severity: it is image/IaC/licence scanning), ZAP alert rules, biome (its only ignore is a config key
// whose globs are relative to the pinned config's own folder, not the repo, so a safe form can not be shown offline) and knip
// (no folder ignore on its command line). A tool with no entry here has no tuning, and a tuning value for it is refused.
import { stringify } from 'yaml';
import { safeText } from '../util/safe-text.js';
import type { Service, StepSpec, ReviewedTool } from '../types.js';
import { EXPR, RenderError, own, show } from './render-error.js';
import type { RenderContext } from './render-step.js';
import { slotProblem } from './slots.js';

export const TUNING_KINDS = ['adds', 'scope-lint'] as const;
export type TuningKind = (typeof TUNING_KINDS)[number];

/**
 * The top-level folders of semgrep/semgrep-rules at the pinned tree (listed with `gh api repos/semgrep/semgrep-rules/git/trees/<tree>`
 * on 2026-10-29, folders only; the live test in test/tuning-live.test.ts re-checks them against the tree in the reviewed list).
 * Not listed: problem-based-packs, scripts, stats, package_managers, trusted_python (not language rule folders).
 */
export const SEMGREP_RULE_FOLDERS: readonly string[] = Object.freeze([
  'ai', 'apex', 'bash', 'c', 'clojure', 'csharp', 'dockerfile', 'elixir', 'generic', 'go', 'html', 'java', 'javascript', 'json', 'kotlin',
  'libsonnet', 'ocaml', 'php', 'python', 'ruby', 'rust', 'scala', 'solidity', 'swift', 'terraform', 'typescript', 'yaml',
]);
const FOLDER_RE = /^[a-z][a-z0-9_]{0,30}$/;
/** Where an extra rule folder is mounted (read-only), beside the base set at /pipegen-rules. */
export const EXTRA_RULES_AT = '/pipegen-rules-extra';
/** The last folder name of a vendored or generated folder (defence in depth: the profile's list must agree with the reader's). */
const GENERATED_BASENAMES: ReadonlySet<string> = new Set(['node_modules', 'vendor', 'dist', 'target', '.next', '.venv', 'generated', '__generated__']);
/** The scripts a service may be started with for a scan (never `dev`: a watcher with hot reload and dev-only behaviour). */
const START_SCRIPTS = ['start', 'serve'] as const;
/** The scripts that read a repo (lint, format CHECK) and may become a hook; a script that writes (format, fix, lint:fix) never. */
const HOOK_SCRIPTS = ['lint', 'lint:check', 'format:check', 'check-format'] as const;
const SCRIPT_NAME_RE = /^[a-z][a-z:-]{0,30}$/;

/** What a tuning option adds to a render. */
export interface TuningFlag {
  flag: string; value: string; key: string;
  /** The value is a reviewed constant (a container path), written in the script text instead of an env variable. */
  literal?: true;
}
export interface TuningEffects {
  flags: TuningFlag[];
  /** Semgrep: extra rule folders to mount read-only (each a name on SEMGREP_RULE_FOLDERS). */
  extraRules: string[];
  /** lefthook: a generated config, written by the step and named by `envName` (the tool is told through that variable). */
  generatedConfig: { envName: 'LEFTHOOK_CONFIG'; fileName: 'lefthook.yml'; content: string } | null;
  /** Plain-English lines (describeTuning), shown in a comment of the step's script. */
  lines: string[];
}

export interface TuningOption {
  readonly id: string;
  /** The reviewed entry id. */
  readonly tool: string;
  readonly kind: TuningKind;
  /** The most values one pick may hold. */
  readonly max: number;
  /** Every command-line flag this option can add (none for an option that only changes files or env). */
  readonly flags: readonly string[];
  /** One plain sentence of what the option does (for the reviewer and the report). */
  readonly summary: string;
}

type SpecLike = Pick<StepSpec, 'choices'> & Partial<Pick<StepSpec, 'service' | 'workingDir'>>;

/** The facts an enum is built from: the profile, the service the step is for, and the folder the step runs in. */
interface Facts {
  ctx: RenderContext; spec: SpecLike; tool: ReviewedTool;
  /** The service the step is for: the named one, else the repo's only service. */
  service: Service | undefined;
  /** Services in scope: the named one, else all. */
  scope: readonly Service[];
  /** The step's working folder (a service folder), or undefined for the repository root. */
  wd: string | undefined;
  /** The working folder was given and is not a plain folder: nothing is offered. */
  badWd: boolean;
}

export interface TuningDef extends TuningOption {
  values(f: Facts): string[];
  /** Why no value can be picked at all (shown instead of the generic message when the enum is empty). */
  emptyReason?(f: Facts): string;
  render(values: readonly string[], f: Facts): Partial<Pick<TuningEffects, 'flags' | 'extraRules' | 'generatedConfig'>>;
  describe(values: readonly string[]): string;
}

// ---------- facts ----------

/** A plain repo-relative path that can fill a repo-path slot, with no empty, `.` or `..` segment and no trailing slash. */
function plainPath(v: unknown): v is string {
  return typeof v === 'string' && slotProblem('repo-path', v) === null && !v.endsWith('/') && v.split('/').every((s) => s !== '' && s !== '.' && s !== '..');
}

function factsOf(spec: SpecLike, ctx: RenderContext, tool: ReviewedTool): Facts {
  const all = ctx.profile?.services ?? [];
  const named = typeof spec.service === 'string' ? all.find((s) => s.name === spec.service) : undefined;
  const wdGiven = spec.workingDir !== undefined;
  const badWd = wdGiven && !(plainPath(spec.workingDir) && spec.workingDir !== '.');
  return {
    ctx, spec, tool, service: named ?? (spec.service === undefined && all.length === 1 ? all[0] : undefined),
    scope: spec.service === undefined ? all : named === undefined ? [] : [named],
    wd: wdGiven && !badWd ? spec.workingDir : undefined, badWd,
  };
}

const under = (f: Facts, path: string): boolean => f.wd === undefined || path.startsWith(`${f.wd}/`);
const relTo = (f: Facts, path: string): string => (f.wd === undefined ? path : path.slice(f.wd.length + 1));
const sortedUnique = (xs: readonly string[]): string[] => [...new Set(xs)].sort();

// ---------- the enums ----------

/** The Semgrep rule folder of each language (also the builder's per-service `rules` enum, Plan F F2 fix round 1). */
export const LANGUAGE_FOLDERS: Readonly<Record<string, readonly string[]>> = { node: ['javascript'], python: ['python'], go: ['go'], java: ['java'], dotnet: ['csharp'], ruby: ['ruby'], php: ['php'] };

function extraRuleFolders(f: Facts): string[] {
  const chosen = f.spec.choices?.rules;
  const base = typeof chosen === 'string' ? chosen : f.tool.choices.rules?.[0];
  const out: string[] = [];
  for (const s of f.scope) {
    for (const lang of [s.language, ...(s.alsoLanguages ?? [])]) {
      out.push(...(own(LANGUAGE_FOLDERS, lang) ?? []));
      if (lang === 'node' && s.quality?.tsconfig === true) out.push('typescript');
    }
    if (typeof s.dockerfile === 'string') out.push('dockerfile');
  }
  const p = f.ctx.profile;
  if ((p.terraformDirs ?? []).length > 0) out.push('terraform');
  if (p.repoFiles?.kubernetes === true || p.hasCompose === true) out.push('yaml');
  // dockerfile/terraform/yaml come after the languages; one entry each; the base set is already mounted
  const ordered = [...new Set(out)];
  return ordered.filter((x) => x !== base && SEMGREP_RULE_FOLDERS.includes(x) && FOLDER_RE.test(x));
}

function generated(f: Facts): string[] {
  if (f.badWd) return [];
  const dirs = f.ctx.profile.generatedDirs ?? [];
  return sortedUnique(dirs.filter((d): d is string => plainPath(d) && GENERATED_BASENAMES.has(d.split('/').at(-1) as string) && under(f, d)));
}

function startScripts(f: Facts): string[] {
  const s = f.service;
  if (s === undefined || s.language !== 'node') return [];
  return START_SCRIPTS.filter((n) => s.scripts.includes(n));
}

function hookScripts(f: Facts): string[] {
  const s = f.service;
  // only a repo with NO hook manager at all: lefthook in any form (the reader knows every name), husky, pre-commit, simple-git-hooks, .githooks.
  // lefthook-local.yml in the repo would still merge over a generated config, which is why a repo with any lefthook file is never offered hooks
  const p = f.ctx.profile;
  if (s === undefined || p.precommit !== null || (p.otherHookManagers ?? []).length > 0 || s.language !== 'node' || s.packageManager !== 'npm') return [];
  if (s.path !== '.' && !(plainPath(s.path))) return [];
  return HOOK_SCRIPTS.filter((n) => s.scripts.includes(n));
}

const list = (values: readonly string[]): string => values.map((v) => safeText(v, 80)).join(', ');
const lineOf = (text: string): string => safeText(text, 400);

// ---------- the model ----------

const skipGenerated = (tool: string, flag: string, how: (rel: string) => string, summary: string): TuningDef => ({
  id: 'skip-generated', tool, kind: 'scope-lint', max: 8, flags: [flag], summary,
  values: generated,
  render: (values, f) => ({ flags: values.map((v, i) => ({ flag, value: how(relTo(f, v)), key: `tune:skip-generated:${i}` })) }),
  describe: (values) => `skips the vendored or generated folders ${list(values)} for this lint or SAST tool only`,
});

const DEFS: readonly TuningDef[] = [
  {
    id: 'extra-rules', tool: 'semgrep', kind: 'adds', max: 4, flags: ['--config'],
    summary: 'Runs more Semgrep rule folders of the pinned rules tree, for the languages and files the service really has.',
    values: extraRuleFolders,
    render: (values) => ({
      extraRules: [...values],
      flags: values.map((v, i) => ({ flag: '--config', value: `${EXTRA_RULES_AT}/${v}`, key: `tune:extra-rules:${i}`, literal: true as const })),
    }),
    describe: (values) => `also runs the Semgrep rule sets ${list(values)} (adds coverage)`,
  },
  // anchored with a leading slash: a bare name skips every folder of that name at any depth (measured, semgrep 1.181.0)
  skipGenerated('semgrep', '--exclude', (rel) => `/${rel}`, 'Skips a folder the profile marks as vendored or generated (SAST class only), at that path only.'),
  skipGenerated('eslint', '--ignore-pattern', (rel) => `${rel}/**`, 'Skips a folder the profile marks as vendored or generated.'),
  skipGenerated('eslint-typescript', '--ignore-pattern', (rel) => `${rel}/**`, 'Skips a folder the profile marks as vendored or generated.'),
  skipGenerated('oxlint-typeaware', '--ignore-pattern', (rel) => `${rel}/**`, 'Skips a folder the profile marks as vendored or generated.'),
  // ./-anchored: jscpd matches a glob against any suffix of the path (measured, jscpd 5.4.2)
  skipGenerated('jscpd', '--ignore', (rel) => `./${rel}/**`, 'Skips a folder the profile marks as vendored or generated.'),
  ...(['zap-baseline', 'nuclei'] as const).map((tool): TuningDef => ({
    id: 'start-script', tool, kind: 'adds', max: 1, flags: [],
    summary: "Names the service's own start or serve script, which Plan G runs to start the app before the scan. The scan step itself does not change.",
    values: startScripts,
    emptyReason: (f) => `the service ${show(f.service?.name ?? f.spec.service ?? 'for this step')} has no start or serve script in its package.json, so pipegen can not start the app for the scan`,
    render: () => ({}),
    describe: (values) => `Plan G starts the app with its own ${list(values)} script before the scan (adds coverage)`,
  })),
  {
    id: 'hooks', tool: 'lefthook', kind: 'adds', max: 4, flags: [],
    summary: "Builds the pre-commit hooks from the service's own lint and format-check scripts, only when the repository has no lefthook hooks of its own.",
    values: hookScripts,
    render: (values, f) => {
      const root = f.service !== undefined && f.service.path !== '.' ? `${f.service.path}/` : undefined;
      const commands = Object.fromEntries(values.map((v) => [v.replace(/:/g, '-'), { ...(root === undefined ? {} : { root }), run: `npm run ${v}` }]));
      return { generatedConfig: { envName: 'LEFTHOOK_CONFIG', fileName: 'lefthook.yml', content: stringify({ 'pre-commit': { commands } }) } };
    },
    describe: (values) => `runs the service's own ${list(values)} script${values.length === 1 ? '' : 's'} as a pre-commit hook (adds coverage)`,
  },
];

/** The model, for the reviewer and the tests (functions stay inside this file's use). */
export const TUNING_OPTIONS: readonly TuningOption[] = DEFS;

/** The definitions again, for tests that swap one in through tuningEffectsWith. */
export const TUNING_OPTIONS_FOR_TESTS: readonly TuningDef[] = DEFS;
const defsOf = (toolId: string, defs: readonly TuningDef[] = DEFS): TuningDef[] => defs.filter((d) => d.tool === toolId);

/** The value enum of every tuning option of a tool, built now from the profile, the service and the working folder of this call. */
export function tuningEnums(tool: ReviewedTool, spec: SpecLike, ctx: RenderContext): Record<string, string[]> {
  const f = factsOf(spec, ctx, tool);
  return Object.fromEntries(defsOf(tool.id).map((d) => [d.id, d.values(f)]));
}

// ---------- validation ----------

/** Plain-English problems with the `tuning` section of a spec (empty = fine), each starting with its field path. */
export function tuningProblems(spec: StepSpec, tool: ReviewedTool, ctx: RenderContext, all: readonly TuningDef[] = DEFS): string[] {
  const picks: unknown = spec.choices?.tuning;
  if (picks === undefined) return [];
  if (typeof picks !== 'object' || picks === null || Array.isArray(picks)) return ['choices.tuning: must be a map of tuning option names to lists of values.'];
  const out: string[] = [];
  const defs = defsOf(tool.id, all);
  const f = factsOf(spec, ctx, tool);
  for (const [name, values] of Object.entries(picks)) {
    const path = `choices.tuning.${safeText(name, 40)}`;
    const def = defs.find((d) => d.id === name);
    if (def === undefined) {
      out.push(`${path}: this tool has no tuning option with that name.${defs.length === 0 ? ' It has none.' : ` It has: ${defs.map((d) => d.id).join(', ')}.`}`);
      continue;
    }
    if (!Array.isArray(values)) { out.push(`${path}: must be a list of values.`); continue; }
    if (values.length > def.max) { out.push(`${path}: at most ${def.max} value${def.max === 1 ? '' : 's'} may be picked, not ${values.length}.`); continue; }
    const enumValues = def.values(f);
    const seen = new Set<string>();
    values.forEach((v: unknown, i) => {
      const at = `${path}[${i}]`;
      if (typeof v !== 'string') out.push(`${at}: must be text.`);
      else if (seen.has(v)) out.push(`${at}: ${show(v)} is listed twice.`);
      else if (!enumValues.includes(v)) {
        out.push(enumValues.length === 0 && def.emptyReason !== undefined ? `${path}: ${def.emptyReason(f)}.` : `${at}: ${show(v)} is not one of the values this call allows (${enumValues.length === 0 ? 'none' : list(enumValues)}).`);
      }
      if (typeof v === 'string') seen.add(v);
    });
  }
  return out;
}

// ---------- rendering ----------

const picksOf = (spec: StepSpec, id: string): string[] => {
  const t: unknown = spec.choices?.tuning;
  const v = typeof t === 'object' && t !== null && !Array.isArray(t) && Object.hasOwn(t, id) ? (t as Record<string, unknown>)[id] : undefined;
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
};

/**
 * What the picked tuning adds to a render. The spec is checked first (tuningProblems), so a value outside the enum of this call
 * is a RenderError and nothing is built from it. Values are checked again where they are used (a script name, a folder name).
 */
export function tuningEffects(spec: StepSpec, tool: ReviewedTool, ctx: RenderContext): TuningEffects {
  return tuningEffectsWith(spec, tool, ctx, DEFS);
}

/** tuningEffects with the option definitions given. FOR TESTS ONLY (the public one has no such parameter): proves the runtime flag check. */
export function tuningEffectsWith(spec: StepSpec, tool: ReviewedTool, ctx: RenderContext, defs: readonly TuningDef[]): TuningEffects {
  const bad = tuningProblems(spec, tool, ctx, defs);
  if (bad.length > 0) throw new RenderError(`The tuning of ${show(spec.needId)} isn't valid: ${bad.join(' ')}`);
  const f = factsOf(spec, ctx, tool);
  const out: TuningEffects = { flags: [], extraRules: [], generatedConfig: null, lines: describeTuning(spec) };
  for (const d of defsOf(tool.id, defs)) {
    const values = picksOf(spec, d.id);
    if (values.length === 0) continue;
    const r = d.render(values, f);
    // a render may emit only the flags its option declares (DECISIONS #108 guard on what is rendered, not on the metadata)
    for (const fl of r.flags ?? []) if (!d.flags.includes(fl.flag)) throw new RenderError(`The tuning option ${show(d.id)} of ${show(tool.id)} emitted ${show(fl.flag)}, which it does not declare.`);
    out.flags.push(...(r.flags ?? []));
    out.extraRules.push(...(r.extraRules ?? []));
    if (r.generatedConfig !== undefined) out.generatedConfig = r.generatedConfig;
  }
  for (const x of out.extraRules) if (!FOLDER_RE.test(x) || !SEMGREP_RULE_FOLDERS.includes(x)) throw new RenderError(`${show(x)} is not a folder of the Semgrep rules tree pipegen reviewed.`);
  for (const x of out.flags) {
    if (/\s/.test(x.value) || x.value.includes(EXPR) || x.value === '' || x.value.startsWith('-') || !/^--[a-z][a-z-]{0,30}$/.test(x.flag)) throw new RenderError(`A tuning value for ${show(tool.id)} is not one pipegen writes into a step.`);
  }
  if (out.generatedConfig !== null) {
    for (const v of picksOf(spec, 'hooks')) if (!SCRIPT_NAME_RE.test(v) || !(HOOK_SCRIPTS as readonly string[]).includes(v)) throw new RenderError(`${show(v)} is not a script pipegen turns into a hook.`);
  }
  return out;
}

/**
 * The start script picked for a web scan (ZAP, nuclei), or null when none was picked. The scan step does not change: Plan G starts
 * the app (repo code, so in an earlier job or a service container) with `npm run <script>` in the service folder, and asks here.
 */
export function startScriptOf(spec: StepSpec, tool: ReviewedTool, ctx: RenderContext): { service: string; script: string } | null {
  const bad = tuningProblems(spec, tool, ctx);
  if (bad.length > 0) throw new RenderError(`The tuning of ${show(spec.needId)} isn't valid: ${bad.join(' ')}`);
  const script = picksOf(spec, 'start-script')[0];
  const service = factsOf(spec, ctx, tool).service;
  return script === undefined || service === undefined ? null : { service: service.name, script };
}

/**
 * Plain-English lines for a spec's tuning, one per tuned option, for a comment in the step's script and for PIPEGEN.md (Plan G).
 * Works from the spec alone and never throws: values are cleaned (safeText), unknown options and odd shapes are left out.
 */
export function describeTuning(spec: StepSpec): string[] {
  try {
    const id: unknown = spec?.tool?.id;
    const t: unknown = spec?.choices?.tuning;
    if (typeof id !== 'string' || typeof t !== 'object' || t === null || Array.isArray(t)) return [];
    const out: string[] = [];
    for (const d of defsOf(id)) {
      if (!Object.hasOwn(t, d.id)) continue;
      const v = (t as Record<string, unknown>)[d.id];
      const values = Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
      if (values.length > 0) out.push(lineOf(d.describe(values)));
    }
    return out;
  } catch {
    return [];
  }
}
