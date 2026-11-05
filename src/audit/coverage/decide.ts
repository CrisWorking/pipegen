// Coverage mapper (see ../coverage.ts for the rules): which runs count for which need, and pipegen's own why texts.
import { posix } from 'node:path';
import { SCHEDULED_CATEGORIES } from '../../engine/need-ids.js';
import type { Layer, Need, Service } from '../../types.js';
import type { Coverage } from '../coverage.js';
import { MAX_HIT_DIRS, MAX_SERVICES } from './bounds.js';
import type { Hooks } from './hooks.js';
import { MAY_NOT_RUN, OLD_PREFIX, UNKNOWN_PREFIX } from './settings.js';
import type { CiLayer, Hit, Reason, Slot } from './types.js';

// ---------- why (pipegen's own text only) ----------

const MISSING_WHY: Readonly<Record<string, string>> = {
  secrets: 'Without a secret scan in CI, a key committed without the local hook is only found after it leaks.',
  sast: 'Without a code scan, common security bugs reach the main branch unnoticed.',
  deps: 'Without a dependency scan, packages with known vulnerabilities ship unnoticed.',
  'unit-tests': 'Without unit tests in CI, broken code is only found after it has been shared.',
  'full-tests': 'Without the full test suite before merge, broken code can reach the main branch.',
  lint: 'Without a lint check in CI, mistakes the linter would catch can be merged.',
  'format-lint': 'Without a format and lint hook, style problems are only found later, in CI or in review.',
  hooks: "Without a git hook manager, no check runs on a developer's machine before a commit.",
  'hooks-ci': 'Without running the hooks in CI, anyone who skips them locally is never caught.',
  'image-build': 'Without one image build in CI, the image that is scanned may not be the image that is deployed.',
  'image-scan': 'Without an image scan, known vulnerabilities in the container image ship unnoticed.',
  dast: 'Without a scan of the running app, security problems that only show at run time go unnoticed.',
  iac: 'Without an infrastructure scan, insecure Terraform settings can be merged and applied.',
  sbom: 'Without an SBOM, nobody can tell later which components went into a build.',
  signing: 'Without image signing, nothing proves that a deployed image came from this pipeline.',
  attestation: 'Without an attestation, nothing records how and where the image was built.',
};
/** Plan U final review M4: the same, for a package that is released and builds no image. */
const RELEASE_MISSING_WHY: Readonly<Record<string, string>> = {
  signing: 'Without release signing, nothing proves that a published release came from this pipeline.',
  attestation: 'Without an attestation, nothing records how and where the release was built.',
};
const PRECOMMIT_SECRETS_WHY = 'Without a secret scan before commit, a leaked key is in git history forever.';
export const GATE_WHY = 'No single required check sums up every scan, so a pull request with a failing scan can still be merged.';
export const DEPLOY_VERIFY_WHY = "Deploys don't check that the commit passed the pipeline, so an unchecked commit can be deployed.";
const FALLBACK_MISSING_WHY = 'No workflow or git hook in this repo runs this check.';

export const OPAQUE_WHY = {
  remoteWorkflow: "A job calls a reusable workflow from another repo, and pipegen can't see inside it.",
  ownerAction: "A step uses an action from the repo owner's own account, and pipegen can't see inside it.",
  localCode: "A step uses a local action that runs its own code, and pipegen can't see inside it.",
  secondLevel: "A called workflow or action calls another local one, and pipegen follows only one level, so it can't tell.",
  unreadable: "A job or step calls a local workflow or action that pipegen couldn't read (missing, a symbolic link, too large or not valid YAML), so it can't tell.",
  outside: "A job or step calls a local workflow or action that points outside the repo, so pipegen didn't read it.",
  truncated: "The workflows are too large to read in full, so pipegen can't tell.",
  workflowsUnreadable: "Some workflow files couldn't be read, so pipegen can't tell.",
  hookUnreadable: "The git hook file couldn't be read (a symbolic link, too large or not valid), so pipegen can't tell.",
  tooMany: "There are too many services or workflow steps to check in full, so pipegen can't tell.",
  unknownShell: "A step runs its commands with a `shell:` setting pipegen doesn't know, so it can't tell what runs.",
} as const;

const LAYER_DONE: Readonly<Record<Slot, string>> = {
  push: 'on every push',
  merge: 'on every pull request',
  deploy: 'when the code is deployed or released',
  scheduled: 'on a schedule or on every push to the default branch',
};
export { MAY_NOT_RUN };
const REASON_WHY: Readonly<Record<Reason, (subject: string, when: string) => string>> = {
  continue: (s) => `${s} runs, but is allowed to fail (continue-on-error), so it can't block anything.`,
  suppressed: (s) => `${s} runs, but its exit code is ignored (by ||, a pipe, an if, set +e, the background & or the step's shell), so it can't block anything.`,
  function: (s) => `${s} runs inside a shell function, so pipegen can't tell whether its failure fails the step.`,
  soft: (s) => `${s} runs, but is set not to fail on findings, so it can't block anything.`,
  inputs: (s) => `${s} runs, but its step sets more inputs than pipegen reads, so pipegen can't tell whether it blocks anything.`,
  'no-fail': (s) => `${s} runs, but doesn't fail on findings unless told to, so it can't block anything.`,
  never: (s) => `${s} reports findings but doesn't fail the job, so it can't block anything.`,
  condition: (s, when) => `${s} runs only when a condition holds, so it may not run ${when}.`,
  'script-condition': (s, when) => `${s} runs the check only under a condition in that script, so it may not run ${when}.`,
  'shell-condition': (s, when) => `${s} runs only under a condition in its shell code (an if or case, a loop over a variable, an && or || chain, or after an early exit), so it may not run ${when}.`,
  'hook-repo': (s) => `${s} comes from a pre-commit hook repo pipegen doesn't know, so pipegen can't tell what it really runs.`,
  files: (s) => `${s} runs only on the files its pre-commit files, exclude or types settings allow, and pipegen doesn't check which files those are.`,
  stage: (s) => `${s} is set up for another pre-commit stage, so it doesn't run before each commit.`,
  skip: (s) => `${s} runs, but SKIP or PREK_SKIP is set in this job, so some pre-commit hooks don't run here.`,
  changed: (s) => `${s} runs only on the files that changed between two commits, not on every file, so a problem in an untouched file isn't caught.`,
  part: (s) => `${s} runs only on part of the repo (a folder, a glob or a list of files), so a problem elsewhere isn't caught.`,
  ref: (s) => `${s} runs at a version pipegen can't place, so pipegen can't tell whether it does this check.`,
  'tox-env': (s) => `${s} runs, but a TOX… variable in this job (like TOXENV) picks which tox environments run, so pipegen can't tell if it runs the tests.`,
  'nox-env': (s) => `${s} runs, but a NOX… variable in this job (like NOXSESSION) picks which nox sessions run, so pipegen can't tell if it runs the tests.`,
  // Plan P Task 3 (a signature's own why, when it has one, is used for unavailable and needs-inputs)
  unavailable: (s) => `${s} runs, but this repo can't use it, so it checks nothing here.`,
  'needs-inputs': (s) => `${s} runs, but isn't set up to do this check, so it can't block anything.`,
  'some-jobs': (s) => `${s} runs, but pipegen found egress control in some release jobs only (or not as their first step), so the other release steps can reach any site.`,
  target: (s) => `${s} runs, but pipegen can't tell whether it scans a container image or a folder here.`,
  long: (s) => `${s} runs with more words than pipegen reads, so pipegen can't tell how it is set up.`,
  // fix round 1 (the run's own why names the variable or file, or the runner)
  config: (s) => `${s} runs, but a config file or variable here can turn it off, and pipegen doesn't follow it.`,
  runner: (s) => `${s} runs, but not on a GitHub-hosted runner it supports, outside a container, so it may not block anything.`,
  // ruling P33 (the run's own why names the never-list reason)
  'never-listed': (s) => `${s} runs, but this action is on pipegen's never-use list; pin a reviewed alternative.`,
};
/** Reasons whose run carries pipegen's own why from the signature (partialWhy, actionRef, unavailableWhy, requireInputs). */
const OWN_WHY: ReadonlySet<Reason> = new Set<Reason>(['never', 'ref', 'unavailable', 'needs-inputs', 'config', 'some-jobs', 'runner', 'never-listed']);

const HOOK_PLACE = { 'pre-commit': 'the pre-commit framework', husky: 'the husky pre-commit hook', lefthook: 'the lefthook pre-commit hook' } as const;
const HOOK_NAME = { 'pre-commit': 'the pre-commit framework', husky: 'husky', lefthook: 'lefthook' } as const;
export const HOOK_FILE = { 'pre-commit': '.pre-commit-config.yaml', husky: '.husky', lefthook: 'lefthook.yml' } as const;

// ---------- which runs count for which need (ruling S26, review C1) ----------

//
// A run in `dir` counts for a service when the service owns `dir` (the longest service path at or above it, '.' always
// at or above; on a tie the service listed first) or when the service sits below `dir` (a job run above several
// services covers each). A run at the root counts for every need, and a run whose dir can't be known only for
// repo-wide needs. The repo is hostile, so the work is linear, not needs × runs × services: each distinct dir is
// matched against the services once, through trees of path segments; one pass over the runs keeps, per (dir,
// category, layer), only the first run of each kind (the run the per-run loop used to pick, so `by` and `where` are
// unchanged); each need then reads those first runs for the dirs that count for it.

const normalPath = (s: string) => {
  const n = posix.normalize(s).replace(/\/+$/, '');
  return n === '' ? '.' : n;
};

const ALL = 0;  // every run, whatever its dir: what a repo-wide need reads
const ROOT = 1; // '.'

/** Distinct dirs that runs were found in, by id. Past MAX_HIT_DIRS a new dir gets no id (its runs count only in ALL). */
export class Dirs {
  readonly names: string[] = ['', '.'];
  private readonly ids = new Map<string, number>([['.', ROOT]]);
  capped = false;
  /** The dir's id, or -1: the dir can't be known (null) or is over the cap. */
  idOf(dir: string | null): number {
    if (dir === null) return -1;
    const known = this.ids.get(dir);
    if (known !== undefined) return known;
    if (this.names.length - 2 >= MAX_HIT_DIRS) {
      this.capped = true;
      return -1;
    }
    this.ids.set(dir, this.names.length);
    this.names.push(dir);
    return this.names.length - 1;
  }
}

// What a run is, for one layer: on the layer's trigger and nothing stops it blocking (FN), on the trigger under an
// `if:` (FC), on the trigger for another reason it can't block (FO), or on another trigger (NF).
const FN = 0;
const FC = 1;
const FO = 2;
const NF = 3;
const LAYER_SLOT: Readonly<Record<Slot, number>> = { push: 0, merge: 4, deploy: 8, scheduled: 12 };
const SLOTS: readonly Slot[] = ['push', 'merge', 'deploy', 'scheduled'];
const OPAQUE_KEY = '\0opaque'; // not a category: the opaque runs (they have none)

/**
 * P57 (C1): the language tag a per-service table key carries. A run is filed under its category plus each language it
 * checks ('*' = any language, '?' = one pipegen can't tell); a repo-wide need reads the plain category (every run).
 */
const ANY_LANG = '*';
export const UNSURE_LANG = '?';
const langKey = (key: string, lang: string) => `${key}\u0001${lang}`;
/** The keys whose runs check a service of these languages (P60 R4: a service may hold several): language-neutral ones and its own. */
export const matchKeys = (key: string, langs: readonly string[] | undefined): string[] => (langs === undefined ? [key] : [langKey(key, ANY_LANG), ...langs.map((l) => langKey(key, l))]);
/** The keys whose runs may or may not check a service of this language (pipegen can't tell which languages they check). */
const unsureKeys = (key: string, langs: readonly string[] | undefined): string[] => (langs === undefined ? [] : [langKey(key, UNSURE_LANG)]);

/** Per (category, language, dir): the index of the first run of each kind, for each layer (-1 = none). */
export class Firsts {
  private readonly byKey = new Map<string, Map<number, Int32Array>>();

  constructor(readonly hits: readonly Hit[], dirs: Dirs) {
    for (let i = 0; i < hits.length; i++) {
      const h = hits[i] as Hit;
      // P50 (I4): an unknown run whose folder can't be known (a script pipegen can't place) could be in any service's
      // folder, so it sits at the root too: every service's row it could cover is unknown, never missing. A real run
      // there never does (that would be a guessed covered).
      const d = h.dir === null && h.categories.length > 0 && h.categories.every((c) => c.startsWith(UNKNOWN_PREFIX)) ? ROOT : dirs.idOf(h.dir);
      const langs = h.opaque || h.langs === undefined ? [ANY_LANG] : h.langs;
      // P59 (3): a run given a path pipegen can't place, that would cover, is unknown for the services under its folder
      // (it still counts for repo-wide rows); one with a reason already is only partial there, never covered
      const unplaced = h.unplaced !== undefined && h.reason === null;
      for (const key of h.opaque ? [OPAQUE_KEY] : h.categories) {
        this.put(key, ALL, h, i);
        const here = unplaced && !key.startsWith(UNKNOWN_PREFIX) ? `${UNKNOWN_PREFIX}${key}` : key;
        if (d >= 0) for (const lang of langs) this.put(langKey(here, lang), d, h, i);
      }
    }
  }

  private put(key: string, dir: number, h: Hit, i: number): void {
    let byDir = this.byKey.get(key);
    if (!byDir) this.byKey.set(key, (byDir = new Map()));
    let at = byDir.get(dir);
    if (!at) byDir.set(dir, (at = new Int32Array(16).fill(-1)));
    for (const layer of SLOTS) {
      const slot = LAYER_SLOT[layer] + (!h.fit[layer] ? NF : h.reason === null ? FN : MAY_NOT_RUN.has(h.reason) ? FC : FO);
      if ((at[slot] as number) < 0) at[slot] = i;
    }
  }

  /** The first run under these keys, in these dirs, of one of these kinds on the layer. */
  first(keys: string | readonly string[], dirs: readonly number[], layer: Slot, kinds: readonly number[]): Hit | undefined {
    let best = -1;
    for (const key of typeof keys === 'string' ? [keys] : keys) {
      const byDir = this.byKey.get(key);
      if (!byDir) continue;
      for (const d of dirs) {
        const at = byDir.get(d);
        if (!at) continue;
        for (const k of kinds) {
          const i = at[LAYER_SLOT[layer] + k] as number;
          if (i >= 0 && (best < 0 || i < best)) best = i;
        }
      }
    }
    return best < 0 ? undefined : this.hits[best];
  }
}

interface SegNode { kids: Map<string, SegNode>; id: number }
const segNode = (): SegNode => ({ kids: new Map(), id: -1 });
function segInsert(tree: SegNode, path: string, id: number): void {
  let n = tree;
  for (const seg of path.split('/')) {
    let next = n.kids.get(seg);
    if (!next) n.kids.set(seg, (next = segNode()));
    n = next;
  }
  if (n.id < 0) n.id = id;
}

/** Which dirs count for each service. Built once per mapCoverage call, after every run's dir is known. */
export class Scope {
  /** More services than MAX_SERVICES: per-service needs read only the runs at the root. */
  readonly capped: boolean;
  private readonly target = new Map<string, string>(); // service name → path of the first service with that name
  private readonly languages = new Map<string, readonly string[]>(); // P57 (C1), P60 (R4): service name → the languages of the first service with that name
  private readonly owned = new Map<string, number[]>(); // service name → the dirs it owns
  private readonly dirTree = segNode();
  private readonly memo = new Map<string, readonly number[]>();

  constructor(services: readonly Service[], dirs: Dirs) {
    this.capped = services.length > MAX_SERVICES;
    for (const s of services) if (!this.languages.has(s.name)) this.languages.set(s.name, [s.language, ...(s.alsoLanguages ?? [])]);
    if (this.capped) return;
    const tree = segNode();
    let root = -1;
    services.forEach((s, i) => {
      const path = normalPath(s.path);
      if (!this.target.has(s.name)) this.target.set(s.name, path);
      if (path !== '.') segInsert(tree, path, i);
      else if (root < 0) root = i;
    });
    for (let d = ROOT + 1; d < dirs.names.length; d++) {
      const dir = dirs.names[d] as string;
      segInsert(this.dirTree, dir, d);
      // the owner: the deepest service path at or above dir; '.' (length 1) wins a tie on length by coming first
      let n: SegNode | undefined = tree;
      let best = -1;
      let bestLen = 0;
      let len = -1;
      for (const seg of dir.split('/')) {
        n = n.kids.get(seg);
        if (!n) break;
        len += seg.length + 1;
        if (n.id >= 0) {
          best = n.id;
          bestLen = len;
        }
      }
      if (root >= 0 && (best < 0 || bestLen < 1 || (bestLen === 1 && root < best))) best = root;
      if (best < 0) continue;
      const name = (services[best] as Service).name;
      const list = this.owned.get(name);
      if (list) list.push(d);
      else this.owned.set(name, [d]);
    }
  }

  /** P57 (C1), P60 (R4): the languages of a service need's service (['other'] when pipegen can't find it); undefined for a repo-wide need. */
  languageOf(service: string | undefined): readonly string[] | undefined {
    return service === undefined ? undefined : (this.languages.get(service) ?? ['other']);
  }

  /** The dirs whose runs count for a need of this service (ALL for a repo-wide need). */
  dirsOf(service: string | undefined): readonly number[] {
    if (service === undefined) return [ALL];
    if (this.capped) return [ROOT];
    const known = this.memo.get(service);
    if (known) return known;
    const out = [ROOT];
    const path = this.target.get(service);
    if (path !== undefined) {
      for (const d of this.owned.get(service) ?? []) out.push(d); // a loop, not a spread: up to MAX_HIT_DIRS entries
      if (path !== '.') {
        // the dirs above the service's path: a run there covers each service below it
        const segs = path.split('/');
        let n: SegNode | undefined = this.dirTree;
        for (let k = 0; k < segs.length - 1 && n; k++) {
          n = n.kids.get(segs[k] as string);
          if (n && n.id >= 0) out.push(n.id);
        }
      }
    }
    this.memo.set(service, out);
    return out;
  }
}

function missingWhy(need: Need, d?: Pick<Decide, 'noImage'>): string {
  if (need.layer === 'pre-commit' && need.category === 'secrets') return PRECOMMIT_SECRETS_WHY;
  const release = d !== undefined && Object.hasOwn(RELEASE_MISSING_WHY, need.category) && d.noImage(need) ? RELEASE_MISSING_WHY[need.category] : undefined;
  return release ?? MISSING_WHY[need.category] ?? FALLBACK_MISSING_WHY;
}

const located = (h: { by?: string; where: string }) => ({ ...(h.by === undefined ? {} : { by: h.by }), where: h.where });

/** The reason that counts for this need: a need that doesn't block (format-lint) only cares whether the tool runs. */
const effectiveReason = (need: Need, reason: Reason | null): Reason | null => (need.blocking || (reason !== null && MAY_NOT_RUN.has(reason)) ? reason : null);
/** The kinds of run that cover a need, and the kinds that run on its trigger but can't block it. */
const coverKinds = (need: Need) => (need.blocking ? [FN] : [FN, FO]);
const partialKinds = (need: Need) => (need.blocking ? [FC, FO] : [FC]);

/** Task 9: a coverage run that is "soft" has its minimum turned off on the command line, or its config swapped; it isn't about findings. */
const COVERAGE_SOFT_WHY = (s: string) => `${s} measures coverage, but a flag on its command line turns the minimum off (0, or not a number) or swaps the coverage config file, so a drop in coverage can't be counted on to fail it.`;

/** P57 (C1): a run of a tool whose languages pipegen can't tell, for a service it may or may not check. */
const UNSURE_LANG_WHY = (s: string) => `${s} runs, but pipegen can't tell whether it checks this service's language, so it may check nothing here.`;

function reasonWhy(h: { subject: string; partialWhy?: string }, reason: Reason, when: string, category?: string): string {
  if (reason === 'soft' && category === 'coverage') return COVERAGE_SOFT_WHY(h.subject);
  return OWN_WHY.has(reason) && h.partialWhy !== undefined ? h.partialWhy : REASON_WHY[reason](h.subject, when);
}

export interface Decide { ci: Firsts; hooks: Firsts; scope: Scope; dirsCapped: boolean; truncated: boolean; unreadable: boolean; noImage: (need: Need) => boolean }

/** A per-service need that a cap kept pipegen from checking in full: never missing, never covered by the cap. */
const capped = (need: Need, d: Decide) => need.service !== undefined && (d.scope.capped || d.dirsCapped);

export function ciCoverage(need: Need, ciLayer: CiLayer, d: Decide): Coverage {
  // Plan P Task 3: a scheduled check (merge-layer need) is read on the scheduled trigger, not on pull requests
  const layer: Slot = (SCHEDULED_CATEGORIES as ReadonlySet<string>).has(need.category) ? 'scheduled' : ciLayer;
  const dirs = d.scope.dirsOf(need.service);
  // P57 (C1): only runs of a tool that checks the service's language count; one whose languages pipegen can't tell is partial
  const lang = d.scope.languageOf(need.service);
  const cat = matchKeys(need.category, lang);
  const cover = d.ci.first(cat, dirs, layer, coverKinds(need));
  if (cover) return { need, status: 'covered', ...located(cover), why: `${cover.subject} runs ${LAYER_DONE[layer]}.` };
  const unknownRun = d.ci.first([...matchKeys(`${UNKNOWN_PREFIX}${need.category}`, lang), ...unsureKeys(`${UNKNOWN_PREFIX}${need.category}`, lang)], dirs, layer, [FN, FC, FO]);
  const unknownWhy = unknownRun?.unplaced ?? unknownRun?.partialWhy;
  if (unknownRun !== undefined && unknownWhy !== undefined) return { need, status: 'unknown', ...located(unknownRun), why: unknownWhy };
  const strongOpaque = d.ci.first(matchKeys(OPAQUE_KEY, lang), dirs, layer, [FN]);
  if (strongOpaque) return { need, status: 'unknown', ...located(strongOpaque), why: strongOpaque.why as string };
  if (d.truncated) return { need, status: 'unknown', why: OPAQUE_WHY.truncated };
  const partialRight = d.ci.first(cat, dirs, layer, partialKinds(need));
  if (partialRight) {
    return { need, status: 'partial', ...located(partialRight), why: reasonWhy(partialRight, effectiveReason(need, partialRight.reason) as Reason, LAYER_DONE[layer], need.category) };
  }
  const partialTrigger = d.ci.first(cat, dirs, layer, [NF]);
  if (partialTrigger) {
    const why = `${partialTrigger.subject} runs, but not ${LAYER_DONE[layer]}.`;
    // J3a (S5): a push row that is partial only because the run's workflow has no every-push trigger. creditEquivalents
    // reads this mark (and the row's unchanged `why`) and nothing else about why the row is partial.
    const mark = layer === 'push' && need.layer === 'push' && partialTrigger.reason === null && partialTrigger.fit.pushDefault === true
      ? { trigger: { kind: 'not-every-push' as const, why } } : {};
    return { need, status: 'partial', ...located(partialTrigger), why, ...mark };
  }
  const unsure = d.ci.first(unsureKeys(need.category, lang), dirs, layer, [FN, FC, FO, NF]);
  if (unsure) return { need, status: 'partial', ...located(unsure), why: UNSURE_LANG_WHY(unsure.subject) };
  const weakOpaque = d.ci.first(matchKeys(OPAQUE_KEY, lang), dirs, layer, [NF]);
  if (weakOpaque) return { need, status: 'unknown', ...located(weakOpaque), why: weakOpaque.why as string };
  if (d.unreadable) return { need, status: 'unknown', why: OPAQUE_WHY.workflowsUnreadable };
  if (capped(need, d)) return { need, status: 'unknown', why: OPAQUE_WHY.tooMany };
  // Task 5 fix round 1 (C1): a version known not to do this check (pypi-publish before v1.11.0): missing, saying why
  const old = d.ci.first(matchKeys(`${OLD_PREFIX}${need.category}`, lang), dirs, layer, [FN, FC, FO, NF]);
  if (old && old.partialWhy !== undefined) return { need, status: 'missing', ...located(old), why: old.partialWhy };
  return { need, status: 'missing', why: missingWhy(need, d) };
}

/** Plan P Task 4: the run behind a CI row that is partial (the first of its kind ciCoverage picks), for the coverage minimum check. */
export function firstPartialHit(need: Need, ciLayer: CiLayer, d: Decide): Hit | undefined {
  return d.ci.first(matchKeys(need.category, d.scope.languageOf(need.service)), d.scope.dirsOf(need.service), ciLayer, partialKinds(need));
}

export function hookCoverage(need: Need, hooks: Hooks, d: Decide): Coverage {
  const m = hooks.manager;
  if (need.category === 'hooks') {
    return m === null
      ? { need, status: 'missing', why: missingWhy(need) }
      : { need, status: 'covered', by: m, where: m === 'lefthook' && hooks.where !== '' ? hooks.where : HOOK_FILE[m], why: `The repo uses ${HOOK_NAME[m]} to run git hooks.` };
  }
  if (m !== null) {
    // the hook's runs sit in their own table, every one on the "push" layer's trigger
    const dirs = d.scope.dirsOf(need.service);
    const lang = d.scope.languageOf(need.service);
    const cat = matchKeys(need.category, lang);
    const cover = d.hooks.first(cat, dirs, 'push', coverKinds(need));
    if (cover) return { need, status: 'covered', by: cover.by as string, where: hooks.where, why: `${cover.subject} runs in ${HOOK_PLACE[m]} before each commit.` };
    const unknownRun = d.hooks.first([...matchKeys(`${UNKNOWN_PREFIX}${need.category}`, lang), ...unsureKeys(`${UNKNOWN_PREFIX}${need.category}`, lang)], dirs, 'push', [FN, FC, FO]);
    const unknownWhy = unknownRun?.unplaced ?? unknownRun?.partialWhy;
    if (unknownRun !== undefined && unknownWhy !== undefined) return { need, status: 'unknown', by: unknownRun.by as string, where: hooks.where, why: unknownWhy };
    const partial = d.hooks.first(cat, dirs, 'push', partialKinds(need));
    if (partial) return { need, status: 'partial', by: partial.by as string, where: hooks.where, why: reasonWhy(partial, effectiveReason(need, partial.reason) as Reason, 'before each commit', need.category) };
    const unsure = d.hooks.first(unsureKeys(need.category, lang), dirs, 'push', [FN, FC, FO]);
    if (unsure) return { need, status: 'partial', by: unsure.by as string, where: hooks.where, why: UNSURE_LANG_WHY(unsure.subject) };
    if (!hooks.readable) return { need, status: 'unknown', where: hooks.where, why: OPAQUE_WHY.hookUnreadable };
    if (capped(need, d)) return { need, status: 'unknown', why: OPAQUE_WHY.tooMany };
  }
  return { need, status: 'missing', why: missingWhy(need) };
}
