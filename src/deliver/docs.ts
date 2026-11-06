// PIPEGEN.md (v0.2 Plan G, G9; plan Task 6; rulings B7, S22, S28, B3, B6, B8, S9, S31). The file pipegen writes into the user's repository, in plain
// English for a non-expert. A PURE function of the draft (and the reviewed list): the referee builds it again from the draft it judges and requires the
// same bytes (docRecomputeProblem, called by the referee), so a bug in a builder can not ship text the referee never saw. The line judge
// (src/engine/created-judges/pipegen-doc.ts) stays under it as the net.
//
// What goes in, and how:
//   - fixed text, written by this file, in the judge's alphabet (letters, digits and . , ; : ! ? ' " ( ) / - _ + = % * ~, inline code, no emoji);
//   - Plan F's doc-final strings (the transcript, the scoreboard, suggestion reasons, test decision reasons, the not-proven reasons) and the notes other
//     layers built (draft.doc): written RAW when they pass the judge's grammar, never through safeMarkdown (its cut mark and backslashes are refused);
//     one that does not pass loses only the characters the judge refuses (a blank in their place), and failing that goes through cleanForDoc;
//   - repo text (a service name, a suggestion name, a path): cleanForDoc, always, inside quotation marks so no neighbouring character can join it into a
//     bare URL or an emoji shortcode (the blank rule, F-9);
//   - the user's typed values (the vault): every variable string is scrubbed with the ACTIVE vault before any cut (F4-R14), and the judge checks the
//     whole text on its cleaned forms. Run the builder inside withActiveVault (pipegenDocWith does; the referee already does).
// No need keys, item ids, objection ids or dispute keys are ever printed, and neither is the creator's own AI note ("The AI explained ...").
import { NEED_ID_CATEGORY } from '../engine/need-ids.js';
import { PUSH_CREDIT_WARNING } from '../audit/coverage/equivalents.js';
import { cleanForDoc, CLEAN_DOC_MAX } from '../debate/clean.js';
import { centralProjectName } from '../engine/central-path.js';
import { CALLER_WORKFLOW, LOCAL_MERGE_WORKFLOW, NIGHTLY_WORKFLOW, PUSH_WORKFLOW } from '../engine/job-rules.js';
import { pipegenDocProblems } from '../engine/created-judges/pipegen-doc.js';
import { BOOTSTRAP_PROOFS_NOTE } from '../engine/reviewed.js';
import { describeTuning } from '../engine/tuning.js';
import { HUSKY_NO_CI_NOTE } from '../layers/precommit.js';
import { GATE_CHECK_NAME, type CreatedFile, type PipelineDraft, type ReviewedTool, type Service, type StepSpec } from '../types.js';
import { scrubActive, withActiveVault } from '../util/known-values.js';
import type { KnownValueCheck } from '../types.js';

// ---------- fixed texts that other sources own ----------

/**
 * C4's note (gate/src/baseline.ts HISTORY_REWRITE_NOTE). Copied, not imported: gate/ is bundled and does not change in this task. A test keeps the two
 * equal (ruling G9-R0 9).
 */
export const HISTORY_REWRITE_NOTE = 'After rewriting main\'s history (a force-push), the gate may stay in block mode until 10 green pushes to main have followed.';
/** The start of GJ's hooks-ci note for husky (src/layers/jobs.ts HOOKS_CI_NOTES.husky): it says what G6's husky note says, so only one of them is printed. */
const GJ_HUSKY_NOTE_START = "husky's hooks are shell scripts";
/** The creator's own note (src/create/tests.ts, dockerfile.ts): AI text, never printed (D-m5). */
const AI_NOTE_START = 'The AI explained';

/** The titles of the 18 sections, in order (plan Task 6; the first one comes first so that no limit is hidden). */
export const SECTION_TITLES: readonly string[] = Object.freeze([
  'What your GitHub plan allows',
  'What pipegen set up',
  'Fix a blocked pull request',
  'The four layers',
  'Suggestions (not running)',
  'Files pipegen created and why',
  'Your tests',
  'Skipped parts',
  'Signing',
  'Deploys',
  'Not proven yet',
  'Pipeline integrity',
  'Warn mode',
  'Deploying old commits and retention',
  'The debate',
  'Hooks setup',
  'Run again, finish, verify, update and uninstall',
  'Words used',
]);

/** The warn mode sentence (plan section 13): never a fixed date. */
export const WARN_MODE_TEXT = 'Warn mode lasts until 7 days after you merge (the exact date is set by `npx pipegen finish`).';

// ---------- the "Fix a blocked pull request" table ----------

/**
 * One row for each reason the gate can block or warn (gate/src/decide.ts header, rules 1-9, and gate/src/integrity.ts). `id` is for tests and never printed.
 * `message` is what the gate's summary shows (the rule id in code where there is one), `means` what it means, `todo` what to do.
 */
export const GATE_REASONS: readonly { id: string; message: string; means: string; todo: string }[] = Object.freeze([
  { id: 'new-finding', message: 'A new critical or high finding', means: 'A check found a serious problem that the base branch did not have.', todo: 'Fix it in the pull request. A false alarm is for a code owner to judge; adding a suppression comment is flagged itself.' },
  { id: 'new-secret', message: 'A new secret', means: 'A scan found a password, key or token in the files of this pull request.', todo: 'Remove it, and treat it as leaked: rotate it. A secret that was ever pushed stays in the history.' },
  { id: 'secret-in-range', message: 'A secret in a commit of this pull request', means: 'A commit of the pull request added a secret, even if a later commit took it out. Any finding in the commit range blocks.', todo: 'Rotate the secret. Then rewrite the branch so the commits no longer hold it, and push again.' },
  { id: 'protected-path', message: 'integrity:protected-path (this file is part of the pipeline)', means: 'The pull request changes a workflow, a tool config or an ignore file, and no code owner approved this exact commit.', todo: 'Ask a code owner to approve the latest commit. After a new push the approval has to be given again.' },
  { id: 'suppression', message: 'integrity:suppression (lines suppress a check)', means: 'Added lines turn a check off for that code (a suppression comment).', todo: 'Remove the suppression, or ask a code owner to approve this exact commit.' },
  { id: 'stale-approval', message: 'An approval on an older commit', means: 'A code owner approved an earlier commit of the pull request. An approval counts only for the commit it was given on.', todo: 'Ask the code owner to approve the latest commit.' },
  { id: 'incomplete-list', message: 'integrity:incomplete-list (the list of changed files is incomplete)', means: 'The pull request is too large to check (3,000 or more files), or GitHub did not give the whole file list, so the gate can not see every change.', todo: 'Split the pull request into smaller ones, or run the checks again if the branch moved.' },
  { id: 'no-patch', message: 'integrity:no-patch (the gate can not read this file\'s changes)', means: 'GitHub gave no readable change for that file, so the gate can not check it for suppressions.', todo: 'Make the change smaller or split the file change into its own pull request. A code owner can approve the exact commit.' },
  { id: 'case-extension', message: 'integrity:case-extension', means: 'A new file has a scanned language\'s extension in another letter case, so the scanners would skip it while a runtime may still load it.', todo: 'Rename the file to the lower-case extension.' },
  { id: 'tool-error', message: 'A tool error', means: 'A check could not finish (it crashed, ran out of time or its result could not be read). A required check that errors blocks.', todo: 'Read the check\'s log, fix the cause and run the checks again.' },
  { id: 'fork-not-run', message: 'Not run on a fork pull request', means: 'GitHub gives no secrets to a pull request from a fork, so a check that needs one did not run. If the check is required, the pull request is blocked.', todo: 'A maintainer can push the branch into this repository and open the pull request from there.' },
  { id: 'not-proven', message: 'A check marked not proven', means: 'pipegen could not prove the check on your repository yet (see Not proven yet). It warns and does not block.', todo: 'Set the secret names listed under Not proven yet. The nightly run then opens an issue and `npx pipegen update` applies the change.' },
  { id: 'skipped', message: 'A check marked skipped', means: 'You skipped that part with --skip, so it has no job and gives no protection.', todo: 'Run pipegen again without the skip if you want the part.' },
  { id: 'tampered', message: 'A check\'s result does not match', means: 'The result file of a check is missing, or its checksum differs from the one its job reported. The gate does not trust it and blocks.', todo: 'Run the checks again. If it keeps happening, someone changed the pipeline: run `npx pipegen verify`.' },
  { id: 'no-base', message: 'No base to compare with', means: 'The base scan did not run on the base commit of this event, so every finding counts as new. On the pull request that installs pipegen it warns instead.', todo: 'Run the checks again. On a new install, merge the setup pull request and the next pull request has a base.' },
  { id: 'malicious', message: 'A known malicious package', means: 'A dependency matches a malicious-package advisory (MAL-). It blocks even when it is old.', todo: 'Remove the package and rotate anything it could have read.' },
  { id: 'dependency', message: 'A new dependency problem or an unknown licence', means: 'A package added by the pull request has a new advisory, or a licence the check does not know. A new advisory blocks; an unknown licence warns because it needs a human.', todo: 'Pick another package, or have a person check the licence.' },
  { id: 'no-coverage', message: 'No coverage', means: 'A check ran but could not look (for example a scan that reported nothing because it had nothing to read). A required one blocks, because nothing was proven.', todo: 'Fix what the check could not read, then run the checks again.' },
  { id: 'warn-mode', message: 'A warning in warn mode', means: 'The check is still in warn mode, so old findings and medium ones warn. A new critical, high or secret finding still blocks.', todo: 'Fix the warnings before warn mode ends (see Warn mode).' },
  { id: 'warn-ended', message: 'Warn mode ended', means: 'The warn period is over, so what used to warn now blocks.', todo: 'Fix the finding. Nothing else changed.' },
  { id: 'settings', message: 'A gate settings problem', means: 'The gate\'s own settings are wrong (for example a required check listed as not proven). The gate blocks, because it can not trust itself.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'image-no-base', message: 'An image finding with no base', means: 'Image findings have no base to compare with yet: on the pull request that installs pipegen they warn, and on every other pull request they block.', todo: 'Fix the finding in the image or its base image.' },
  { id: 'missing-check', message: 'The required check `pipegen / gate` never reported', means: 'GitHub waits for a check that did not run, so the pull request can not merge.', todo: 'Run the workflow again. With the org required workflow, re-run the `pipegen required` run after a code owner approves.' },
]);

// ---------- the four layers ----------

const LAYERS = ['pre-commit', 'push', 'merge', 'deploy'] as const;
const LAYER_TEXT: Readonly<Record<(typeof LAYERS)[number], string>> = Object.freeze({
  'pre-commit': 'Runs on your machine before each commit.',
  push: 'Runs on a push to a branch that has no open pull request.',
  merge: `Runs on every pull request and decides whether it can merge. The gate (the check \`${GATE_CHECK_NAME}\`) reads every result.`,
  deploy: 'Runs on a push to the default branch: it builds, signs and checks the images that are deployed.',
});
/** Label and plain reason for every need category. */
const CATEGORY_TEXT: Readonly<Record<string, readonly [string, string]>> = Object.freeze({
  secrets: ['Secret scan', 'Looks for passwords, keys and tokens in the code and in the commits of a pull request.'],
  sast: ['Code scan', 'Looks for insecure code patterns in your source.'],
  deps: ['Dependency scan', 'Looks for known vulnerabilities in the packages you depend on.'],
  'unit-tests': ['Unit tests', 'Runs your tests so a change that breaks them is caught.'],
  'full-tests': ['Full tests', 'Runs your whole test suite with the services it needs.'],
  lint: ['Lint', 'Checks code style and common mistakes.'],
  'format-lint': ['Format and lint', 'Checks formatting and common mistakes on the files you commit.'],
  hooks: ['Local hooks', 'Runs checks on your machine before each commit.'],
  'hooks-ci': ['Hooks in CI', 'Runs the same hooks in CI, so skipping them locally does not skip them for the team.'],
  'image-build': ['Image build', 'Builds the container image of the pull request without publishing it.'],
  'image-scan': ['Image scan', 'Scans the built image for known vulnerabilities.'],
  dast: ['Running app scan', 'Starts the app and probes it the way an attacker would.'],
  iac: ['Infrastructure scan', 'Checks Terraform, Kubernetes and similar files for risky settings.'],
  sbom: ['Software bill of materials', 'Lists what is inside the published image.'],
  signing: ['Image signing', 'Signs the published image so a deploy can check where it came from.'],
  attestation: ['Build attestation', 'Records how the image was built.'],
  'deploy-verify': ['Verify before deploy', 'Checks that the commit being deployed passed the gate and that the image is the signed one.'],
  gate: ['The gate', 'Reads every result and decides whether the pull request can merge.'],
  format: ['Format check', 'Checks that files are formatted.'],
  'type-check': ['Type check', 'Runs the type checker.'],
  coverage: ['Test coverage', 'Checks how much of the code the tests run.'],
  'dead-code': ['Dead code', 'Finds code and packages that nothing uses.'],
  duplication: ['Copy-paste check', 'Finds code copied from other places in the repository.'],
  'dockerfile-lint': ['Dockerfile lint', 'Checks Dockerfiles for risky or wasteful steps.'],
  'workflow-lint': ['Workflow lint', 'Checks GitHub workflow files for unsafe patterns.'],
  'workflow-pin-check': ['Workflow pin check', 'Checks that the actions in workflows are pinned to a commit.'],
  'dependency-review': ['New dependency check', 'Looks at the dependencies a pull request adds.'],
  licences: ['Licence check', 'Checks the licences of your dependencies.'],
  'api-dast': ['API scan', 'Tests the running API against its description.'],
  publishing: ['Publishing', 'Publishes a package with a short-lived token instead of a stored one.'],
  egress: ['Network block', 'Limits which hosts a CI job can reach.'],
  'update-config': ['Update settings', 'Keeps dependencies and actions up to date.'],
  scorecard: ['OpenSSF Scorecard', 'Scores the repository on common supply-chain practices.'],
  fuzzing: ['Fuzzing', 'Feeds odd input to your code to find crashes.'],
});
const categoryOf = (id: string, fallback: string): string => (Object.hasOwn(NEED_ID_CATEGORY, id) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[id] as string : fallback);

/** What a part's skip takes away (plan section 8: the protection that is missing because of it). */
const SKIP_MISSING: Readonly<Record<string, string>> = Object.freeze({
  tests: 'Nothing runs your tests in CI, so a change that breaks them is not caught.',
  precommit: 'There are no local hooks, so a secret or a style problem is only caught in CI.',
  docker: 'pipegen wrote no Dockerfile, so a service without one has no image to build and scan.',
  compose: 'pipegen wrote no test services file, so checks that need a database or a queue can not start them.',
  deploy: 'There is no image publish, signing or verify before a deploy, so a deploy is not checked against the gate.',
  locks: 'pipegen applies no merge locks, so nothing forces the required check or a review before merging.',
  slack: 'There are no Slack messages about findings.',
  'test-migration': 'pipegen did not change your test runner, so the starter tests may not run with it.',
});

// ---------- writing helpers ----------

const STUB_OPTS = { owner: 'o', repo: 'r', containsKnownValue: (): boolean => false };
// a variable string never holds a link or a bracket: the one link of the file is built by secretsLink, and the stub owner and repo would let a link to them through
const itemOk = (s: string): boolean => s !== '' && !/[[\]]/.test(s) && pipegenDocProblems(`- ${s}`, STUB_OPTS).length === 0;
const ALLOWED_CH = /^[\p{L}\p{N} .,;:!?'"()/\-_+=%*~`]$/u;
/** `s` with each character the judge refuses replaced by a blank (the meaning stays; ruling G9-R0 7). */
const mild = (s: string): string => Array.from(s).map((c) => (ALLOWED_CH.test(c) ? c : ' ')).join('').replace(/ {2,}/g, ' ').trim();
const oneLine = (s: string): string => s.replace(/\r\n?|[\n\v\f\u0085\u2028\u2029\t]+/g, ' ').trim();
/** The cap of a variable line (cleanForDoc's own default). */
const CAP = CLEAN_DOC_MAX;
const isStr = (x: unknown): x is string => typeof x === 'string';
const strs = (x: unknown): string[] => (Array.isArray(x) ? x.filter(isStr) : []);

/**
 * A variable string for a list item or a table cell: scrubbed with the active vault BEFORE any cut (F4-R14), then written as it is when it passes the
 * judge's grammar, else with the characters the judge refuses blanked, else through cleanForDoc. Over the cap it is cut by cleanForDoc (after the scrub).
 */
function fit(raw: unknown, max: number = CAP): string {
  const scrubbed = scrubActive(isStr(raw) ? raw : '');
  const s = oneLine(scrubbed);
  if (Array.from(s).length <= max) {
    if (itemOk(s)) return s;
    const m = mild(s);
    if (itemOk(m)) return m;
  }
  return cleanForDoc(scrubbed, max);
}
/** Repo text (a service name, a suggestion name, a path): cleanForDoc after the vault scrub, in quotation marks so no neighbour joins it (F-9). */
const q = (raw: unknown, max = 120): string => `"${cleanForDoc(scrubActive(isStr(raw) ? raw : ''), max)}"`;
const code = (s: string): string => (s !== '' && /^[\p{L}\p{N} .,;:!?'"()/\-_+=%*~]+$/u.test(s) && itemOk(`\`${s}\``) ? `\`${s}\`` : fit(s));

class Doc {
  readonly lines: string[] = [];
  /** A list is open (so the next paragraph needs a blank line before it). */
  private open = false;
  h(level: 1 | 2 | 3, text: string): void { this.close(); this.lines.push(`${'#'.repeat(level)} ${text}`, ''); }
  p(text: string): void { this.close(); this.lines.push(text, ''); }
  li(text: string): void { this.open = true; this.lines.push(`- ${text}`); }
  /** A fenced block (the judge's text info string). */
  fence(info: 'sh' | 'text' | 'yaml', body: readonly string[]): void { this.close(); this.lines.push(`\`\`\`${info}`, ...body, '```', ''); }
  row(cells: readonly string[]): void { this.open = true; this.lines.push(`| ${cells.join(' | ')} |`); }
  private close(): void { if (this.open) { this.lines.push(''); this.open = false; } }
  text(): string { this.close(); return `${this.lines.join('\n').replace(/\n+$/, '')}\n`; }
}

/** A note (a build note, a lock note) as list items: one line is one item; several lines become the first line and a text fence of the rest. */
function noteItems(d: Doc, raw: string): void {
  const scrubbed = scrubActive(raw);
  const lines = scrubbed.split(/\r\n?|[\n\u2028\u2029]/);
  const first = lines[0] ?? '';
  if (lines.length > 1) {
    const rest = lines.slice(1).filter((l) => l.trim() !== '');
    const snippet = ['```text', ...rest, '```'].join('\n');
    if (itemOk(oneLine(first)) && rest.length > 0 && rest.length <= 40 && pipegenDocProblems(snippet, STUB_OPTS).length === 0) {
      d.li(oneLine(first));
      d.fence('text', rest);
      return;
    }
  }
  d.li(fit(scrubbed));
}

const DEFAULT_DOC = { transcript: [], deployGaps: [], lockNotes: [], estimates: { monthlyMinutes: 0, includedMinutes: null }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] } as const;
type DocData = {
  transcript: string[]; deployGaps: { path: string; triggers: string[]; why: string }[]; lockNotes: string[]; est: { monthlyMinutes: number; includedMinutes: number | null; prWaitMinutes?: number } | null;
  setupCommand: string; testNotes: string[]; uncoveredMinimum: { category: string; why: string; service?: string }[]; notes: string[]; credits: { text: string; kind: string }[];
};
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
/** draft.doc read defensively: whatever shape a caller hands over, the builder reads only strings and whole numbers. */
function dataOf(draft: PipelineDraft): DocData {
  const raw: unknown = draft.doc ?? DEFAULT_DOC;
  const o = isObj(raw) ? raw : {};
  const list = (k: string): unknown[] => (Array.isArray(o[k]) ? (o[k] as unknown[]) : []);
  const est = isObj(o.estimates) ? o.estimates : {};
  const whole = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  return {
    transcript: strs(o.transcript),
    deployGaps: list('deployGaps').filter(isObj).map((g) => ({ path: isStr(g.path) ? g.path : '', triggers: strs(g.triggers), why: isStr(g.why) ? g.why : '' })),
    lockNotes: strs(o.lockNotes),
    est: whole(est.monthlyMinutes) ? { monthlyMinutes: est.monthlyMinutes, includedMinutes: whole(est.includedMinutes) ? est.includedMinutes : null, ...(whole(est.prWaitMinutes) ? { prWaitMinutes: est.prWaitMinutes } : {}) } : null,
    setupCommand: isStr(o.setupCommand) ? o.setupCommand : '',
    testNotes: strs(o.testNotes),
    uncoveredMinimum: list('uncoveredMinimum').filter(isObj).map((u) => ({ category: isStr(u.category) ? u.category : '', why: isStr(u.why) ? u.why : '', ...(isStr(u.service) ? { service: u.service } : {}) })),
    notes: strs(o.notes),
    credits: list('credits').filter(isObj).filter((c) => isStr(c.text)).map((c) => ({ text: c.text as string, kind: isStr(c.kind) ? c.kind : '' })),
  };
}

// ---------- facts read from the draft ----------

const NAME_OK = /^[A-Za-z0-9._-]{1,100}$/;
const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const hasCat = (draft: PipelineDraft, cat: string): boolean => draft.needs.some((n) => categoryOf(n.id, n.category) === cat);
const stepsOf = (draft: PipelineDraft, needId: string, service: string | undefined): StepSpec[] => draft.steps.filter((s) => s.needId === needId && s.service === service);
const planWord = (plan: string): string => (['free', 'pro', 'team', 'enterprise'].includes(plan) ? plan : 'not known');
const SETUP_COMMANDS: ReadonlySet<string> = new Set(['pre-commit install', 'npm install', 'lefthook install']);

/** The link to this repository's secrets page, only when owner and repo are plain names (the judge allows links to this repository only). */
function secretsLink(owner: string, repo: string): string | null {
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner) || !NAME_OK.test(repo) || /^\.+$/.test(repo)) return null;
  const url = `https://github.com/${owner}/${repo}/settings/secrets/actions`;
  try { if (new URL(url).href !== url) return null; } catch { return null; }
  return `[the secrets page of this repository](${url})`;
}

// ---------- the sections ----------

function planSection(d: Doc, draft: PipelineDraft, data: DocData): void {
  const p = draft.profile;
  const c = draft.capabilities;
  d.h(2, SECTION_TITLES[0] as string);
  d.p('This section comes first so that no limit is hidden.');
  d.li(`This repository is ${p.private ? 'private' : 'public'}. Your GitHub plan: ${planWord(p.plan)}.`);
  d.li(c.branchProtection ? `Branch rules: available, so the check \`${GATE_CHECK_NAME}\` can be required before a pull request merges.` : `Branch rules: not available on this plan, so GitHub can not require the check \`${GATE_CHECK_NAME}\` or a review before a merge. The gate still runs and reports, but nothing forces it.`);
  d.li(c.environments ? 'Environments: available. The environment `pipegen-signing` holds the signing key and limits the verify step to the default branch.' : 'Environments: not available on this plan, so there is no `pipegen-signing` environment: the verify job runs without one, and the default-branch limit can not be enforced there.');
  d.li(c.envRequiredReviewers ? 'Required reviewers on an environment: available.' : 'Required reviewers on an environment: not available, so a deploy does not wait for a person.');
  d.li(c.deploymentBranchPolicies ? 'Deployment branch policies: available, so only the default branch can use the signing environment.' : 'Deployment branch policies: not confirmed, so pipegen does not store a signing key in key mode.');
  d.li(c.attestations ? 'Build attestations: available.' : 'Build attestations: not available on this plan.');
  d.li(c.codeScanning ? 'Code scanning results: available.' : 'Code scanning results: not available on this plan, so findings are shown by the gate, not in the Security tab.');
  d.li(c.keylessSigningAllowed ? 'Keyless signing: allowed (a public repository: its signing log is public).' : 'Keyless signing: not used here (the signing log of a private repository would be public).');
  if (p.private && (!c.branchProtection || !c.environments)) d.li('A paid GitHub plan (Pro for a personal account, Team for an organisation) adds what is missing here, such as branch rules and environments on a private repository.');
  d.li('Anyone who can add a workflow can add a job that reports under the name of the gate. The guard is CODEOWNERS plus a required code-owner review of the pipeline files. On a private repository with a free plan GitHub can not enforce that review, so this is a limit that stays.');
  d.li('Where GitHub can not enforce this (a private repository on a free plan, or a repository with one writer), the deploy check trusts the people who can edit the workflow files.');
  d.li('Pull requests from forks: on a public repository, a first-time contributor\'s workflow run waits for a maintainer to approve it. On a private repository, workflows on fork pull requests are off by default. A check that needs a secret shows as not run on a fork pull request.');
  d.li('The network block on CI jobs lets only the allowed hosts through. A site that sits behind the same CDN as an allowed host stays reachable, so the block limits traffic and is not a wall.');
  if (!p.private) d.li(`On a public repository anyone can submit a review on a pull request, and that starts a run on the review event. It does not cancel the pull request's own run.`);
  if (data.lockNotes.length > 0) {
    d.h(3, 'Locks on merging');
    for (const n of data.lockNotes) noteItems(d, n);
  }
}

function setupSection(d: Doc, draft: PipelineDraft, data: DocData): void {
  const p = draft.profile;
  d.h(2, SECTION_TITLES[1] as string);
  d.li('pipegen v0.2 is for repositories owned by CrisWorking. A public repository uses the gate in the normal way.');
  d.li(p.private
    ? `This repository is private, so its checks run from central workflows in the pipelines repository of the same owner, pinned to one commit. The caller file in this repository is \`${CALLER_WORKFLOW}\`.`
    : `This repository is public, so its checks are written inline in this repository: \`${CALLER_WORKFLOW}\`, \`${LOCAL_MERGE_WORKFLOW}\`, \`${PUSH_WORKFLOW}\` and \`${NIGHTLY_WORKFLOW}\`. Its install record is kept in a private pipelines repository.`);
  d.li('pipegen does not change what or how you deploy. It adds a verify job and `needs` entries to your existing deploy jobs, and nothing else in them.');
  d.li('pipegen offers three strictness levels, Starter, Standard (the default) and Strict. They decide which checks block a pull request and which only warn. The Standard level is used unless you chose another.');
  if (data.est !== null) {
    const incl = p.private ? (data.est.includedMinutes === null ? ' pipegen could not tell how many minutes your plan includes.' : ` Your plan includes ${data.est.includedMinutes} minutes a month for private repositories.`) : ' Actions minutes on a public repository are free.';
    d.li(`Estimated monthly Actions minutes: about ${data.est.monthlyMinutes}, counted from the activity of the last 30 days.${incl}`);
    if (data.est.prWaitMinutes !== undefined) d.li(`A pull request waits about ${data.est.prWaitMinutes} minutes for the checks.`);
  }
  const typed = p.services.filter((s: Service) => s.projectType !== undefined);
  if (p.services.length > 0) {
    d.h(3, 'Services pipegen found');
    for (const s of p.services) {
      const t = s.projectType;
      const types = t === undefined ? '' : t.types.length === 0 ? ', type: none of static site, library, cli, server or container' : `, type: ${t.types.join(', ')}${t.overridden === true ? ' (set by you)' : ''}`;
      const unsure = t !== undefined && t.unsure ? ' It looks like a static site, but a sign of a server was found, so pipegen treats it as a server.' : '';
      d.li(`Service ${q(s.name)} (${s.language})${types}.${unsure}`);
    }
    if (typed.length === 0) d.p('pipegen did not record a type for these services.');
  }
  if (data.credits.length > 0) {
    d.h(3, 'Checks your repository already has');
    let warned = false;
    for (const c of data.credits) {
      d.li(fit(c.text));
      if (c.kind === 'push-default' && !warned) { d.li(PUSH_CREDIT_WARNING); warned = true; }
    }
  }
}

function tableSection(d: Doc): void {
  d.h(2, SECTION_TITLES[2] as string);
  d.p(`The required check is \`${GATE_CHECK_NAME}\`. When it fails, or only warns, its summary on the run gives a message. Find it in the first column.`);
  d.row(['Message', 'What it means', 'What to do']);
  d.row(['---', '---', '---']);
  for (const r of GATE_REASONS) d.row([r.message, r.means, r.todo]);
}

function layersSection(d: Doc, draft: PipelineDraft, data: DocData): void {
  d.h(2, SECTION_TITLES[3] as string);
  d.p('Each check has a tool, a reason and a mode: it either blocks a pull request or only warns.');
  for (const layer of LAYERS) {
    const needs = draft.needs.filter((n) => n.layer === layer);
    d.h(3, `${layer === 'pre-commit' ? 'Pre-commit' : layer === 'push' ? 'Push' : layer === 'merge' ? 'Merge' : 'Deploy'} layer`);
    d.p(LAYER_TEXT[layer]);
    if (needs.length === 0) { d.p('No check of this layer is set up here.'); continue; }
    for (const n of needs) {
      const cat = categoryOf(n.id, n.category);
      const [label, why] = Object.hasOwn(CATEGORY_TEXT, cat) ? (CATEGORY_TEXT[cat] as readonly [string, string]) : ['A check pipegen added', 'See the tool name.'];
      const tools = [...new Set(stepsOf(draft, n.id, n.service).map((s) => fit(s.tool.name, 80)))];
      const warnFirst = draft.warnFirst !== undefined && Object.hasOwn(draft.warnFirst, n.id);
      const blocks = layer === 'pre-commit' ? 'Blocks the commit.' : layer === 'merge' ? 'Blocks a pull request.' : 'Fails the run.';
      const mode = !n.blocking ? 'Warns only.' : warnFirst ? 'Starts in warn mode, then blocks.' : blocks;
      const tool = cat === 'gate' ? 'tool the pipegen gate action' : tools.length === 0 ? 'no tool listed (see the notes below)' : `tool ${tools.join(', ')}`;
      d.li(`${label}${n.service === undefined ? '' : `, service ${q(n.service)}`}, ${tool}. ${why} ${mode}`);
    }
  }
  limitsSection(d, draft);
  tuningSection(d, draft);
  d.h(3, 'Notes from the build');
  const notes = buildNotes(data);
  if (notes.length === 0) d.p('There are no notes.');
  for (const n of notes) noteItems(d, n);
}

/** The build notes in the order given, with GJ's husky line kept and G6's husky line dropped (one line per hook manager). */
function buildNotes(data: DocData): string[] {
  const all = data.notes;
  const gj = all.some((n) => n.startsWith(GJ_HUSKY_NOTE_START));
  return all.filter((n, i) => all.indexOf(n) === i && !(gj && n === HUSKY_NO_CI_NOTE));
}

function limitsSection(d: Doc, draft: PipelineDraft): void {
  const has = (c: string): boolean => hasCat(draft, c);
  d.h(3, 'Limits of these checks');
  if (has('type-check')) d.li('The type-check follows your own tsconfig.json. The repo\'s tsconfig decides what tsc checks and how strictly, and a pull request can edit it (`exclude`, `skipLibCheck`, `extends`, a `ts-nocheck` comment). pipegen refuses only the plain no-op layouts: no file selected, `noCheck`, and a missing or linked tsconfig.json. It is not a protected path.');
  if (has('dast')) {
    d.li('The raw result of the running app scan travels unscrubbed between the job that runs the app and the job that reads the result. It holds only what an app without secrets answered. A hostile app can always answer a scanner cleanly.');
    d.li('The running app scan has no base twin, so its findings warn on the pull request that installs pipegen and are new after it.');
  }
  if (has('image-scan') || has('image-build')) {
    d.li('Image findings have no base yet: there is no base twin, so image findings warn on the pull request that installs pipegen and block on every other.');
    d.li('The scanned image is not the published image. The scan covers the build of the pull request head; the publish job builds again at the merge commit, so a moving base image tag can make them differ.');
  }
  if (has('licences')) d.li('The licence scan reads lockfiles only.');
  if (has('sast')) d.li('The code scan runs Semgrep with a pinned copy of the semgrep-rules repository. Those rules have their own licence (the Semgrep Rules License v1.0). It lets you use them to check your own code, but not to sell them or offer them as a service. Read it before you use the rules anywhere else.');
  if (has('publishing')) d.li('Publishing uses a trusted publisher, so no token is stored. Set it up once: on npmjs.com open the package settings and add a trusted publisher for GitHub Actions with this repository and the publish workflow file name; on PyPI open the project, then Publishing, and add a trusted publisher with the same details. The publish job needs npm 11.5.1 or newer and Node 22.14.0 or newer, and it is the only job that gets the `id-token` permission.');
  if (has('duplication')) d.li('The copy-paste check warns only, at first: it reports new copy-paste in changed code, and old copies are not counted. A repository can make it blocking. The mode of a check is part of the pipeline files, which are protected paths, so that change goes through a pull request that a code owner approves.');
  if (draft.signing?.mode === 'keyless') d.li('Keyless signing runs without a network block for now.');
  if (draft.profile.services.some((s) => s.packageManager === 'npm')) d.li('Each service installs with `npm ci`, which needs a `package-lock.json` in that service\'s folder. A lock file at the workspace root is not enough: the check then fails closed, it does not pass.');
  if (has('unit-tests') || has('full-tests') || has('lint') || has('format-lint') || has('coverage')) d.li('Project scripts that pipegen runs get no declared secrets yet. A test that needs a secret can get it only through the coverage check.');
  d.li('npm only: pnpm, yarn and bun are not supported yet. A Vue, Svelte or Astro TypeScript repository stops at assembly with a plain reason, because pipegen has no reviewed type checker for it.');
  d.li('The nightly job has a `concurrency` group, so runs never overlap. An issue it opened and any bot closed (even a stale bot running as the github-actions bot) is reopened by design. Only a person can dismiss it.');
  d.li(HISTORY_REWRITE_NOTE);
}

function tuningSection(d: Doc, draft: PipelineDraft): void {
  const reduced: string[] = [];
  const tuned: string[] = [];
  for (const s of draft.steps) {
    const lines = describeTuning(s);
    if (lines.length === 0) continue;
    const skip = isObj(s.choices?.tuning) && Object.hasOwn(s.choices.tuning as object, 'skip-generated');
    for (const l of lines) (skip ? reduced : tuned).push(`${fit(s.tool.name, 80)}: ${fit(l)}`);
  }
  if (reduced.length > 0) {
    d.h(3, 'Reduced coverage');
    d.p('These checks skip folders that pipegen found to be vendored or generated. Nothing in those folders is checked by them.');
    for (const l of reduced) d.li(l);
  }
  if (tuned.length > 0) {
    d.h(3, 'Tuning');
    for (const l of tuned) d.li(l);
  }
}

function suggestionsSection(d: Doc, draft: PipelineDraft): void {
  d.h(2, SECTION_TITLES[4] as string);
  d.p('A suggestion is a tool that pipegen does not run for you. It may be a tool pipegen has not reviewed, or a reviewed tool that had nothing to run on in this repository (its reason says which). Suggestions are mention-only: they never run. A tool can join the reviewed list only through a reviewed pull request to pipegen.');
  if (draft.suggestions.length === 0) { d.p('There are no suggestions.'); return; }
  for (const sg of draft.suggestions) d.li(`${q(sg.name, 80)} (repository ${fit(sg.repo, 100)}): ${fit(sg.why)}`);
}

function filesSection(d: Doc, draft: PipelineDraft, data: DocData): void {
  const p = draft.profile;
  d.h(2, SECTION_TITLES[5] as string);
  d.li('`PIPEGEN.md`: this file.');
  d.li(`\`${CALLER_WORKFLOW}\`: the workflow that starts the pipeline.${p.private ? '' : ` Its jobs sit beside it in \`${LOCAL_MERGE_WORKFLOW}\`, \`${PUSH_WORKFLOW}\` and \`${NIGHTLY_WORKFLOW}\`.`}`);
  if (p.private) d.li(`In the pipelines repository: the central workflows \`${centralProjectName(p.repo)}--push.yml\`, \`${centralProjectName(p.repo)}--merge.yml\`, \`${centralProjectName(p.repo)}--nightly.yml\` and the shared signing workflow, with the install record.`);
  d.li('Dependabot, in `.github/dependabot.yml` when pipegen adds an entry: it keeps the pinned actions up to date, each update at least 7 days old. The entry ignores the central repository, because Dependabot can not read it, so Dependabot does not bump the central commit. pipegen keeps that pin fresh: `npx pipegen update` opens the pull request and the nightly run warns when the pin is old. There are two opt-ins, not on by default: an organisation grant through the API, or a git registry entry with a read-only token you make yourself. A repository that uses Renovate keeps it and gets no Dependabot file (set `minimumReleaseAge` to 7 days in Renovate).');
  for (const f of draft.created) {
    if (f.path === 'PIPEGEN.md') continue;
    d.li(`${q(f.path, 160)}: ${f.aiEdited === true ? cleanForDoc(scrubActive(f.reason), CAP) : fit(f.reason)}`);
  }
  d.li('Files that were already in your repository, identical to what pipegen writes, are listed in the setup pull request. pipegen never rewrites them, and uninstall asks before it deletes one.');
  for (const n of data.testNotes) {
    if (n.startsWith(AI_NOTE_START)) continue;
    noteItems(d, n);
  }
}

function testsSection(d: Doc, draft: PipelineDraft): void {
  d.h(2, SECTION_TITLES[6] as string);
  d.p('Starter tests describe what your code does today. They are a coverage floor, not proof: they can lock in today\'s bugs, so review them. App code runs with full power (process, network and files), so the CI job that runs it has no secrets, a read-only token and no network except the registry.');
  if (hasCat(draft, 'coverage')) d.p('If a coverage waiver is needed, the owners in pipegen\'s CODEOWNERS block can approve it, also for a file whose own CODEOWNERS rule names no user.');
  if (draft.testDecisions.length === 0) { d.p('No test decision was recorded.'); return; }
  for (const t of draft.testDecisions) {
    const choice = t.choice === 'keep' ? 'pipegen keeps your tests' : t.choice === 'switch' ? 'pipegen switches the test tool' : 'pipegen changes nothing';
    d.li(`Service ${q(t.service)}: ${choice}. ${t.reasons.filter(isStr).map((r) => fit(r)).join(' ')}`);
  }
}

function skippedSection(d: Doc, draft: PipelineDraft): void {
  d.h(2, SECTION_TITLES[7] as string);
  if (draft.skipped.length === 0 && draft.layersSkipped.length === 0) { d.p('Nothing was skipped.'); return; }
  for (const s of draft.skipped) {
    const missing = Object.hasOwn(SKIP_MISSING, s.part) ? (SKIP_MISSING[s.part] as string) : 'The protection of this part is missing.';
    d.li(`Part ${fit(s.part, 40)}: skipped with --skip. ${fit(s.reason)} What is missing: ${missing}`);
  }
  for (const l of draft.layersSkipped) d.li(`Layer ${fit(l.layer, 40)}: skipped. ${fit(l.reason)}`);
}

function signingSection(d: Doc, draft: PipelineDraft): void {
  const s = draft.signing;
  d.h(2, SECTION_TITLES[8] as string);
  if (s === undefined) {
    d.p('pipegen signs nothing in this setup.');
    if (draft.skipped.some((x) => x.part === 'deploy')) d.li('You skipped the deploy part.');
    else if (draft.profile.private && !draft.capabilities.environments) d.li('This plan has no environments, which hold the signing key.');
    else d.li('No service builds an image that pipegen publishes, or the signing mode is not available here.');
  } else if (s.mode === 'key-env') {
    d.p('Images are signed with a cosign key. `npx pipegen finish` makes the key pair and stores it as environment secrets of `pipegen-signing`, which only the default branch can use. The public key is the environment variable `PIPEGEN_COSIGN_PUB` of `pipegen-signing`. The verify job checks the sha256 of that variable against the value in the install record before it uses it, so a changed variable is a finding. Signing uses `--tlog-upload=false`.');
    d.p('`npx pipegen finish --rotate-key` makes a new key pair. Images signed with the old key no longer verify. The verify literal changes through a pull request, and verify fails closed until that pull request is merged. A key rotation resets the gate\'s marker and baseline, and `npx pipegen verify` says so.');
  } else if (s.mode === 'keyless') {
    d.p('Images are signed without a key of your own: the signature names the workflow that made it, and it is written to the public log of the signing service.');
  } else {
    d.p('Images get a build attestation (`actions/attest`), checked with `gh attestation verify` against the signing workflow.');
  }
  d.p('Signing covers images only. A service that builds no image has report-only signing: pipegen signs nothing for it, and the notes in The four layers name each one.');
}

function deploysSection(d: Doc, draft: PipelineDraft, data: DocData): void {
  d.h(2, SECTION_TITLES[9] as string);
  const edited = draft.created.filter((f) => f.inserted !== undefined);
  if (edited.length > 0) {
    d.p('These deploy workflows got the verify job, and their deploy jobs wait for it:');
    for (const f of edited) d.li(q(f.path, 160));
  }
  d.p('Deploy with the verified image digest (the verify job output `digest`). A signature only protects a deploy that uses that digest, so deploy by digest, not by tag.');
  d.h(3, 'Unprotected deploys');
  if (data.deployGaps.length === 0) {
    d.p(draft.profile.existingWorkflows.some((w) => w.deploys) && edited.length === 0 ? 'pipegen found deploy workflows but added no verify job and listed no gap. Treat every deploy workflow of this repository as unprotected.' : 'pipegen listed no unprotected deploy workflow.');
  } else {
    for (const g of data.deployGaps) d.li(`${q(g.path, 160)} (triggers: ${g.triggers.length === 0 ? 'unknown' : g.triggers.map((t) => fit(t, 40)).join(', ')}): ${fit(g.why)}`);
  }
  d.li('A deploy workflow with any other trigger than a push to the default branch gets no verify job, so it is an unprotected gap. A deploy started by `workflow_run` is a gap too, and so is a deploy from a branch other than the default branch (the verify job passes only for the default branch).');
  if (draft.profile.private && !draft.capabilities.environments) d.li('On a private repository with a free plan the verify job runs without an environment, so the default-branch limit can not be enforced there.');
  d.li('Each edit pipegen made to a deploy workflow is listed under Not proven yet until you have checked it.');
}

function notProvenSection(d: Doc, draft: PipelineDraft, data: DocData, reviewed: readonly ReviewedTool[]): void {
  const p = draft.profile;
  d.h(2, SECTION_TITLES[10] as string);
  if (draft.notProven.length === 0) d.p('Every check pipegen set up is proven.');
  for (const n of draft.notProven) {
    const cat = n.needId === undefined ? '' : categoryOf(n.needId, n.needId);
    const label = cat !== '' && Object.hasOwn(CATEGORY_TEXT, cat) ? (CATEGORY_TEXT[cat] as readonly [string, string])[0] : '';
    const names = strs(n.missingSecrets);
    const secrets = names.length === 0 ? '' : ` Secret names to set: ${names.map((x) => (SECRET_NAME_RE.test(x) ? `\`${x}\`` : fit(x, 60))).join(', ')}.`;
    d.li(`Part ${fit(n.part, 40)}${label === '' ? '' : `, ${label}`}: ${fit(n.reason)}${secrets}`);
  }
  const link = secretsLink(p.owner, p.repo);
  d.p(`Set a missing secret in the repository settings: Settings, Secrets and variables, Actions${link === null ? '' : ` (${link})`}. When the key exists, the nightly run opens an issue with the exact patch: run \`npx pipegen update\` and it applies the change as a pull request. CI never edits workflow files itself.`);
  const where = p.private ? `\`.github/workflows/${centralProjectName(p.repo)}--merge.yml\` in the pipelines repository` : `\`${LOCAL_MERGE_WORKFLOW}\``;
  d.p(`The not-proven list is one line in ${where}, marked \`pipegen:not-proven\`. It never holds a check that every repository needs.`);
  if (data.uncoveredMinimum.length > 0) {
    d.h(3, 'Minimum checks with no job (not covered)');
    d.p('pipegen requires these checks for every repository, but it could not write a job for them here. Until you add them yourself, nothing runs for them.');
    for (const u of data.uncoveredMinimum) {
      const cat = Object.hasOwn(CATEGORY_TEXT, u.category) ? (CATEGORY_TEXT[u.category] as readonly [string, string])[0] : fit(u.category, 60);
      d.li(`${cat}${u.service === undefined ? '' : `, service ${q(u.service)}`}: not covered. ${fit(u.why)}`);
    }
  }
  const proofless = draft.steps.some((s) => reviewed.some((t) => t.id === s.tool.id && t.proofs === 0));
  if (proofless) d.li(BOOTSTRAP_PROOFS_NOTE);
}

function integritySection(d: Doc, draft: PipelineDraft): void {
  d.h(2, SECTION_TITLES[11] as string);
  d.li('The gate protects the files that define the pipeline: workflows, tool configs, ignore files and the hook files. A pull request that changes one is blocked unless a code owner approved the exact head commit.');
  const extra = draft.gateSettings?.protectedPaths ?? [];
  if (extra.length > 0) d.li(`Extra protected paths: ${extra.filter(isStr).map((x) => q(x, 120)).join(', ')}.`);
  const co = draft.codeOwners;
  if (co !== undefined && co.owners.length > 0) d.li(`Code owners in pipegen's CODEOWNERS block: ${co.owners.filter(isStr).map((o) => q(o.replace(/^@/, ''), 60)).join(', ')}. ${co.writers} ${co.writers === 1 ? 'person can' : 'people can'} write to this repository.`);
  else d.li('pipegen wrote no CODEOWNERS block, so there is no code-owner review of the pipeline files (see the locks notes in the first section).');
  d.li('A one-person repository: pull requests need no approval, so whoever merges can also change the pipeline that judges them, and pipegen can not prevent that. Run `npx pipegen verify` to see whether the pipeline still matches what pipegen set up.');
  d.li('Code-owner review is the guard against a job that fakes the gate\'s name. Where GitHub can not enforce it, the limit is stated in the first section.');
  d.li('A patch issue the nightly run opens is only a prompt: `npx pipegen update` works out the change itself from its built-in reviewed pins.');
}

function warnSection(d: Doc, draft: PipelineDraft): void {
  d.h(2, SECTION_TITLES[12] as string);
  d.p(WARN_MODE_TEXT);
  d.p('In warn mode old findings and medium ones warn, and a new critical, high or secret finding still blocks. A new blocking check starts in warn mode for about 14 days, then the nightly run opens an issue to switch it to blocking.');
  const w = draft.warnFirst === undefined ? [] : Object.keys(draft.warnFirst);
  if (w.length > 0) {
    d.p('These checks start in warn mode:');
    for (const id of w) { const cat = categoryOf(id, id); d.li(Object.hasOwn(CATEGORY_TEXT, cat) ? (CATEGORY_TEXT[cat] as readonly [string, string])[0] : 'A check pipegen added'); }
  }
}

function retentionSection(d: Doc): void {
  d.h(2, SECTION_TITLES[13] as string);
  d.p('Runs past the retention period can not be verified, so re-run the pipeline first before you deploy an old commit. GitHub Actions keeps runs and artifacts 90 days by default. On private repositories you can raise it to 400 days (Settings, Actions, General).');
}

function debateSection(d: Doc, draft: PipelineDraft, data: DocData): void {
  d.h(2, SECTION_TITLES[14] as string);
  d.p('pipegen chose its tools in a short debate between AI models. The code, not the AI, checks every choice against pipegen\'s reviewed list.');
  if (draft.scoreboard.length > 0) { d.h(3, 'Scoreboard'); for (const l of draft.scoreboard) d.li(fit(l)); }
  if (data.transcript.length > 0) { d.h(3, 'Transcript'); for (const l of data.transcript) d.li(fit(l)); }
  if (draft.scoreboard.length === 0 && data.transcript.length === 0) d.p('No debate was recorded.');
}

function hooksSection(d: Doc, data: DocData): void {
  d.h(2, SECTION_TITLES[15] as string);
  const cmd = data.setupCommand;
  if (cmd === '') { d.p('pipegen wrote no hook file, so there is no setup command. The notes in The four layers say why.'); return; }
  d.p(`After you clone the repository, run \`${SETUP_COMMANDS.has(cmd) ? cmd : fit(cmd, 60)}\` once, so the hooks are active on your machine.`);
  d.p('The secrets hook runs pipegen from npm, at the exact version that wrote the hook, and pipegen runs its pinned secret scanner on the staged changes. The command is:');
  d.fence('sh', ['npx --yes --prefix=/ --registry=https://registry.npmjs.org pipegen@VERSION hook secrets']);
  d.p('VERSION is the exact pipegen version that wrote the hook. The first commit trusts npm\'s metadata for that exact version. It is not pinned by a lockfile hash.');
  d.li('The hook needs `node` and `npx` and a connection to the npm registry, in every language repository. If one is missing the hook fails and blocks the commit (it fails closed).');
  d.li('`git commit --no-verify` is the way out when npm is unreachable or the version is not published. CI still scans.');
  d.li('If the pipegen version that wrote the hook is not on npm (a build that was never published), every commit fails with npm\'s own `E404` text. That means npm has no such version. Use `git commit --no-verify` until a published version is in the hook.');
  d.li('In CI the hooks run with `--all-files`, so nothing is staged and the secrets hook passes at once. The secret scan job of CI is the cover.');
  d.li('The local hook is a convenience a repo\'s own scripts can turn off; CI is the gate.');
}

function commandsSection(d: Doc): void {
  d.h(2, SECTION_TITLES[16] as string);
  d.li('Run the pipegen setup again at any time. It updates the same pull request `pipegen/setup` and opens central changes through a central pull request, so there are no duplicates.');
  d.li('A re-run with `--yes`, or in CI, needs the local record file. Without it pipegen shows what the install record claims and you type `owner/repo` to confirm.');
  d.li('`npx pipegen finish` runs after you merge the setup pull request. It turns on the merge locks and the settings pipegen planned. None of them is turned on before the merge, or the setup pull request could not merge.');
  d.li('`npx pipegen finish --print` changes nothing: it prints the exact commands, so you can run them yourself.');
  d.li('`npx pipegen finish --rotate-key` makes a new signing key pair (key mode only). Old images do not verify with the new key, and the verify literal changes through a pull request.');
  d.li('`npx pipegen verify` compares the pipeline in the repository with the install record. It also warns about a CODEOWNERS rule after pipegen\'s block that names only teams: the gate can not read a team\'s members, so name users there.');
  d.li('`npx pipegen update` makes only gate pin swaps and the central re-pin. It never touches `PIPEGEN.md`. A file you edited is never overwritten; it goes to a conflict list.');
  d.li('Uninstall removes only what the install record shows pipegen made. It asks before it deletes a file that was already in your repository.');
}

const GLOSSARY: readonly (readonly [string, string])[] = [
  ['Gate', `The check \`${GATE_CHECK_NAME}\`. It reads every result and decides whether a pull request can merge.`],
  ['Finding', 'One problem a check reports, such as a vulnerable package or a leaked key.'],
  ['Baseline', 'The findings that were already there before a pull request, so only new ones count against it.'],
  ['Warn mode', 'A period in which most findings warn and do not block.'],
  ['Protected path', 'A file that defines the pipeline. Changing it needs a code-owner approval.'],
  ['Code owner', 'A person named in CODEOWNERS whose review is required for the files they own.'],
  ['Ruleset', 'GitHub\'s rules for a branch, such as a required check or a required review.'],
  ['Not proven', 'A check pipegen could not prove on your repository yet. It warns and does not block.'],
  ['Verify-first', 'A job that runs before a deploy and checks the commit passed the gate and the image is the signed one.'],
  ['Signing', 'A signature on an image that shows which workflow made it.'],
  ['Digest', 'The checksum that names one exact image. A digest never changes; a tag can move.'],
  ['Suggestion', 'A tool pipegen mentions but does not run.'],
];
function glossarySection(d: Doc): void {
  d.h(2, SECTION_TITLES[17] as string);
  for (const [w, m] of GLOSSARY) d.li(`${w}: ${m}`);
}

// ---------- the builder ----------

/** The reason of the file (a fixed text). */
const DOC_REASON = 'Explains in plain English what pipegen set up, what it does not cover, and what to do when a pull request is blocked.';

/**
 * PIPEGEN.md for a draft. Pure: the same draft and reviewed list always give the same bytes (with the same active vault). `draft.doc` holds the inputs
 * that are not on the draft (an absent `doc` reads as empty here; the referee refuses a PIPEGEN.md whose draft has none). Never throws for the draft's
 * content: a string that can not be written as it is gets cleaned.
 */
export function pipegenDoc(draft: PipelineDraft, reviewed: readonly ReviewedTool[]): CreatedFile {
  const data = dataOf(draft);
  const d = new Doc();
  d.h(1, 'What pipegen set up in this repository');
  d.p('pipegen wrote this file in plain English. If you edit it, pipegen keeps your edits and never replaces the file.');
  planSection(d, draft, data);
  setupSection(d, draft, data);
  tableSection(d);
  layersSection(d, draft, data);
  suggestionsSection(d, draft);
  filesSection(d, draft, data);
  testsSection(d, draft);
  skippedSection(d, draft);
  signingSection(d, draft);
  deploysSection(d, draft, data);
  notProvenSection(d, draft, data, reviewed);
  integritySection(d, draft);
  warnSection(d, draft);
  retentionSection(d);
  debateSection(d, draft, data);
  hooksSection(d, data);
  commandsSection(d);
  glossarySection(d);
  return { path: 'PIPEGEN.md', content: d.text(), part: 'docs', reason: DOC_REASON, repo: 'app' };
}

/** pipegenDoc with the user's secret vault active, so every variable string is scrubbed before any cut (F4-R14). G13 calls this one. */
export function pipegenDocWith(draft: PipelineDraft, reviewed: readonly ReviewedTool[], vault?: Pick<KnownValueCheck, 'scrubber'>): CreatedFile {
  return withActiveVault(vault, () => pipegenDoc(draft, reviewed));
}

/**
 * The referee's check (B7): the PIPEGEN.md file must be exactly what pipegenDoc builds from the draft being judged. A draft without `doc` has no inputs
 * to build from, so it is refused. Returns the reason, or null when the file is the one the builder makes.
 */
export function docRecomputeProblem(file: CreatedFile, draft: PipelineDraft, reviewed: readonly ReviewedTool[]): string | null {
  if (draft.doc === undefined) return 'the draft carries no doc data (draft.doc), so the referee can not build PIPEGEN.md again to compare it';
  let again: CreatedFile;
  try { again = pipegenDoc(draft, reviewed); } catch { return 'PIPEGEN.md could not be built again from the draft'; }
  if (file.content !== again.content) return 'PIPEGEN.md is not the file pipegen builds from the draft (the referee builds it again and requires the same bytes)';
  if (file.reason !== again.reason || file.part !== again.part) return 'PIPEGEN.md does not carry the part and reason pipegen gives it';
  return null;
}
