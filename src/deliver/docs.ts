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
import { FINDINGS_CATEGORIES, gateJobList, isResultFormat, jobIdFor, PIPEGEN_JOB_CATEGORIES, readableFormat, type JobListEntry } from '../engine/gate-job-list.js';
import { HOOK_FILES, hookCommands, SECRETS_HOOK_ID, type HookCommand } from '../engine/created-builders.js';
import { PUSH_CREDIT_WARNING } from '../audit/coverage/equivalents.js';
import { cleanForDoc, CLEAN_DOC_MAX, CLEAN_DOC_PLACEHOLDER } from '../debate/clean.js';
import { centralProjectName } from '../engine/central-path.js';
import { CALLER_WORKFLOW, LOCAL_MERGE_WORKFLOW, NIGHTLY_WORKFLOW, PUSH_WORKFLOW } from '../engine/job-rules.js';
import { pipegenDocProblems } from '../engine/created-judges/pipegen-doc.js';
import { BOOTSTRAP_PROOFS_NOTE } from '../engine/reviewed.js';
import { floorNeeds, MINIMUM_CATEGORIES } from '../engine/needs.js';
import { describeTuning } from '../engine/tuning.js';
import { HUSKY_NO_CI_NOTE, SETUP_COMMANDS } from '../layers/precommit.js';
import { FLOOR_NEEDS, GATE_CHECK_NAME, type CreatedFile, type Need, type PipelineDraft, type ReviewedTool, type Service, type StepSpec } from '../types.js';
import { scrubActive, withActiveVault } from '../util/known-values.js';
import type { KnownValueCheck } from '../types.js';

// ---------- fixed texts that other sources own ----------

/**
 * C4's note (gate/src/baseline.ts HISTORY_REWRITE_NOTE). Copied, not imported: gate/ is bundled and does not change in this task. A test keeps the two
 * equal (ruling G9-R0 9).
 */
export const HISTORY_REWRITE_NOTE = 'After rewriting main\'s history (a force-push), the gate may stay in block mode until 10 green pushes to main have followed.';
/**
 * The gate's ZAP rule (gate/src/zap.ts ZAP_TOOL, ZAP_JSON_VERIFIED): while ZAP's report is unverified the gate judges every non-floor check that runs ZAP as
 * not proven (a warning, never a block). Verified since G15a round 5 (real reports of the pinned image), so the not-proven lines are not written. Copied, not imported (gate/ is bundled); a test keeps both equal.
 */
export const ZAP_TOOL = 'zap-baseline';
export const ZAP_JSON_VERIFIED = true;
/** The start of GJ's hooks-ci note for husky (src/layers/jobs.ts HOOKS_CI_NOTES.husky): it says what G6's husky note says, so only one of them is printed. */
const GJ_HUSKY_NOTE_START = "husky's hooks are shell scripts";

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
 * `message` is the stable leading text the gate's summary shows (or the rule id of an integrity finding): a test finds each one in the gate's source, so
 * a user can copy a line of the summary and find its row. `means` says what it means, `todo` what to do.
 */
export const GATE_REASONS: readonly { id: string; message: string; means: string; todo: string }[] = Object.freeze([
  { id: 'new-finding', message: 'a new critical, high or secret finding blocks in any mode', means: 'A check found a serious problem or a secret that the base branch did not have.', todo: 'Fix it in the pull request. A false alarm is for a code owner to judge; adding a suppression comment is flagged itself. Treat a secret as leaked and rotate it: a secret that was ever pushed stays in the history.' },
  { id: 'secret-in-range', message: 'secret added in this PR\'s history', means: 'A scan of the commits of this pull request found a secret. A commit that added a secret still counts after a later commit took it out. Any finding in the commit range blocks.', todo: 'Rotate the secret now. Then rewrite the branch so the commits no longer hold it, and push again.' },
  { id: 'range-unproven', message: 'the pull request\'s commits are not proven free of secrets', means: 'The scan of the commits of this pull request could not run or gave no result, so nothing is proven. It blocks on a pull request.', todo: 'Run the job again.' },
  { id: 'dependency-review', message: 'a new vulnerability in dependency review', means: 'A package added by the pull request has a known vulnerability that the base did not have.', todo: 'Pick another package or version.' },
  { id: 'malicious', message: 'a malicious package advisory (MAL-): blocks even when old', means: 'A dependency matches a malicious-package advisory. It blocks even when it is old.', todo: 'Remove the package and rotate anything it could have read.' },
  { id: 'licence', message: 'an unknown licence: needs a human, never blocks', means: 'A package has a licence the check does not know. It only warns.', todo: 'Have a person check the licence.' },
  { id: 'protected-path', message: 'integrity:protected-path', means: 'The pull request changes a workflow, a tool config or an ignore file (a file that is part of the pipeline), and no code owner approved this exact commit. An approval counts only for the commit it was given on, so a code owner who approved an older commit has to approve the latest one.', todo: 'Ask a code owner to approve the latest commit. After a new push the approval has to be given again.' },
  { id: 'suppression', message: 'integrity:suppression', means: 'Added lines turn a check off for that code (a suppression comment).', todo: 'Remove the suppression, or ask a code owner to approve this exact commit.' },
  { id: 'incomplete-list', message: 'integrity:incomplete-list', means: 'The pull request is too large to check (3,000 or more files), or GitHub did not give the whole file list, so the gate can not see every change.', todo: 'Split the pull request into smaller ones, or run the checks again if the branch moved.' },
  { id: 'no-patch', message: 'integrity:no-patch', means: 'GitHub gave no readable change for that file, so the gate can not check it for suppressions.', todo: 'Make the change smaller or split the file change into its own pull request. A code owner can approve the exact commit.' },
  { id: 'case-extension', message: 'integrity:case-extension', means: 'A new file has a scanned language\'s extension in another letter case, so the scanners would skip it while a runtime may still load it.', todo: 'Rename the file to the lower-case extension.' },
  { id: 'integrity-banner', message: 'pipeline files changed or suppressions added without code-owner approval on the current commit', means: 'This heading of the summary comes with the integrity findings above. The pull request is blocked until a code owner approves the current commit.', todo: 'Ask a code owner to approve the latest commit.' },
  { id: 'installing', message: 'installing pipegen: review these files', means: 'This is the pull request that installs pipegen, so the pipeline files are new. It warns and does not block.', todo: 'Read the files, then merge.' },
  { id: 'tool-error', message: 'tool error in', means: 'A check could not finish (it crashed, ran out of time or its result could not be read). A required check that errors blocks; a not proven check only warns.', todo: 'Read the check\'s log, fix the cause and run the job again.' },
  { id: 'did-not-report', message: 'did not report', means: 'A scanner finished without a result. A required one blocks; a not proven or non-blocking one only warns or notes it.', todo: 'Run the job again.' },
  { id: 'fork-not-run', message: 'not run on a fork PR (no secrets)', means: 'GitHub gives no secrets to a pull request from a fork, so a check that needs one did not run. If the check is required, the pull request is blocked.', todo: 'A maintainer can push the branch into this repository and open the pull request from there.' },
  { id: 'not-proven', message: 'not-proven check', means: 'pipegen could not prove the check on your repository yet (see Not proven yet). It warns and does not block.', todo: 'Set the secret names listed under Not proven yet. The nightly run then opens an issue and `npx pipegen update` applies the change.' },
  { id: 'non-blocking', message: 'non-blocking check', means: 'A check that never blocks. The summary notes its result.', todo: 'Read the note; nothing is required.' },
  { id: 'warn-first', message: 'warn-first check', means: 'A check judged by its job status, in its own warn period: a failed job is a warning until a reviewed pull request makes the check blocking.', todo: 'Fix the failure before the period ends (see Warn mode).' },
  { id: 'warn-first-finding', message: 'warn-first: a warning until a reviewed pull request makes the check blocking', means: 'A finding of a check that reads findings, in its own warn period, is a warning. A new critical, high or secret finding still blocks, and so does a failed job of such a check (an image scan or a Dockerfile lint, for example).', todo: 'Fix the findings before the period ends (see Warn mode).' },
  { id: 'not-proven-finding', message: 'not proven: never blocks', means: 'A finding of a check that is not proven yet is a warning and never blocks.', todo: 'Make the check proven (see Not proven yet).' },
  { id: 'non-blocking-finding', message: 'a non-blocking check: never blocks', means: 'A finding of a check that is not meant to block is shown and never blocks.', todo: 'Read it; nothing is required.' },
  { id: 'failed-check', message: 'required check', means: 'A required check failed, so the pull request is blocked.', todo: 'Open the job\'s log, fix the failure and push again.' },
  { id: 'missing-check', message: 'is not in the job list (missing)', means: 'The gate expects a check that did not run, so the pull request can not merge.', todo: 'Run the workflow again. With the org required workflow, re-run the `pipegen required` run after a code owner approves.' },
  { id: 'empty-list', message: 'the job list is empty', means: 'No check ran, so nothing is proven and the gate blocks.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'tampered', message: 'result tampered or missing', means: 'The result file of a check is missing, or its checksum differs from the one its job reported. The gate does not trust it and blocks.', todo: 'Run the checks again. If it keeps happening, someone changed the pipeline: run `npx pipegen verify`.' },
  { id: 'no-coverage', message: 'no coverage for', means: 'A check ran but could not look (for example a scan that reported nothing because it had nothing to read). A required one blocks, because nothing was proven.', todo: 'Fix what the check could not read, then run the checks again.' },
  { id: 'no-base', message: 'no base:', means: 'The base scan could not be used for this event, so every finding compared with it counts as new. A new critical or high finding therefore blocks, and so does a new secret. Only a scanner that could not run on the base commit of the pull request that installs pipegen warns instead (the next row).', todo: 'Run the checks again. On a new install, merge the setup pull request and the next pull request has a base.' },
  { id: 'image-no-base', message: 'no base: the scanner couldn\'t run on the base commit (installing pipegen)', means: 'Image findings have no earlier scan to compare with yet: on the pull request that installs pipegen they warn, and on every other pull request they block.', todo: 'Fix the finding in the image or its base image.' },
  { id: 'settings-input-refused', message: 'input is refused', means: 'One of the gate\'s own inputs (the job list, the policy, the service roots, the protected paths, a date) is not one the gate accepts. The gate blocks, because it can not trust its own settings.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'settings-input-missing', message: 'input is missing', means: 'One of the gate\'s own inputs (the job list, the GitHub token, the service roots) is missing. The gate blocks.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'settings-jobs', message: 'the jobs input (toJSON(needs)) is', means: 'The results of the jobs the gate reads are missing, too large or not an object. The gate blocks.', todo: 'Run the workflow again. If it keeps happening, run `npx pipegen verify`.' },
  { id: 'settings-mode-name', message: 'the mode input is not gate', means: 'The gate was started in a mode other than gate. The gate blocks.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'settings-mode', message: 'does not take the input', means: 'The gate was given an input it does not know, or the wrong mode. The gate blocks.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'settings-policy', message: 'the policy is refused', means: 'The gate\'s own settings are wrong, so it uses the default policy and blocks.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'settings-floor', message: 'not-proven can\'t include floor need', means: 'A check every repository needs is listed as not proven, which the gate does not allow.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'settings-skip', message: 'can never be skipped', means: 'A check that can never be skipped is listed as skipped.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'settings-warn-first', message: 'warn-first can\'t be set on floor need', means: 'A check every repository needs was put in warn-first mode, which the gate does not allow.', todo: 'Run `npx pipegen verify`, then `npx pipegen update`.' },
  { id: 'skipped', message: 'skipped,', means: 'You skipped that part with --skip, so it has no job and gives no protection. The summary lists it under Skipped.', todo: 'Run pipegen again without the skip if you want the part.' },
  { id: 'warn-mode', message: '(warn mode)', means: 'The summary heading says warn mode: old findings and medium ones warn, and a new critical, high or secret finding still blocks.', todo: 'Fix the warnings before warn mode ends (see Warn mode).' },
  { id: 'warn-ended', message: '(block mode)', means: 'The summary heading says block mode: the warn period is over, so what used to warn now blocks.', todo: 'Fix the finding. Nothing else changed.' },
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
const mild = (s: string): string => Array.from(s).map((c) => (ALLOWED_CH.test(c) && c !== '~' ? c : ' ')).join('').replace(/ {2,}/g, ' ').trim();
/** What cleanForDoc does to the two spellings the judge lets through but GitHub renders: a single tilde strikes text through, `GH-1` links to issue 1. */
const plainer = (s: string): string => s.replace(/~/g, ' ').replace(/\b(GH)-(?=\d)/gi, '$1 ').replace(/ {2,}/g, ' ');
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
  const s = plainer(oneLine(scrubbed)).trim();
  if (Array.from(s).length <= max) {
    if (itemOk(s)) return s;
    const m = plainer(mild(s)).trim();
    if (itemOk(m)) return m;
  }
  return cleanForDoc(scrubbed, max);
}
/** Repo text (a service name, a suggestion name, a path): cleanForDoc after the vault scrub, in quotation marks so no neighbour joins it (F-9). */
const q = (raw: unknown, max = 120): string => {
  const c = cleanForDoc(scrubActive(isStr(raw) ? raw : ''), max).replace(/"/g, ' ').replace(/ {2,}/g, ' ').trim();
  return c === '' || c === CLEAN_DOC_PLACEHOLDER ? '(unnamed)' : `"${c}"`;
};

class Doc {
  readonly lines: string[] = [];
  /** A list is open (so the next paragraph needs a blank line before it). */
  private open = false;
  h(level: 1 | 2 | 3, text: string): void { this.close(); this.lines.push(`${'#'.repeat(level)} ${text}`, ''); }
  p(text: string): void { this.close(); this.lines.push(text, ''); }
  li(text: string): void { this.open = true; this.lines.push(`- ${text}`); }
  /** A fenced block (the judge's text info string). */
  fence(info: 'sh' | 'text', body: readonly string[]): void { this.close(); this.lines.push(`\`\`\`${info}`, ...body, '```', ''); }
  row(cells: readonly string[]): void { this.open = true; this.lines.push(`| ${cells.join(' | ')} |`); }
  private close(): void { if (this.open) { this.lines.push(''); this.open = false; } }
  text(): string { this.close(); return `${this.lines.join('\n').replace(/\n+$/, '')}\n`; }
}

/** The creator's own AI note (D-m5): dropped from every field, on its trimmed text. */
const isAiNote = (t: string): boolean => /^the ai explained\b/i.test(t.trim());
const FENCE_LIKE = /^\s*(?:`{3,}|~{3,})/;
/** A package name with its version (`@scope/pkg@1.2.3`, `pkg@1.2`): the judge refuses `@` in text, a text fence holds it. Only this shape, never a bare `@name` (a mention). */
const AT_NAME = /(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@\d+(?:\.\d+){1,3}[a-z0-9._-]*/gi;
/**
 * A note (a build note, a lock note) as list items: one line is one item; several lines become the first line and a text fence of the rest, unless a
 * later line looks like a fence marker (it could close the block and open the file's own structure), then the whole note is one cleaned item.
 * A name with an at sign (`@biomejs/biome@2.5.15`) is kept exact in a text fence after the item, because the item itself has to lose the `@`.
 */
function noteItems(d: Doc, raw: string): void {
  if (isAiNote(raw)) return;
  const scrubbed = scrubActive(raw);
  const lines = scrubbed.split(/\r\n?|[\n\u2028\u2029]/);
  const first = lines[0] ?? '';
  if (lines.length > 1) {
    const rest = lines.slice(1).filter((l) => l.trim() !== '');
    const snippet = ['```text', ...rest, '```'].join('\n');
    if (!rest.some((l) => FENCE_LIKE.test(l)) && itemOk(oneLine(first)) && rest.length > 0 && rest.length <= 40 && pipegenDocProblems(snippet, STUB_OPTS).length === 0) {
      d.li(oneLine(first));
      d.fence('text', rest);
      return;
    }
  }
  d.li(fit(scrubbed));
  const names = lines.length === 1 ? [...new Set(scrubbed.match(AT_NAME) ?? [])].map((x) => x.replace(/[.\-]+$/, '')).filter((x) => x.length <= 120) : [];
  if (names.length > 0 && names.length <= 8 && pipegenDocProblems(['```text', ...names, '```'].join('\n'), STUB_OPTS).length === 0) {
    d.p('The exact names in the note above, written with their at signs:');
    d.fence('text', names);
  }
}

const DEFAULT_DOC = { transcript: [], deployGaps: [], lockNotes: [], estimates: { monthlyMinutes: 0, includedMinutes: null }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] } as const;
/** `bad`: how many entries of each list could not be read and were left out; the doc says so where the list is printed. */
type DocData = {
  transcript: string[]; deployGaps: { path: string; triggers: string[]; why: string }[]; lockNotes: string[]; est: { monthlyMinutes: number; includedMinutes: number | null; prWaitMinutes?: number; strictness?: string } | null;
  gateRequired: boolean | undefined; setupCommand: string; testNotes: string[]; uncoveredMinimum: { category: string; why: string; service?: string }[]; notes: string[]; credits: { text: string; kind: string }[];
  bad: Record<'transcript' | 'deployGaps' | 'lockNotes' | 'testNotes' | 'uncoveredMinimum' | 'notes' | 'credits', number>;
};
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const LIST_FIELDS = ['transcript', 'deployGaps', 'lockNotes', 'testNotes', 'uncoveredMinimum', 'notes'] as const;
/**
 * Why draft.doc is not the data the builder reads (the referee refuses it): it must be an object that holds each list as an array, the setup command as a
 * string and the estimates as an object, so a doc that simply leaves a field out is never taken for "nothing to say" (ruling B7, review sec I1).
 */
export function docShapeProblem(doc: unknown): string | null {
  if (!isObj(doc)) return 'the draft\'s doc data is not an object';
  for (const k of LIST_FIELDS) if (!Array.isArray(doc[k])) return `the draft's doc data has no list ${k}`;
  if (!isStr(doc.setupCommand)) return 'the draft\'s doc data has no setupCommand text';
  if (!isObj(doc.estimates)) return 'the draft\'s doc data has no estimates';
  if (doc.credits !== undefined && !Array.isArray(doc.credits)) return 'the draft\'s doc credits are not a list';
  if (doc.gateRequired !== undefined && typeof doc.gateRequired !== 'boolean') return 'the draft\'s doc gateRequired is not true or false';
  return null;
}
/** draft.doc read defensively: whatever shape a caller hands over, the builder reads only strings and whole numbers, and counts what it could not read. */
function dataOf(draft: PipelineDraft): DocData {
  const raw: unknown = draft.doc ?? DEFAULT_DOC;
  const o = isObj(raw) ? raw : {};
  const bad = { transcript: 0, deployGaps: 0, lockNotes: 0, testNotes: 0, uncoveredMinimum: 0, notes: 0, credits: 0 };
  const list = (k: keyof typeof bad): unknown[] => (Array.isArray(o[k]) ? (o[k] as unknown[]) : []);
  const texts = (k: 'transcript' | 'lockNotes' | 'testNotes' | 'notes'): string[] => { const l = list(k); bad[k] += l.filter((x) => !isStr(x)).length; return l.filter(isStr); };
  const objs = (k: 'deployGaps' | 'uncoveredMinimum' | 'credits'): Record<string, unknown>[] => { const l = list(k); bad[k] += l.filter((x) => !isObj(x)).length; return l.filter(isObj); };
  const est = isObj(o.estimates) ? o.estimates : {};
  const whole = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  const gaps = objs('deployGaps').filter((g) => { const ok = isStr(g.path) && g.path !== ''; if (!ok) bad.deployGaps++; return ok; });
  const unc = objs('uncoveredMinimum').filter((u) => { const ok = isStr(u.category); if (!ok) bad.uncoveredMinimum++; return ok; });
  const cred = objs('credits').filter((c) => { const ok = isStr(c.text); if (!ok) bad.credits++; return ok; });
  return {
    transcript: texts('transcript'),
    deployGaps: gaps.map((g) => ({ path: g.path as string, triggers: strs(g.triggers), why: isStr(g.why) ? g.why : '' })),
    lockNotes: texts('lockNotes'),
    est: whole(est.monthlyMinutes) ? { monthlyMinutes: est.monthlyMinutes, includedMinutes: whole(est.includedMinutes) ? est.includedMinutes : null, ...(whole(est.prWaitMinutes) ? { prWaitMinutes: est.prWaitMinutes } : {}), ...(isStr(est.strictness) && STRICTNESS.has(est.strictness) ? { strictness: est.strictness } : {}) } : null,
    gateRequired: typeof o.gateRequired === 'boolean' ? o.gateRequired : undefined,
    setupCommand: isStr(o.setupCommand) ? o.setupCommand : '',
    testNotes: texts('testNotes'),
    uncoveredMinimum: unc.map((u) => ({ category: u.category as string, why: isStr(u.why) ? u.why : '', ...(isStr(u.service) ? { service: u.service } : {}) })),
    notes: texts('notes'),
    credits: cred.map((c) => ({ text: c.text as string, kind: isStr(c.kind) ? c.kind : '' })),
    bad,
  };
}
const STRICTNESS: ReadonlySet<string> = new Set(['Starter', 'Standard', 'Strict']);
/** The line that stands where entries of a list could not be read (a gap or a limit must never vanish without a trace). */
const unreadable = (d: Doc, n: number): void => { if (n > 0) d.li(n === 1 ? 'An entry could not be read, so it is not shown here.' : `${n} entries could not be read, so they are not shown here.`); };

// ---------- facts read from the draft ----------

const NAME_OK = /^[A-Za-z0-9._-]{1,100}$/;
const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const hasCat = (draft: PipelineDraft, cat: string): boolean => draft.needs.some((n) => categoryOf(n.id, n.category) === cat);
const stepsOf = (draft: PipelineDraft, needId: string, service: string | undefined): StepSpec[] => draft.steps.filter((s) => s.needId === needId && s.service === service);
const planWord = (plan: string): string => (['free', 'pro', 'team', 'enterprise'].includes(plan) ? plan : 'not known');

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
  if (data.lockNotes.length > 0 || data.bad.lockNotes > 0) {
    d.h(3, 'Locks on merging');
    for (const n of data.lockNotes) noteItems(d, n);
    unreadable(d, data.bad.lockNotes);
  }
}

function setupSection(d: Doc, draft: PipelineDraft, data: DocData): void {
  const p = draft.profile;
  d.h(2, SECTION_TITLES[1] as string);
  d.li('pipegen v0.2 is for repositories owned by CrisWorking. A public repository uses the gate in the normal way.');
  d.li(p.private
    ? `This repository is private, so its checks run from central workflows in the pipelines repository of the same owner, pinned to one commit. The caller file in this repository is \`${CALLER_WORKFLOW}\`.`
    : `This repository is public, so its checks are written inline in this repository: \`${CALLER_WORKFLOW}\`, \`${LOCAL_MERGE_WORKFLOW}\`, \`${PUSH_WORKFLOW}\` and \`${NIGHTLY_WORKFLOW}\`. Its install record is kept in a private pipelines repository.`);
  d.li('pipegen does not change what or how you deploy. It adds a verify job, `needs` entries on your existing deploy jobs, and its head check as the first step of each of those jobs (so a deploy that waited for an approval, or a re-run, stops once a newer commit is on the default branch), and nothing else in them. Two kinds of deploy job get no head check: a job that calls another workflow (it has no steps of its own), and one pipegen gates only for its runner or vars that can not start with the check; the notes below say which jobs and what that leaves open.');
  d.li(`pipegen offers three strictness levels, Starter, Standard (the default) and Strict. They decide which checks block a pull request and which only warn.${data.est?.strictness === undefined ? '' : ` This setup uses ${data.est.strictness}.`}`);
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
  if (data.credits.length > 0 || data.bad.credits > 0) {
    d.h(3, 'Checks your repository already has');
    let warned = false;
    for (const c of data.credits) {
      d.li(fit(c.text));
      if (c.kind === 'push-default' && !warned) { d.li(PUSH_CREDIT_WARNING); warned = true; }
    }
    unreadable(d, data.bad.credits);
  }
}

function tableSection(d: Doc, f: Facts): void {
  d.h(2, SECTION_TITLES[2] as string);
  d.p(f.gateRequired
    ? `The required check is \`${GATE_CHECK_NAME}\`. When it fails, or only warns, its summary on the run gives messages. The first column holds the start of the message as the gate writes it (or the rule name of an integrity finding), so you can find your line.`
    : `The check is \`${GATE_CHECK_NAME}\`. Nothing requires it to pass on this repository, so a failed gate does not stop a merge: the rows below say what the gate reports. When it fails, or only warns, its summary on the run gives messages. The first column holds the start of the message as the gate writes it (or the rule name of an integrity finding), so you can find your line.`);
  d.row(['Message', 'What it means', 'What to do']);
  d.row(['---', '---', '---']);
  for (const r of GATE_REASONS) d.row([r.message, soft(r.means, f), soft(r.todo, f)]);
}

/** The builder refuses a draft whose facts contradict each other (a label that does not fit the checks): G13 fixes the input. */
export class PipegenDocError extends Error {}

/** What the builder works out itself, once, from the draft: the gate's job list, whether anything can require the gate, and what the hook file really holds. */
interface Facts {
  list: JobListEntry[];
  /** The hook files pipegen wrote (part precommit) and the hooks it put in them. */
  hookFiles: CreatedFile[];
  hooks: HookCommand[];
  /** A hook config exists for hooks-ci to run: the repository's own manager, or the file pipegen wrote. */
  hookConfig: boolean;
  /** The hook manager of the file pipegen wrote (by path), or null when none was written. */
  manager: keyof typeof HOOK_FILES | null;
  /** Whether a written file holds the secrets hook. */
  secretsHook: boolean;
  /** Whether the merge lock can require the gate to pass (branch rules available, locks not skipped, and the doc's own word when G13 gives one). */
  gateRequired: boolean;
}
function factsOf(draft: PipelineDraft, reviewed: readonly ReviewedTool[], data: DocData): Facts {
  let list: JobListEntry[];
  try { list = gateJobList(draft); } catch (e) { throw new PipegenDocError(`the gate's job list can not be built from the draft, so PIPEGEN.md can not say what blocks (${e instanceof Error ? e.message.slice(0, 200) : 'an error'})`); }
  if (data.est?.strictness === 'Strict' && draft.warnFirst !== undefined && Object.keys(draft.warnFirst).length > 0) {
    throw new PipegenDocError('the strictness label is Strict, but some checks start in warn mode (Strict has no warn period), so PIPEGEN.md would say two things that do not fit');
  }
  const hookFiles = draft.created.filter((f) => f.part === 'precommit');
  let hooks: HookCommand[] = [];
  try { hooks = hookCommands(draft, reviewed); } catch { hooks = []; }
  const gateRequired = draft.capabilities.branchProtection === true && !draft.skipped.some((x) => x.part === 'locks') && data.gateRequired !== false;
  // the setup command is the written file's manager's, or empty when no file was written: anything else is a doc that says one thing and a file another
  const manager = (Object.keys(HOOK_FILES) as (keyof typeof HOOK_FILES)[]).find((m) => hookFiles.some((f) => f.path === HOOK_FILES[m])) ?? null;
  const expected = manager === null ? '' : SETUP_COMMANDS[manager];
  if (data.setupCommand !== expected) {
    throw new PipegenDocError(manager === null
      ? 'the setup command is set, but no hook file was written, so PIPEGEN.md would say hooks are active that do not exist'
      : `the setup command does not fit the hook file that was written (${HOOK_FILES[manager]} is for ${manager}), so PIPEGEN.md would give a command for another hook manager`);
  }
  const secrets = hooks.find((h) => h.id === SECRETS_HOOK_ID);
  return { list, gateRequired, hookFiles, hooks, hookConfig: hookFiles.length > 0 || draft.profile.precommit !== null, manager, secretsHook: secrets !== undefined && hookFiles.some((f) => f.content.includes(secrets.run)) };
}

/**
 * The gate's own rule (gate/src/decide.ts, level): a check that is not a floor need is judged as not proven, a warning that never blocks, when its need is
 * in notProven, or when it runs ZAP while ZAP's report is unverified. Null: the check keeps its mode.
 */
function warnOnlyWhy(draft: PipelineDraft, n: { id: string; category: string; service?: string }): string | null {
  const cat = categoryOf(n.id, n.category);
  if (FLOOR_NEEDS.includes(n.id) || FLOOR_NEEDS.includes(cat)) return null;
  if (draft.notProven.some((x) => x.needId === n.id)) return 'it is not proven yet (see Not proven yet)';
  if (!ZAP_JSON_VERIFIED && stepsOf(draft, n.id, n.service).some((s) => s.tool.id === ZAP_TOOL)) return 'ZAP results are not verified yet, so the gate does not let this check block';
  return null;
}
const NOT_REQUIRED = 'Runs on each pull request, but nothing requires it to pass.';
/**
 * When nothing requires the gate to pass, text about what it "blocks" is said in other words: the gate fails, and nothing stops the merge.
 * (The same words as the merge lines: "nothing requires it".)
 */
const soft = (text: string, f: Facts): string => (f.gateRequired ? text : text
  .replace(/\bThe gate blocks\b/g, 'The gate fails').replace(/\bblocks\b/g, 'fails the gate').replace(/\bblocked\b/g, 'failed by the gate')
  .replace(/\bblock\b/g, 'fail the gate').replace(/\bblocking\b/g, 'required'));
const FOR_INFO = 'Runs for information; the gate does not use it.';

/** The mode line of one check, from facts the builder derived (the gate's job list, the hook file, the lock), never from the need's flags alone. */
function modeOf(draft: PipelineDraft, reviewed: readonly ReviewedTool[], f: Facts, n: Need): string {
  const cat = categoryOf(n.id, n.category);
  const layer = n.layer;
  const specs = stepsOf(draft, n.id, n.service);
  // hooks: what was written is what is set up
  if (layer === 'pre-commit') {
    if (f.hookFiles.length === 0) return 'Not set up: pipegen wrote no hook file (see Hooks setup).';
    if (n.id === 'secrets') {
      const h = f.hooks.find((x) => x.id === SECRETS_HOOK_ID);
      if (h === undefined) return reviewed.some((t) => t.id === 'gitleaks' && t.categories.includes('secrets')) ? 'Not set up: the secrets hook was not written (see the notes below).' : 'Not set up: the reviewed list has no gitleaks entry here, so no secrets hook was written.';
      if (!f.hookFiles.some((x) => x.content.includes(h.run))) return 'Not set up: the hook file does not hold the secrets hook.';
    } else if (n.id === 'format-lint') {
      const mine = f.hooks.filter((x) => x.id !== SECRETS_HOOK_ID);
      if (mine.length === 0) return 'Not set up: the format and lint hook was left out (it needs the repository\'s own Biome at the reviewed version in its lockfile; see the notes below).';
      if (!mine.some((h) => f.hookFiles.some((x) => x.content.includes(h.run)))) return 'Not set up: the hook file does not hold the format and lint hook.';
    }
    return n.blocking ? 'Blocks the commit.' : 'Warns only.';
  }
  if (cat === 'hooks-ci' && !f.hookConfig) return 'Not set up: there is no hook config for it to run.';
  if (layer !== 'merge') {
    const only = warnOnlyWhy(draft, n);
    return only !== null ? `Warns only: ${only}.` : !n.blocking ? 'Warns only.' : 'Fails the run.';
  }
  // the merge layer: the gate's own list decides
  if (PIPEGEN_JOB_CATEGORIES.has(cat)) return f.gateRequired ? 'Blocks a pull request.' : NOT_REQUIRED;
  let key: string;
  try { key = jobIdFor(n.id, n.service); } catch { return FOR_INFO; }
  const e = f.list.find((x) => x.job === key && x.range !== true);
  if (e === undefined) {
    const demoted = n.blocking && FINDINGS_CATEGORIES.has(cat) && specs.length > 0 && !specs.every((s) => readableFormat(cat, s.output.format));
    return demoted ? 'Warns only: its tool writes no results file the gate can read.' : FOR_INFO;
  }
  const floor = FLOOR_NEEDS.includes(e.needId) || FLOOR_NEEDS.includes(e.category);
  const zapUnverified = e.tool === ZAP_TOOL && !ZAP_JSON_VERIFIED;
  if (!floor && draft.notProven.some((x) => x.needId === e.needId)) return 'Warns only: it is not proven yet (see Not proven yet).';
  if (!floor && zapUnverified) return 'Warns only: ZAP results are not verified yet, so the gate does not let this check block.';
  if (!floor && !e.blocking) return 'Warns only.';
  if (!f.gateRequired) return NOT_REQUIRED;
  if (e.warnFirst !== undefined) {
    return !isResultFormat(e.format)
      ? 'Starts in warn mode: a failure warns until a reviewed pull request makes the check blocking.'
      : 'Starts in warn mode: old and medium findings warn, but a new critical or high finding still blocks, and so does a failed job.';
  }
  return 'Blocks a pull request.';
}

function layersSection(d: Doc, draft: PipelineDraft, data: DocData, reviewed: readonly ReviewedTool[], facts: Facts): void {
  d.h(2, SECTION_TITLES[3] as string);
  d.p('Each check has a tool, a reason and a mode. The mode is worked out from what pipegen wrote and from the gate\'s own rules, not only from what the plan asked for.');
  for (const layer of LAYERS) {
    const needs = draft.needs.filter((n) => n.layer === layer);
    d.h(3, `${layer === 'pre-commit' ? 'Pre-commit' : layer === 'push' ? 'Push' : layer === 'merge' ? 'Merge' : 'Deploy'} layer`);
    d.p(LAYER_TEXT[layer]);
    if (needs.length === 0) { d.p('No check of this layer is set up here.'); continue; }
    for (const n of needs) {
      const cat = categoryOf(n.id, n.category);
      const [label, why] = Object.hasOwn(CATEGORY_TEXT, cat) ? (CATEGORY_TEXT[cat] as readonly [string, string]) : ['A check pipegen added', 'See the tool name.'];
      const tools = [...new Set(stepsOf(draft, n.id, n.service).map((s) => fit(s.tool.name, 80)))];
      const mode = modeOf(draft, reviewed, facts, n);
      const tool = cat === 'gate' ? 'tool the pipegen gate action' : tools.length === 0 ? 'no tool listed (see the notes below)' : `tool ${tools.join(', ')}`;
      d.li(`${label}${n.service === undefined ? '' : `, service ${q(n.service)}`}, ${tool}. ${why} ${mode}`);
    }
  }
  limitsSection(d, draft);
  tuningSection(d, draft);
  d.h(3, 'Notes from the build');
  const notes = buildNotes(data);
  if (notes.length === 0 && data.bad.notes === 0) d.p('There are no notes.');
  for (const n of notes) noteItems(d, n);
  unreadable(d, data.bad.notes);
}

/** The build notes in the order given, with GJ's husky line kept and G6's husky line dropped (one line per hook manager). */
function buildNotes(data: DocData): string[] {
  const all = data.notes;
  const gj = all.some((n) => n.startsWith(GJ_HUSKY_NOTE_START));
  return all.filter((n, i) => all.indexOf(n) === i && !isAiNote(n) && !(gj && n === HUSKY_NO_CI_NOTE));
}

function limitsSection(d: Doc, draft: PipelineDraft): void {
  const has = (c: string): boolean => hasCat(draft, c);
  d.h(3, 'Limits of these checks');
  if (has('type-check')) d.li('The type-check follows your own tsconfig.json. The repo\'s tsconfig decides what tsc checks and how strictly, and a pull request can edit it (`exclude`, `skipLibCheck`, `extends`, a `ts-nocheck` comment). pipegen refuses only the plain no-op layouts: no file selected, `noCheck`, and a missing or linked tsconfig.json. It is not a protected path.');
  if (has('dast')) {
    d.li('The raw result of the running app scan travels unscrubbed between the job that runs the app and the job that reads the result. It holds only what an app without secrets answered. A hostile app can always answer a scanner cleanly.');
    d.li('The running app scan has no earlier scan to compare with, so its findings warn on the pull request that installs pipegen and count as new after it.');
  }
  if (has('image-scan') || has('image-build')) {
    d.li('Image findings have no base yet: there is no earlier scan of the base commit to compare with, so image findings warn on the pull request that installs pipegen and block on every other.');
    d.li('The scanned image is not the published image. The scan covers the build of the pull request head; the publish job builds again at the merge commit, so a moving base image tag can make them differ.');
  }
  if (has('licences')) d.li('The licence scan reads lockfiles only.');
  if (has('sast')) d.li('The code scan runs Semgrep with a pinned copy of the semgrep-rules repository. Those rules have their own licence (the Semgrep Rules License v1.0). It lets you use them to check your own code, but not to sell them or offer them as a service. Read it before you use the rules anywhere else.');
  if (has('publishing')) d.li('Publishing uses a trusted publisher, so no token is stored. Set it up once: on npmjs.com open the package settings and add a trusted publisher for GitHub Actions with this repository and the publish workflow file name; on PyPI open the project, then Publishing, and add a trusted publisher with the same details. The publish job needs npm 11.5.1 or newer and Node 22.14.0 or newer, and it is the only job that gets the `id-token` permission.');
  if (has('duplication')) d.li('The copy-paste check warns only, at first: it reports new copy-paste in changed code, and old copies are not counted. A repository can make it blocking. The mode of a check is part of the pipeline files, which are protected paths, so that change goes through a pull request that a code owner approves.');
  if (draft.signing?.mode === 'keyless') d.li('The keyless signing job runs without a network block: it needs a per-run token host that can not be listed exactly. Only pipegen\'s own steps run there.');
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
  for (const n of data.testNotes) noteItems(d, n);
  unreadable(d, data.bad.testNotes);
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
  for (const g of data.deployGaps) d.li(`${q(g.path, 160)} (triggers: ${g.triggers.length === 0 ? 'unknown' : g.triggers.map((t) => fit(t, 40)).join(', ')}): ${fit(g.why)}`);
  // derived here, so the byte-equal recompute covers it: a deploy workflow of the repository that is neither edited nor listed as a gap is never read as protected
  const handled = new Set([...edited.map((f) => f.path), ...data.deployGaps.map((g) => g.path)]);
  const loose = draft.profile.existingWorkflows.filter((w) => w.deploys === true && !handled.has(w.path));
  for (const w of loose) d.li(`${q(w.path, 160)}: pipegen added no verify job and listed no gap for this deploy workflow. Treat it as unprotected.`);
  unreadable(d, data.bad.deployGaps);
  if (data.deployGaps.length === 0 && loose.length === 0 && data.bad.deployGaps === 0) d.p(draft.profile.existingWorkflows.some((w) => w.deploys === true) ? 'Every deploy workflow of this repository got the verify job.' : 'pipegen found no deploy workflow in this repository.');
  d.li('A deploy workflow with any other trigger than a push to the default branch gets no verify job, so it is an unprotected gap. A deploy started by `workflow_run` is a gap too, and so is a deploy from a branch other than the default branch (the verify job passes only for the default branch).');
  if (draft.profile.private && !draft.capabilities.environments) d.li('On a private repository with a free plan the verify job runs without an environment, so the default-branch limit can not be enforced there.');
  d.li('Each edit pipegen made to a deploy workflow is listed under Not proven yet until you have checked it.');
}

/**
 * A minimum check the plan owes (floorNeeds, merge layer, MINIMUM_CATEGORIES) that the gate would not wait for: it has no entry in the gate's job list
 * (gateJobList, merge layer), or, for the gate itself, no merge-layer need. Not covered, whatever doc.uncoveredMinimum says.
 */
function missingMinimum(draft: PipelineDraft, f: Facts): { category: string; service?: string }[] | 'unknown' {
  try {
    return floorNeeds(draft.profile, draft.capabilities)
      .filter((n) => n.layer === 'merge' && (MINIMUM_CATEGORIES as readonly string[]).includes(categoryOf(n.id, n.category)))
      .filter((n) => (categoryOf(n.id, n.category) === 'gate'
        ? !draft.needs.some((x) => x.layer === 'merge' && x.id === n.id)
        : !f.list.some((e) => e.job === jobIdFor(n.id, n.service))))
      .map((n) => ({ category: categoryOf(n.id, n.category), ...(n.service === undefined ? {} : { service: n.service }) }));
  } catch { return 'unknown'; }
}

function notProvenSection(d: Doc, draft: PipelineDraft, data: DocData, reviewed: readonly ReviewedTool[], facts: Facts): void {
  const p = draft.profile;
  d.h(2, SECTION_TITLES[10] as string);
  // ZAP while its report is unverified: the gate's own list says which checks run it
  const zap = facts.list.filter((e) => e.tool === ZAP_TOOL && !ZAP_JSON_VERIFIED && !FLOOR_NEEDS.includes(e.needId) && !FLOOR_NEEDS.includes(e.category) && !draft.notProven.some((x) => x.needId === e.needId));
  // every file pipegen edited is not proven by design: derived here, so a "proven" line can never stand next to one
  const edits = draft.created.filter((f) => f.inserted !== undefined);
  const proofless = draft.steps.some((s) => reviewed.some((t) => t.id === s.tool.id && t.proofs === 0));
  const warnOnly = draft.notProven.length > 0 || zap.length > 0 || edits.length > 0 || proofless;
  if (!warnOnly) d.p('Every check pipegen set up is proven.');
  for (const n of draft.notProven) {
    const cat = n.needId === undefined ? '' : categoryOf(n.needId, n.needId);
    const label = cat !== '' && Object.hasOwn(CATEGORY_TEXT, cat) ? (CATEGORY_TEXT[cat] as readonly [string, string])[0] : '';
    const names = strs(n.missingSecrets);
    const secrets = names.length === 0 ? '' : ` Secret names to set: ${names.map((x) => (SECRET_NAME_RE.test(x) ? `\`${x}\`` : fit(x, 60))).join(', ')}.`;
    d.li(`Part ${fit(n.part, 40)}${label === '' ? '' : `, ${label}`}: ${fit(n.reason)}${secrets}`);
  }
  for (const e of zap) {
    const need = draft.needs.find((n) => n.layer === 'merge' && n.id === e.needId && jobIdFor(n.id, n.service) === e.job);
    const spec = draft.steps.find((st) => st.needId === e.needId && st.service === need?.service && st.tool.id === ZAP_TOOL);
    const label = Object.hasOwn(CATEGORY_TEXT, e.category) ? (CATEGORY_TEXT[e.category] as readonly [string, string])[0] : 'A check pipegen added';
    d.li(`${label}${need?.service === undefined ? '' : `, service ${q(need.service)}`}, tool ${fit(spec?.tool.name ?? ZAP_TOOL, 80)}: ZAP results are not verified yet, so the gate judges this check as not proven. It only warns and never blocks a pull request.`);
  }
  for (const f of edits) d.li(`Part deploy-verify: pipegen edited ${q(f.path, 160)} (it added the verify job, \`needs\` entries and its head check as the first step of each deploy job, except a job that calls another workflow, or one pipegen gates only for its runner or vars and can not start with the check (see the notes)). Check the edit by hand before you rely on it.`);
  const link = secretsLink(p.owner, p.repo);
  d.p(`Set a missing secret in the repository settings: Settings, Secrets and variables, Actions${link === null ? '' : ` (${link})`}. When the key exists, the nightly run opens an issue with the exact patch: run \`npx pipegen update\` and it applies the change as a pull request. CI never edits workflow files itself.`);
  const where = p.private ? `\`.github/workflows/${centralProjectName(p.repo)}--merge.yml\` in the pipelines repository` : `\`${LOCAL_MERGE_WORKFLOW}\``;
  d.p(`The not-proven list is one line in ${where}, marked \`pipegen:not-proven\`. It never holds a check that every repository needs.`);
  if (proofless) d.p(BOOTSTRAP_PROOFS_NOTE);
  // the minimum checks without a job: the ones the plan reported, and any the builder finds missing itself (a doc that leaves one out is still complete)
  const miss = missingMinimum(draft, facts);
  const derived = miss === 'unknown' ? [] : miss.filter((m) => !data.uncoveredMinimum.some((u) => u.category === m.category && u.service === m.service));
  if (data.uncoveredMinimum.length > 0 || derived.length > 0 || miss === 'unknown' || data.bad.uncoveredMinimum > 0) {
    d.h(3, 'Minimum checks with no job (not covered)');
    d.p('pipegen requires these checks for every repository, but it could not write a job for them here. Until you add them yourself, nothing runs for them.');
    for (const u of data.uncoveredMinimum) {
      const cat = Object.hasOwn(CATEGORY_TEXT, u.category) ? (CATEGORY_TEXT[u.category] as readonly [string, string])[0] : fit(u.category, 60);
      d.li(`${cat}${u.service === undefined ? '' : `, service ${q(u.service)}`}: not covered. ${fit(u.why)}`);
    }
    for (const m of derived) {
      const cat = Object.hasOwn(CATEGORY_TEXT, m.category) ? (CATEGORY_TEXT[m.category] as readonly [string, string])[0] : fit(m.category, 60);
      d.li(`${cat}${m.service === undefined ? '' : `, service ${q(m.service)}`}: not covered. This setup has no job for it.`);
    }
    if (miss === 'unknown') d.li('pipegen could not work out whether a minimum check is missing, so treat the minimum checks as not covered until you have looked.');
    unreadable(d, data.bad.uncoveredMinimum);
  }
}

function integritySection(d: Doc, draft: PipelineDraft, f: Facts): void {
  d.h(2, SECTION_TITLES[11] as string);
  d.li(f.gateRequired
    ? 'The gate protects the files that define the pipeline: workflows, tool configs, ignore files and the hook files. A pull request that changes one is blocked unless a code owner approved the exact head commit.'
    : 'The gate watches the files that define the pipeline: workflows, tool configs, ignore files and the hook files. It reports a pull request that changes one unless a code owner approved the exact head commit, but nothing requires it to pass, so it does not stop the merge.');
  const extra = draft.gateSettings?.protectedPaths ?? [];
  if (extra.length > 0) d.li(`Extra protected paths: ${extra.filter(isStr).map((x) => q(x, 120)).join(', ')}.`);
  const co = draft.codeOwners;
  if (co !== undefined && co.owners.length > 0) d.li(`Code owners in pipegen's CODEOWNERS block: ${co.owners.filter(isStr).map((o) => q(o.replace(/^@/, ''), 60)).join(', ')}. ${co.writers} ${co.writers === 1 ? 'person can' : 'people can'} write to this repository.`);
  else d.li('pipegen wrote no CODEOWNERS block, so there is no code-owner review of the pipeline files (see the locks notes in the first section).');
  d.li('A one-person repository: pull requests need no approval, so whoever merges can also change the pipeline that judges them, and pipegen can not prevent that. Run `npx pipegen verify` to see whether the pipeline still matches what pipegen set up.');
  d.li('Code-owner review is the guard against a job that fakes the gate\'s name. Where GitHub can not enforce it, the limit is stated in the first section.');
  d.li('A patch issue the nightly run opens is only a prompt: `npx pipegen update` works out the change itself from its built-in reviewed pins.');
}

function warnSection(d: Doc, draft: PipelineDraft, f: Facts): void {
  d.h(2, SECTION_TITLES[12] as string);
  d.p(WARN_MODE_TEXT);
  d.p(soft('In warn mode old findings and medium ones warn, and a new critical, high or secret finding still blocks.', f) + (f.gateRequired ? '' : ' Nothing requires it to pass here.'));
  d.p(soft('There are two timers. The first (7 days after you merge) is for the whole gate: it warns until then and blocks after. The second is for one check: a new blocking check can start in its own warn mode for about 14 days, and then the nightly run opens an issue to switch it to blocking.', f));
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
  if (data.transcript.length > 0 || data.bad.transcript > 0) { d.h(3, 'Transcript'); for (const l of data.transcript) d.li(fit(l)); unreadable(d, data.bad.transcript); }
  if (draft.scoreboard.length === 0 && data.transcript.length === 0 && data.bad.transcript === 0) d.p('No debate was recorded.');
}

function hooksSection(d: Doc, f: Facts): void {
  d.h(2, SECTION_TITLES[15] as string);
  // everything here is about the file pipegen wrote: its manager's command, and the secrets hook only when the file holds it
  if (f.manager === null) { d.p('pipegen wrote no hook file, so there is no setup command. The notes in The four layers say why.'); return; }
  d.p(`After you clone the repository, run \`${SETUP_COMMANDS[f.manager]}\` once, so the hooks pipegen wrote in \`${HOOK_FILES[f.manager]}\` are active on your machine.`);
  if (f.secretsHook) {
    d.p('The secrets hook runs pipegen from npm, at the exact version that wrote the hook, and pipegen runs its pinned secret scanner on the staged changes. The command is:');
    d.fence('sh', ['npx --yes --prefix=/ --registry=https://registry.npmjs.org pipegen@VERSION hook secrets']);
    d.p('VERSION is the exact pipegen version that wrote the hook. The first commit trusts npm\'s metadata for that exact version. It is not pinned by a lockfile hash.');
    d.li('The hook needs `node` and `npx` and a connection to the npm registry, in every language repository. If one is missing the hook fails and blocks the commit (it fails closed).');
    d.li('`git commit --no-verify` is the way out when npm is unreachable or the version is not published. CI still scans.');
    d.li('If the pipegen version that wrote the hook is not on npm (a build that was never published), every commit fails with npm\'s own `E404` text. That means npm has no such version. Use `git commit --no-verify` until a published version is in the hook.');
    d.li('In CI the hooks run with `--all-files`, so nothing is staged and the secrets hook passes at once. The secret scan job of CI is the cover.');
  } else {
    d.li('pipegen wrote no secrets hook (see the secret scan line in The four layers), so the local hooks do not scan for secrets; the secret scan job of CI does.');
    d.li('`git commit --no-verify` skips the local hooks. CI still scans.');
  }
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
  const facts = factsOf(draft, reviewed, data);
  const d = new Doc();
  d.h(1, 'What pipegen set up in this repository');
  d.p('pipegen wrote this file in plain English. If you edit it, pipegen keeps your edits and never replaces the file.');
  planSection(d, draft, data);
  setupSection(d, draft, data);
  tableSection(d, facts);
  layersSection(d, draft, data, reviewed, facts);
  suggestionsSection(d, draft);
  filesSection(d, draft, data);
  testsSection(d, draft);
  skippedSection(d, draft);
  signingSection(d, draft);
  deploysSection(d, draft, data);
  notProvenSection(d, draft, data, reviewed, facts);
  integritySection(d, draft, facts);
  warnSection(d, draft, facts);
  retentionSection(d);
  debateSection(d, draft, data);
  hooksSection(d, facts);
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
  const shape = docShapeProblem(draft.doc);
  if (shape !== null) return `${shape}, so the referee can not build PIPEGEN.md again to compare it`;
  let again: CreatedFile;
  try { again = pipegenDoc(draft, reviewed); } catch (e) { return e instanceof PipegenDocError ? `PIPEGEN.md could not be built again from the draft: ${e.message}` : 'PIPEGEN.md could not be built again from the draft'; }
  if (file.content !== again.content) return 'PIPEGEN.md is not the file pipegen builds from the draft (the referee builds it again and requires the same bytes)';
  if (file.reason !== again.reason || file.part !== again.part) return 'PIPEGEN.md does not carry the part and reason pipegen gives it';
  return null;
}
