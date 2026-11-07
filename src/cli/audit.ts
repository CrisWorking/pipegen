// `pipegen audit` (Plan U Task 4b): the read-only report on a repo's CI, with an optional `--ai` step after consent.
// The audited repo is attacker-controlled; GitHub and the AI are only read from or asked; nothing is ever written to
// GitHub, and no file is written unless --out names one (outside the repo, unless --force).
//
// Flow (ruling B1): readProject (owner/repo) → getAuth({ mode: 'read' }) → makeOctokit(token or null, per-request
// timeout) → GET /user only with a token → readGitHubContext (reusing getAuth's anonymous GET /repos, M6) → probeCapabilities → buildAudit with the full run's
// permissions (permissionsTable('write', …)), ONE rate budget for every GitHub call of the run (S18).
// - GitHub can't be read (no access, a refused token, no answer): only what is on disk is reported, with
//   "GitHub: not read", and the exit code is 1 (the inspect R10 rule). No GitHub fact is guessed.
// - GitHub's rate limit stops the reads (DoD run 2026-10-29): the full report from the files, what GitHub answered
//   kept, every check that needed the rest unknown, a top warning with the reset time (and the read-only token that
//   lifts the anonymous limit), `githubIncomplete` in --json, exit code 3.
// - The reviewed tool list can't be used (B3: the release build refuses it while entries wait for review): the audit
//   runs with no reviewed tools and a warning at the top, exit 0.
// - `--ai`: everything that can refuse it is checked first, before any GitHub call (S21 platform, PIPEGEN_SECRET_SCANNER,
//   S15 provider, the Ollama checks of U15/H2, the scanner's pin). After the plain audit: the estimate (an unpriced model
//   stops here, U14), from the counting bundle (no secret scan, no child process) the plain audit already counted with, built once
//   per run (final review M9), then the consent screen (default No). Only a yes
//   gives the ConsentToken addAiSuggestions requires; it then downloads the secret scanner, builds the checked bundle and asks the AI.
// - Plan J J5 (DECISIONS #124, ruling B1): before all of this, main.ts runs unsafeFolderStop (the swap-risk stop, exit
//   EXIT_UNSAFE_FOLDER). After the local read, the --type values are checked against the services read; without them,
//   at a terminal (CliIO.interactive) and without --json, confirmTypes asks whether the detected types are right. Both
//   come before any GitHub call; a cancel there exits 0 with nothing read from GitHub and no report. The types chosen go
//   to buildAudit / buildLocalAudit as data (typeOverrides).
// - Output: the terminal report (default) or JSON (--json) on stdout; --out writes the Markdown report through
//   writeOutFile; errors and status lines on stderr. Every output gets the run's known values (the GitHub token and
//   the AI keys, S19/U10), so neither is ever printed, and every line passes hideToken.
import { resolve } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { checkOllamaModelRunsThere } from '../ai/ollama.js';
import { AiError, makeProvider } from '../ai/provider.js';
import { bundleCode, chooseSecretScanner, scrubKnownValues, SecretScanError, type ScanFound, type SecretScanner, type SecretScannerName } from '../ai/redact.js';
import { countingSummary } from '../audit/consent-token.js';
import { writeOutFile, OutFileError } from '../audit/out-file.js';
import {
  addAiSuggestions, buildAudit, buildLocalAudit, CONSENT_INCOMPLETE, needsRequestBytes, safeRunCommand, SWAP_TEXT, SWAP_TEXT_NO_COMMAND, swapRiskWhy, type AuditReport,
} from '../audit/model.js';
import { renderJson, renderLocalJson, renderLocalTerminal, renderMarkdown, renderTerminal, type RenderOptions } from '../audit/render.js';
import { isRateStop, newRateBudget, rateStopOf, type RateClock } from '../engine/github-rate.js';
import { loadPinnedBinaries, PinnedBinaryError, PLATFORM_KEYS } from '../engine/linters.js';
import { openMemory } from '../engine/memory.js';
import { loadQualityBar, type QualityBar } from '../engine/quality-bar.js';
import { loadReviewed, ReviewedListError } from '../engine/reviewed.js';
import { estimateAuditAi } from '../estimate/estimate.js';
import { probeCapabilities } from '../github/capabilities.js';
import {
  getAuth, GitHubAccessError, GITHUB_TIMEOUT_MS, hideToken, makeOctokit, permissionsTable, readAccessSteps, readGitHubContext,
} from '../github/client.js';
import { NotGitHubRepoError, readProject } from '../read/project.js';
import type { TypeOverride } from '../read/project-type.js';
import type { AiProvider, Auth, Capabilities, RepoProfile, ReviewedTool } from '../types.js';
import { packageVersion } from '../util/package-data.js';
import { knownValuesFrom, makeSafeOutput, OUTPUT_CAP, usableKnownValues } from '../util/safe-output.js';
import { safeText } from '../util/safe-text.js';
import { askConsent, consentScreen } from './consent.js';
import { tokenLogin } from './inspect.js';
import type { CliIO, Prompter } from './io.js';
import { typeStep } from './type-confirm.js';

/** The AI providers `--ai` accepts (ruling S15). */
export const AI_CHOICES = ['claude', 'openai', 'ollama'] as const;
export type AiChoice = (typeof AI_CHOICES)[number];

export interface AuditFlags {
  /** --dir as given (default: the current folder). */
  dir?: string;
  /** --out as given: writeOutFile resolves it from the current folder, never from --dir. */
  out?: string;
  force: boolean;
  json: boolean;
  /** null: no --ai. Otherwise the provider named after --ai, or undefined (bare --ai: from the keys that are set). */
  ai: { provider: AiChoice | undefined } | null;
  model?: string;
  effort?: string;
  allowBroad: boolean;
  /** Plan J J5: the --type values (parseTypeFlags); [] or absent: none, and at a terminal the type question is asked. */
  types?: readonly TypeOverride[];
  /** Plan J J5: --verbose, passed to the terminal renderer (RenderOptions.verbose: the full report; J4 makes the short one the default). */
  verbose?: boolean;
}

/** Ruling S15: the audit's own wording (MISSING_AI_MESSAGE talks about the full job). */
export const AUDIT_AI_MISSING = 'audit --ai needs an AI provider: set ANTHROPIC_API_KEY or OPENAI_API_KEY, or use --ai ollama.';
/** Ruling S21 (Plan B S27): the pinned secret scanners exist for these platforms only. */
export const AUDIT_AI_PLATFORM = 'audit --ai needs Linux or macOS for now (WSL works).';
/**
 * Ruling B3: the top warning when the reviewed tool list can't be used in this build. `why` is the loader's short
 * reason when it gave one (review M7: "23 entries still wait for human review (…)"), else its whole message.
 */
export const reviewedUnavailableWarning = (why: string) =>
  `pipegen's reviewed tool list isn't usable in this build: ${why.trim().replace(/\.+$/, '')}. The 'would add' section shows no tools.`;
/** Needs the AI may add on top of the floor, for the consent estimate (estimateAuditAi caps the discovery calls itself). */
const EXTRA_NEEDS_MARGIN = 2;

type GitHubContext = Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'>;
/**
 * `context` null and `unread`: what GitHub's rate limit kept the run from reading (DoD run 2026-10-29); `caps` is then
 * a placeholder for the unread capabilities.
 */
interface GitHubRead { auth: Auth; gh: Octokit; context: GitHubContext | null; caps: Capabilities; unread: (keyof Capabilities)[] }
/** The capabilities when none could be read (a placeholder: buildAudit treats every one as unread). */
const NO_CAPABILITIES: Capabilities = {
  branchProtection: false, environments: false, deploymentBranchPolicies: false, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false,
};
/** `pipegen audit`'s exit code when the report is complete from the files but GitHub's rate limit left GitHub facts unread. */
export const EXIT_INCOMPLETE = 3;
/** Plan J J5 (owner choice 7): stopped before reading anything, because this folder could change which pipegen runs. */
export const EXIT_UNSAFE_FOLDER = 4;
/** The line after a cancelled type question (stderr; no report follows). */
export const TYPE_CANCELLED = 'Cancelled: nothing was read from GitHub and no report was made.';

/**
 * Plan J J5 (DECISIONS #124, ruling S8): the swap-risk stop, run by main.ts before `audit` and `inspect` do anything
 * else (before the --ai checks, any read of the repo or any GitHub call). When swapRiskWhy finds something in the
 * folders npm read for this start (the current folder up to the audited repo when it is inside it, and up to the
 * current folder's own repo whatever --dir says), it prints what it found, SWAP_TEXT and the safe-mode command on
 * stderr and returns EXIT_UNSAFE_FOLDER; else null (a risk only in the audited repo, run from outside, stays a warning).
 */
export async function unsafeFolderStop(io: CliIO, dir: string): Promise<number | null> {
  const why = await swapRiskWhy(io.cwd ?? process.cwd(), dir);
  if (why === null) return null;
  const command = safeRunCommand(packageVersion());
  io.err(`pipegen stopped before reading the repo: it found ${safeText(why, 500)}.`);
  io.err(command === null ? SWAP_TEXT_NO_COMMAND : SWAP_TEXT);
  if (command !== null) io.err(`  ${command}`);
  io.err(`If this is your own repo, remove what was found and start pipegen again; otherwise run the command above from a folder you trust, outside the repo (replace ./repo with the repo's folder). exit code ${EXIT_UNSAFE_FOLDER}.`);
  return EXIT_UNSAFE_FOLDER;
}
interface AiReady { provider: AiProvider; secretScanner: Pick<SecretScanner, 'name' | 'version'>; bar: QualityBar }

/**
 * Runs `pipegen audit`. 0: a report was printed (also with the reviewed list unusable); 1: a refusal or an error (also
 * GitHub not read at all: no access, a refused token, no answer); 3 (EXIT_INCOMPLETE): a report was printed, but
 * GitHub's rate limit left some GitHub facts unread, so the checks that need them are unknown.
 */
export async function audit(io: CliIO, flags: AuditFlags): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const knownValues: string[] = knownValuesFrom(io.env); // the token and the AI keys (S19), never printed nor sent
  let token: string | null = null;
  /** pipegen's own wording around a value: every step of the output helper but redact (it would cut "this token: …"). */
  const clean = (s: string, max: number = OUTPUT_CAP.text) => makeSafeOutput(knownValues)(s, { target: 'terminal', max, redact: false });
  /** Text pipegen didn't write (an unexpected error's message): the whole helper, redact included (final review M1). */
  const cleanForeign = (s: string, max: number) => makeSafeOutput(knownValues)(s, { target: 'terminal', max });
  const say = (s: string) => { io.out(hideToken(s, token)); };
  const fail = (s: string) => { io.err(hideToken(s, token)); };
  try {
    return await run();
  } catch (e) {
    // anything unexpected: one cleaned line, never a token or key, never a stack trace
    fail(`pipegen audit failed: ${cleanForeign(e instanceof Error ? e.message : String(e), 500)}`);
    return 1;
  }

  async function run(): Promise<number> {
    const dir = resolve(cwd, flags.dir ?? '.');
    const notes: string[] = [];

    // 1. --ai: every refusal before any GitHub call, and long before consent
    let ai: AiReady | null = null;
    if (flags.ai !== null) {
      const ready = await prepareAi(io, flags, notes);
      if (typeof ready === 'string') {
        fail(clean(ready));
        return 1;
      }
      ai = ready;
    }

    // 2. the repo on disk (owner and repo for the GitHub calls)
    let local: Awaited<ReturnType<typeof readProject>>;
    try {
      local = await readProject(dir);
    } catch (e) {
      if (!(e instanceof NotGitHubRepoError)) throw e;
      fail(`pipegen audit needs a clone of a GitHub repository: ${makeSafeOutput(knownValues)(e.message, { target: 'terminal', max: 400 })}`);
      fail('Pass the clone\'s folder with --dir <folder>, and run pipegen from outside it.');
      return 1;
    }
    const { owner, repo } = local;

    // 2b. the types (B1): --type checked against the services read; else, at a terminal and without --json, the type
    //     question (S9). Both before any GitHub call; a cancel reads nothing from GitHub and prints no report.
    const typed = await typeStep(scrubbed(io.prompt), io.interactive === true && !flags.json, local, flags.types ?? []);
    if ('error' in typed) {
      fail(clean(typed.error));
      return 1;
    }
    if ('cancel' in typed) {
      fail(TYPE_CANCELLED);
      return 0;
    }
    const typeOverrides: readonly TypeOverride[] = typed.overrides;

    // 3. GitHub, read-only, one rate budget for the whole run (S18). DoD run 2026-10-29 (Plan U: "discovery stops
    //    early, keeping what passed"): a rate stop at any point keeps what was read and goes on from the files; the
    //    report marks every check that needed the rest as unknown and exits EXIT_INCOMPLETE. Other failures are unchanged.
    const clock: RateClock = { budget: newRateBudget() };
    let github: GitHubRead;
    try {
      const repoAnswer: { data?: unknown } = {}; // getAuth's anonymous GET /repos, reused below (review M6)
      let auth: Auth;
      try {
        auth = await getAuth({ owner, repos: [repo], allowBroad: flags.allowBroad, mode: 'read' }, { env: io.env, fetch: io.fetch, clock, notes, repoAnswer });
      } catch (e) {
        // only the anonymous check (is the repo public?) asks GitHub before a token is chosen; with a token set, keep
        // the old behaviour (a GitHub App login can't be confirmed without GitHub)
        if (!isRateStop(e) || (io.env.GITHUB_TOKEN ?? '').trim() !== '') throw e;
        auth = { kind: 'anonymous', token: null, repos: [repo], canCreateRepos: false, canDeleteRepos: false };
      }
      token = auth.token;
      if (auth.token !== null) knownValues.push(auth.token);
      const gh = makeOctokit(auth.token, { fetch: io.fetch, clock, timeoutMs: GITHUB_TIMEOUT_MS, log: fail });
      let context: GitHubContext | null = null;
      let caps: Capabilities = NO_CAPABILITIES;
      const unread = new Set<keyof Capabilities>();
      try {
        // after a rate stop in getAuth nothing more is asked (an anonymous run has 60 requests an hour)
        if (rateStopOf(clock.budget) !== null) throw clock.budget.stopped;
        const login = await tokenLogin(gh, auth, clock, notes);
        context = await readGitHubContext(gh, owner, repo, login, clock, notes, { known: repoAnswer.data, planRateStop: 'unknown' });
        caps = await probeCapabilities(gh, owner, repo, { ...local, ...context }, notes, clock, { onRateStop: (keys) => { for (const k of keys) unread.add(k); } });
      } catch (e) {
        if (!isRateStop(e)) throw e;
      }
      github = { auth, gh, context, caps, unread: [...unread] };
    } catch (e) {
      if (!(e instanceof GitHubAccessError) && !isRateStop(e)) throw e;
      // a token that can't see the repo: the same read-only steps as without one (never `gh auth login`)
      const steps = token !== null && e instanceof GitHubAccessError && (e.status === 404 || e.status === 403) ? ` ${readAccessSteps(owner, repo)}` : '';
      return localOnly(dir, `${e instanceof Error ? e.message : String(e)}${steps}`, notes, typeOverrides);
    }

    // 4. the reviewed tool list (B3: unusable in this build → no tools, a top warning, exit 0)
    let reviewed: ReviewedTool[] = [];
    let reviewedProblem: string | null = null;
    try {
      reviewed = loadReviewed();
    } catch (e) {
      if (!(e instanceof ReviewedListError)) throw e;
      reviewedProblem = e.reason ?? e.message;
    }

    // 5. the plain audit, with the code bundle counted once (no secret scan, no child process): the report's count and,
    //    with --ai, the consent screen's count are this one count (final review M9)
    const anonymous = github.auth.kind === 'anonymous';
    const counted = await bundleCode(dir, { knownValues });
    let r: AuditReport = await buildAudit(dir, {
      gh: github.gh, anonymous, context: github.context, capabilities: github.caps, unreadCapabilities: github.unread,
      permissions: permissionsTable('write', { appCreatesRepos: github.auth.canCreateRepos }),
      reviewed, reviewedUnavailable: reviewedProblem !== null, now: Date.now, notes, budget: clock.budget, bundle: counted, typeOverrides,
    });
    if (reviewedProblem !== null) r = { ...r, warnings: [{ text: reviewedUnavailableWarning(reviewedProblem) }, ...r.warnings] };

    // 6. --ai: consent first (default No); only a yes gives the token the AI step requires
    // P40/P45: what the secret scan found, masked in the whole report below (the plain-audit parts too)
    let found: ScanFound | undefined;
    if (ai !== null) {
      const nullRows = r.wouldAdd.filter((w) => w.tool === null).length;
      const est = estimateAuditAi(ai.provider, nullRows + EXTRA_NEEDS_MARGIN, needsRequestBytes({ ...r, aiBundle: { ...r.aiBundle, bytes: counted.bytes } }, knownValues));
      if (est.unpriced !== null) {
        fail(clean(est.unpriced.message));
        return 1;
      }
      const screen = consentScreen(r.profile, ai.provider, est, countingSummary(counted), permissionsTable('read'), [], 'audit-ai', { secretScanner: ai.secretScanner, ...(r.githubIncomplete === null ? {} : { incompleteNote: CONSENT_INCOMPLETE }) });
      // defence in depth: the screen is pipegen's own text with cleaned repo names; known values are hidden all the same
      const consent = await askConsent(scrubbed(io.prompt), screen, fail);
      if (consent === null) {
        fail('No consent (you said no, or the question was cancelled): nothing was sent to an AI. The report below is the plain audit.');
      } else {
        r = await addAiSuggestions(r, dir, {
          ai: ai.provider, gh: github.gh, memory: await openMemory(), fetch: io.fetch ?? globalThis.fetch, reviewed, bar: ai.bar,
          budget: clock.budget, now: Date.now, knownValues: [...knownValues], anonymous, capUsd: est.capUsd, consent, onScanFound: (f) => { found = f; },
        });
      }
    }

    // 7. the report
    const opts: RenderOptions & { verbose: boolean } = { knownValues, verbose: flags.verbose === true, ...(found === undefined ? {} : { found }) };
    say(flags.json ? renderJson(r, opts) : renderTerminal(r, opts));
    if (flags.out !== undefined) {
      try {
        // dir is always passed (the default --dir is the current folder): a report inside the repo needs --force
        await writeOutFile(flags.out, hideToken(renderMarkdown(r, opts), token), { force: flags.force, dir: flags.dir ?? '.', ...(io.cwd === undefined ? {} : { cwd: io.cwd }) });
      } catch (e) {
        if (!(e instanceof OutFileError)) throw e;
        fail(e.message); // already cleaned by writeOutFile
        return 1;
      }
      fail(`The Markdown report was written to ${clean(resolve(cwd, flags.out), OUTPUT_CAP.path)}.`);
    }
    if (r.githubIncomplete !== null) {
      fail(`GitHub's rate limit was reached: the report is complete from the files, but the checks that needed GitHub show as unknown (see the warning at the top). exit code ${EXIT_INCOMPLETE}.`);
      return EXIT_INCOMPLETE;
    }
    return 0;
  }

  /**
   * Every question's text with the run's known values hidden (defence in depth: the texts are pipegen's own, with
   * cleaned repo names). `token` is read when a question is asked, so a question after getAuth hides it too.
   */
  function scrubbed(p: Prompter): Prompter {
    const scrub = (s: string) => scrubKnownValues(hideToken(s, token), usableKnownValues(knownValues));
    return { ...p, confirm: (msg, def) => p.confirm(scrub(msg), def), select: (msg, opts, def) => p.select(scrub(msg), opts, def) };
  }

  /** GitHub couldn't be read: what is on disk only, "GitHub: not read", the reason on stderr, exit 1 (R10). */
  async function localOnly(dir: string, why: string, notes: string[], typeOverrides: readonly TypeOverride[]): Promise<number> {
    const l = await buildLocalAudit(dir, { notes, typeOverrides });
    const opts: RenderOptions & { verbose: boolean } = { knownValues, verbose: flags.verbose === true };
    say(flags.json ? renderLocalJson(l, opts) : renderLocalTerminal(l, opts));
    // pipegen's own access message (repo names already cleaned): redact would cut its wording ("this token: …")
    fail(`GitHub: not read: ${clean(why, 2000)}`);
    if (flags.out !== undefined) fail('No report file was written: GitHub could not be read.');
    return 1;
  }
}

/**
 * Everything that can refuse `--ai`, before any GitHub call: the platform (S21), the secret scanner
 * (PIPEGEN_SECRET_SCANNER: betterleaks by default, or gitleaks; anything else is refused), the provider and its key
 * (S15), for Ollama the host and the model (U15/H2: never ollama.com, never a cloud model behind a local name; fail
 * closed), and the scanner's pinned version the consent screen names. A string is the refusal to show.
 */
async function prepareAi(io: CliIO, flags: AuditFlags, notes: string[]): Promise<AiReady | string> {
  if (!(PLATFORM_KEYS as readonly string[]).includes(`${process.platform}-${process.arch}`)) return AUDIT_AI_PLATFORM;
  let scanner: SecretScannerName;
  try {
    scanner = chooseSecretScanner(io.env);
  } catch (e) {
    if (!(e instanceof SecretScanError)) throw e;
    return e.message;
  }
  let provider: AiProvider;
  try {
    provider = makeProvider({
      env: io.env, ai: flags.ai?.provider, model: flags.model, effort: flags.effort, fetch: io.fetch,
      log: (line) => { notes.push(line); }, // the Ollama experimental note goes to the report's notes (S15)
    });
  } catch (e) {
    if (!(e instanceof AiError)) throw e;
    // a missing key is the audit's own message; a missing --model (OpenAI) or a bad flag value says what to fix
    return e.kind === 'missing' && !/--model/.test(e.message) ? AUDIT_AI_MISSING : e.message;
  }
  if (provider.name === 'ollama') {
    try {
      await checkOllamaModelRunsThere(io.env.OLLAMA_HOST, provider.model, io.fetch ?? globalThis.fetch);
    } catch (e) {
      if (!(e instanceof AiError)) throw e;
      return e.message;
    }
  }
  let secretScanner: AiReady['secretScanner'];
  try {
    secretScanner = { name: scanner, version: loadPinnedBinaries()[scanner].version };
  } catch (e) {
    if (!(e instanceof PinnedBinaryError)) throw e;
    return `audit --ai can't run in this build: ${e.message}`;
  }
  return { provider, secretScanner, bar: loadQualityBar() };
}

/**
 * `--ai` takes an optional provider name: `--ai`, `--ai claude`, `--ai=claude`. node's parseArgs needs a value for a
 * string option, so a bare `--ai` (or one followed by anything that isn't a provider name) becomes `--ai=` (auto).
 * Nothing after `--` is touched.
 */
export function normalizeAiFlag(argv: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === '--') {
      out.push(...argv.slice(i));
      break;
    }
    if (a !== '--ai') {
      out.push(a);
      continue;
    }
    const next = argv[i + 1];
    if (next !== undefined && (AI_CHOICES as readonly string[]).includes(next)) {
      out.push(`--ai=${next}`);
      i++;
    } else {
      out.push('--ai=');
    }
  }
  return out;
}
