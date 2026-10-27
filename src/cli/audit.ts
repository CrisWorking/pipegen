// `pipegen audit` (Plan U Task 4b): the read-only report on a repo's CI, with an optional `--ai` step after consent.
// The audited repo is attacker-controlled; GitHub and the AI are only read from or asked; nothing is ever written to
// GitHub, and no file is written unless --out names one (outside the repo, unless --force).
//
// Flow (ruling B1): readProject (owner/repo) → getAuth({ mode: 'read' }) → makeOctokit(token or null, per-request
// timeout) → GET /user only with a token → readGitHubContext (reusing getAuth's anonymous GET /repos, M6) → probeCapabilities → buildAudit with the full run's
// permissions (permissionsTable('write', …)), ONE rate budget for every GitHub call of the run (S18).
// - GitHub can't be read (no access, a refused token, no answer, a rate stop): only what is on disk is reported, with
//   "GitHub: not read", and the exit code is 1 (the inspect R10 rule). No GitHub fact is guessed.
// - The reviewed tool list can't be used (B3: the release build refuses it while entries wait for review): the audit
//   runs with no reviewed tools and a warning at the top, exit 0.
// - `--ai`: everything that can refuse it is checked first, before any GitHub call (S21 platform, S15 provider, the
//   Ollama checks of U15/H2, the gitleaks pin). After the plain audit: the counting bundle (no gitleaks, no child
//   process) and the estimate (an unpriced model stops here, U14), then the consent screen (default No). Only a yes
//   gives the ConsentToken addAiSuggestions requires; it then downloads gitleaks, builds the checked bundle and asks the AI.
// - Output: the terminal report (default) or JSON (--json) on stdout; --out writes the Markdown report through
//   writeOutFile; errors and status lines on stderr. Every output gets the run's known values (the GitHub token and
//   the AI keys, S19/U10), so neither is ever printed, and every line passes hideToken.
import { resolve } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { checkOllamaModelRunsThere } from '../ai/ollama.js';
import { AiError, makeProvider } from '../ai/provider.js';
import { bundleCode, scrubKnownValues } from '../ai/redact.js';
import { countingSummary } from '../audit/consent-token.js';
import { writeOutFile, OutFileError } from '../audit/out-file.js';
import { addAiSuggestions, buildAudit, buildLocalAudit, needsRequestBytes, type AuditReport } from '../audit/model.js';
import { renderJson, renderLocalJson, renderLocalTerminal, renderMarkdown, renderTerminal, type RenderOptions } from '../audit/render.js';
import { isRateStop, newRateBudget, type RateClock } from '../engine/github-rate.js';
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
import type { AiProvider, Auth, Capabilities, RepoProfile, ReviewedTool } from '../types.js';
import { makeSafeOutput, OUTPUT_CAP, usableKnownValues } from '../util/safe-output.js';
import { askConsent, consentScreen } from './consent.js';
import { tokenLogin } from './inspect.js';
import type { CliIO } from './io.js';

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
}

/** Ruling S15: the audit's own wording (MISSING_AI_MESSAGE talks about the full job). */
export const AUDIT_AI_MISSING = 'audit --ai needs an AI provider: set ANTHROPIC_API_KEY or OPENAI_API_KEY, or use --ai ollama.';
/** Ruling S21 (Plan B S27): the pinned gitleaks exists for these platforms only. */
export const AUDIT_AI_PLATFORM = 'audit --ai needs Linux or macOS for now (WSL works).';
/**
 * Ruling B3: the top warning when the reviewed tool list can't be used in this build. `why` is the loader's short
 * reason when it gave one (review M7: "23 entries still wait for human review (…)"), else its whole message.
 */
export const reviewedUnavailableWarning = (why: string) =>
  `pipegen's reviewed tool list isn't usable in this build: ${why.trim().replace(/\.+$/, '')}. The 'would add' section shows no tools.`;
/** The environment variables whose values are never printed nor sent to the AI (ruling S19: the token and the AI keys). */
const KNOWN_VALUE_VARS = ['GITHUB_TOKEN', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY'] as const;
/** Needs the AI may add on top of the floor, for the consent estimate (estimateAuditAi caps the discovery calls itself). */
const EXTRA_NEEDS_MARGIN = 2;

type GitHubContext = Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'>;
interface GitHubRead { auth: Auth; gh: Octokit; context: GitHubContext; caps: Capabilities }
interface AiReady { provider: AiProvider; gitleaksVersion: string; bar: QualityBar }

/** Runs `pipegen audit`. 0: a report was printed (also with the reviewed list unusable); 1: a refusal or an error. */
export async function audit(io: CliIO, flags: AuditFlags): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const knownValues: string[] = [];
  for (const v of KNOWN_VALUE_VARS) {
    const value = io.env[v];
    if (typeof value === 'string' && value.trim() !== '') knownValues.push(value, value.trim());
  }
  let token: string | null = null;
  const clean = (s: string, max: number = OUTPUT_CAP.text) => makeSafeOutput(knownValues)(s, { target: 'terminal', max, redact: false });
  const say = (s: string) => { io.out(hideToken(s, token)); };
  const fail = (s: string) => { io.err(hideToken(s, token)); };
  try {
    return await run();
  } catch (e) {
    // anything unexpected: one cleaned line, never a token or key, never a stack trace
    fail(`pipegen audit failed: ${clean(e instanceof Error ? e.message : String(e), 500)}`);
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

    // 3. GitHub, read-only, one rate budget for the whole run (S18)
    const clock: RateClock = { budget: newRateBudget() };
    let github: GitHubRead;
    try {
      const repoAnswer: { data?: unknown } = {}; // getAuth's anonymous GET /repos, reused below (review M6)
      const auth = await getAuth({ owner, repos: [repo], allowBroad: flags.allowBroad, mode: 'read' }, { env: io.env, fetch: io.fetch, clock, notes, repoAnswer });
      token = auth.token;
      if (auth.token !== null) knownValues.push(auth.token);
      const gh = makeOctokit(auth.token, { fetch: io.fetch, clock, timeoutMs: GITHUB_TIMEOUT_MS, log: fail });
      const login = await tokenLogin(gh, auth, clock, notes);
      const context = await readGitHubContext(gh, owner, repo, login, clock, notes, { known: repoAnswer.data });
      const caps = await probeCapabilities(gh, owner, repo, { ...local, ...context }, notes, clock);
      github = { auth, gh, context, caps };
    } catch (e) {
      if (!(e instanceof GitHubAccessError) && !isRateStop(e)) throw e;
      // a token that can't see the repo: the same read-only steps as without one (never `gh auth login`)
      const steps = token !== null && e instanceof GitHubAccessError && (e.status === 404 || e.status === 403) ? ` ${readAccessSteps(owner, repo)}` : '';
      return localOnly(dir, `${e instanceof Error ? e.message : String(e)}${steps}`, notes);
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

    // 5. the plain audit
    const anonymous = github.auth.kind === 'anonymous';
    let r: AuditReport = await buildAudit(dir, {
      gh: github.gh, anonymous, context: github.context, capabilities: github.caps,
      permissions: permissionsTable('write', { appCreatesRepos: github.auth.canCreateRepos }),
      reviewed, reviewedUnavailable: reviewedProblem !== null, now: Date.now, notes, budget: clock.budget,
    });
    if (reviewedProblem !== null) r = { ...r, warnings: [{ text: reviewedUnavailableWarning(reviewedProblem) }, ...r.warnings] };

    // 6. --ai: consent first (default No); only a yes gives the token the AI step requires
    if (ai !== null) {
      const counted = await bundleCode(dir, { knownValues }); // counting only: no gitleaks, no child process
      const nullRows = r.wouldAdd.filter((w) => w.tool === null).length;
      const est = estimateAuditAi(ai.provider, nullRows + EXTRA_NEEDS_MARGIN, needsRequestBytes({ ...r, aiBundle: { ...r.aiBundle, bytes: counted.bytes } }, knownValues));
      if (est.unpriced !== null) {
        fail(clean(est.unpriced.message));
        return 1;
      }
      const screen = consentScreen(r.profile, ai.provider, est, countingSummary(counted), permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: ai.gitleaksVersion });
      // defence in depth: the screen is pipegen's own text with cleaned repo names; known values are hidden all the same
      const scrub = (s: string) => scrubKnownValues(hideToken(s, token), usableKnownValues(knownValues));
      const consent = await askConsent({ ...io.prompt, confirm: (msg, def) => io.prompt.confirm(scrub(msg), def) }, screen, fail);
      if (consent === null) {
        fail('No consent (you said no, or the question was cancelled): nothing was sent to an AI. The report below is the plain audit.');
      } else {
        r = await addAiSuggestions(r, dir, {
          ai: ai.provider, gh: github.gh, memory: await openMemory(), fetch: io.fetch ?? globalThis.fetch, reviewed, bar: ai.bar,
          budget: clock.budget, now: Date.now, knownValues: [...knownValues], anonymous, capUsd: est.capUsd, consent,
        });
      }
    }

    // 7. the report
    const opts: RenderOptions = { knownValues };
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
    return 0;
  }

  /** GitHub couldn't be read: what is on disk only, "GitHub: not read", the reason on stderr, exit 1 (R10). */
  async function localOnly(dir: string, why: string, notes: string[]): Promise<number> {
    const l = await buildLocalAudit(dir, { notes });
    const opts: RenderOptions = { knownValues };
    say(flags.json ? renderLocalJson(l, opts) : renderLocalTerminal(l, opts));
    // pipegen's own access message (repo names already cleaned): redact would cut its wording ("this token: …")
    fail(`GitHub: not read: ${clean(why, 2000)}`);
    if (flags.out !== undefined) fail('No report file was written: GitHub could not be read.');
    return 1;
  }
}

/**
 * Everything that can refuse `--ai`, before any GitHub call: the platform (S21), the provider and its key (S15), for
 * Ollama the host and the model (U15/H2: never ollama.com, never a cloud model behind a local name; fail closed), and
 * the pinned gitleaks version the consent screen names. A string is the refusal to show.
 */
async function prepareAi(io: CliIO, flags: AuditFlags, notes: string[]): Promise<AiReady | string> {
  if (!(PLATFORM_KEYS as readonly string[]).includes(`${process.platform}-${process.arch}`)) return AUDIT_AI_PLATFORM;
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
  let gitleaksVersion: string;
  try {
    gitleaksVersion = loadPinnedBinaries().gitleaks.version;
  } catch (e) {
    if (!(e instanceof PinnedBinaryError)) throw e;
    return `audit --ai can't run in this build: ${e.message}`;
  }
  return { provider, gitleaksVersion, bar: loadQualityBar() };
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
