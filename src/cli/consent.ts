// The consent screen (Plan A Task 8): what pipegen is about to do, shown before any code leaves the machine. The
// user must say yes; the default answer is No.
//
// Two modes (Plan U ruling B2):
// - 'full' (the whole run): the files sent to the AI, the provider and where it runs, the private helper repos,
//   Actions minutes (setup + hard limit, monthly afterwards), the AI cost split into input and output with its hard
//   cap, the time, and the write permissions (one Administration row, worded for App or token mode).
// - 'audit-ai' (`pipegen audit --ai`): the files, the provider and where it runs, the refusal-fallback note, the
//   audit's own AI cost (estimateAuditAi) and its cap, and read-only permissions. No Actions minutes, no repos.
// Helper repos (DECISIONS #87): with pipegen's GitHub App, pipegen creates the missing ones itself and deletes the
// scratch repo after the proof; with a token, the user creates them (the exact `gh repo create … --private` commands
// are shown) and pipegen never creates or deletes a repo.
// The files section's repo-derived strings (the repo name and the top folders, on both screens) pass the one output
// helper (safe-output.ts, ruling U10: redact, then safeText), so a token-shaped name is hidden as in the report (Plan U
// final review M2); the audit CLI's confirm wrapper also scrubs the run's known values from the whole screen. The
// 'full' screen's helper repo names stay on safeText alone: they go into the copyable `gh repo create` commands, which
// redact would break (the full run is Plan E; its own review decides). The model name (from a flag) and the estimate's
// basis lines pass safeText.
// The facts the rulings require are required arguments, so a caller can't leave them out: the secret scanner and its version (S21)
// and, for 'full', whether pipegen's App creates the repos (#87). Where an Ollama provider sends comes from the
// provider itself (ollamaHostOf); when it isn't known, the screen never claims the code stays on this computer.
// Two facts are tied to their real sources by construction (final review batch 2, I1): the file facts are a
// BundleSummary, which only bundleSummary() of a secret-scanned bundle makes, and the estimate must say it was
// priced for the provider and model shown (Estimates.pricedFor), or the screen is refused.
// Either mode may take a CountingSummary instead ('audit-ai': Plan U T4b; 'full': G13-R1 sec I1; ruling S21: the scanner download happens only after
// consent, so the screen counts the bundle before the secret scan, says so, and calls the counts "at most"; the AI
// step reads only the counted files, bundleCode `onlyPaths`, with CountingSummary.covers() as the backstop).
// "No AI call without consent" is a type rule backed by runtime checks (Plan U T4b, review M1/M2): consentScreen() makes
// the screen (its text plus the terms a yes agrees to; a module-private set records every screen it made), askConsent()
// turns a yes into a ConsentToken with the minter this module claims once from src/audit/consent-token.ts, and nothing
// else can make one. addAiSuggestions requires the token, checks its terms (provider, model, cap, folder) and spends it.
import { ollamaHostOf } from '../ai/ollama.js';
import { refusalFallbackNoteFor } from '../ai/provider.js';
import { BundleSummary, excludedSummaryLines, type SecretScanner } from '../ai/redact.js';
import { claimTokenMinter, CountingSummary, type ConsentMode, type ConsentTerms, type ConsentToken } from '../audit/consent-token.js';
import type { AiCost, AuditAiEstimate, Estimates, PricedFor } from '../estimate/estimate.js';
import type { AiProvider, RepoProfile } from '../types.js';
import { plural, size, usd } from '../util/format.js';
import { hostPlace } from '../util/local-host.js';
import { makeSafeOutput } from '../util/safe-output.js';
import { safeText } from '../util/safe-text.js';
import { PromptCancelledError, type Prompter } from './io.js';

export { bundleSummary, BundleSummary } from '../ai/redact.js';
export { ConsentToken, countingSummary, CountingSummary, type ConsentMode, type ConsentTerms } from '../audit/consent-token.js';
/** A private helper repo pipegen uses (`pipelines`, `pipegen-proof-<repo>`), checked before consent. */
export interface HelperRepo { name: string; exists: boolean }
export type PermissionRows = { permission: string; why: string }[];

/** Facts the 'audit-ai' screen must show (ruling S21). */
export interface AuditConsentFacts {
  /** The pinned secret scanner pipegen downloads, checksum-verified, into its cache before bundling, and its version. */
  secretScanner: Pick<SecretScanner, 'name' | 'version'>;
  /** P51 (M5): pipegen's own note when GitHub's rate limit left facts unread (shown right after the opening lines). */
  incompleteNote?: string;
}
/** Facts the 'full' screen must show. */
export interface FullConsentFacts extends AuditConsentFacts {
  /** Auth.canCreateRepos: pipegen's own GitHub App login creates and deletes the helper repos (#87); false = token mode. */
  appCreatesRepos: boolean;
}

const MAX_TOP_FOLDERS = 10;
const INDENT = '  ';
const SCRATCH_PREFIX = 'pipegen-proof-';
/** What the App does with the scratch repo; the same words as the Administration permission (permissionsTable). */
const APP_DELETES = 'after the proof if you allow it';

const range = (r: { low: number; high: number }) => `${usd(r.low)}–${usd(r.high)}`;
/** A repo-derived name on the screen: the one output helper (redact, then safeText). Known values: the CLI's wrapper. */
const shownName = (s: string, max: number) => makeSafeOutput([])(s, { target: 'terminal', max });

/** Where the AI runs. For Ollama: local, a named remote host, or unknown (host null), which is never shown as local. */
type Place = { kind: 'vendor' } | { kind: 'local' } | { kind: 'remote'; host: string | null };

function placeOf(provider: AiProvider): Place {
  if (provider.name !== 'ollama') return { kind: 'vendor' };
  const host = ollamaHostOf(provider);
  const where = hostPlace(host);
  if (where === 'local') return { kind: 'local' };
  return { kind: 'remote', host: where === 'remote' ? host : null };
}

/** Where the provider runs, in one sentence. */
function whereItRuns(provider: AiProvider, place: Place): string {
  const model = safeText(provider.model, 80);
  if (provider.name === 'claude') return `Claude (${model}), run by Anthropic: the files are sent to Anthropic's API.`;
  if (provider.name === 'openai') return `OpenAI (${model}), experimental: the files are sent to OpenAI's API.`;
  if (place.kind === 'local') return `Ollama (${model}), experimental: it runs on this computer, so your code stays on this computer.`;
  if (place.kind === 'remote' && place.host !== null) {
    return `Ollama (${model}), experimental: the files are sent to the Ollama server at ${safeText(place.host, 120)}, not only this computer.`;
  }
  return `Ollama (${model}), experimental: the files are sent to an Ollama server whose address pipegen couldn't confirm; it may not be this computer.`;
}

function filesSection(p: RepoProfile, bundle: BundleSummary | CountingSummary, scanner: AuditConsentFacts['secretScanner']): string[] {
  const name = safeText(scanner.name, 20);
  const shown = bundle.topFolders.slice(0, MAX_TOP_FOLDERS).map((f) => shownName(f, 60));
  const more = bundle.topFolders.length - shown.length;
  const folders = shown.length === 0 ? '(all at the top level)' : `${shown.join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
  const counted = CountingSummary.isSummary(bundle);
  return [
    'Your code',
    `${INDENT}pipegen sends ${counted ? 'at most ' : ''}${plural(bundle.files, 'file', 'files')} (${size(bundle.bytes)}) from ${shownName(`${p.owner}/${p.repo}`, 200)} to the AI.`,
    `${INDENT}Top folders: ${folders}`,
    `${INDENT}Never sent:`,
    ...excludedSummaryLines().map((l) => `${INDENT}${INDENT}${l}`),
    `${INDENT}Before anything is sent, every file is checked for secrets with ${name} ${safeText(scanner.version, 20)}, which pipegen downloads (checksum-verified) into its cache, and secret-looking values are hidden.`,
    ...(counted
      ? [`${INDENT}These counts were made before the ${name} check, which runs only after you say yes. It may leave out a few more files; pipegen never sends a file that isn't counted here.`]
      : []),
  ];
}

function providerSection(provider: AiProvider, place: Place): string[] {
  const note = refusalFallbackNoteFor(provider);
  return ['The AI', `${INDENT}${whereItRuns(provider, place)}`, ...(note === null ? [] : [`${INDENT}${note}`])];
}

function costSection(title: string, cost: AiCost | 'local', cap: number | null, place: Place): string[] {
  if (cost === 'local') {
    return [title, `${INDENT}${place.kind === 'local' ? 'AI cost: free, local.' : 'AI cost: none counted (an Ollama server, not a paid API).'}`];
  }
  return [
    title,
    `${INDENT}Input: ${range(cost.input)}`,
    `${INDENT}Output: ${range(cost.output)}`,
    `${INDENT}Total: ${range(cost)}`,
    ...(cap === null ? [] : [`${INDENT}pipegen stops if the AI cost reaches ${usd(cap)}.`]),
  ];
}

function reposSection(p: RepoProfile, repos: HelperRepo[], app: boolean): string[] {
  if (repos.length === 0) return [];
  const full = (name: string) => safeText(`${p.owner}/${name}`, 200);
  const scratch = repos.find((r) => r.name.startsWith(SCRATCH_PREFIX));
  const lines = ['Private repos pipegen uses'];
  for (const r of repos) {
    if (r.exists) lines.push(`${INDENT}${full(r.name)}: exists; pipegen uses it.`);
    else if (app) lines.push(`${INDENT}${full(r.name)}: doesn't exist yet; pipegen's GitHub App creates it (private), and it joins the App's installation.`);
    else lines.push(`${INDENT}${full(r.name)}: doesn't exist yet; create it before pipegen uses it (command below).`);
  }
  const missing = repos.filter((r) => !r.exists);
  if (app) {
    if (scratch !== undefined) lines.push(`${INDENT}pipegen's GitHub App deletes the scratch repo ${full(scratch.name)} ${APP_DELETES}.`);
  } else {
    if (missing.length > 0) {
      lines.push(`${INDENT}Create the missing ${missing.length === 1 ? 'repo' : 'repos'} with:`);
      for (const r of missing) lines.push(`${INDENT}${INDENT}gh repo create ${full(r.name)} --private`);
    }
    lines.push(`${INDENT}With a token, pipegen never creates or deletes repos${scratch === undefined ? '.' : `; after the proof it empties the scratch repo ${full(scratch.name)}.`}`);
  }
  return lines;
}

function minutesSection(p: RepoProfile, est: Estimates): string[] {
  const included = !p.private
    ? 'public repo: minutes on GitHub-hosted runners are free'
    : est.includedMinutes === null
      ? "pipegen couldn't tell how many minutes your plan includes"
      : `your ${p.plan} plan includes ${plural(est.includedMinutes, 'minute', 'minutes')} a month for private repos`;
  return [
    'GitHub Actions minutes',
    `${INDENT}Setup: about ${plural(est.setupMinutes, 'minute', 'minutes')}; hard limit ${plural(est.setupMinutesCap, 'minute', 'minutes')} (the proof stops there).`,
    `${INDENT}Afterwards: about ${plural(est.monthlyMinutes, 'minute', 'minutes')} a month (${included}).`,
  ];
}

/** Every assumption behind the estimates (estimate's `basis`), cleaned for the terminal, shown under the cost lines. */
function basisSection(title: string, basis: readonly string[]): string[] {
  if (basis.length === 0) return [];
  return [title, ...basis.map((b) => `${INDENT}- ${safeText(b, 1000)}`)];
}

const choiceText = (c: PricedFor | null) => (c === null ? 'no AI provider' : `${c.provider} / ${c.model}${c.host === undefined ? '' : ` at ${c.host}`}`);

/** Refuses an estimate priced for another provider, model or (Ollama) host than the one the screen shows. */
function checkPricedFor(provider: AiProvider, pricedFor: PricedFor | null): void {
  const host = provider.name === 'ollama' ? ollamaHostOf(provider) ?? undefined : undefined;
  if (pricedFor === null || pricedFor.provider !== provider.name || pricedFor.model !== provider.model || pricedFor.host !== host) {
    const shown: PricedFor = { provider: provider.name, model: provider.model, ...(host === undefined ? {} : { host }) };
    throw new Error(`The estimate was priced for ${safeText(choiceText(pricedFor), 300)}, but the consent screen shows ${safeText(choiceText(shown), 300)}; `
      + 'estimate it for the provider that will be used (pass the provider itself).');
  }
}

function permissionsSection(title: string, perms: PermissionRows): string[] {
  return [title, ...perms.map((r) => `${INDENT}- ${r.permission}: ${r.why}`)];
}

/** Words a token-mode screen must never use about repos (DECISIONS #87). */
const CREATES_OR_DELETES = /create the private helper repos|delete the scratch repo/i;

// The one minter of consent tokens (claimed once, at load): only askConsent below uses it.
const mintToken = claimTokenMinter();
let makeScreen: (text: string, terms: ConsentTerms) => ConsentScreen;
/** Every screen consentScreen() made: `private constructor` is TypeScript only (review M1). */
const ISSUED_SCREENS = new WeakSet<object>();

/** The consent screen: its text and the terms a yes agrees to. Only consentScreen() makes one. */
export class ConsentScreen {
  readonly #made = true;
  private constructor(readonly text: string, readonly terms: ConsentTerms) {
    Object.freeze(this);
  }
  /** True only for an object consentScreen() made (not one made with `new` through a cast, nor a subclass's). */
  static isScreen(x: unknown): x is ConsentScreen {
    return typeof x === 'object' && x !== null && #made in x && ISSUED_SCREENS.has(x);
  }
  static {
    makeScreen = (text, terms) => {
      const made = new ConsentScreen(text, Object.freeze({ ...terms }));
      ISSUED_SCREENS.add(made);
      return made;
    };
  }
}

/**
 * The consent text. `est`: estimate() for 'full', estimateAuditAi() for 'audit-ai', both given `provider` itself, so
 * `est.pricedFor` matches it. `bundle`: bundleSummary() of the secret-scanned bundle that will be sent, or
 * countingSummary() of the counted bundle (consent before the scanner download, ruling S21; 'full' too since G13-R1).
 * `perms`: permissionsTable('write', { appCreatesRepos }) for 'full', permissionsTable('read') for 'audit-ai'.
 * `repos`: `pipelines` and `pipegen-proof-<repo>` with whether each exists ('full' only; 'audit-ai' shows none).
 * Refused (programming errors): a bundle summary bundleSummary()/countingSummary() didn't make; an estimate priced for another provider, model or Ollama host (or for none); a write permission in
 * 'audit-ai'; in token mode, a permission saying pipegen creates or deletes a repo (a table built for the App).
 */
export function consentText(p: RepoProfile, provider: AiProvider, est: Estimates, bundle: BundleSummary | CountingSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'full', facts: FullConsentFacts): string;
export function consentText(p: RepoProfile, provider: AiProvider, est: AuditAiEstimate, bundle: BundleSummary | CountingSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'audit-ai', facts: AuditConsentFacts): string;
export function consentText(p: RepoProfile, provider: AiProvider, est: Estimates | AuditAiEstimate, bundle: BundleSummary | CountingSummary, perms: PermissionRows, repos: HelperRepo[], mode: ConsentMode, facts: AuditConsentFacts | FullConsentFacts): string {
  return screenFor(p, provider, est, bundle, perms, repos, mode, facts).text;
}

/** consentText's screen with the terms a yes agrees to, for askConsent (same arguments, same refusals). */
export function consentScreen(p: RepoProfile, provider: AiProvider, est: Estimates, bundle: BundleSummary | CountingSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'full', facts: FullConsentFacts): ConsentScreen;
export function consentScreen(p: RepoProfile, provider: AiProvider, est: AuditAiEstimate, bundle: BundleSummary | CountingSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'audit-ai', facts: AuditConsentFacts): ConsentScreen;
export function consentScreen(p: RepoProfile, provider: AiProvider, est: Estimates | AuditAiEstimate, bundle: BundleSummary | CountingSummary, perms: PermissionRows, repos: HelperRepo[], mode: ConsentMode, facts: AuditConsentFacts | FullConsentFacts): ConsentScreen {
  return screenFor(p, provider, est, bundle, perms, repos, mode, facts);
}

function screenFor(p: RepoProfile, provider: AiProvider, est: Estimates | AuditAiEstimate, bundle: BundleSummary | CountingSummary, perms: PermissionRows, repos: HelperRepo[], mode: ConsentMode, facts: AuditConsentFacts | FullConsentFacts): ConsentScreen {
  const counted = CountingSummary.isSummary(bundle);
  if (!counted && !BundleSummary.isSummary(bundle)) {
    throw new Error('The consent screen needs the file facts from bundleSummary() of the secret-scanned code bundle.');
  }
  checkPricedFor(provider, est.pricedFor);
  const place = placeOf(provider);
  const sections: string[][] = [];
  let capUsd: number | null;
  if (mode === 'audit-ai') {
    if (perms.some((r) => /\bwrite\b/i.test(r.permission))) {
      throw new Error('The audit --ai consent lists read-only permissions; it was given a write permission.');
    }
    const a = est as AuditAiEstimate;
    // A model with no price can't keep the hard cost limit this screen would promise (ruling U14): the CLI stops first.
    if (a.unpriced !== null && a.unpriced !== undefined) throw new Error(a.unpriced.message);
    capUsd = a.capUsd;
    sections.push(
      ['pipegen audit --ai is about to send part of your code to an AI. Nothing has left this computer yet.', 'This audit only reads: it changes nothing on GitHub.'],
      ...(facts.incompleteNote === undefined ? [] : [[facts.incompleteNote]]),
      filesSection(p, bundle, facts.secretScanner),
      providerSection(provider, place),
      costSection('AI cost of this audit (estimate)', a.costUsd, a.capUsd, place),
      basisSection('How this estimate was made', a.basis),
      permissionsSection('GitHub permissions (read-only)', perms),
    );
  } else {
    const e = est as Estimates;
    const app = (facts as FullConsentFacts).appCreatesRepos;
    if (!app && perms.some((r) => CREATES_OR_DELETES.test(r.why))) {
      throw new Error('In token mode pipegen never creates or deletes repos; pass permissionsTable(\'write\', { appCreatesRepos: false }).');
    }
    capUsd = e.aiCostCapUsd;
    sections.push(
      ['pipegen is about to start. Nothing has left this computer yet. This is what it will do:'],
      filesSection(p, bundle, facts.secretScanner),
      providerSection(provider, place),
      reposSection(p, repos, app),
      minutesSection(p, e),
      costSection('AI cost (estimate)', e.aiCostUsd, e.aiCostCapUsd, place),
      basisSection('How these estimates were made', e.basis),
      ['Time', `${INDENT}About ${e.durationMinutes.low}–${e.durationMinutes.high} minutes.`],
      permissionsSection('GitHub permissions pipegen asks for', perms),
    );
  }
  const text = sections.filter((s) => s.length > 0).map((s) => s.join('\n')).join('\n\n');
  // checkPricedFor above proved est.pricedFor is set and matches the provider shown
  const secretScanner = Object.freeze({ name: facts.secretScanner.name, version: facts.secretScanner.version });
  return makeScreen(text, { mode, pricedFor: { ...(est.pricedFor as PricedFor) }, capUsd, files: bundle, dir: counted ? (bundle as CountingSummary).dir : null, secretScanner });
}

/**
 * Shows the consent screen and asks. A yes gives a ConsentToken for the screen's terms; anything else gives null. The
 * default answer is No. A cancel (or no terminal) is No. Any other failure is No too, but it is reported through
 * `err`, so a broken prompt never reads as "the user declined". A screen consentScreen() didn't make is refused
 * (thrown) before anything is asked.
 */
export async function askConsent(io: Prompter, screen: ConsentScreen, err: (s: string) => void): Promise<ConsentToken | null> {
  if (!ConsentScreen.isScreen(screen)) throw new Error('askConsent needs the screen from consentScreen().');
  try {
    return (await io.confirm(`${screen.text}\n\nGo ahead?`, false)) === true ? mintToken(screen.terms) : null;
  } catch (e) {
    if (!(e instanceof PromptCancelledError)) {
      err(`pipegen couldn't ask for your consent (${safeText(e instanceof Error ? e.message : String(e), 300)}), so it takes the answer as No.`);
    }
    return null;
  }
}
