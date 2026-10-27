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
// Every repo-derived string (owner, repo and folder names) passes safeText; so does the model name (from a flag).
// The facts the rulings require are required arguments, so a caller can't leave them out: the gitleaks version (S21)
// and, for 'full', whether pipegen's App creates the repos (#87). Where an Ollama provider sends comes from the
// provider itself (ollamaHostOf); when it isn't known, the screen never claims the code stays on this computer.
import { ollamaChatUrl, ollamaHostOf } from '../ai/ollama.js';
import { refusalFallbackNoteFor } from '../ai/provider.js';
import { EXCLUDED_KEPT, EXCLUDED_PATTERN_GROUPS } from '../ai/redact.js';
import type { AiCost, AuditAiEstimate, Estimates } from '../estimate/estimate.js';
import type { AiProvider, RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { PromptCancelledError, type Prompter } from './io.js';

/** What the code bundle holds, counted before consent (not the bundle itself). */
export interface BundleSummary { files: number; bytes: number; topFolders: string[] }
/** A private helper repo pipegen uses (`pipelines`, `pipegen-proof-<repo>`), checked before consent. */
export interface HelperRepo { name: string; exists: boolean }
export type PermissionRows = { permission: string; why: string }[];
export type ConsentMode = 'full' | 'audit-ai';

/** Facts the 'audit-ai' screen must show (ruling S21). */
export interface AuditConsentFacts {
  /** The pinned gitleaks version pipegen downloads, checksum-verified, into its cache before bundling. */
  gitleaksVersion: string;
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

const usd = (n: number) => `$${n.toFixed(2)}`;
const range = (r: { low: number; high: number }) => `${usd(r.low)}–${usd(r.high)}`;
const plural = (n: number, one: string, many: string) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
const size = (bytes: number) => (bytes >= 1024 * 1024 ? `about ${(bytes / (1024 * 1024)).toFixed(1)} MB` : `about ${Math.max(1, Math.round(bytes / 1024))} KB`);

/** Hosts that are this computer: loopback, and the any-address that Ollama's own client treats as local. */
const LOCAL_HOSTS = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|\[::\])$/i;

/** Where the AI runs. For Ollama: local, a named remote host, or unknown (host null), which is never shown as local. */
type Place = { kind: 'vendor' } | { kind: 'local' } | { kind: 'remote'; host: string | null };

function placeOf(provider: AiProvider): Place {
  if (provider.name !== 'ollama') return { kind: 'vendor' };
  const host = ollamaHostOf(provider);
  if (host === null) return { kind: 'remote', host: null };
  try {
    return LOCAL_HOSTS.test(ollamaChatUrl(host).hostname) ? { kind: 'local' } : { kind: 'remote', host };
  } catch {
    return { kind: 'remote', host: null };
  }
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

function filesSection(p: RepoProfile, bundle: BundleSummary, gitleaksVersion: string): string[] {
  const shown = bundle.topFolders.slice(0, MAX_TOP_FOLDERS).map((f) => safeText(f, 60));
  const more = bundle.topFolders.length - shown.length;
  const folders = shown.length === 0 ? '(all at the top level)' : `${shown.join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
  return [
    'Your code',
    `${INDENT}pipegen sends ${plural(bundle.files, 'file', 'files')} (${size(bundle.bytes)}) from ${safeText(`${p.owner}/${p.repo}`, 200)} to the AI.`,
    `${INDENT}Top folders: ${folders}`,
    `${INDENT}Never sent:`,
    ...EXCLUDED_PATTERN_GROUPS.map((g) => `${INDENT}${INDENT}- ${g.label}: ${g.summary}`),
    `${INDENT}${INDENT}- binary files (images, archives, compiled programs), found by their content`,
    `${INDENT}${INDENT}kept: ${EXCLUDED_KEPT.join(', ')}`,
    `${INDENT}Before anything is sent, every file is checked for secrets with gitleaks ${safeText(gitleaksVersion, 20)}, which pipegen downloads (checksum-verified) into its cache, and secret-looking values are hidden.`,
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

function permissionsSection(title: string, perms: PermissionRows): string[] {
  return [title, ...perms.map((r) => `${INDENT}- ${r.permission}: ${r.why}`)];
}

/** Words a token-mode screen must never use about repos (DECISIONS #87). */
const CREATES_OR_DELETES = /create the private helper repos|delete the scratch repo/i;

/**
 * The consent text. `est`: estimate() for 'full', estimateAuditAi() for 'audit-ai' (both for the chosen provider and
 * model). `perms`: permissionsTable('write', { appCreatesRepos }) for 'full', permissionsTable('read') for 'audit-ai'.
 * `repos`: `pipelines` and `pipegen-proof-<repo>` with whether each exists ('full' only; 'audit-ai' shows none).
 * Refused (programming errors): a write permission in 'audit-ai'; in token mode, a permission saying pipegen creates
 * or deletes a repo (a table built for the App).
 */
export function consentText(p: RepoProfile, provider: AiProvider, est: Estimates, bundle: BundleSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'full', facts: FullConsentFacts): string;
export function consentText(p: RepoProfile, provider: AiProvider, est: AuditAiEstimate, bundle: BundleSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'audit-ai', facts: AuditConsentFacts): string;
export function consentText(p: RepoProfile, provider: AiProvider, est: Estimates | AuditAiEstimate, bundle: BundleSummary, perms: PermissionRows, repos: HelperRepo[], mode: ConsentMode, facts: AuditConsentFacts | FullConsentFacts): string {
  const place = placeOf(provider);
  const sections: string[][] = [];
  if (mode === 'audit-ai') {
    if (perms.some((r) => /\bwrite\b/i.test(r.permission))) {
      throw new Error('The audit --ai consent lists read-only permissions; it was given a write permission.');
    }
    const a = est as AuditAiEstimate;
    sections.push(
      ['pipegen audit --ai is about to send part of your code to an AI. Nothing has left this computer yet.', 'This audit only reads: it changes nothing on GitHub.'],
      filesSection(p, bundle, facts.gitleaksVersion),
      providerSection(provider, place),
      costSection('AI cost of this audit (estimate)', a.costUsd, a.capUsd, place),
      permissionsSection('GitHub permissions (read-only)', perms),
    );
  } else {
    const e = est as Estimates;
    const app = (facts as FullConsentFacts).appCreatesRepos;
    if (!app && perms.some((r) => CREATES_OR_DELETES.test(r.why))) {
      throw new Error('In token mode pipegen never creates or deletes repos; pass permissionsTable(\'write\', { appCreatesRepos: false }).');
    }
    sections.push(
      ['pipegen is about to start. Nothing has left this computer yet. This is what it will do:'],
      filesSection(p, bundle, facts.gitleaksVersion),
      providerSection(provider, place),
      reposSection(p, repos, app),
      minutesSection(p, e),
      costSection('AI cost (estimate)', e.aiCostUsd, e.aiCostCapUsd, place),
      ['Time', `${INDENT}About ${e.durationMinutes.low}–${e.durationMinutes.high} minutes.`],
      permissionsSection('GitHub permissions pipegen asks for', perms),
    );
  }
  return sections.filter((s) => s.length > 0).map((s) => s.join('\n')).join('\n\n');
}

/**
 * Shows the consent text and asks. The default answer is No. A cancel (or no terminal) is No. Any other failure is No
 * too, but it is reported through `err`, so a broken prompt never reads as "the user declined".
 */
export async function askConsent(io: Prompter, text: string, err: (s: string) => void): Promise<boolean> {
  try {
    return (await io.confirm(`${text}\n\nGo ahead?`, false)) === true;
  } catch (e) {
    if (!(e instanceof PromptCancelledError)) {
      err(`pipegen couldn't ask for your consent (${safeText(e instanceof Error ? e.message : String(e), 300)}), so it takes the answer as No.`);
    }
    return false;
  }
}
