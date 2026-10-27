// The consent screen (Plan A Task 8): what pipegen is about to do, shown before any code leaves the machine. The
// user must say yes; the default answer is No.
//
// Two modes (Plan U ruling B2):
// - 'full' (the whole run): the files sent to the AI, the provider and where it runs, the private helper repos,
//   Actions minutes (setup + hard limit, monthly afterwards), the AI cost split into input and output with its hard
//   cap, the time, and the write permissions with one line on Administration.
// - 'audit-ai' (`pipegen audit --ai`): the files, the provider and where it runs, the refusal-fallback note, the
//   audit's own AI cost (estimateAuditAi) and its cap, and read-only permissions. No Actions minutes, no repos.
// Helper repos (DECISIONS #87): with pipegen's GitHub App, pipegen creates the missing ones itself and deletes the
// scratch repo after the proof; with a token, the user creates them (the exact `gh repo create … --private` commands
// are shown) and pipegen never creates or deletes a repo.
// Every repo-derived string (owner, repo and folder names) passes safeText; so do the model name and Ollama host,
// which come from flags and the environment.
import { refusalFallbackNoteFor } from '../ai/provider.js';
import { ollamaChatUrl } from '../ai/ollama.js';
import { EXCLUDED_PATTERNS } from '../ai/redact.js';
import type { AiCost, AuditAiEstimate, Estimates } from '../estimate/estimate.js';
import type { AiProvider, RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import type { Prompter } from './io.js';

/** What the code bundle holds, counted before consent (not the bundle itself). */
export interface BundleSummary { files: number; bytes: number; topFolders: string[] }
/** A private helper repo pipegen uses (`pipelines`, `pipegen-proof-<repo>`), checked before consent. */
export interface HelperRepo { name: string; exists: boolean }
export type PermissionRows = { permission: string; why: string }[];
export type ConsentMode = 'full' | 'audit-ai';

export interface ConsentOptions {
  /** true when pipegen's own GitHub App login may create and delete the helper repos (Auth.canCreateRepos, #87). Default false: token mode. */
  appCreatesRepos?: boolean;
  /** The pinned gitleaks version pipegen downloads, checksum-verified, into its cache before bundling (ruling S21). */
  gitleaksVersion?: string;
  /** OLLAMA_HOST as set: a host that isn't this computer is named instead of "stays on this computer". */
  ollamaHost?: string;
}

const MAX_TOP_FOLDERS = 10;
const LINE_WIDTH = 100;
const INDENT = '  ';
const SCRATCH_PREFIX = 'pipegen-proof-';

const usd = (n: number) => `$${n.toFixed(2)}`;
const range = (r: { low: number; high: number }) => `${usd(r.low)}–${usd(r.high)}`;
const plural = (n: number, one: string, many: string) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
const size = (bytes: number) => (bytes >= 1024 * 1024 ? `about ${(bytes / (1024 * 1024)).toFixed(1)} MB` : `about ${Math.max(1, Math.round(bytes / 1024))} KB`);

/** Items joined with ", " and wrapped at LINE_WIDTH, each line indented. */
function wrapList(items: readonly string[], indent: string): string[] {
  const lines: string[] = [];
  let line = '';
  for (const item of items) {
    const next = line === '' ? item : `${line}, ${item}`;
    if (line !== '' && indent.length + next.length > LINE_WIDTH) {
      lines.push(`${indent}${line},`);
      line = item;
    } else {
      line = next;
    }
  }
  if (line !== '') lines.push(`${indent}${line}`);
  return lines;
}

const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1)$/i;

/** Where the provider runs, in one sentence. */
function whereItRuns(provider: AiProvider, ollamaHost: string | undefined): string {
  const model = safeText(provider.model, 80);
  if (provider.name === 'claude') return `Claude (${model}), run by Anthropic: the files are sent to Anthropic's API.`;
  if (provider.name === 'openai') return `OpenAI (${model}), experimental: the files are sent to OpenAI's API.`;
  let host: string | null = null; // null: this computer
  if (ollamaHost !== undefined && ollamaHost.trim() !== '') {
    try {
      const url = ollamaChatUrl(ollamaHost);
      if (!LOOPBACK.test(url.hostname)) host = url.host; // host and port only, never a credential or path
    } catch {
      host = 'the address in OLLAMA_HOST';
    }
  }
  return host === null
    ? `Ollama (${model}), experimental: it runs on this computer, so your code stays on this computer.`
    : `Ollama (${model}), experimental: the files are sent to the Ollama server at ${safeText(host, 120)}, not only this computer.`;
}

function filesSection(p: RepoProfile, bundle: BundleSummary, gitleaksVersion: string | undefined): string[] {
  const shown = bundle.topFolders.slice(0, MAX_TOP_FOLDERS).map((f) => safeText(f, 60));
  const more = bundle.topFolders.length - shown.length;
  const folders = shown.length === 0 ? '(all at the top level)' : `${shown.join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
  const gitleaks = gitleaksVersion === undefined
    ? 'gitleaks (a pinned download, checksum-verified, kept in pipegen\'s cache)'
    : `gitleaks ${safeText(gitleaksVersion, 20)}, which pipegen downloads (checksum-verified) into its cache`;
  return [
    'Your code',
    `${INDENT}pipegen sends ${plural(bundle.files, 'file', 'files')} (${size(bundle.bytes)}) from ${safeText(`${p.owner}/${p.repo}`, 200)} to the AI.`,
    `${INDENT}Top folders: ${folders}`,
    `${INDENT}Never sent, files matching these patterns:`,
    ...wrapList(EXCLUDED_PATTERNS, INDENT + INDENT),
    `${INDENT}Never sent: binary files (images, archives, compiled programs), found by their content.`,
    `${INDENT}Before anything is sent, every file is checked for secrets with ${gitleaks}, and secret-looking values are hidden.`,
  ];
}

function providerSection(provider: AiProvider, ollamaHost: string | undefined): string[] {
  const note = refusalFallbackNoteFor(provider);
  return ['The AI', `${INDENT}${whereItRuns(provider, ollamaHost)}`, ...(note === null ? [] : [`${INDENT}${note}`])];
}

function costSection(title: string, cost: AiCost | 'local', cap: number | null, provider: AiProvider, ollamaHost: string | undefined): string[] {
  if (cost === 'local') {
    const local = provider.name === 'ollama' && !whereItRuns(provider, ollamaHost).includes('Ollama server at');
    return [title, `${INDENT}${local ? 'AI cost: free, local.' : 'AI cost: none counted (your own Ollama server).'}`];
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
    if (scratch !== undefined) lines.push(`${INDENT}pipegen's GitHub App deletes the scratch repo ${full(scratch.name)} after the proof.`);
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

function permissionsSection(title: string, perms: PermissionRows, admin: string | null): string[] {
  return [
    title,
    ...perms.map((r) => `${INDENT}- ${r.permission}: ${r.why}`),
    ...(admin === null ? [] : [`${INDENT}${admin}`]),
  ];
}

const ADMIN_BASE = 'Administration (write): to apply the merge rules (rulesets), deploy environments and Actions settings after you merge the setup PR';
const adminLine = (app: boolean) => (app
  ? `${ADMIN_BASE}, to create the private helper repos, and to delete the scratch repo after the proof if you allow it. Read-only commands never ask for it.`
  : `${ADMIN_BASE}. With a token pipegen never creates or deletes repos. Read-only commands never ask for it.`);

/**
 * The consent text. `est`: estimate() for 'full', estimateAuditAi() for 'audit-ai' (both for the chosen provider and
 * model). `perms`: permissionsTable('write') for 'full', permissionsTable('read') for 'audit-ai' (a write row there is
 * refused). `repos`: `pipelines` and `pipegen-proof-<repo>` with whether each exists ('full' only; 'audit-ai' shows none).
 */
export function consentText(p: RepoProfile, provider: AiProvider, est: Estimates, bundle: BundleSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'full', opts?: ConsentOptions): string;
export function consentText(p: RepoProfile, provider: AiProvider, est: AuditAiEstimate, bundle: BundleSummary, perms: PermissionRows, repos: HelperRepo[], mode: 'audit-ai', opts?: ConsentOptions): string;
export function consentText(p: RepoProfile, provider: AiProvider, est: Estimates | AuditAiEstimate, bundle: BundleSummary, perms: PermissionRows, repos: HelperRepo[], mode: ConsentMode, opts: ConsentOptions = {}): string {
  const sections: string[][] = [];
  if (mode === 'audit-ai') {
    if (perms.some((r) => /\bwrite\b/i.test(r.permission))) {
      throw new Error('The audit --ai consent lists read-only permissions; it was given a write permission.');
    }
    const a = est as AuditAiEstimate;
    sections.push(
      ['pipegen audit --ai is about to send part of your code to an AI. Nothing has left this computer yet.', 'This audit only reads: it changes nothing on GitHub.'],
      filesSection(p, bundle, opts.gitleaksVersion),
      providerSection(provider, opts.ollamaHost),
      costSection('AI cost of this audit (estimate)', a.costUsd, a.capUsd, provider, opts.ollamaHost),
      permissionsSection('GitHub permissions (read-only)', perms, null),
    );
  } else {
    const e = est as Estimates;
    const app = opts.appCreatesRepos === true;
    sections.push(
      ['pipegen is about to start. Nothing has left this computer yet. This is what it will do:'],
      filesSection(p, bundle, opts.gitleaksVersion),
      providerSection(provider, opts.ollamaHost),
      reposSection(p, repos, app),
      minutesSection(p, e),
      costSection('AI cost (estimate)', e.aiCostUsd, e.aiCostCapUsd, provider, opts.ollamaHost),
      ['Time', `${INDENT}About ${e.durationMinutes.low}–${e.durationMinutes.high} minutes.`],
      permissionsSection('GitHub permissions pipegen asks for', perms, adminLine(app)),
    );
  }
  return sections.filter((s) => s.length > 0).map((s) => s.join('\n')).join('\n\n');
}

/** Shows the consent text and asks. The default answer is No; a cancelled or failed question is No too. */
export async function askConsent(io: Prompter, text: string): Promise<boolean> {
  try {
    return (await io.confirm(`${text}\n\nGo ahead?`, false)) === true;
  } catch {
    return false;
  }
}
