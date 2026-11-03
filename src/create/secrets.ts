// Secret requests, the in-memory vault and sealed storage (v0.2 Plan D, D5; rulings S8 and S10).
// When a service needs env vars that pipegen can't generate (an API key), pipegen asks the user for TEST values, holds them in the vault and
// seals them with GitHub's public key (libsodium crypto_box_seal) before storing them as repo or environment secrets.
//
// These values are the most sensitive data pipegen ever touches. They are:
//   - never logged, never in a file, never sent to the AI, never in an error message (errors carry a name and an HTTP status only);
//   - held as Buffers in the vault, zeroed by wipe() (called by the one exit-hook registry on exit, SIGINT and SIGTERM, and by the caller after delivery);
//   - never listed: the vault has no values() method and shows only names to JSON.stringify, util.inspect and template literals;
//   - checked for in every created file (containsKnownValue: the value, its base64 and its URL forms; the guard and the referee call it).
// The sealed text is random per call (crypto_box_seal uses a fresh ephemeral key), so it reveals nothing about the value.
import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import type { Octokit } from '@octokit/rest';
import sodium from 'libsodium-wrappers';
import { knownValueScrubber } from '../ai/redact.js';
import type { Prompter } from '../cli/io.js';
import { dockerfilesOf } from '../engine/created-judges/compose.js';
import { isDangerousName } from '../engine/job-rules.js';
import { NAME_RE } from '../read/manifest.js';
import type { CreatedFile, Dependency, KnownValueCheck, RepoProfile } from '../types.js';
import { onExit } from '../util/exit-hooks.js';
import { holdsEscape, textForms } from '../util/known-values.js';
import { displayForm, safeText } from '../util/safe-text.js';
import { composeCoveredNames } from './compose.js';
import { ENV_TABLE, isDepKey } from './compose-tables.js';

// ---------- requests ----------

export interface SecretRequest { name: string; service: string; why: string; example?: string }

/** Names that are not secrets whatever the service says (any letter case). */
const NON_SECRETS: ReadonlySet<string> = new Set(['PORT', 'NODE_ENV', 'LOG_LEVEL', 'HOST']);
const CANT_MAP = "pipegen can't map this name into a step: rename it";

/** The names compose fills for this repo, so they are not asked. The Dockerfiles pipegen creates count (D4 carry C2): the default empty list would ask for DATABASE_URL. */
export function coveredNames(profile: RepoProfile, files: readonly CreatedFile[]): Set<string> {
  return new Set(composeCoveredNames(profile, { createdDockerfiles: dockerfilesOf(files) }));
}

/** PIPEGEN_* and GITHUB_* (any case): reserved, never taken from a request or a caller. */
const reserved = (name: string): boolean => /^(?:PIPEGEN|GITHUB)_/i.test(name);

/** Why a name can't be mapped into a step (it becomes `${{ secrets.NAME }}` in an env), or null. The secret is stored under the upper-case name. */
function mapProblem(name: string): boolean {
  if (!NAME_RE.test(name)) return true;
  const up = name.toUpperCase();
  return isDangerousName(name) || isDangerousName(up) || reserved(name);
}

/**
 * The env vars pipegen can't generate and must ask the user for: all `service.envVars` minus the compose-covered names, the well-known
 * non-secrets, and names that can't be mapped (dangerous, GITHUB_*, PIPEGEN_*, not a plain name, or two spellings of one name after
 * upper-casing: those go to `cantMap`). A name of a dependency pipegen starts that its table can't map gets a note and is not asked.
 * Text built from repo names passes safeText; the rest is fixed.
 */
export function secretRequests(profile: RepoProfile, ctx: { covered: Set<string> }): { requests: SecretRequest[]; cantMap: string[]; notes: string[] } {
  const out = { requests: [] as SecretRequest[], cantMap: [] as string[], notes: [] as string[] };
  const services = Array.isArray(profile?.services) ? profile.services : [];
  const covered = new Set([...ctx.covered].map((n) => n.toUpperCase()));   // compose reads the names as written, but a spelling that differs only in case is the same secret
  interface Seen { service: string; owners: Dependency[] }
  const seen = new Map<string, Seen>();
  for (const s of services) {
    if (s === null || typeof s !== 'object' || !Array.isArray(s.envVars)) continue;
    const deps = Array.isArray(s.dependsOn) ? s.dependsOn.filter((d): d is Dependency => d !== null && typeof d === 'object' && Array.isArray(d.envVars)) : [];
    for (const name of s.envVars) {
      if (typeof name !== 'string' || name === '' || NON_SECRETS.has(name.toUpperCase()) || covered.has(name.toUpperCase())) continue;
      const entry = seen.get(name) ?? { service: typeof s.name === 'string' ? s.name : 'app', owners: [] };
      entry.owners.push(...deps.filter((d) => d.envVars.includes(name)));
      seen.set(name, entry);
    }
  }
  const spellings = new Map<string, number>();
  for (const name of seen.keys()) spellings.set(name.toUpperCase(), (spellings.get(name.toUpperCase()) ?? 0) + 1);
  const said = new Set<string>();
  const say = (list: string[], line: string): void => { if (!said.has(line)) { said.add(line); list.push(line); } };
  for (const [name, { service, owners }] of seen) {
    if (mapProblem(name) || (spellings.get(name.toUpperCase()) ?? 0) > 1) { say(out.cantMap, `${safeText(name, 80)}: ${CANT_MAP}`); continue; }
    const mapped = owners.some((d) => !isDepKey(d.kind) || Object.hasOwn(ENV_TABLE[d.kind], name));
    if (owners.length > 0 && !mapped) {
      say(out.notes, `The variable ${safeText(name, 80)} belongs to the ${owners.map((d) => safeText(String(d.kind), 20)).join('/')} dependency, but pipegen does not know what it holds, so it does not ask for it; set it yourself if the test run needs it.`);
      continue;
    }
    const external = owners.find((d) => d.kind === 'external');
    out.requests.push({
      name, service: safeText(service, 80),
      why: `The service ${safeText(service, 80)} needs ${safeText(name, 80)} to start, and pipegen can't generate it.`,
      ...(external === undefined ? {} : { example: `${safeText(external.name, 60)}: use a **test** key, never a production one` }),
    });
  }
  return out;
}

// ---------- the vault ----------

/**
 * The values the user typed (and PIPEGEN_FP_KEY), in memory only. `get` returns a string and exists for sealing; nothing lists the values.
 * Held values register `wipe` with the exit-hook registry (exit, SIGINT, SIGTERM); wipe unregisters it.
 */
/**
 * Why a typed value can't be kept, or null (the text never holds the value). Well-formed Unicode only (a lone surrogate is stored as U+FFFD, so
 * it would not match what the user typed); nothing that the display changes (invisible, control and bidi characters, line separators: a needle
 * that vanishes on screen can't be matched or scrubbed); at least MIN_VALUE_LENGTH code points (not bytes, not UTF-16 units).
 */
export function valueProblem(value: unknown): string | null {
  if (typeof value !== 'string') return 'is not text';
  // a lone surrogate (String.prototype.isWellFormed is newer than the project's lib setting)
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(value)) return 'is not well-formed text';
  if (displayForm(value) !== value) return 'contains invisible or control characters';
  if ([...value].length < MIN_VALUE_LENGTH) return `is too short to protect: pipegen needs at least ${MIN_VALUE_LENGTH} characters`;
  return null;
}

/** The shortest value pipegen keeps (a shorter one would make the scrubber and the file check flag ordinary text, and its place in a text would give it away). */
export const MIN_VALUE_LENGTH = 8;
let putReserved: (v: SecretVault, name: string, value: string) => void;

export class SecretVault implements KnownValueCheck {
  readonly #values = new Map<string, Buffer>();
  #unhook: (() => void) | null = null;
  #scrub: ((text: string) => string) | null = null;

  set(name: string, value: string): void {
    if (typeof name === 'string' && reserved(name)) throw new Error(`${safeText(name, 80)} is a name pipegen reserves for itself, so it can not hold a value you typed`);
    this.#put(name, value);
  }
  /** The one write path. Buffers are allocated with Buffer.alloc (never a slice of Node's shared pool) and filled in place. */
  #put(name: string, value: string): void {
    if (typeof name !== 'string' || !NAME_RE.test(name)) throw new Error('a secret name must be a plain environment variable name');
    const problem = valueProblem(value);
    if (problem !== null) throw new Error(`the value for ${safeText(name, 80)} ${problem}`);
    this.#values.get(name)?.fill(0);
    const buf = Buffer.alloc(Buffer.byteLength(value, 'utf8'));
    buf.write(value, 'utf8');
    this.#values.set(name, buf);
    this.#scrub = null;
    this.#unhook ??= onExit(() => this.wipe());
  }
  static {
    putReserved = (v, name, value) => v.#put(name, value);
  }
  get(name: string): string | undefined {
    return this.#values.get(name)?.toString('utf8');
  }
  has(name: string): boolean {
    return this.#values.has(name);
  }
  names(): string[] {
    return [...this.#values.keys()];
  }
  /** Zeroes every Buffer, then forgets them. Safe to call twice. */
  wipe(): void {
    for (const b of this.#values.values()) b.fill(0);
    this.#values.clear();
    this.#scrub = null;
    const off = this.#unhook;
    this.#unhook = null;
    off?.();
  }
  /**
   * A function that replaces each value, its base64 forms and its URL forms with [REDACTED], also when the text holds the value in the other
   * Unicode normalisation (NFC or NFD). Built once and kept until the next `set` or `wipe`.
   */
  scrubber(): (text: string) => string {
    this.#scrub ??= knownValueScrubber([...new Set([...this.#values.values()].flatMap((b) => { const v = b.toString('utf8'); return [v, v.normalize('NFC'), v.normalize('NFD')]; }))]);
    return this.#scrub;
  }
  /**
   * Whether `text` holds a value (or its base64 or URL form): as written, as displayed, with controls and invisibles removed, or in NFC form.
   * Fails closed: a text with ESC or a C1 control counts as holding one, even in an empty vault (an escape sequence can eat and split a value
   * so that no form shows it). Used by the guard and the referee.
   */
  containsKnownValue(text: string): boolean {
    if (typeof text !== 'string') return false;
    if (holdsEscape(text)) return true;
    if (this.#values.size === 0) return false;
    const scrub = this.scrubber();
    return textForms(text).some((t) => scrub(t) !== t);
  }
  toJSON(): string { return '[vault]'; }
  toString(): string { return '[vault]'; }
  [inspect.custom](): string { return `SecretVault { names: ${inspect(this.names())} }`; }
}

// ---------- asking ----------

export const TEST_KEYS_ONLY = "Use TEST keys only (never production). They're used for the proof and deleted from the test repo afterwards.";
const LIVE_REFUSED = 'That looks like a LIVE (production) key, so pipegen did not take it. Paste a TEST key instead, or press Enter to skip.';
const TOO_SHORT = `That value is too short to protect: pipegen needs at least ${MIN_VALUE_LENGTH} characters. Paste the full value, or press Enter to skip and set it yourself.`;
const BAD_VALUE = (problem: string): string => (problem.startsWith('is too short') ? TOO_SHORT : `That value ${problem}, so pipegen can not keep it out of logs and files. Paste it again without them, or press Enter to skip and set it yourself.`);
/** Live-key prefixes of payment providers (Stripe sk/rk/pk_live_, Razorpay rzp_live_, Mollie live_). Test keys never carry them. */
const LIVE_KEY_RE = /(?:^|[^A-Za-z0-9])(?:sk|rk|pk|rzp)_live_|^live_/i;

/**
 * Asks for each request, masked. Enter (or only spaces) skips: the name is `missing`. A live-key look is refused with the test-key message and asked
 * once more; a second live key counts as missing. Nothing typed ever reaches a message, a list or an error. A cancelled prompt throws (the caller wipes).
 */
export async function askSecrets(io: Prompter, reqs: readonly SecretRequest[], vault: SecretVault): Promise<{ missing: string[] }> {
  const missing: string[] = [];
  for (const r of reqs) {
    // a name pipegen could not map into a step (reserved, dangerous, not plain) is never asked: whoever built the request, the vault does not take it
    if (typeof r?.name !== 'string' || mapProblem(r.name)) { missing.push(String(r?.name)); continue; }
    const what = `${r.name} (${r.why})${r.example === undefined ? '' : ` ${r.example}`}`;
    let value = (await io.text(`${TEST_KEYS_ONLY}\n${what}`, { secret: true })).trim();
    const refusal = (v: string): string | null => (v === '' ? null : LIVE_KEY_RE.test(v) ? LIVE_REFUSED : ((p) => (p === null ? null : BAD_VALUE(p)))(valueProblem(v)));
    const first = refusal(value);
    if (first !== null) value = (await io.text(`${TEST_KEYS_ONLY}\n${first}\n${what}`, { secret: true })).trim();
    if (value === '' || refusal(value) !== null) { missing.push(r.name); continue; }
    vault.set(r.name, value);
  }
  return { missing };
}

// ---------- storing ----------

/** A failed store: a name and an HTTP status, never a value, a sealed text or a server message. */
export class SecretStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretStoreError';
  }
}
const statusOf = (e: unknown): string => {
  const s = typeof e === 'object' && e !== null ? (e as { status?: unknown }).status : undefined;
  return typeof s === 'number' && Number.isInteger(s) ? ` (HTTP ${s})` : '';
};
const PART_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const ENV_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

/** The upper-case secret name, or an error: a plain name, never GITHUB_*. */
function secretName(name: unknown): string {
  if (typeof name !== 'string' || !NAME_RE.test(name)) throw new SecretStoreError(`${safeText(String(name), 80)} is not a plain secret name`);
  const up = name.toUpperCase();
  if (up.startsWith('GITHUB_')) throw new SecretStoreError(`${safeText(up, 80)}: GitHub does not allow secret names that start with GITHUB_`);
  return up;
}

interface PublicKey { keyId: string; key: Uint8Array }
/** GitHub's key reply, checked: a key_id and a standard-base64 key of exactly 32 bytes. Anything else is an error and nothing is sent. */
function checkKey(data: unknown): PublicKey {
  const d = (typeof data === 'object' && data !== null ? data : {}) as { key_id?: unknown; key?: unknown };
  const bad = (): never => { throw new SecretStoreError("GitHub's public key for secrets is not valid (not a key_id and a 32-byte base64 key), so nothing was sent."); };
  if (typeof d.key_id !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(d.key_id)) return bad();
  if (typeof d.key !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(d.key)) return bad();
  const key = Buffer.from(d.key, 'base64');
  return key.length === sodium.crypto_box_PUBLICKEYBYTES ? { keyId: d.key_id, key: new Uint8Array(key) } : bad();
}

async function fetchKey(fn: () => Promise<{ data: unknown }>): Promise<PublicKey> {
  let reply: { data: unknown };
  try { reply = await fn(); } catch (e) { throw new SecretStoreError(`Could not read GitHub's public key for secrets${statusOf(e)}.`); }
  await sodium.ready;
  return checkKey(reply.data);
}

/** crypto_box_seal of `value` to `key`, base64. The plaintext Buffer made here is zeroed. */
function seal(value: string, key: Uint8Array): string {
  const plain = Buffer.alloc(Buffer.byteLength(value, 'utf8'));
  plain.write(value, 'utf8');
  try { return Buffer.from(sodium.crypto_box_seal(plain, key)).toString('base64'); } finally { plain.fill(0); }
}

async function put(fn: () => Promise<unknown>, name: string): Promise<void> {
  try { await fn(); } catch (e) { throw new SecretStoreError(`Could not store the secret ${safeText(name, 80)}${statusOf(e)}.`); }
}

/**
 * Stores the vault's `names` as repo secrets: GET the repo's public key, seal each value (crypto_box_seal), PUT `encrypted_value` + `key_id`.
 * Names are upper-cased; GITHUB_* is refused. All names are checked before anything is sent. Does NOT wipe the vault (the caller wipes after delivery).
 * Environment secrets never go through here (storeEnvSecret). Returns the stored (upper-case) names.
 */
export async function storeSecrets(gh: Octokit, repo: { owner: string; repo: string }, vault: SecretVault, names: readonly string[]): Promise<string[]> {
  if (!PART_RE.test(String(repo?.owner)) || !PART_RE.test(String(repo?.repo))) throw new SecretStoreError('the repository owner or name is not a plain name');
  const todo = names.map((n) => ({ from: n, up: secretName(n) }));
  if (new Set(todo.map((t) => t.up)).size !== todo.length) throw new SecretStoreError('two of the secret names are the same after upper-casing');
  for (const t of todo) if (!vault.has(t.from)) throw new SecretStoreError(`there is no value for ${safeText(t.up, 80)} in the vault`);
  if (todo.length === 0) return [];
  const { owner, repo: name } = repo;
  const key = await fetchKey(() => gh.request('GET /repos/{owner}/{repo}/actions/secrets/public-key', { owner, repo: name }));
  const done: string[] = [];
  for (const t of todo) {
    const encrypted = seal(vault.get(t.from) as string, key.key);
    await put(() => gh.request('PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}', { owner, repo: name, secret_name: t.up, encrypted_value: encrypted, key_id: key.keyId }), t.up);
    done.push(t.up);
  }
  return done;
}

/**
 * THE way to store an environment secret (for example PIPEGEN_COSIGN_KEY in `pipegen-signing`): GET the environment's public key
 * (/repos/{owner}/{repo}/environments/{env}/secrets/public-key, the path in GitHub's current API description; S8 amended, DECISIONS #105),
 * seal, PUT. `owner`, `repo`, `env` and `name` are validated first; Octokit URL-encodes the path parts.
 */
export async function storeEnvSecret(gh: Octokit, repo: { owner: string; repo: string }, env: string, name: string, value: string): Promise<void> {
  if (!PART_RE.test(String(repo?.owner)) || !PART_RE.test(String(repo?.repo))) throw new SecretStoreError('the repository owner or name is not a plain name');
  if (typeof env !== 'string' || !ENV_RE.test(env)) throw new SecretStoreError('the environment name is not a plain name');
  const up = secretName(name);
  const problem = valueProblem(value);
  if (problem !== null) throw new SecretStoreError(`the value for ${safeText(up, 80)} ${problem}`);
  const params = { owner: repo.owner, repo: repo.repo, environment_name: env };
  const key = await fetchKey(() => gh.request('GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/public-key', params));
  const encrypted = seal(value, key.key);
  await put(() => gh.request('PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { ...params, secret_name: up, encrypted_value: encrypted, key_id: key.keyId }), up);
}

// ---------- the fingerprint key ----------

/** PIPEGEN_FP_KEY (the HMAC key for secret fingerprints, spec §19): 32 bytes from crypto.randomBytes, hex, kept in the vault. Never shown, logged or sent to the AI. */
export function generateFpKey(vault: SecretVault): void {
  putReserved(vault, 'PIPEGEN_FP_KEY', randomBytes(32).toString('hex'));
}
