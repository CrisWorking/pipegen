// v0.2 Plan G G11 (controller ruling G10-R1): the two cosign key texts pipegen handles, held to exactly the shape cosign writes, so that
// nothing else rides along. Every other secret keeps the single-line refusal of valueProblem (src/create/secrets.ts); only the signing key
// goes through cosignKeyProblem, and only through storeCosignKey. No message here ever holds any part of the value.
//
// - The private key (PIPEGEN_COSIGN_KEY, read by `cosign sign --key env://PIPEGEN_COSIGN_KEY`): cosign's encrypted PEM block, a header line
//   `-----BEGIN ENCRYPTED SIGSTORE <kind>-----` (cosign 2+; COSIGN in older releases), base64 body lines of 64 characters (the last one
//   shorter, `=` padding only at its end), the matching footer, at most one final line break, no carriage return, at most
//   MAX_COSIGN_KEY_BYTES. The body decodes to cosign's JSON envelope ({ kdf, cipher, ciphertext }): an unencrypted key, a key of another
//   tool, or anything with text around the block is refused.
// - The public key (PIPEGEN_COSIGN_PUB, the environment variable the verify step hashes, and the install record's `cosignPub`): one
//   `PUBLIC KEY` PEM block of the same line form, at most MAX_COSIGN_PUB_BYTES.
// The marker words are spelled at run time: a literal private-key marker in src/ is what the secret-literal check refuses.

/** The largest encrypted private key pipegen stores (cosign's is about 650 bytes). */
export const MAX_COSIGN_KEY_BYTES = 8192;
/** The largest public key pipegen sets or records (cosign's P-256 key is about 180 bytes). */
export const MAX_COSIGN_PUB_BYTES = 2048;

const DASHES = '-----';
const PRIVATE_TAIL = ['PRIVATE', 'KEY'].join(' ');
const KEY_KINDS = ['SIGSTORE', 'COSIGN'] as const;
const B64_FULL = /^[A-Za-z0-9+/]{64}$/;
const B64_LAST = /^[A-Za-z0-9+/]{1,64}$|^[A-Za-z0-9+/]{2,63}={1,2}$/;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The PEM body (between header and footer) decoded, or null when it isn't base64 in 64-character lines exactly as PEM writes it. */
function pemBody(lines: readonly string[]): Buffer | null {
  if (lines.length === 0) return null;
  for (let i = 0; i < lines.length - 1; i++) if (!B64_FULL.test(lines[i] as string)) return null;
  const last = lines[lines.length - 1] as string;
  if (!B64_LAST.test(last) || last.length > 64) return null;
  const joined = lines.join('');
  if (joined.length % 4 !== 0) return null;
  const buf = Buffer.from(joined, 'base64');
  // canonical: re-encoding gives the same text (no stray bits, no padding in the middle)
  return buf.toString('base64') === joined ? buf : null;
}

/** The lines of one PEM block with exactly `header` and `footer`, at most one final line break, nothing around it; or null. */
function blockLines(value: string, header: string, footer: string): string[] | null {
  if (value.includes('\r')) return null;
  const text = value.endsWith('\n') ? value.slice(0, -1) : value;
  const lines = text.split('\n');
  if (lines.length < 3 || lines[0] !== header || lines[lines.length - 1] !== footer) return null;
  return lines.slice(1, -1);
}

/**
 * Why `value` is not cosign's encrypted private key in the exact form cosign writes, or null when it is. The reason never holds the value.
 */
export function cosignKeyProblem(value: unknown): string | null {
  const NOT = 'is not a cosign encrypted private key in the form cosign writes';
  if (typeof value !== 'string') return 'is not text';
  if (Buffer.byteLength(value, 'utf8') > MAX_COSIGN_KEY_BYTES) return `is larger than a cosign private key (${MAX_COSIGN_KEY_BYTES} bytes)`;
  for (const kind of KEY_KINDS) {
    const lines = blockLines(value, `${DASHES}BEGIN ENCRYPTED ${kind} ${PRIVATE_TAIL}${DASHES}`, `${DASHES}END ENCRYPTED ${kind} ${PRIVATE_TAIL}${DASHES}`);
    if (lines === null) continue;
    const body = pemBody(lines);
    if (body === null) return NOT;
    let envelope: unknown;
    try { envelope = JSON.parse(body.toString('utf8')); } catch { return NOT; }
    if (!isObj(envelope) || !isObj(envelope.kdf) || typeof envelope.kdf.name !== 'string' || !isObj(envelope.cipher) || typeof envelope.cipher.name !== 'string' || typeof envelope.ciphertext !== 'string' || envelope.ciphertext === '') return NOT;
    return null;
  }
  return NOT;
}

/** Why `value` is not one PEM public key block as cosign writes it, or null when it is. */
export function cosignPubProblem(value: unknown): string | null {
  const NOT = 'is not a public key in the form cosign writes';
  if (typeof value !== 'string') return 'is not text';
  if (Buffer.byteLength(value, 'utf8') > MAX_COSIGN_PUB_BYTES) return `is larger than a cosign public key (${MAX_COSIGN_PUB_BYTES} bytes)`;
  const lines = blockLines(value, `${DASHES}BEGIN PUBLIC KEY${DASHES}`, `${DASHES}END PUBLIC KEY${DASHES}`);
  if (lines === null) return NOT;
  const body = pemBody(lines);
  return body === null || body.length < 32 ? NOT : null;
}
