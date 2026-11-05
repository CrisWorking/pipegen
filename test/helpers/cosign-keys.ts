// Test key texts in cosign's exact forms (G11, ruling G10-R1). The private-key marker is spelled at run time (test/no-secret-literals.test.ts).
const TAIL = ['PRIV', 'ATE KEY'].join('');
export const keyHead = (kind = 'SIGSTORE'): string => `-----BEGIN ENCRYPTED ${kind} ${TAIL}-----`;
export const keyFoot = (kind = 'SIGSTORE'): string => `-----END ENCRYPTED ${kind} ${TAIL}-----`;
export const keyTail = TAIL;
export const lines64 = (b64: string): string[] => b64.match(/.{1,64}/g) ?? [];
/** cosign's JSON envelope, base64 (what the PEM body holds); `seed` makes each key different. */
export const envelope = (over: Record<string, unknown> = {}, seed = 'c2FsdA=='): string => Buffer.from(JSON.stringify({ kdf: { name: 'scrypt', params: { N: 65536, r: 8, p: 1 }, salt: seed }, cipher: { name: 'nacl/secretbox', nonce: 'bm9uY2U=' }, ciphertext: 'Y2lwaGVy'.repeat(30), ...over })).toString('base64');
/** An encrypted private key in cosign's form (`kind`: SIGSTORE, cosign 2+; COSIGN, older releases). */
export const cosignKey = (kind = 'SIGSTORE', body = envelope()): string => [keyHead(kind), ...lines64(body), keyFoot(kind), ''].join('\n');
/** A public key in cosign's form; `n` makes each key different. */
export const cosignPub = (n = 7): string => ['-----BEGIN PUBLIC KEY-----', ...lines64(Buffer.alloc(91, n).toString('base64')), '-----END PUBLIC KEY-----', ''].join('\n');
