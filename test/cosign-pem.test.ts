// v0.2 Plan G G11 (controller ruling G10-R1): the cosign private key is the one multi-line value pipegen stores, through its own path
// (storeCosignKey) that accepts exactly cosign's encrypted PEM block; every other secret keeps the single-line refusal; no value is ever
// in a message. The marker words are spelled at run time (test/no-secret-literals.test.ts).
import { describe, expect, it } from 'vitest';
import { SecretStoreError, storeCosignKey, storeEnvSecret } from '../src/create/secrets.js';
import { cosignKeyProblem, cosignPubProblem, MAX_COSIGN_KEY_BYTES } from '../src/util/cosign-pem.js';
import { cosignKey, cosignPub, envelope, keyFoot, keyHead, keyTail } from './helpers/cosign-keys.js';
import { FakeGitHub } from './helpers/deliver-github.js';

const TAIL = keyTail;
const head = keyHead;
const foot = keyFoot;
const pub = (): string => cosignPub();

describe('G11 cosign key shapes (G10-R1)', () => {
  it('storeCosignKey: accepts exactly cosign\'s encrypted PEM; every other secret keeps the single-line refusal', async () => {
    expect(cosignKeyProblem(cosignKey())).toBeNull();
    expect(cosignKeyProblem(cosignKey('COSIGN'))).toBeNull();
    expect(cosignKeyProblem(cosignKey().slice(0, -1))).toBeNull();   // no final line break
    expect(cosignPubProblem(pub())).toBeNull();
    const g = new FakeGitHub();
    const r = g.addRepo('o/r');
    r.envs.set('pipegen-signing', { id: 1, created_at: '2026-11-05T12:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    await storeCosignKey(g.octokit(), { owner: 'o', repo: 'r' }, 'pipegen-signing', cosignKey());
    expect([...r.envs.get('pipegen-signing')?.stored.keys() ?? []]).toEqual(['PIPEGEN_COSIGN_KEY']);
    const put = g.calls.find((c) => c.route.startsWith('PUT '));
    expect(JSON.stringify(put?.params)).not.toContain('BEGIN');   // sealed, never the text
    // the same text through the ordinary path is still refused (a line break)
    await expect(storeEnvSecret(g.octokit(), { owner: 'o', repo: 'r' }, 'pipegen-signing', 'PIPEGEN_COSIGN_KEY', cosignKey())).rejects.toThrow(/invisible or control characters/);
  });

  it('storeCosignKey: near-misses refused before anything is sent, and no message holds the value', async () => {
    const good = cosignKey();
    const body = good.split('\n').slice(1, -2);
    const near: [string, string][] = [
      ['unencrypted key', [`-----BEGIN ${TAIL}-----`, ...body, `-----END ${TAIL}-----`, ''].join('\n')],
      ['another tool\'s key', [`-----BEGIN RSA ${TAIL}-----`, ...body, `-----END RSA ${TAIL}-----`, ''].join('\n')],
      ['footer of another kind', [head('SIGSTORE'), ...body, foot('COSIGN'), ''].join('\n')],
      ['no footer', [head(), ...body, ''].join('\n')],
      ['text before', `junk\n${good}`],
      ['text after', `${good}junk\n`],
      ['two final line breaks', `${good}\n`],
      ['carriage returns', good.replace(/\n/g, '\r\n')],
      ['a long body line', [head(), `${body[0]}${body[1]}`, ...body.slice(2), foot(), ''].join('\n')],
      ['a short line in the middle', [head(), (body[0] as string).slice(0, 60), ...body.slice(1), foot(), ''].join('\n')],
      ['not base64', [head(), (body[0] as string).replace(/^./, '!'), ...body.slice(1), foot(), ''].join('\n')],
      ['padding in the middle', [head(), `${(body[0] as string).slice(0, 62)}==`, ...body.slice(1), foot(), ''].join('\n')],
      ['empty body', [head(), foot(), ''].join('\n')],
      ['not cosign\'s envelope', cosignKey('SIGSTORE', Buffer.from('{"hello":"world","x":"' + 'y'.repeat(80) + '"}').toString('base64'))],
      ['no ciphertext', cosignKey('SIGSTORE', envelope({ ciphertext: '' }))],
      ['oversize', cosignKey('SIGSTORE', envelope({ ciphertext: 'A'.repeat(MAX_COSIGN_KEY_BYTES) }))],
      ['a bidi character', good.replace('\n', '\u202e\n')],
      ['a public key', pub()],
    ];
    const g = new FakeGitHub();
    g.addRepo('o/r');
    for (const [what, v] of near) {
      expect(cosignKeyProblem(v), what).not.toBeNull();
      const e = await storeCosignKey(g.octokit(), { owner: 'o', repo: 'r' }, 'pipegen-signing', v).then(() => null, (x: unknown) => x);
      expect(e, what).toBeInstanceOf(SecretStoreError);
      expect((e as Error).message, what).not.toContain((body[0] as string).slice(0, 20));
      expect((e as Error).message, what).not.toContain('junk');
    }
    expect(g.calls).toEqual([]);
    expect(cosignPubProblem(good)).not.toBeNull();
    expect(cosignPubProblem(`${pub()}x`)).not.toBeNull();
    expect(cosignPubProblem(['-----BEGIN PUBLIC KEY-----', 'AAAA', '-----END PUBLIC KEY-----'].join('\n'))).not.toBeNull();   // too short to be a key
  });
});
