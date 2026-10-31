// Built by the secrets bundle test with tsup into a temp folder (the release build's settings) and run as its own node process, with no
// node_modules beside it: the BUNDLED libsodium seals through the real storeSecrets and storeEnvSecret, and the same bundle opens the result.
import type { Octokit } from '@octokit/rest';
import sodium from 'libsodium-wrappers';
import { SecretVault, storeEnvSecret, storeSecrets } from '../../src/create/secrets.js';

await sodium.ready;
const kp = sodium.crypto_box_keypair();
const sent: Record<string, unknown>[] = [];
const gh = {
  request: async (route: string, p: Record<string, unknown>) => {
    if (route.startsWith('GET')) return { data: { key_id: 'k1', key: Buffer.from(kp.publicKey).toString('base64') } };
    sent.push(p);
    return { data: {} };
  },
} as unknown as Octokit;
const vault = new SecretVault();
vault.set('STRIPE_KEY', 'sk_test_bundled_value_1');
await storeSecrets(gh, { owner: 'o', repo: 'r' }, vault, ['STRIPE_KEY']);
await storeEnvSecret(gh, { owner: 'o', repo: 'r', id: 7 }, 'pipegen-signing', 'PIPEGEN_COSIGN_KEY', 'cosign_bundled_value_2');
const open = (p: Record<string, unknown>): string => sodium.to_string(sodium.crypto_box_seal_open(Buffer.from(p.encrypted_value as string, 'base64'), kp.publicKey, kp.privateKey));
console.log(JSON.stringify({ repo: open(sent[0] as Record<string, unknown>), env: open(sent[1] as Record<string, unknown>), keyId: (sent[0] as Record<string, unknown>).key_id }));
vault.wipe();
