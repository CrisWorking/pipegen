// E8: the child process of `state: SIGINT cancels, cleans and saves interrupted` (test/state.test.ts bundles it with
// esbuild and runs it in plain node, then sends it a real SIGINT). A proof in the `proving` stage: a run going, the user's
// real key stored, a proof branch and its PR. The hooks are armed as Plan G arms them (armProofCleanup). Everything the
// child sees goes to the file named by E8_OUT, line by line. No network: GitHub is the in-process fake.
import { appendFileSync } from 'node:fs';
import { SecretVault } from '../../src/create/secrets.js';
import { armProofCleanup, cleanupAfterProof } from '../../src/proof/cleanup.js';
import { ScratchKeys } from '../../src/proof/keys.js';
import { StateStore } from '../../src/proof/state.js';
import { proofTarget } from '../../src/proof/target.js';
import { onExit } from '../../src/util/exit-hooks.js';
import { cleanupWorld } from '../helpers/cleanup-github.js';
import { app, quietIo } from '../helpers/scratch-secrets.js';

const out = process.env.E8_OUT as string;
const home = process.env.E8_HOME as string;
const RUN = '20261104-090000-abc123';
const REAL = ['sk', 'test', '51RealValueOfTheChild00000'].join('_');   // built at runtime (no-secret-literals)
const line = (s: string): void => { appendFileSync(out, `${s}\n`); };

const w = cleanupWorld({}, Object.fromEntries([['STRIPE_SECRET_KEY', REAL]]), 77_100);
w.f.runs.push({ id: 21, status: 'in_progress' });
w.f.branches.add(`proof/${RUN}/main`);
w.f.prs.push({ number: 5, head: `proof/${RUN}/main`, state: 'open' });
const t = proofTarget(app(), { runId: RUN });
const store = await StateStore.open(app(), { home, env: {} });
store.begin(RUN, app(), { cap: 100, aiCap: 1 });
for (const s of ['planned', 'debated', 'created', 'proving'] as const) store.setStage(s);
const vault = new SecretVault();
vault.set('STRIPE_SECRET_KEY', REAL);
const keys = new ScratchKeys(w.g.gh, t, vault, { io: quietIo });
armProofCleanup(store, async (ctx) => {
  line(`stage-at-cleanup ${store.load()?.stage} ${store.load()?.interruptedAt}`);
  const res = await cleanupAfterProof(w.g.gh, t, store, keys, { canDeleteRepo: false, signal: ctx.signal, settleMs: 1_000, cancelWaitMs: 0 });
  line(`writes ${JSON.stringify(w.g.writes().map((c) => `${c.method} ${decodeURIComponent(c.url.pathname)}`))}`);
  line(`after stored=${w.s.values.size} runs=${JSON.stringify(w.f.runs)} branches=${JSON.stringify([...w.f.branches])} open-prs=${w.f.prs.filter((p) => p.state === 'open').length} leftovers=${res.leftovers.length}`);
});
// a sync hook registered after the vault's: it runs after the vault wipe (B2: the vault is wiped on interrupt, not by the cleanup)
onExit(() => { line(`sync-hooks vault=${vault.get('STRIPE_SECRET_KEY') === undefined ? 'wiped' : 'kept'}`); });
console.log('READY');
setInterval(() => {}, 1_000);
