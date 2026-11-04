// E8 fix round 2: an armed StateStore in a temp home, for tests that create a helper repo (createHelperRepo needs a permit
// that only an armed store issues). The temp folder goes when the process exits.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { StateStore } from '../../src/proof/state.js';
import type { ProofApp } from '../../src/proof/target.js';

const RUN = '20261104-090000-abc123';

export async function armedStore(app: ProofApp): Promise<StateStore> {
  const h = mkdtempSync(join(tmpdir(), 'pg-armed-'));
  process.once('exit', () => rmSync(h, { recursive: true, force: true }));
  const store = await StateStore.open(app, { home: h, env: {} });
  store.begin(RUN, app, { cap: 10, aiCap: 1 });
  store.markArmed(true);
  return store;
}
