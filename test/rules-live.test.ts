// LIVE (PIPEGEN_LIVE_TESTS=1, uses the network and the real git): the rendered rules step fetches the REAL pinned semgrep
// rules commit from GitHub and the reviewed tree matches (6c, ruling S12). Skipped by default.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { renderStepWith } from '../src/engine/render-step.js';
import { ctxFor, entry, platform, specFor } from './helpers/render.js';
import { exec, sandbox, stepEnv } from './helpers/step-harness.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform !== 'win32';

describe.skipIf(!live)('live: the pinned semgrep rules commit has the reviewed tree', () => {
  it('fetch, HEAD and HEAD^{tree} check out; the python rules folder is there and .git is gone', () => {
    const t = entry('semgrep');
    const r = renderStepWith(specFor(t, { needId: 'sast', choices: { rules: 'python' } }), t, platform(), ctxFor());
    const step = r.steps.find((s) => s.name.includes('rules')) as NonNullable<(typeof r.steps)[number]>;
    const sb = sandbox();
    const res = exec(step, sb, stepEnv(step, sb));
    expect(res.status, res.stderr).toBe(0);
    const dir = join(sb.rt, 'pipegen-rules', 'pipegen-out-sast');
    expect(existsSync(join(dir, 'python'))).toBe(true);
    expect(existsSync(join(dir, '.git'))).toBe(false);
  }, 180_000);
});
