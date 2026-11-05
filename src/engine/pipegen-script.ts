// v0.2 Plan G G2 (G2-R1 m2): the one preamble of pipegen's own fixed bash steps (signing.ts, image-handoff.ts): strict mode, no CDPATH, the
// fixed PATH, a failure helper; the step gets empty BASH_ENV and ENV so no startup file runs. Every value a script holds is checked by its caller.
import type { RenderedStep } from './job-rules.js';

const FIXED_PATH = 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
export const SCRIPT_HEAD: readonly string[] = Object.freeze(['set -euo pipefail', 'unset CDPATH', FIXED_PATH, 'pg_fail() { echo "pipegen: $1" >&2; exit 1; }']);

/** A pipegen bash step: the preamble, then `lines`, with its env on top of the empty startup files. */
export const pipegenScriptStep = (id: string, name: string, lines: readonly string[], env: Record<string, string> = {}): RenderedStep =>
  ({ id, name, run: [...SCRIPT_HEAD, ...lines, ''].join('\n'), shell: 'bash', env: { BASH_ENV: '', ENV: '', ...env } });
