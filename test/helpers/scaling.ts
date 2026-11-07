// G17: linear-time checks that don't depend on how fast (or how loaded) the machine is. Instead of a wall-clock budget, the same
// work is timed at a small and a large size, and the ratio of the two is bounded: a linear pass grows about as much as its input,
// a quadratic one (or a backtracking regex) grows by the square of it. Each size is timed twice and the faster run counts, and the
// whole measurement is tried up to `attempts` times: a pause from other processes only ever makes one run slower, so a linear pass
// passes in some attempt, while a quadratic one fails every attempt.
import { expect } from 'vitest';

export interface ScalingResult { small: number; big: number; ratio: number }

/**
 * `timed(size)` does the work for one size and returns its milliseconds (setup outside the timed part). The test fails when
 * big/small exceeds `maxRatio` in every attempt.
 */
export async function expectScaling(
  label: string,
  timed: (size: 'small' | 'big') => number | Promise<number>,
  maxRatio: number,
  attempts = 3,
): Promise<ScalingResult[]> {
  const seen: ScalingResult[] = [];
  for (let a = 0; a < attempts; a++) {
    let small = Infinity;
    let big = Infinity;
    for (let k = 0; k < 2; k++) {
      small = Math.min(small, await timed('small'));
      big = Math.min(big, await timed('big'));
    }
    const r = { small: Math.round(small), big: Math.round(big), ratio: big / Math.max(small, 1) };
    seen.push(r);
    if (process.env.SCALING_LOG) process.stderr.write(`${label}: ${r.big}/${r.small} ms = ${r.ratio.toFixed(2)} (max ${maxRatio})\n`);
    if (r.ratio <= maxRatio) return seen;
  }
  expect.fail(`${label}: big/small time ratio over ${maxRatio} in every attempt: ${seen.map((r) => `${r.big}/${r.small} ms = ${r.ratio.toFixed(1)}`).join(', ')}`);
}
