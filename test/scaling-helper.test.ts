import { describe, expect, it } from 'vitest';
import { expectScaling } from './helpers/scaling.js';

describe('expectScaling (G17 row 76: a minimum baseline)', () => {
  it('a baseline under the floor (timer noise) does not turn a few ms into a huge ratio', async () => {
    // 0.05 ms at the small size and 40 ms at the big one: ratio 800 on the raw numbers, 8 against the 5 ms floor
    const seen = await expectScaling('tiny baseline', (size) => (size === 'small' ? 0.05 : 40), 10, 1, 5);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.ratio).toBe(8);
  });
  it('a real growth well past the floor still fails in every attempt', async () => {
    let calls = 0;
    await expect(expectScaling('quadratic', (size) => { calls++; return size === 'small' ? 20 : 2000; }, 16, 2, 5)).rejects.toThrow(/over 16 in every attempt/);
    expect(calls).toBe(8);
  });
  it('the default floor is positive: a 0 ms small run is not a divide by nothing', async () => {
    const seen = await expectScaling('zero', (size) => (size === 'small' ? 0 : 1), 4);
    expect(Number.isFinite(seen[0]?.ratio)).toBe(true);
  });
});
