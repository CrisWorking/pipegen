// The secret-scanner upgrade checklist (P46): a required live test must really assert. counted() wraps its body:
// expect.hasAssertions() fails it when nothing was asserted, and the number of assertions is recorded in the test's
// meta (`assertionCalls`), which vitest's JSON report carries, so scripts/scanner-live.ts can require it to be above 0.
import { expect, type TestContext } from 'vitest';

declare module 'vitest' {
  interface TaskMeta {
    assertionCalls?: number;
  }
}

export function counted(body: () => unknown): (ctx: TestContext) => Promise<void> {
  return async (ctx) => {
    expect.hasAssertions();
    await body();
    ctx.task.meta.assertionCalls = expect.getState().assertionCalls;
  };
}
