// Plan C Task C5a: the two engine pieces the gate's input side needs. Written first.
//  - CF3b / C0c review: base-scan hands the gate the commit it checked out as the job output `base-sha`, exactly
//    `${{ steps.pipegen-checkout.outputs.commit }}` of its one base checkout; any other form, or the output on another job, is an injection.
//  - C4 r2 CF3 / C5a: the gate step takes `service-roots` (a JSON list of plain relative folders, mode gate only), so the root-scoped config
//    names are protected at each service root too.
import { describe, expect, it } from 'vitest';
import { BASE_CHECKOUT_ID, BASE_SCAN_JOB, BASE_SHA_OUTPUT, jobOutputsFor, jobOutputsProblems } from '../src/engine/job-rules.js';
import * as gateSettings from '../gate/src/settings.js';
import { renderGateStep, renderJobPrelude, type RenderedStep } from '../src/engine/render-step.js';
import { PIPEGEN_GATE_USES, rendererInputProblems } from '../src/engine/tool-flags.js';
import { gateEntry, platform } from './helpers/render.js';

const p = platform();
const prelude = (baseRef?: true): RenderedStep[] => renderJobPrelude(baseRef === undefined ? {} : { baseRef }, p).steps;
const WANT = '${{ steps.pipegen-checkout.outputs.commit }}';

describe('base-scan: the base-sha output (CF3b)', () => {
  it('the base checkout has the id pipegen-checkout; a plain checkout has none', () => {
    expect(BASE_CHECKOUT_ID).toBe('pipegen-checkout');
    expect(BASE_SHA_OUTPUT).toBe('base-sha');
    // the gate reads the same names (settings.ts keeps its own copy so the bundle does not pull in the engine's order rules)
    expect(gateSettings.BASE_SHA_OUTPUT).toBe(BASE_SHA_OUTPUT);
    expect(gateSettings.BASE_SCAN_JOB).toBe(BASE_SCAN_JOB);
    expect(prelude(true)[0]?.id).toBe('pipegen-checkout');
    expect(prelude()[0]?.id).toBeUndefined();
  });
  it('jobOutputsFor gives base-sha for a job holding the base checkout, and nothing for any other job', () => {
    expect(jobOutputsFor(prelude(true))).toEqual({ 'base-sha': WANT });
    expect(jobOutputsFor(prelude())).toEqual({});
  });
  it('jobOutputsProblems: base-sha only on the base-scan job, only in that exact form, only with its base checkout', () => {
    expect(jobOutputsProblems('base-scan', { 'base-sha': WANT }, prelude(true))).toEqual([]);
    expect(jobOutputsProblems('secrets', { 'base-sha': WANT }, prelude(true)).join(' ')).toMatch(/base-scan/);
    for (const v of ['${{ steps.pipegen-checkout.outputs.ref }}', '${{ github.sha }}', '${{ steps.other.outputs.commit }}', 'b'.repeat(40), `${WANT} `]) {
      expect(jobOutputsProblems('base-scan', { 'base-sha': v }, prelude(true)).length, v).toBeGreaterThan(0);
    }
    expect(jobOutputsProblems('base-scan', { 'base-sha': WANT }, prelude()).length).toBeGreaterThan(0);   // no base checkout in the job
    const renamed = prelude(true).map((s) => ({ ...s, id: 'other' }));
    expect(jobOutputsProblems('base-scan', { 'base-sha': '${{ steps.other.outputs.commit }}' }, renamed).length).toBeGreaterThan(0);
    // a second checkout carrying the id would be refused by the base-scan rules anyway; the output rule wants exactly one
    expect(jobOutputsProblems('base-scan', { 'base-sha': WANT }, [...prelude(true), ...prelude(true)]).length).toBeGreaterThan(0);
  });
});

describe('the gate step: service-roots', () => {
  it('RENDERER_INPUTS: service-roots a JSON list of plain relative folders (or "."), in mode gate only', () => {
    const ok = (v: string): string[] => rendererInputProblems(PIPEGEN_GATE_USES, { 'service-roots': v }, { mode: 'gate', 'service-roots': v });
    expect(ok('[]')).toEqual([]);
    expect(ok('[".", "apps/web", "services/api/"]')).toEqual([]);
    for (const v of ['x', '["../x"]', '["/x"]', '["a/*"]', '["-x"]', '[1]', '["a b"]', JSON.stringify(Array.from({ length: 101 }, (_, i) => `s${i}`))]) expect(ok(v).length, v).toBeGreaterThan(0);
    expect(rendererInputProblems(PIPEGEN_GATE_USES, { 'service-roots': '[]' }, { mode: 'scrub', 'service-roots': '[]' }).length).toBeGreaterThan(0);
  });
  it('renderGateStep writes it when given', () => {
    const s = renderGateStep(gateEntry(), [], { serviceRoots: ['apps/web', '.'] });
    expect(s.with?.['service-roots']).toBe('["apps/web","."]');
    expect(renderGateStep(gateEntry(), []).with?.['service-roots']).toBeUndefined();
  });
});
