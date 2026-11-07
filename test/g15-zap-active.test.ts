// G15a round 5 (b3): the reviewed AF plan of the nightly ZAP active scan (src/engine/zap-active.ts) is the plan the real reports were
// captured with (test/fixtures/zap/plans/af-active-capture.yaml), its target read from the container env, its policy ZAP's defaults.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { slotProblem } from '../src/engine/slots.js';
import { ZAP_ACTIVE_COMMAND, ZAP_ACTIVE_PLAN, ZAP_ACTIVE_POLICY, ZAP_ACTIVE_REPORT, ZAP_ACTIVE_TARGET_ENV } from '../src/engine/zap-active.js';

const CAPTURE = readFileSync(join(import.meta.dirname, 'fixtures', 'zap', 'plans', 'af-active-capture.yaml'), 'utf8');
type Job = { type: string; parameters?: Record<string, unknown>; policyDefinition?: Record<string, unknown> };

describe('zap-active: the reviewed AF plan', () => {
  it('zap-active: the plan is the captured plan with the target read from the container env (${PIPEGEN_ZAP_TARGET}), nothing else changed', () => {
    expect(ZAP_ACTIVE_TARGET_ENV).toBe('PIPEGEN_ZAP_TARGET');
    expect(ZAP_ACTIVE_PLAN).toBe(CAPTURE.replaceAll('http://<target>:8080', '${PIPEGEN_ZAP_TARGET}'));
    expect(ZAP_ACTIVE_PLAN).not.toContain('${{');
  });

  it('zap-active: spider, passive wait, active scan with ZAP\'s default policy (no rule changed), and the traditional-json report the gate reads, in that order', () => {
    const plan = parse(ZAP_ACTIVE_PLAN) as { env: { contexts: { name: string; urls: string[]; includePaths: string[] }[]; parameters: Record<string, unknown> }; jobs: Job[] };
    expect(plan.jobs.map((j) => j.type)).toEqual(['passiveScan-config', 'spider', 'passiveScan-wait', 'activeScan', 'report']);
    expect(plan.env.parameters).toEqual({ failOnError: true, failOnWarning: false, progressToStdout: true });
    expect(plan.env.contexts).toEqual([{ name: 'pipegen', urls: ['${PIPEGEN_ZAP_TARGET}'], includePaths: ['${PIPEGEN_ZAP_TARGET}.*'] }]);
    const active = plan.jobs[3] as Job;
    expect(active.policyDefinition).toEqual({ defaultStrength: ZAP_ACTIVE_POLICY.defaultStrength, defaultThreshold: ZAP_ACTIVE_POLICY.defaultThreshold });
    expect(ZAP_ACTIVE_POLICY).toMatchObject({ defaultStrength: 'medium', defaultThreshold: 'medium' });
    expect(active.parameters).toEqual({ context: 'pipegen', maxRuleDurationInMins: 5, maxScanDurationInMins: 30 });
    expect(plan.jobs[4]?.parameters).toMatchObject({ template: 'traditional-json', reportDir: '/zap/wrk', reportFile: ZAP_ACTIVE_REPORT });
    // nothing turns a rule off, filters an alert or runs a script
    expect(ZAP_ACTIVE_PLAN).not.toMatch(/rules:|alertFilter|script|threshold: off|strength: off|exclude/i);
  });

  it('zap-active: the command runs the plan by its absolute path (zap.sh reads a relative one from /zap), silent, with no UI', () => {
    expect([...ZAP_ACTIVE_COMMAND]).toEqual(['zap.sh', '-autorun', '/zap/wrk/zap-active.yaml', '-cmd', '-silent']);
    // round 6: the order the renderer writes (the pinned config flag first), measured on the pinned image
  });

  it('zap-active: every value the target env can hold is a local-url slot value, which can not break out of a quoted YAML string', () => {
    for (const ok of ['http://127.0.0.1:8080', 'http://localhost:3000/app/']) expect(slotProblem('local-url', ok)).toBeNull();
    for (const bad of ['http://127.0.0.1:8080/"\n  - x', 'http://127.0.0.1:8080/a b', 'http://evil.example:80', "http://127.0.0.1:1/'", 'http://127.0.0.1:1/${X}']) expect(slotProblem('local-url', bad), bad).not.toBeNull();
  });
});
