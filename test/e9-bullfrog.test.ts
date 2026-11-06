// E9 (ruling B5, carry E3-R1): Bullfrog reads `allowed-domains` as literal host names, one per line. The reviewed entry offers LABELS
// (github-core, npm, …) as its choices, and before E9 the bundled policy accepted exactly one label as the value, which Bullfrog would
// read as a host named "npm" (every real host blocked). Now:
// - the labels stay the choice names, and the three E3-R1 exact-host sets are labels too (github-releases, trivy-db, osv);
// - the value a workflow carries is the sorted, de-duplicated, newline-joined union of whole reviewed sets, github-core always among
//   them (tool-flags.ts allowedDomainsProblem: one rule for the renderer, the referee and the proof workflow check);
// - a raw domain, a part of a set, an unsorted or repeated list, a list without github-core: a problem.
// Written first.
import { describe, expect, it } from 'vitest';
import { E3_EGRESS_SETS, G15_EGRESS_SETS, EGRESS_DOMAIN_SETS, REVIEWED_EGRESS_LABELS, renderEgressStep } from '../src/engine/egress.js';
import { renderStep } from '../src/engine/render-step.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import { ACTION_POLICIES, allowedDomainsProblem, egressDomains } from '../src/engine/tool-flags.js';
import { ctxFor, entry, platform, service, specFor } from './helpers/render.js';

// (G15a: the Sigstore set of the keyless verify job is the ninth)
const LABELS = ['github-core', 'npm', 'pypi', 'dockerhub', 'ghcr', 'github-releases', 'trivy-db', 'osv', 'sigstore'];
const union = (...sets: (keyof typeof EGRESS_DOMAIN_SETS)[]): string => [...new Set(sets.flatMap((s) => EGRESS_DOMAIN_SETS[s]))].sort().join('\n');

describe('E9: the bullfrog allowed-domains policy', () => {
  it('bullfrog policy: allowed-domains = union of reviewed sets; a raw domain → problem', () => {
    // every union of whole sets that holds github-core passes, in the renderer's own form
    expect(allowedDomainsProblem(union('github-core'), LABELS)).toBeNull();
    expect(allowedDomainsProblem(union('github-core', 'npm', 'dockerhub'), LABELS)).toBeNull();
    expect(allowedDomainsProblem(union(...LABELS as (keyof typeof EGRESS_DOMAIN_SETS)[]), LABELS)).toBeNull();
    for (const l of LABELS) expect(allowedDomainsProblem(union('github-core', l as keyof typeof EGRESS_DOMAIN_SETS), LABELS), l).toBeNull();
    expect(egressDomains(['npm', 'github-core', 'npm'])).toBe(union('github-core', 'npm'));
    // a raw domain, alone or added to a good list
    expect(allowedDomainsProblem('example.com', LABELS)).toMatch(/example\.com/);
    expect(allowedDomainsProblem(`${union('github-core', 'npm')}\nexample.com`.split('\n').sort().join('\n'), LABELS)).toMatch(/example\.com/);
    // a label as the value (the old form: Bullfrog would read it as a host)
    expect(allowedDomainsProblem('npm', LABELS)).not.toBeNull();
    // part of a set (one Docker Hub host without the others), unsorted, repeated, empty lines, no github-core
    expect(allowedDomainsProblem([...EGRESS_DOMAIN_SETS['github-core'], 'auth.docker.io'].sort().join('\n'), LABELS)).toMatch(/whole/);
    expect(allowedDomainsProblem(union('github-core', 'npm').split('\n').reverse().join('\n'), LABELS)).toMatch(/sorted/);
    expect(allowedDomainsProblem(`${union('github-core')}\n${EGRESS_DOMAIN_SETS['github-core'].at(-1)}`, LABELS)).toMatch(/sorted/);
    expect(allowedDomainsProblem(`${union('github-core')}\n`, LABELS)).not.toBeNull();
    expect(allowedDomainsProblem(union('npm'), LABELS)).toMatch(/github-core/);
    expect(allowedDomainsProblem('', LABELS)).not.toBeNull();
    // only the labels the entry offers: a set it does not offer is not allowed
    expect(allowedDomainsProblem(union('github-core', 'osv'), ['github-core', 'npm'])).toMatch(/no reviewed egress set offered/);
    // github-core is always among the offered sets, even when the entry's labels leave it out (mutant B4)
    expect(allowedDomainsProblem(union('github-core', 'npm'), ['npm'])).toBeNull();
    expect(allowedDomainsProblem(union('github-core', 'npm'), ['github-core', 'npm', 'not-a-set'])).toMatch(/not-a-set/);
  });

  it('the labels are the choice names: the policy and the reviewed entry offer all eight, the E3-R1 sets included', () => {
    expect([...ACTION_POLICIES['bullfrogsec/bullfrog']!['allowed-domains']!.values].sort()).toEqual([...LABELS].sort());
    const t = loadReviewed().find((e) => e.id === 'bullfrog')!;
    expect([...t.choices['allowed-domains']!].sort()).toEqual([...LABELS].sort());
    expect([...REVIEWED_EGRESS_LABELS, ...E3_EGRESS_SETS, ...G15_EGRESS_SETS].sort()).toEqual([...LABELS].sort());
    expect(Object.keys(EGRESS_DOMAIN_SETS).sort()).toEqual([...LABELS].sort());
  });

  it('renderEgressStep\'s value passes the policy; renderStep of the bullfrog entry writes the union for the chosen label, never the label', () => {
    for (const sets of [[], ['npm'], ['dockerhub', 'npm'], ['github-releases', 'trivy-db', 'ghcr'], ['osv']] as const) {
      const v = renderEgressStep([...sets], { dockerNetworks: false }).with?.['allowed-domains'] as string;
      expect(allowedDomainsProblem(v, LABELS), sets.join(',')).toBeNull();
    }
    const ctx = ctxFor([service({ name: 'app', path: '.' })]);
    const t = entry('bullfrog');
    const step = renderStep(specFor(t, { needId: 'egress', choices: { 'allowed-domains': 'npm' } }), t, platform(), ctx).steps.find((s) => s.uses?.startsWith('bullfrogsec/bullfrog@'));
    expect(step?.with?.['allowed-domains']).toBe(union('github-core', 'npm'));
  });
});
