import { afterAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ACTION_EGRESS, E3_EGRESS_SETS, EGRESS_DOMAIN_SETS, G15_EGRESS_SETS, egressSetsForTool, renderEgressCheckStep, renderEgressStep, REVIEWED_EGRESS_LABELS, type EgressSet } from '../src/engine/egress.js';
import { RenderError } from '../src/engine/render-error.js';
import { stepsToYaml } from '../src/engine/render-step.js';
import { Document, parse } from 'yaml';
import { loadReviewed } from '../src/engine/reviewed.js';

const bullfrog = () => loadReviewed().find((t) => t.id === 'bullfrog')!;
const lines = (s: ReturnType<typeof renderEgressStep>) => (s.with?.['allowed-domains'] ?? '').split('\n');
const HOST_RE = /^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/;

describe('egress', () => {
  it('egress: sets github-core, npm, pypi, dockerhub (with production.cloudfront.docker.com and the R2 host), ghcr', () => {
    // the five reviewed choices, plus the E3-R1 exact-host sets (since E9 all eight are the bullfrog choices)
    // G15a: plus the mode-scoped Sigstore set (test/g15-sigstore.test.ts) and gh's attestation set (test/g15-attest-verify.test.ts)
    expect(Object.keys(EGRESS_DOMAIN_SETS).sort()).toEqual(['dockerhub', 'ghcr', 'github-attest', 'github-core', 'github-releases', 'npm', 'osv', 'pypi', 'sigstore', 'trivy-db']);
    expect([...REVIEWED_EGRESS_LABELS, ...E3_EGRESS_SETS, ...G15_EGRESS_SETS].sort()).toEqual([...bullfrog().choices['allowed-domains']!].sort());
    expect([...E3_EGRESS_SETS].sort()).toEqual(['github-releases', 'osv', 'trivy-db']);
    expect([...REVIEWED_EGRESS_LABELS, ...E3_EGRESS_SETS, ...G15_EGRESS_SETS].sort()).toEqual(Object.keys(EGRESS_DOMAIN_SETS).sort());
    const s = EGRESS_DOMAIN_SETS;
    expect(s['github-core']).toEqual(expect.arrayContaining(['github.com', 'api.github.com', 'codeload.github.com', 'objects.githubusercontent.com']));
    expect(s.npm).toEqual(['registry.npmjs.org']);
    expect([...s.pypi].sort()).toEqual(['files.pythonhosted.org', 'pypi.org']);
    expect(s.dockerhub).toEqual(expect.arrayContaining(['registry-1.docker.io', 'auth.docker.io', 'production.cloudfront.docker.com', 'production.cloudflare.docker.com',
      'docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com']));
    expect([...s.ghcr].sort()).toEqual(['ghcr.io', 'pkg-containers.githubusercontent.com']);
    for (const hosts of Object.values(s)) for (const h of hosts) expect(h, h).toMatch(HOST_RE);
    for (const h of Object.values(s).flat()) expect(h).toBe(h.toLowerCase());
    expect(Object.isFrozen(s)).toBe(true);
    for (const hosts of Object.values(s)) expect(Object.isFrozen(hosts)).toBe(true);
  });

  it('egress: renderEgressStep renders the union one per line, sorted, deduped, bullfrog pin and fixed inputs', () => {
    const t = bullfrog();
    const step = renderEgressStep(['pypi', 'npm', 'npm', 'github-core'], { dockerNetworks: false });
    expect(step.uses).toBe(t.step.action!.uses);
    expect(step.usesComment).toBe(t.candidate.version);
    expect(step.with).toMatchObject(t.fixedInputs.with!);
    const hosts = lines(step);
    expect(hosts).toEqual([...new Set(hosts)].sort());
    expect(hosts).toEqual([...new Set([...EGRESS_DOMAIN_SETS['github-core'], ...EGRESS_DOMAIN_SETS.npm, ...EGRESS_DOMAIN_SETS.pypi])].sort());
    expect(step.with!['allowed-domains']).not.toMatch(/\n$/);
    expect(Object.keys(step.with!).sort()).toEqual([...Object.keys(t.fixedInputs.with!), 'allowed-domains'].sort());
    expect(Object.keys(renderEgressStep(['npm'], { dockerNetworks: true }).with!).sort()).toEqual([...Object.keys(t.fixedInputs.with!), 'allowed-domains', 'allowed-ips'].sort());
    expect(hosts).not.toContain('npm');
  });

  it('github-core is always included, and an empty list renders github-core only', () => {
    expect(lines(renderEgressStep([], { dockerNetworks: false }))).toEqual([...EGRESS_DOMAIN_SETS['github-core']].sort());
    expect(lines(renderEgressStep(['ghcr'], { dockerNetworks: false }))).toEqual(expect.arrayContaining(['github.com', 'ghcr.io']));
  });

  it('egress: allowed-ips 172.16.0.0/12 only with services or docker networks', () => {
    expect(renderEgressStep(['npm'], { dockerNetworks: true }).with!['allowed-ips']).toBe('172.16.0.0/12');
    const off = renderEgressStep(['npm'], { dockerNetworks: false });
    expect(Object.hasOwn(off.with!, 'allowed-ips')).toBe(false);
  });

  it('egress: an unknown set or a raw domain → RenderError', () => {
    for (const bad of ['docker', 'example.com', 'github.com', '*.npmjs.org', '', 'toString', '__proto__', 'constructor']) {
      expect(() => renderEgressStep([bad as EgressSet], { dockerNetworks: false }), bad).toThrow(RenderError);
    }
    expect(() => renderEgressStep([{} as unknown as EgressSet], { dockerNetworks: false })).toThrow(RenderError);
    expect(() => renderEgressStep('npm' as unknown as EgressSet[], { dockerNetworks: false })).toThrow(RenderError);
    for (const bad of ['true', 1, undefined, null, 0]) {
      expect(() => renderEgressStep(['npm'], { dockerNetworks: bad as unknown as boolean }), String(bad)).toThrow(RenderError);
    }
    expect(() => renderEgressStep(['npm'], undefined as never)).toThrow(RenderError);
  });

  it('egress: the rendered YAML parses back to the exact host list', () => {
    const step = renderEgressStep(['dockerhub', 'ghcr', 'npm', 'pypi'], { dockerNetworks: true });
    const doc = new Document();
    doc.contents = stepsToYaml([step, renderEgressCheckStep()]);
    const back = parse(doc.toString()) as { with: Record<string, string>; uses: string; run?: string }[];
    expect(back[0]!.with['allowed-domains'].split('\n')).toEqual(lines(step));
    expect(back[0]!.with).toEqual(step.with);
    expect(back[0]!.uses).toBe(step.uses);
    expect(back[1]!.run).toBe(renderEgressCheckStep().run);
  });

  it('egress (E3-R1): new exact-host sets github-releases, trivy-db and osv, no wildcard', () => {
    expect([...EGRESS_DOMAIN_SETS['github-releases']]).toEqual(['release-assets.githubusercontent.com']);
    expect([...EGRESS_DOMAIN_SETS['trivy-db']]).toEqual(['mirror.gcr.io']);
    expect([...EGRESS_DOMAIN_SETS.osv]).toEqual(['api.osv.dev']);
    for (const h of Object.values(EGRESS_DOMAIN_SETS).flat()) expect(h).not.toMatch(/[*?\s/:]/);
    // a host is in one set only (a set is the unit a job asks for)
    const all = Object.values(EGRESS_DOMAIN_SETS).flat();
    expect(new Set(all).size).toBe(all.length);
    const step = renderEgressStep(['trivy-db', 'osv', 'github-releases'], { dockerNetworks: false });
    expect(lines(step)).toEqual([...new Set([...EGRESS_DOMAIN_SETS['github-core'], 'mirror.gcr.io', 'api.osv.dev', 'release-assets.githubusercontent.com'])].sort());
  });

  it('egress (E3-R1): egressSetsForTool lists exactly the sets a reviewed tool needs', () => {
    const list = loadReviewed();
    const of = (id: string) => egressSetsForTool(list.find((t) => t.id === id)!);
    expect(of('trivy-image')).toEqual(['ghcr', 'github-releases', 'trivy-db']);
    expect(of('trivy-config')).toEqual(['github-releases']);   // --skip-check-update: no checks bundle download
    expect(of('trivy-licence')).toEqual(['github-releases']);
    expect(of('osv-scanner')).toEqual(['github-releases', 'osv']);
    expect(of('cosign')).toEqual(['github-releases']);
    expect(of('semgrep')).toEqual(['dockerhub']);                // the rules come from github.com (github-core, always on)
    expect(of('zap-baseline')).toEqual(['dockerhub']);
    expect(of('vitest-coverage')).toEqual(['npm']);
    expect(of('biome')).toEqual(['npm']);
    expect(of('schemathesis')).toEqual(['pypi']);
    expect(of('registry')).toEqual(['dockerhub']);
    expect(of('actions-checkout')).toEqual([]);                  // github.com only (github-core, always on)
    expect(of('bullfrog')).toEqual([]);                          // it downloads its agent before the block is on
    expect(of('docker-setup-buildx-action')).toEqual(['dockerhub']);   // the docker-container driver pulls moby/buildkit (M1)
    expect(of('scorecard-action')).toEqual(['osv']);
    // every reviewed entry maps without throwing, to known set names only, sorted and unique
    for (const t of list) {
      const sets = egressSetsForTool(t);
      expect(sets, t.id).toEqual([...new Set(sets)].sort());
      for (const s of sets) expect(Object.hasOwn(EGRESS_DOMAIN_SETS, s), `${t.id} ${s}`).toBe(true);
    }
  });

  it('egress (M1): every reviewed action has an explicit entry with its source; unverified ones are visible, unknown ones refused', () => {
    const list = loadReviewed();
    const actions = list.filter((t) => t.step.action !== undefined).map((t) => t.id).sort();
    expect(Object.keys(ACTION_EGRESS).sort()).toEqual(actions);
    for (const id of actions) {
      const e = ACTION_EGRESS[id]!;
      expect(e.source.length, id).toBeGreaterThan(10);
      expect(typeof e.verified, id).toBe('boolean');
      if (!e.verified) expect(e.liveCheck, id).toMatch(/\S/);
    }
    // the unverified list is what the live checklist must confirm (test-visible, never a silent empty list)
    expect(actions.filter((id) => !ACTION_EGRESS[id]!.verified).sort()).toEqual([
      'actions-attest', 'actions-download-artifact', 'actions-setup-node', 'actions-setup-python', 'actions-upload-artifact',
      'docker-build-push-action', 'docker-setup-buildx-action', 'pipegen-gate', 'pypi-publish', 'scorecard-action',
    ]);
    // an action the table doesn't know is refused, never mapped to nothing
    const odd = structuredClone(list.find((t) => t.id === 'actions-checkout')!);
    odd.id = 'some-new-action';
    expect(() => egressSetsForTool(odd)).toThrow(RenderError);
  });

  it('egress (E3-R1): egressSetsForTool reads the image registry; an unknown install method or image is refused', () => {
    const list = loadReviewed();
    const semgrep = structuredClone(list.find((t) => t.id === 'semgrep')!);
    semgrep.step.cli!.install.package = 'ghcr.io/semgrep/semgrep';
    expect(egressSetsForTool(semgrep)).toEqual(['ghcr']);
    semgrep.step.cli!.install.package = 'quay.io/semgrep/semgrep';
    expect(() => egressSetsForTool(semgrep)).toThrow(RenderError);
    const odd = structuredClone(list.find((t) => t.id === 'cosign')!);
    (odd.step.cli!.install as { method: string }).method = 'curl';
    expect(() => egressSetsForTool(odd)).toThrow(RenderError);
  });

  it('egress: the actions.githubusercontent.com hosts are not listed (least privilege; live checklist decides)', () => {
    for (const h of Object.values(EGRESS_DOMAIN_SETS).flat()) expect(h).not.toMatch(/actions\.githubusercontent\.com$/);
  });

  it('renderEgressStep does not mutate the table and has no expression opener', () => {
    const before = JSON.stringify(EGRESS_DOMAIN_SETS);
    const step = renderEgressStep(['dockerhub', 'ghcr'], { dockerNetworks: true });
    expect(JSON.stringify(EGRESS_DOMAIN_SETS)).toBe(before);
    expect(JSON.stringify(step)).not.toContain('${{');
  });
});

describe('egress-check step', () => {
  const step = renderEgressCheckStep();
  const dirs: string[] = [];
  afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
  /** Runs the step's script in bash -e with PATH = a dir holding only bash and a fake curl (no real curl, no network).
   *  The fake exits `a` for the example.com probe and `b` for any other (the raw IP), and logs argv and proxy env. */
  const run = (curl: { a: number; b: number } | null, env: Record<string, string> = {}) => {
    const dir = mkdtempSync(join(tmpdir(), 'egress-'));
    dirs.push(dir);
    if (curl !== null) {
      writeFileSync(join(dir, 'curl'), `#!${join(dir, 'bash')}\necho "$*|\${HTTPS_PROXY-unset}|\${https_proxy-unset}|\${ALL_PROXY-unset}" >> ${dir}/log\ncase "$*" in *example.com*) exit ${curl.a};; *) exit ${curl.b};; esac\n`);
      chmodSync(join(dir, 'curl'), 0o755);
    }
    symlinkSync(spawnSync('which', ['bash']).stdout.toString().trim(), join(dir, 'bash'));
    const r = spawnSync(join(dir, 'bash'), ['-e', '-c', step.run!], { env: { PATH: dir, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const log = existsSync(join(dir, 'log')) ? readFileSync(join(dir, 'log'), 'utf8').trim().split('\n') : [];
    return { status: r.status, out: r.stdout + r.stderr, log };
  };

  it('is a fixed run step: curl --max-time 10 to https://example.com', () => {
    expect(step.run).toContain('--max-time 10');
    expect(step.run).toContain('https://example.com');
    expect(step.run).toContain('https://1.1.1.1');
    expect(step.run).toContain('::error::');
    expect(step.uses).toBeUndefined();
    expect(step.shell).toBe('bash');
    expect(renderEgressCheckStep()).toEqual(step);
  });
  it('egress: check passes only for curl exits 6, 7, 28 on the name and 7, 28 on the raw IP', () => {
    for (const rc of [6, 7, 28]) expect(run({ a: rc, b: 7 }).status, `name ${rc}`).toBe(0);
    for (const rc of [7, 28]) expect(run({ a: 7, b: rc }).status, `ip ${rc}`).toBe(0);
  });
  it('egress: check fails with ::error:: when the name or the IP answers (exit 0)', () => {
    for (const c of [{ a: 0, b: 7 }, { a: 7, b: 0 }, { a: 0, b: 0 }]) {
      const r = run(c);
      expect(r.status).toBe(1);
      expect(r.out).toMatch(/::error::egress is open/);
    }
  });
  it('egress: check fails with ::error:: naming the code for every other curl exit', () => {
    for (const rc of [35, 52, 56, 92, 5, 60, 77, 1, 22, 127]) {
      for (const c of [{ a: rc, b: 7 }, { a: 7, b: rc }]) {
        const r = run(c);
        expect(r.status, `${rc}`).toBe(1);
        expect(r.out).toMatch(new RegExp(`::error::.*exit ${rc}\\b`));
      }
    }
    // 6 (DNS) means nothing for a raw IP: not a pass there
    expect(run({ a: 7, b: 6 }).status).toBe(1);
  });
  it('fails when curl is missing (no silent pass)', () => {
    const r = run(null);
    expect(r.status).not.toBe(0);
    expect(r.out).toMatch(/::error::.*curl is missing/);
  });
  it('egress: a curl shell function from BASH_ENV is ignored; the PATH curl runs', () => {
    const dir = mkdtempSync(join(tmpdir(), 'egress-env-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'env.sh'), 'curl() { return 7; }\nexport -f curl\n');
    // the fake PATH curl answers 0 (open): if the function stood in, the step would pass
    const r = run({ a: 0, b: 0 }, { BASH_ENV: join(dir, 'env.sh') });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/::error::egress is open/);
    expect(r.log.length).toBeGreaterThan(0);
  });
  it('egress: curl runs with -q first, --noproxy, and the proxy variables unset', () => {
    const r = run({ a: 7, b: 7 }, { HTTPS_PROXY: 'http://p:1', https_proxy: 'http://p:1', ALL_PROXY: 'http://p:1' });
    expect(r.status).toBe(0);
    expect(r.log).toHaveLength(2);
    for (const line of r.log) {
      expect(line).toMatch(/^-q /);
      expect(line).toContain("--noproxy *");
      expect(line).toContain('--max-time 10');
      expect(line).toMatch(/\|unset\|unset\|unset$/);
    }
  });
});
