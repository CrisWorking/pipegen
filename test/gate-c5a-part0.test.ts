// Plan C Task C5a, Part 0: the C4 re-review carry-forwards (review-C4-r2.md CF1 to CF4). Written first.
//  - CF1: trivy loads trivy-secret.yaml from its working folder by default; the pinned config sets `secret.config: ""`, which loads none
//    (checked live against the pinned trivy 0.76.0 when PIPEGEN_LIVE_TRIVY names its binary), and the name is a root config file.
//  - CF2: an added or renamed file whose extension is a letter-case variant of a scanned language's extension is an integrity finding.
//  - CF3: serviceRoots (effectiveProtectedPaths) and codeowners (readPrContext) are required (type-level, checked by tsc).
//  - CF4: INI `k = ""` keeps its quotes (Python's RawConfigParser); a TOML integer and a float of the same value differ.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import type { GateGithub } from '../gate/src/baseline.js';
import { integrityFindings, parseConfigDoc, readConfigSections, readPrContext, type PrContext, type PrFile } from '../gate/src/integrity.js';
import { effectiveProtectedPaths } from '../src/engine/reviewed.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { reviewedList } from './helpers/render.js';

const TRIVY_IDS = ['trivy-config', 'trivy-image', 'trivy-licence'] as const;
const SHA = (c: string): string => c.repeat(40);
const HEAD = SHA('a');
const BASE = SHA('b');
const REPO = { owner: 'acme', name: 'app', id: 7 };
const PATCH = '@@ -0,0 +1 @@\n+module.exports = 1';
const file = (filename: string, over: Partial<PrFile> = {}): PrFile => ({ filename, status: 'added', changes: 1, patch: PATCH, ...over });
const ctx = (files: PrFile[], over: Partial<PrContext> = {}): PrContext => ({
  number: 5, headSha: HEAD, baseSha: BASE, isFork: false, files, filesComplete: true, approvals: [], approvalsComplete: true, problems: [], ...over,
});

describe('CF1: trivy never loads a repo trivy-secret.yaml', () => {
  it('data: every trivy entry pins secret.config to "" in its --config file (entry and policy alike), and lists trivy-secret.yaml as a root config file', () => {
    const list = reviewedList();
    for (const id of TRIVY_IDS) {
      const t = list.find((e) => e.id === id);
      const content = t?.fixedInputs.config?.content ?? '';
      expect(content, id).toBe(ARGV_POLICIES[id]?.config?.content);
      const doc = parse(content) as Record<string, Record<string, unknown>>;
      expect(Object.keys(doc).sort(), id).toEqual(['cache', 'secret']);
      expect(doc.cache, id).toEqual({ backend: 'memory' });
      expect(Object.entries(doc.secret ?? {}), id).toEqual([['config', '']]);   // an empty path: trivy loads no secret config at all
      expect(t?.fixedInputs.config?.passAs, id).toEqual({ flag: '--config' });
      expect(t?.rootConfigFiles, id).toContain('trivy-secret.yaml');
      expect(t?.reviewedBy, id).toBe('Claude delegated DECISIONS 105');
      expect(t?.reviewedAt, id).toBe(id === 'trivy-licence' ? '2026-11-06' : '2026-10-30');   // G15a G11-2: the licence scan's JSON form
    }
  });

  it('protected: trivy-secret.yaml at the root and at each service root, not in other folders (root scope)', () => {
    const paths = effectiveProtectedPaths(reviewedList(), ['services/api']);
    expect(paths).toContain('/trivy-secret.yaml');
    expect(paths).toContain('/services/api/trivy-secret.yaml');
    const prot = (p: string): boolean => integrityFindings(ctx([file(p, { status: 'modified' })]), paths, []).some((f) => f.ruleId === 'integrity:protected-path');
    expect(prot('trivy-secret.yaml')).toBe(true);
    expect(prot('services/api/trivy-secret.yaml')).toBe(true);
    expect(prot('TRIVY-SECRET.YAML')).toBe(true);
    expect(prot('docs/trivy-secret.yaml')).toBe(false);
  });

  const bin = process.env.PIPEGEN_LIVE_TRIVY;
  it.skipIf(bin === undefined || bin === '')('live (pinned trivy 0.76.0): a trivy-secret.yaml in the working folder hides a secret without the pin, and is ignored with it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pg-trivy-secret-'));
    const repo = join(dir, 'repo');
    mkdirSync(repo);
    // a fake AWS key id, built at run time so no secret-shaped text sits in the repository
    writeFileSync(join(repo, 'app.py'), `${['aws', 'access', 'key', 'id'].join('_')} = "${['AKIA', 'ZZ', 'QQQQ', '3333', 'XXXXXX'].join('')}"\n`);
    writeFileSync(join(repo, 'trivy-secret.yaml'), 'disable-rules:\n  - aws-access-key-id\n');
    const run = (config: string): string[] => {
      const cfg = join(dir, `cfg-${Math.random().toString(16).slice(2)}.yaml`);
      writeFileSync(cfg, config);
      const out = execFileSync(bin as string, ['fs', '--disable-telemetry', '--skip-version-check', '--skip-check-update', '--config', cfg, '--scanners', 'secret', '--format', 'json', '--quiet', '.'], { cwd: repo, encoding: 'utf8' });
      const doc = JSON.parse(out) as { Results?: { Secrets?: { RuleID: string }[] }[] };
      return (doc.Results ?? []).flatMap((r) => (r.Secrets ?? []).map((s) => s.RuleID));
    };
    expect(run("# the old pinned config\ncache:\n  backend: memory\n")).toEqual([]);   // the control: the repo file silenced the rule
    expect(run(ARGV_POLICIES['trivy-image']?.config?.content as string)).toEqual(['aws-access-key-id']);
  });
});

describe('CF2: an extension in another letter case hides a file from the scanners', () => {
  const find = (files: PrFile[], approvals: string[] = []) => integrityFindings(ctx(files, { approvals }), [], [{ pattern: '*', owners: ['olga'] }]);
  it('an added, renamed or copied file with .JS, .Ts, .PY, … is integrity:case-extension (high); the plain spelling is not', () => {
    for (const name of ['src/B.JS', 'src/c.Js', 'lib/x.TS', 'app/m.Py', 'web/v.VUE', 'k8s/deploy.YAML', 'cmd/main.GO', 'a/b.TSX', 'a/b.MJS']) {
      const f = find([file(name)]);
      expect(f.map((x) => x.ruleId), name).toEqual(['integrity:case-extension']);
      expect(f[0]?.severity, name).toBe('high');
      expect(f[0]?.file, name).toBe(name);
      expect(f[0]?.message, name).not.toContain(name.slice(name.lastIndexOf('.')));   // a fixed text: never the repository's own name
    }
    expect(find([file('src/a.JS', { status: 'renamed', previous_filename: 'src/a.js' })]).map((x) => x.ruleId)).toEqual(['integrity:case-extension']);
    expect(find([file('src/b.JS', { status: 'copied', previous_filename: 'src/b.js' })]).map((x) => x.ruleId)).toEqual(['integrity:case-extension']);
    for (const name of ['src/a.js', 'README.MD', 'img/LOGO.PNG', 'Makefile', 'docs/x.TXT', 'src/.JS']) expect(find([file(name)]), name).toEqual([]);
  });
  it('a modified or removed file is not (only a new name can be chosen to hide); a code owner approval on the head waives it', () => {
    expect(find([file('src/B.JS', { status: 'modified' })])).toEqual([]);
    expect(find([file('src/B.JS', { status: 'removed', changes: 1 })])).toEqual([]);
    expect(find([file('src/B.JS')], ['olga'])).toEqual([]);
    expect(find([file('src/B.JS')], ['mallory']).map((x) => x.ruleId)).toEqual(['integrity:case-extension']);
  });
});

describe('CF3: the parameters that were silently optional are required', () => {
  it('effectiveProtectedPaths needs serviceRoots and readPrContext needs codeowners (tsc checks the two ts-expect-error lines)', async () => {
    // @ts-expect-error serviceRoots is required: the default [] silently dropped the service-root copies of root-scoped names
    expect(() => effectiveProtectedPaths([])).toThrow();   // and a list missing at run time is loud, never a silent []
    const gh = {
      getPull: async () => ({ number: 5, head: { sha: HEAD, repo: { id: 7 } }, base: { sha: BASE }, changed_files: 0, user: { login: 'author' } }),
      listPullFiles: async () => [], listPullReviews: async () => [{ id: 1, user: { login: 'eve' }, state: 'APPROVED', commit_id: HEAD }],
      collaboratorPermission: async () => ({ permission: 'admin' }),
    } as unknown as GateGithub;
    // @ts-expect-error codeowners is required: without it no approver was filtered by CODEOWNERS (the approver flood)
    const pr = await readPrContext(gh, REPO, 5, {});
    expect(pr.approvals).toEqual([]);   // a missing list at run time counts as none: nobody is an owner
    expect((await readPrContext(gh, REPO, 5, { codeowners: [{ pattern: '*', owners: ['eve'] }] })).approvals).toEqual(['eve']);
  });
});

describe('CF4: parser parity minors', () => {
  it('INI: k = "" keeps the two quote characters, as Python 3.12 RawConfigParser does ({"k": "\\"\\"", "j": ""})', () => {
    expect(parseConfigDoc('setup.cfg', '[s]\nk = ""\nj =\n')).toEqual({ s: { k: '""', j: '' } });
  });
  const changes = async (path: string, spec: string, base: string, head: string): Promise<unknown[]> => {
    const b64 = (t: string): unknown => ({ type: 'file', encoding: 'base64', size: Buffer.byteLength(t), content: Buffer.from(t).toString('base64') });
    const gh = { fileAt: async (_o: string, _n: string, _p: string, ref: string) => b64(ref === BASE ? base : head) } as unknown as GateGithub;
    return readConfigSections(gh, REPO, ctx([file(path, { status: 'modified' })]), [spec], []);
  };
  it('INI: k = "" to k = (empty) is a change of the watched section', async () => {
    expect(await changes('setup.cfg', 'setup.cfg:mypy', '[mypy]\nk = ""\n', '[mypy]\nk =\n')).toEqual([{ file: 'setup.cfg', section: 'mypy' }]);
  });
  it('TOML: 1 and 1.0 differ (the type is kept); equal integers stay equal; a 64-bit integer parses instead of failing closed', async () => {
    expect(await changes('pyproject.toml', 'pyproject.toml:tool.mypy', '[tool.mypy]\nx = 1\n', '[tool.mypy]\nx = 1.0\n')).toEqual([{ file: 'pyproject.toml', section: 'tool.mypy' }]);
    expect(await changes('pyproject.toml', 'pyproject.toml:tool.mypy', '[tool.mypy]\nx = 1\n', '[tool.mypy]\nx = 0x1\n')).toEqual([]);
    expect(await changes('pyproject.toml', 'pyproject.toml:tool.mypy', '[tool.mypy]\nx = 9223372036854775807\n', '[tool.mypy]\nx = 9223372036854775807\n')).toEqual([]);
    expect(parseConfigDoc('pyproject.toml', 'x = 9223372036854775807\n')).toBeDefined();
  });
});
