// v0.2 Plan G, sub-task G6 (plan Task 3, ruling B4; carries G1-R2 m5/m6, the G1 r1 husky minor, the secrets-hook gap; Plan J ruling G-J1):
// the pre-commit layer. pipegen appends its reviewed local hooks to the repository's own hook manager (pre-commit, husky, lefthook; lefthook
// set up new when there is none), byte for byte after the user's text, and records the exact inserted text. A hook runs only a reviewed,
// pinned command: the secrets hook is pipegen itself at its exact version, which runs its pinned gitleaks on the staged changes.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { guardCreatedFiles, gitBlobSha, type BaseTree } from '../src/create/guard.js';
import { HOOK_FILES, hookCommands, hookFile, hookFileMode, huskyAppendProblem, SECRETS_HOOK_ID, secretsHookRun } from '../src/engine/created-builders.js';
import { createdFileProblems, CREATED_RULES } from '../src/engine/created-files.js';
import { existingSecretsHook } from '../src/audit/hook-credit.js';
import { precommitFiles, SETUP_COMMANDS } from '../src/layers/precommit.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { CreatedFile, Need, PipelineDraft, ReviewedTool, Service } from '../src/types.js';
import { packageVersion } from '../src/util/package-data.js';
import { draftOf, jobsOf, prof, run, show, workflow } from './helpers/gate-pipeline.js';
import { entry, reviewedList, specFor } from './helpers/render.js';

const made: string[] = [];
afterEach(() => { for (const x of made.splice(0)) rmSync(x, { recursive: true, force: true }); });
function repo(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-precommit-'));
  made.push(dir);
  for (const [p, t] of Object.entries(files)) { mkdirSync(join(dir, dirname(p)), { recursive: true }); writeFileSync(join(dir, p), t); }
  return dir;
}
const base = (files: Record<string, string> = {}): BaseTree => ({ complete: true, entries: new Map(Object.entries(files).map(([p, t]) => [p, { sha: gitBlobSha(t), mode: '100644', read: async () => t }])) });

const VERSION = packageVersion() as string;
const BIOME = entry('biome');
const BIOME_VERSION = BIOME.step.cli?.install.version as string;
const need = (id: string, service?: string): Need => ({ id, layer: 'pre-commit', category: id, ...(service === undefined ? {} : { service }), why: 't', blocking: id !== 'format-lint', floor: true });
/** The root service with @biomejs/biome installed (from its lockfile) at `version`; null: not installed. */
const withBiome = (version: string | null, fromRange = false): Service[] => prof.services.map((s, i) => (i !== 0 ? s : {
  ...s, quality: { ...emptyServiceQuality(), versions: version === null ? {} : { '@biomejs/biome': version }, fromRange: fromRange ? ['@biomejs/biome'] : [] },
}));
/** The floor's pre-commit needs (hooks, secrets, the root service's format-lint), the biome step, and biome installed at its reviewed version. */
function hookDraft(precommit: PipelineDraft['profile']['precommit'], over: Partial<PipelineDraft> = {}, biome: string | null = BIOME_VERSION): PipelineDraft {
  const d = draftOf();
  return draftOf({
    profile: { ...prof, precommit, services: withBiome(biome) },
    needs: [...d.needs, need('hooks'), need('secrets'), need('format-lint', 'app')],
    steps: [...d.steps, specFor(BIOME, { needId: 'format-lint', service: 'app' })],
    ...over,
  });
}
const judge = (f: CreatedFile, draft: PipelineDraft, reviewed: readonly ReviewedTool[] = reviewedList()): string[] => createdFileProblems(f, draft, CREATED_RULES, { reviewed, inputs: {} }).problems;
const SCAN_HOOK_RUN = `npx --yes --prefix=/ --registry=https://registry.npmjs.org pipegen@${VERSION} hook secrets`;
const BIOME_RUN = `npx --no --package=@biomejs/biome@${BIOME_VERSION} -- biome check --staged --no-errors-on-unmatched --vcs-enabled=true --vcs-client-kind=git`;

const PRE_COMMIT = 'repos:\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: 2c9f875913ee60ca25ce70243dc24d5b6415598c   # v6.0.0\n    hooks:\n      - id: trailing-whitespace\n';
const LEFTHOOK = 'commit-msg:\n  commands:\n    lint:\n      run: npx --no -- commitlint --edit {1}\n';
const HUSKY = 'npm test\n';

describe('G6: the pre-commit layer (plan Task 3, B4)', () => {
  it('precommit: existing config gets hooks appended, existing untouched, edit recorded', async () => {
    for (const [manager, original] of [['pre-commit', PRE_COMMIT], ['lefthook', LEFTHOOK], ['husky', HUSKY]] as const) {
      const path = HOOK_FILES[manager];
      const dir = repo({ [path]: original });
      const r = await precommitFiles(hookDraft(manager), reviewedList(), dir);
      expect(r.files.map((f) => f.path), manager).toEqual([path]);
      const f = r.files[0] as CreatedFile;
      expect(f.content.startsWith(original), manager).toBe(true);
      expect(f).toMatchObject({ part: 'precommit', repo: 'app', edited: { original } });
      expect(f.needsConfirm).toBeUndefined();
      const inserted = f.content.slice(original.length);
      expect(inserted).toContain('pipegen:hooks');
      expect(inserted).toContain(SCAN_HOOK_RUN);
      expect(inserted).toContain(BIOME_RUN);
      // the edit: exactly the inserted bytes, the original's blob sha and the sha pipegen writes (InstallEdit kind 'hooks')
      expect(r.edits).toEqual([{ repo: 'app', path, kind: 'hooks', inserted, originalSha: gitBlobSha(original), writtenShas: [gitBlobSha(f.content)] }]);
    }
    // the pre-commit data: the user's repos unchanged, then pipegen's local repo with the secrets hook first
    const r = await precommitFiles(hookDraft('pre-commit'), reviewedList(), repo({ [HOOK_FILES['pre-commit']]: PRE_COMMIT }));
    const data = parse((r.files[0] as CreatedFile).content) as { repos: { repo: string; hooks: { id: string; entry: string }[] }[] };
    expect(data.repos[0]).toEqual(parse(PRE_COMMIT).repos[0]);
    expect(data.repos[1]?.repo).toBe('local');
    expect(data.repos[1]?.hooks.map((h) => [h.id, h.entry])).toEqual([[SECRETS_HOOK_ID, SCAN_HOOK_RUN], ['pipegen-biome', BIOME_RUN]]);
    // no hook manager: lefthook set up new (original ''), its edit recorded with no original sha
    const fresh = await precommitFiles(hookDraft(null), reviewedList(), repo());
    expect(fresh.files.map((f) => [f.path, f.edited?.original])).toEqual([['lefthook.yml', '']]);
    expect(fresh.edits[0]).toMatchObject({ path: 'lefthook.yml', kind: 'hooks', originalSha: null, inserted: (fresh.files[0] as CreatedFile).content });
  });

  it('precommit: husky project appends lines only', async () => {
    const r = await precommitFiles(hookDraft('husky'), reviewedList(), repo({ [HOOK_FILES.husky]: HUSKY }));
    const f = r.files[0] as CreatedFile;
    const added = f.content.slice(HUSKY.length).split('\n').filter((l) => l !== '');
    // plain shell lines: pipegen's marker comments and the reviewed commands, nothing else
    expect(added).toEqual(['# pipegen:hooks begin: pipegen\'s reviewed hooks; the install record holds this text', `${SCAN_HOOK_RUN} || exit 1`, `${BIOME_RUN} || exit 1`, '# pipegen:hooks end']);
    expect(f.content.slice(0, HUSKY.length)).toBe(HUSKY);
    // a husky project without a pre-commit hook yet: a new script with a shebang (m5), written executable
    const fresh = await precommitFiles(hookDraft('husky'), reviewedList(), repo({ '.husky/commit-msg': 'npx commitlint --edit "$1"\n' }));
    const nf = fresh.files[0] as CreatedFile;
    expect(nf.edited?.original).toBe('');
    expect(nf.content.startsWith('#!/usr/bin/env sh\n# pipegen:hooks begin')).toBe(true);
    expect(judge(nf, hookDraft('husky'))).toEqual([]);
    expect(hookFileMode(HOOK_FILES.husky)).toBe('100755');
    for (const p of [HOOK_FILES['pre-commit'], HOOK_FILES.lefthook, '.husky/pre-push', 'x/.husky/pre-commit']) expect(hookFileMode(p), p).toBeNull();
    // a husky original that sources, evals or returns gets no append, only a note (G1 r1 minor), like exit and exec
    for (const original of ['. "$(dirname -- "$0")/_/husky.sh"\nnpm test\n', 'source ./env.sh\nnpm test\n', 'eval "exit 0"\n', 'npm test\nreturn 0\n', 'npm test && . ./x.sh\n', 'if true; then . ./x.sh; fi\n', '{ . ./x.sh; }\n',
      // G6-R2 I1: a trap or errexit turned off; M1: quoted and escaped forms, command/builtin, a command word from a variable, an npx of its own
      "trap 'exit 0' EXIT\nnpm test\n", 'trap cleanup EXIT\nnpm test\n', 'set +e\nnpm test\n', 'set -u +e\n', 'set +o errexit\n', '"exit" 0\n', "'exit' 0\n", 'e"x"it 0\n', 'ex\\it 0\n', '"." ./x\n', '\\. ./x\n',
      'command . ./x\n', 'builtin source ./x\n', '${x}it 0\n', '$CMD\n', 'npx() { :; }\n', 'function npx { :; }\n', "alias npx='true'\n", 'echo "source of truth"\n', "echo 'eval me'\n",
      // G6-R3 N3: no-exec mode, a dangling `||` that would swallow pipegen's first line, a hashed npx
      'set -n\n', 'set -o noexec\n', 'set -euxn\n', 'set -nu\n', 'npm test && set -n\n', 'set -o  noexec\nnpm test\n', 'set -eo noexec\n',
      'npm test ||\n', 'npm test || # later\n', 'npm test ||   \n', 'npm test ||\t# x\n',
      'hash -p /bin/true npx\n', 'hash npx\n', 'hash -r npx\n']) {
      expect(huskyAppendProblem(original), JSON.stringify(original)).not.toBeNull();
      const res = await precommitFiles(hookDraft('husky'), reviewedList(), repo({ [HOOK_FILES.husky]: original }));
      expect(res.files, JSON.stringify(original)).toEqual([]);
      expect(res.edits).toEqual([]);
      expect(res.notes.join('\n'), JSON.stringify(original)).toMatch(/can not add its hooks to \.husky\/pre-commit safely/);
    }
    // a dot or the word inside a string, a comment, or as an argument is no command
    for (const original of ['npx biome check .\n', '# . ./x.sh\nnpm test\n', 'ls ./src\n', 'x=$(date)\nnpm test "$x"\n', 'set -e\nnpm test\n', 'set -eu\nnpm test\n', 'npm test || npm run fix\n', 'echo set -n\n', '# set -n\nnpm test\n', 'hash -r\nnpm test\n', 'npm run lint -- --no-cache\n']) {
      expect(huskyAppendProblem(original), JSON.stringify(original)).toBeNull();
    }
  });

  it('precommit: no remote hook repo is added; hook commands are reviewed pinned commands', async () => {
    // (replaces the plan's `precommit: revs are commit shas`: ruling B4 adds no hook repo, so no rev at all)
    const r = await precommitFiles(hookDraft('pre-commit'), reviewedList(), repo({ [HOOK_FILES['pre-commit']]: PRE_COMMIT }));
    const inserted = r.edits[0]?.kind === 'hooks' ? r.edits[0].inserted : '';
    expect(inserted).not.toMatch(/^\s*(?:-\s+)?rev\s*:/m);
    expect(inserted.match(/^\s*-?\s*repo:\s*(.*)$/gm)?.map((l) => l.trim())).toEqual(['- repo: local']);
    // every hook command is one of the reviewed forms: pipegen at its own exact version from npm's registry, or a reviewed npm tool at its reviewed version
    const cmds = hookCommands(hookDraft('pre-commit'), reviewedList());
    expect(cmds).toEqual([{ id: SECRETS_HOOK_ID, run: SCAN_HOOK_RUN }, { id: 'pipegen-biome', run: BIOME_RUN }]);
    expect(secretsHookRun(VERSION)).toBe(SCAN_HOOK_RUN);
    // no exact pipegen version: no secrets hook is written (the builder refuses rather than run whatever owns the name today)
    for (const v of [null, '', 'latest', '^1.2.3', '1.2', '1.2.3 && x']) expect(() => secretsHookRun(v), String(v)).toThrow(/exact version/);
    // the secrets hook needs the reviewed gitleaks entry (the pinned binary it runs); without it, no secrets hook
    expect(hookCommands(hookDraft('pre-commit'), reviewedList().filter((t) => t.id !== 'gitleaks')).map((c) => c.id)).toEqual(['pipegen-biome']);
    // a judge given a hook with another pipegen version, an unpinned pipegen or another registry: refused
    const f = r.files[0] as CreatedFile;
    for (const bad of [SCAN_HOOK_RUN.replace(`@${VERSION}`, '@9.9.9'), SCAN_HOOK_RUN.replace(`@${VERSION}`, ''), SCAN_HOOK_RUN.replace('registry.npmjs.org', 'registry.example.com'), SCAN_HOOK_RUN.replace('--yes', '--no')]) {
      expect(judge({ ...f, content: f.content.replace(SCAN_HOOK_RUN, bad) }, hookDraft('pre-commit')), bad).not.toEqual([]);
    }
  });

  it('precommit: revs are commit shas', async () => {
    // B4: nothing is fetched by rev, so no rev is written; the pins are the exact versions in the commands (pipegen's and the npm tool's)
    for (const manager of ['pre-commit', 'lefthook', 'husky'] as const) {
      const original = { 'pre-commit': PRE_COMMIT, lefthook: LEFTHOOK, husky: HUSKY }[manager];
      const r = await precommitFiles(hookDraft(manager), reviewedList(), repo({ [HOOK_FILES[manager]]: original }));
      const inserted = r.edits[0]?.kind === 'hooks' ? r.edits[0].inserted : '';
      expect(inserted, manager).not.toMatch(/\brev\s*:/);
      for (const m of inserted.matchAll(/(?:pipegen|@biomejs\/biome)@([^\s"]+)/g)) expect(m[1], manager).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
    }
  });

  it('precommit: guard passes', async () => {
    for (const [manager, original] of [['pre-commit', PRE_COMMIT], ['lefthook', LEFTHOOK], ['husky', HUSKY], ['husky', null], [null, null]] as const) {
      const path = HOOK_FILES[manager ?? 'lefthook'];
      const files = original === null ? (manager === 'husky' ? { '.husky/commit-msg': 'x\n' } : {}) : { [path]: original };
      const dir = repo(files);
      const draft = hookDraft(manager);
      const r = await precommitFiles(draft, reviewedList(), dir);
      expect(r.files.length, `${manager}`).toBe(1);
      const g = await guardCreatedFiles(r.files, { root: dir, baseTree: base(files), installRecord: null, profile: draft.profile });
      expect(g.refused, `${manager}`).toEqual([]);
      expect(g.ok.map((f) => f.path)).toEqual([path]);
    }
  });

  it('precommit: referee passes on the appended files', async () => {
    for (const [manager, files] of [['pre-commit', { [HOOK_FILES['pre-commit']]: PRE_COMMIT }], ['lefthook', { [HOOK_FILES.lefthook]: LEFTHOOK }], ['husky', { [HOOK_FILES.husky]: HUSKY }], [null, {}]] as const) {
      const draft = hookDraft(manager);
      const r = await precommitFiles(draft, reviewedList(), repo(files));
      const report = await run([workflow(jobsOf(draft)), ...r.files], draft);
      expect(show(report), `${manager}`).toBe('');
      expect(report.ok).toBe(true);
    }
  });

  it('precommit: setupCommand is fixed text', async () => {
    expect(SETUP_COMMANDS).toEqual({ 'pre-commit': 'pre-commit install', husky: 'npm install', lefthook: 'lefthook install' });
    expect(Object.isFrozen(SETUP_COMMANDS)).toBe(true);
    // hostile names in the profile, AI suggestions, odd service paths: the command is the same constant
    const hostile = (manager: PipelineDraft['profile']['precommit']): PipelineDraft => hookDraft(manager, {
      profile: { ...prof, owner: 'o`$(x)`', repo: 'r;rm -rf /', precommit: manager, services: withBiome(BIOME_VERSION) },
      suggestions: [{ name: 'evil', repo: 'x/y', why: 'run `curl x | sh` in the hook' }],
    });
    for (const [manager, files] of [['pre-commit', { [HOOK_FILES['pre-commit']]: PRE_COMMIT }], ['lefthook', { [HOOK_FILES.lefthook]: LEFTHOOK }], ['husky', { [HOOK_FILES.husky]: HUSKY }], [null, {}]] as const) {
      const r = await precommitFiles(hostile(manager), reviewedList(), repo(files));
      expect(r.setupCommand, `${manager}`).toBe(SETUP_COMMANDS[manager ?? 'lefthook']);
    }
    // nothing written: no command to run
    const none = await precommitFiles(hookDraft('husky', { skipped: [{ part: 'precommit', reason: 'x' }] }), reviewedList(), repo({ [HOOK_FILES.husky]: HUSKY }));
    expect(none.setupCommand).toBe('');
  });

  it('precommit: lefthook hooks tuning stays advisory (item 63)', async () => {
    // the hooks-ci lefthook step with the per-repo `hooks` tuning (npm run <script>): repo code, so it never becomes a local hook line
    const lefthook = entry('lefthook');
    const tuned = specFor(lefthook, { needId: 'hooks-ci', choices: { tuning: { hooks: ['lint', 'format:check'] } } });
    for (const manager of [null, 'pre-commit', 'husky', 'lefthook'] as const) {
      const files = manager === null ? {} : { [HOOK_FILES[manager]]: { 'pre-commit': PRE_COMMIT, lefthook: LEFTHOOK, husky: HUSKY }[manager] };
      const d = hookDraft(manager);
      const r = await precommitFiles({ ...d, steps: [...d.steps, tuned] }, reviewedList(), repo(files));
      const text = r.files.map((f) => f.content).join('\n');
      expect(text, `${manager}`).not.toMatch(/npm run/);
      expect(r.notes.join('\n'), `${manager}`).toMatch(/advisory/);
      expect(r.notes.join('\n')).toMatch(/lint, format:check/);
    }
    // without the tuning: no such note
    const plain = await precommitFiles(hookDraft(null), reviewedList(), repo());
    expect(plain.notes.join('\n')).not.toMatch(/advisory/);
  });
});

describe('G6: carries (G1-R2 m5, m6; secrets hook; Plan J G-J1)', () => {
  it('precommit: the floor decides the hooks: the secrets hook always, format and lint only when a need asks for it', async () => {
    const d = hookDraft(null);
    const noFormat = { ...d, needs: d.needs.filter((n) => n.id !== 'format-lint') };
    expect(hookCommands(noFormat, reviewedList()).map((c) => c.id)).toEqual([SECRETS_HOOK_ID]);
    const r = await precommitFiles(noFormat, reviewedList(), repo());
    expect((r.files[0] as CreatedFile).content).toContain(SCAN_HOOK_RUN);
    expect((r.files[0] as CreatedFile).content).not.toContain('biome');
    // the secrets hook comes from the pre-commit secrets need (the floor's), never from another layer's
    const withoutScanNeed = { ...d, needs: d.needs.filter((n) => !(n.layer === 'pre-commit' && n.id === 'secrets')) };
    expect(hookCommands(withoutScanNeed, reviewedList()).map((c) => c.id)).toEqual(['pipegen-biome']);
  });

  it('precommit: the biome hook only with @biomejs/biome installed at the reviewed version; else no hook and a note', async () => {
    for (const [version, fromRange] of [[null, false], ['0.0.1', false], [BIOME_VERSION, true]] as const) {
      const d = hookDraft('husky', {}, null);
      const draft = { ...d, profile: { ...d.profile, services: withBiome(version, fromRange) } };
      expect(hookCommands(draft, reviewedList()).map((c) => c.id), `${version}`).toEqual([SECRETS_HOOK_ID]);
      const r = await precommitFiles(draft, reviewedList(), repo({ [HOOK_FILES.husky]: HUSKY }));
      expect((r.files[0] as CreatedFile).content).not.toContain('biome');
      expect(r.notes.join('\n'), `${version}`).toMatch(new RegExp(`@biomejs/biome@${BIOME_VERSION.replace(/\./g, '\\.')}`));
    }
    // m6: biome's --staged reads git through its VCS integration, so the hook turns it on with the reviewed flags
    expect(BIOME_RUN).toMatch(/--staged .*--vcs-enabled=true --vcs-client-kind=git$/);
  });

  it('precommit: an existing secrets hook gets no second one, with a note', async () => {
    // G6-R3 (H1): credited only as the canonical remote gitleaks hook: the official repo, a pinned rev, id gitleaks, no
    // entry, language or args of the user's, pass_filenames not true, at the commit stage (stages, else default_stages)
    const withGitleaks = `${PRE_COMMIT}  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.30.1\n    hooks:\n      - id: gitleaks\n`;
    const hookWith = (extra: string) => withGitleaks.replace('      - id: gitleaks\n', `      - id: gitleaks\n${extra}`);
    const credited = [
      withGitleaks,
      withGitleaks.replace('v8.30.1', 'v10.0.0'),
      withGitleaks.replace('https://github.com/gitleaks/gitleaks', 'https://github.com/gitleaks/gitleaks.git'),
      withGitleaks.replace('https://github.com/gitleaks/gitleaks', 'https://github.com/zricethezav/gitleaks'),
      hookWith('        name: scan for keys\n        verbose: true\n        pass_filenames: false\n'),
      hookWith('        stages: [pre-commit, pre-push]\n'),
      hookWith('        stages: [commit]\n'),
      hookWith('        stages: []\n'),
      `default_stages: [pre-commit]\n${hookWith('        stages: []\n')}`,
    ];
    for (const original of credited) {
      expect(existingSecretsHook('pre-commit', original), original).toBe(true);
      const draft = hookDraft('pre-commit');
      const r = await precommitFiles(draft, reviewedList(), repo({ [HOOK_FILES['pre-commit']]: original }));
      const f = r.files[0] as CreatedFile;
      expect(f.content, original).not.toContain('hook secrets');
      expect(f.content, original).toContain(BIOME_RUN);
      expect(r.notes.join('\n'), original).toMatch(/already scans for secrets/);
      expect(judge(f, draft), original).toEqual([]);
    }
    const local = (body: string) => `${PRE_COMMIT}  - repo: local\n    hooks:\n      - id: gitleaks\n        name: gitleaks\n        language: system\n${body}`;
    const notCredited: [PipelineDraft['profile']['precommit'], string][] = [
      ['lefthook', 'pre-push:\n  commands:\n    scan:\n      run: trufflehog git file://. --since-commit HEAD --fail\n'],
      ['pre-commit', hookWith('        stages: [manual]\n')],
      // G6-R-sec2: the remote hook's language or entry overridden, so it never runs the scan the signature expects
      ['pre-commit', hookWith('        language: fail\n')],
      ['pre-commit', hookWith('        language: system\n')],
      ['pre-commit', hookWith('        entry: "true"\n')],
      ['pre-commit', hookWith('        entry: gitleaks git --pre-commit --staged\n')],
      ['pre-commit', `default_stages: [pre-commit, pre-push]\n${hookWith('        stages: [pre-push]\n')}`],
      ['pre-commit', hookWith('        exclude: ^docs/\n')],
      ['pre-commit', `exclude: ^\\.gitleaks\\.toml$\n${withGitleaks}`],
      // review H1 a: any args of the user's (pre-commit runs shlex.split(entry) + args, no shell: `#` is no comment)
      ['pre-commit', hookWith('        args: ["#", "--exit-code=0"]\n')],
      ['pre-commit', hookWith('        args: [--exit-code=0]\n')],
      ['pre-commit', hookWith('        args: [--verbose]\n')],
      // review H1 b: pass_filenames true makes gitleaks read a one-file commit's file name as its repo path
      ['pre-commit', hookWith('        pass_filenames: true\n')],
      // not the canonical hook: another id, no pinned rev, a fork, a key pipegen doesn't read
      ['pre-commit', withGitleaks.replace('id: gitleaks', 'id: gitleaks-docker')],
      ['pre-commit', withGitleaks.replace('id: gitleaks', 'id: gitleaks-system')],
      ['pre-commit', withGitleaks.replace('    rev: v8.30.1\n', '')],
      ['pre-commit', withGitleaks.replace('v8.30.1', 'master')],
      ['pre-commit', withGitleaks.replace('v8.30.1', 'v7.6.1')],
      ['pre-commit', withGitleaks.replace('v8.30.1', 'v8.30')],
      // G6-R-sec3: a bare commit sha may be a fork-network commit reachable through the upstream URL, never released: no credit
      ['pre-commit', withGitleaks.replace('v8.30.1', '83d9cd684c87d95d656c1458ef04895a7f1cbd8e')],
      ['pre-commit', withGitleaks.replace('v8.30.1', '83d9cd684c87d95d656c1458ef04895a7f1cbd8e  # v8.30.1')],
      ['pre-commit', withGitleaks.replace('github.com/gitleaks/gitleaks', 'github.com/someone/gitleaks')],
      ['pre-commit', hookWith('        additional_dependencies: [x]\n')],
      ['pre-commit', hookWith('        stages: pre-commit\n')],
      ['pre-commit', `default_install_hook_types: [pre-push]\n${withGitleaks}`],
      // review H1 a/b/c: a local hook is never credited, whatever its entry
      ['pre-commit', local('        entry: "gitleaks protect\\nexit 0"\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: true && gitleaks git --pre-commit --staged\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: echo && gitleaks git --pre-commit --staged\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: "true\\ngitleaks git --pre-commit --redact --staged"\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: "gitleaks git --pre-commit --redact --staged\\n--exit-code=0"\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: gitleaks git --pre-commit --redact --staged # --exit-code=0\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: |\n          gitleaks git --pre-commit --redact --staged\n          --exit-code 0\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: gitleaks git --pre-commit --redact --staged --verbose\n')],
      ['pre-commit', local('        entry: gitleaks protect\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: gitleaks git\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: gitleaks detect\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: gitleaks git --pre-commit\n        pass_filenames: false\n')],
      ['pre-commit', local('        entry: gitleaks git --pre-commit --redact --staged\n        pass_filenames: false\n')],
      // husky and lefthook are never credited (N1: git may run .husky/pre-commit without -e)
      ['husky', 'gitleaks git --pre-commit --redact --staged\n'],
      ['husky', '#!/bin/sh\ngitleaks protect --staged\nnpx lint-staged\n'],
      ['husky', 'npx gitleaks detect\n'], ['husky', 'gitleaks protect\n'], ['husky', 'gitleaks git --pre-commit\n'],
      ['husky', 'trufflehog git file://. --since-commit HEAD --fail\n'],
      ['husky', 'gitleaks version\nnpm test\n'], ['husky', 'detect-secrets scan > .secrets.baseline\n'], ['husky', 'gitleaks git --staged || true\n'],
      ['husky', 'npm test # gitleaks runs in CI\n'], ['husky', 'echo "TODO: add gitleaks"\n'], ['husky', '# TODO: gitleaks\nnpm test\n'],
    ];
    for (const [manager, original] of notCredited) {
      const m = manager ?? 'lefthook';
      expect(existingSecretsHook(m, original), original).toBe(false);
      // run through the builder: the secrets line stays (or the file is refused with its own note), never "already scans"
      const r = await precommitFiles(hookDraft(manager), reviewedList(), repo({ [HOOK_FILES[m]]: original }));
      expect(r.notes.join('\n'), original).not.toMatch(/already scans/);
      if (r.files.length > 0) expect(r.files.map((f) => f.content).join(''), original).toContain(SCAN_HOOK_RUN);
      else expect(r.notes.length, original).toBeGreaterThan(0);
    }
    // only the pre-commit framework reads that config: the same text as a husky or lefthook file is no scan
    for (const m of ['husky', 'lefthook'] as const) expect(existingSecretsHook(m, withGitleaks), m).toBe(false);
    // N2: an empty `stages` falls back to default_stages, as pre-commit reads it (an empty default_stages runs nowhere)
    for (const ds of ['[pre-push]', '[]']) expect(existingSecretsHook('pre-commit', `default_stages: ${ds}\n${hookWith('        stages: []\n')}`), ds).toBe(false);
    // only a secrets hook to add and the repo has one: no file at all, and the one true reason (spec I3)
    const d = hookDraft('pre-commit');
    const onlyScanHook = { ...d, needs: d.needs.filter((n) => n.id !== 'format-lint') };
    const r = await precommitFiles(onlyScanHook, reviewedList(), repo({ [HOOK_FILES['pre-commit']]: withGitleaks }));
    expect(r.files).toEqual([]);
    expect(r.notes).toEqual(['Your .pre-commit-config.yaml already scans for secrets at commit, so pipegen adds no secrets hook of its own there.']);
    // no gitleaks entry in the reviewed list: a note says the local secrets hook is not added
    const noGitleaks = await precommitFiles(hookDraft('husky'), reviewedList().filter((t) => t.id !== 'gitleaks'), repo({ [HOOK_FILES.husky]: HUSKY }));
    expect(noGitleaks.notes.join('\n')).toMatch(/no gitleaks entry/);
  });

  it('precommit: a pre-commit config whose default_stages leave out commit gets no append, a note (M3)', async () => {
    for (const ds of ['[pre-push]', '[manual]', '[]', 'pre-commit']) {
      const r = await precommitFiles(hookDraft('pre-commit'), reviewedList(), repo({ [HOOK_FILES['pre-commit']]: `default_stages: ${ds}\n${PRE_COMMIT}` }));
      expect(r.files, ds).toEqual([]);
      expect(r.notes.join('\n'), ds).toMatch(/default_stages/);
    }
    for (const ds of ['[pre-commit]', '[commit, pre-push]']) {
      const r = await precommitFiles(hookDraft('pre-commit'), reviewedList(), repo({ [HOOK_FILES['pre-commit']]: `default_stages: ${ds}\n${PRE_COMMIT}` }));
      expect(r.files.length, ds).toBe(1);
    }
  });

  it('precommit: the husky block stops at a failed hook under plain sh, with or without -e (I1)', async () => {
    const bin = mkdtempSync(join(tmpdir(), 'pipegen-fake-npx-'));
    made.push(bin);
    const log = join(bin, 'log');
    // a fake npx: the secrets hook fails, biome passes, each call logged
    writeFileSync(join(bin, 'npx'), `#!/bin/sh\necho "$*" >> "${log}"\ncase "$*" in *"hook secrets"*) exit 1 ;; esac\nexit 0\n`, { mode: 0o755 });
    for (const original of [null, HUSKY]) {
      const dir = repo(original === null ? { '.husky/commit-msg': 'x\n' } : { [HOOK_FILES.husky]: original });
      const r = await precommitFiles(hookDraft('husky'), reviewedList(), dir);
      const script = join(dir, 'built-pre-commit');
      writeFileSync(script, (r.files[0] as CreatedFile).content.replace('npm test', 'true'), { mode: 0o755 });
      for (const sh of [['sh', script], ['sh', '-e', script]]) {
        rmSync(log, { force: true });
        const res = spawnSync(sh[0] as string, sh.slice(1), { env: { PATH: `${bin}:/usr/bin:/bin` }, encoding: 'utf8' });
        expect(res.status, `${sh.join(' ')} ${String(original)}`).not.toBe(0);
        // the commands after the failed one never ran
        expect(readFileSync(log, 'utf8').trim().split('\n')).toEqual([expect.stringContaining('hook secrets')]);
      }
    }
  });

  it('precommit: the secrets hook reads no repository package and no project .npmrc (I3, --prefix=/)', async () => {
    const dir = repo({
      'package.json': '{"name":"app","version":"1.0.0"}\n',
      'node_modules/pipegen/package.json': `{"name":"pipegen","version":"${VERSION}","bin":{"pipegen":"cli.js"}}\n`,
      'node_modules/pipegen/cli.js': `#!/usr/bin/env node\nrequire('fs').writeFileSync(${JSON.stringify('LOCAL_MARK')}, 'local');\n`,
      '.npmrc': `node-options=--require=${'./evil.cjs'}\n`,
      'evil.cjs': "require('fs').writeFileSync('NPMRC_MARK', 'npmrc');\n",
    });
    mkdirSync(join(dir, 'node_modules', '.bin'), { recursive: true });
    symlinkSync('../pipegen/cli.js', join(dir, 'node_modules', '.bin', 'pipegen'));
    chmodSync(join(dir, 'node_modules', 'pipegen', 'cli.js'), 0o755);
    const words = secretsHookRun(VERSION).split(' ');
    // offline (no network in tests): npx can only fail; it must not run the local package or load the .npmrc's node-options on the way
    const cache = mkdtempSync(join(tmpdir(), 'pipegen-npm-cache-'));
    made.push(cache);
    const res = spawnSync(words[0] as string, words.slice(1), { cwd: dir, env: { PATH: process.env.PATH, HOME: process.env.HOME, npm_config_offline: 'true', npm_config_cache: cache }, encoding: 'utf8', timeout: 120_000 });
    expect(res.status).not.toBe(0);
    expect(existsSync(join(dir, 'LOCAL_MARK'))).toBe(false);
    expect(existsSync(join(dir, 'NPMRC_MARK'))).toBe(false);
  }, 150_000);

  it('precommit: the hooks sit where hooks-ci runs them (pre-commit run --all-files, lefthook run pre-commit --all-files)', async () => {
    const pc = await precommitFiles(hookDraft('pre-commit'), reviewedList(), repo({ [HOOK_FILES['pre-commit']]: PRE_COMMIT }));
    const local = (parse((pc.files[0] as CreatedFile).content) as { repos: { repo: string; hooks: Record<string, unknown>[] }[] }).repos.find((x) => x.repo === 'local');
    // no stages limit (the default pre-commit stage runs them, in CI too), every hook always runs
    for (const h of local?.hooks ?? []) { expect(h.stages).toBeUndefined(); expect(h.always_run).toBe(true); expect(h.language).toBe('system'); }
    const lh = await precommitFiles(hookDraft(null), reviewedList(), repo());
    const data = parse((lh.files[0] as CreatedFile).content) as Record<string, { commands: Record<string, { run: string }> }>;
    expect(Object.keys(data)).toEqual(['pre-commit']);
    expect(Object.values(data['pre-commit']?.commands ?? {}).map((c) => c.run)).toEqual([SCAN_HOOK_RUN, BIOME_RUN]);
    // husky has no CI command (J's chooser): the note says the hooks run on the developer's machine only
    const hk = await precommitFiles(hookDraft('husky'), reviewedList(), repo({ [HOOK_FILES.husky]: HUSKY }));
    expect(hk.notes.join('\n')).toMatch(/husky.*CI/);
  });

  it('precommit: a skipped part, another hook manager, a missing or linked config: no file, a note', async () => {
    const cases: [string, PipelineDraft, Record<string, string>, RegExp][] = [
      ['skipped', hookDraft('husky', { skipped: [{ part: 'precommit', reason: 'x' }] }), { [HOOK_FILES.husky]: HUSKY }, /skipped/],
      ['other manager', hookDraft(null, { profile: { ...prof, precommit: null, otherHookManagers: ['simple-git-hooks'], services: withBiome(BIOME_VERSION) } }), {}, /another hook manager/],
      ['pre-commit config elsewhere', hookDraft('pre-commit'), { '.pre-commit-config.yml': PRE_COMMIT }, /\.pre-commit-config\.yaml/],
      ['lefthook config elsewhere', hookDraft('lefthook'), { '.lefthook.yml': LEFTHOOK }, /lefthook\.yml/],
      ['re-run', hookDraft('husky'), { [HOOK_FILES.husky]: `${HUSKY}# pipegen:hooks begin: x\n# pipegen:hooks end\n` }, /no second time/],
    ];
    for (const [name, draft, files, re] of cases) {
      const r = await precommitFiles(draft, reviewedList(), repo(files));
      expect(r.files, name).toEqual([]);
      expect(r.edits, name).toEqual([]);
      expect(r.notes.join('\n'), name).toMatch(re);
    }
    // a hook file that is a symbolic link is never read or written through
    const dir = repo({ 'elsewhere.yaml': PRE_COMMIT });
    symlinkSync(join(dir, 'elsewhere.yaml'), join(dir, HOOK_FILES['pre-commit']));
    const r = await precommitFiles(hookDraft('pre-commit'), reviewedList(), dir);
    expect(r.files).toEqual([]);
    expect(r.notes.join('\n')).toMatch(/symbolic link|could not read/);
  });
});
