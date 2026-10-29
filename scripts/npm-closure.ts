// Generates pipegen's npm closure locks (Plan B 6b fix round 1, DECISIONS #107). USES THE NETWORK; run it by hand.
//
// A checker tool whose verdict the gate trusts (biome, eslint, oxlint, prettier, knip) is never installed from the
// repo's lockfile (any PR author can change that). Instead each one has a complete npm lockfile v3 in
// data/npm-closures/<entry-id>.json for a minimal package.json that depends on exactly the pinned tool, its pinned
// plugins and, where a plugin peers on it, one pinned `typescript`. The renderer installs from that file into a fresh
// folder under runner temp.
//
//   node scripts/npm-closure.ts [--only id,id] [--before <ISO date>]
//
// For each entry it runs, in an empty temp dir with empty user and global npmrc files:
//   npm install --package-lock-only --ignore-scripts --no-audit --no-fund --before=<date 7 days ago>
//       --registry=https://registry.npmjs.org/ --userconfig <empty> --globalconfig <empty>
// then checks that the top-level versions and integrities equal the reviewed entry's (it fails otherwise) and writes
// the lock plus `<id>.meta.json` (`generatedAt`, `before`, npm version). The strict validation of the files is code
// (src/engine/npm-closure.ts, run by the loader and by a test over every file); scripts/cooldown.ts re-checks that
// every package in a changed closure was published before its `before` date and that its integrity is the registry's.
// Keep to syntax Node's type stripping can run: `node scripts/npm-closure.ts`.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parse } from 'yaml';

/**
 * The entries that get a closure (the "checker" class: they only read code), with the extra pinned dependencies a
 * plugin peers on. `typescript` is the newest 6.0.x (typescript-eslint and knip accept `>=4.8.4 <6.1.0`): type-aware
 * checks use pipegen's TypeScript, not the repo's. A test pins this list to the argv policies in tool-flags.ts.
 */
export const CLOSURES: Readonly<Record<string, { extra?: Readonly<Record<string, string>> }>> = {
  biome: {},
  eslint: {},
  'eslint-typescript': { extra: { typescript: '6.0.3' } },
  'oxlint-typeaware': {},
  prettier: {},
  knip: { extra: { typescript: '6.0.3' } },
};

const DAY_MS = 86_400_000;
const REGISTRY = 'https://registry.npmjs.org/';

interface Dep { name: string; version: string; integrity?: string }

function arg(argv: string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
}

function depsOf(entry: Record<string, unknown>, extra: Readonly<Record<string, string>>): Dep[] {
  const step = entry.step as { cli: { install: { package: string; version: string }; plugins?: { package: string; version: string; checksum: string }[] } };
  const candidate = entry.candidate as { pin: { checksum: string } };
  return [
    { name: step.cli.install.package, version: step.cli.install.version, integrity: candidate.pin.checksum },
    ...(step.cli.plugins ?? []).map((p) => ({ name: p.package, version: p.version, integrity: p.checksum })),
    ...Object.entries(extra).map(([name, version]) => ({ name, version })),
  ];
}

function makeClosure(id: string, deps: Dep[], before: string, outDir: string): void {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-closure-'));
  try {
    // two files: npm refuses to load one file as both the user and the global config
    const userrc = join(dir, 'user.npmrc');
    const globalrc = join(dir, 'global.npmrc');
    writeFileSync(userrc, '');
    writeFileSync(globalrc, '');
    const home = join(dir, 'home');
    mkdirSync(home);
    const work = join(dir, 'work');
    mkdirSync(work);
    const pkg = { name: 'pipegen-closure', version: '0.0.0', private: true, dependencies: Object.fromEntries(deps.map((d) => [d.name, d.version])) };
    writeFileSync(join(work, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
    const args = ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', `--before=${before}`, `--registry=${REGISTRY}`, '--userconfig', userrc, '--globalconfig', globalrc];
    const r = spawnSync('npm', args, { cwd: work, env: { PATH: process.env.PATH ?? '', HOME: home }, encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`npm failed for ${id}: ${(r.stderr || r.stdout).slice(0, 600)}`);
    const lock = JSON.parse(readFileSync(join(work, 'package-lock.json'), 'utf8')) as { lockfileVersion: number; packages: Record<string, { version?: string; integrity?: string }> };
    if (lock.lockfileVersion !== 3) throw new Error(`${id}: npm wrote lockfileVersion ${lock.lockfileVersion}, not 3`);
    for (const d of deps) {
      const p = lock.packages[`node_modules/${d.name}`];
      if (p?.version !== d.version) throw new Error(`${id}: ${d.name} is ${p?.version ?? 'missing'} in the closure, not the pinned ${d.version}`);
      if (d.integrity !== undefined && p.integrity !== d.integrity) throw new Error(`${id}: ${d.name} ${d.version} has a different integrity in the closure than in the reviewed entry`);
    }
    const npmVersion = spawnSync('npm', ['--version'], { env: { PATH: process.env.PATH ?? '', HOME: home }, encoding: 'utf8' }).stdout.trim();
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, `${id}.json`), `${JSON.stringify(lock, null, 2)}\n`);
    writeFileSync(join(outDir, `${id}.meta.json`), `${JSON.stringify({ generatedAt: new Date().toISOString(), before, npm: npmVersion }, null, 2)}\n`);
    console.log(`${id}: ${Object.keys(lock.packages).length - 1} packages, before ${before}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function main(argv: string[]): number {
  const only = arg(argv, '--only')?.split(',');
  const before = arg(argv, '--before') ?? new Date(Date.now() - 7 * DAY_MS).toISOString();
  const data = parse(readFileSync(resolve('data/reviewed-tools.yml'), 'utf8')) as { tools: Record<string, unknown>[] };
  const outDir = resolve('data/npm-closures');
  for (const [id, c] of Object.entries(CLOSURES)) {
    if (only !== undefined && !only.includes(id)) continue;
    const entry = data.tools.find((t) => t.id === id);
    if (entry === undefined) throw new Error(`no reviewed entry ${id}`);
    makeClosure(id, depsOf(entry, c.extra ?? {}), before, outDir);
  }
  return 0;
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
