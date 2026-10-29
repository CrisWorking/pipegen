// Coverage mapper (see ../coverage.ts for the rules): own package.json scripts, read and followed per (dir, script).
import { posix } from 'node:path';
import { asObj } from '../../read/manifest.js';
import { MAX_GLOB_NAME, MAX_GLOB_WORK, MAX_PACKAGE_FILES, MAX_SCRIPTS, MAX_SCRIPT_FILES, MAX_SCRIPT_TARGETS } from './bounds.js';
import { UNKNOWN_PREFIX, flagGiven, gateOf, gated } from './settings.js';
import {
  OK_COMMANDS, PYTEST_NO_RUN, SCRIPT_CATEGORIES, shebangOk, UNKNOWN_SCRIPT_CATEGORIES, globCappedWhy, probeCall, scanShell, scriptCall, type CmdInfo,
  type ShellMode,
} from './shell.js';
import { buildRuns, placeComposeRun } from './docker.js';
import { compileGlob } from './triggers.js';
import type { Compiled, Ctx, Found, Reason } from './types.js';

// ---------- own scripts read from package.json (Task 5) ----------

/** Fix round 1 (P8): a script's tool keeps its softEnv names and config files, so the job's env and files reach it. */
const carriedConfig = (g: Found) => ({
  ...(g.softEnv === undefined ? {} : { softEnv: g.softEnv }), ...(g.configFiles === undefined ? {} : { configFiles: g.configFiles }),
  // P57 (C1): and the languages it checks and the paths it was given
  ...(g.langs === undefined ? {} : { langs: g.langs }), ...(g.pathArgs === undefined ? {} : { pathArgs: g.pathArgs }),
  ...(g.unplaced === undefined ? {} : { unplaced: g.unplaced }),
});

/**
 * P57 (C1): the languages a script counted by name checks, from what its text runs for the row's categories: the
 * known tools' languages when every one of them is known; else the caller's (a Node package's script, '?').
 */
function byNameLangs(f: Found, runs: readonly Found[]): readonly string[] | undefined {
  const own = runs.filter((g) => g.categories.some((c) => f.categories.includes(c)));
  if (own.length === 0 || own.some((g) => g.langs === undefined || g.langs.includes('?'))) return f.langs;
  return [...new Set(own.flatMap((g) => g.langs as readonly string[]))];
}

/** Plan P Task 3 (PS11): the own-script categories a by-name script (test, lint) also counts for through its text. */
const PLAN_P_SCRIPT_CATEGORIES: ReadonlySet<string> = new Set(['format', 'type-check', 'coverage', 'dead-code', 'duplication']);

/** How npm runs a script: `/bin/sh -c` on POSIX (https://docs.npmjs.com/cli/v11/using-npm/scripts), so no -e. */
const NPM_SCRIPT_SHELL: ShellMode = { errexit: false, pipefail: false };

/** The `scripts` of `<dir>/package.json` (string values only), or null when it can't be read. */
function packageScripts(ctx: Ctx, dir: string): Promise<ReadonlyMap<string, string> | null> {
  let r = ctx.pkgScripts.get(dir);
  if (r === undefined) {
    r = ctx.pkgScripts.size >= MAX_PACKAGE_FILES ? Promise.resolve(null) : ctx.pkgRead.text(dir === '.' ? 'package.json' : `${dir}/package.json`).then((t) => {
      if (!('ok' in t)) return null;
      try {
        const scripts = asObj(asObj(JSON.parse(t.ok)).scripts);
        return new Map(Object.entries(scripts).filter((e): e is [string, string] => typeof e[1] === 'string'));
      } catch {
        return null;
      }
    });
    ctx.pkgScripts.set(dir, r);
  }
  return r;
}

/**
 * What the script `name` of `<dir>/package.json` runs that counts for an own script (tests, lint, format-lint): its
 * text is read as npm runs it (sh -c, no -e), and the own scripts it calls in turn are read the same way. Worked out
 * once per (dir, name); a cycle, an unreadable package.json or a missing script gives [].
 */
async function scriptRuns(ctx: Ctx, dir: string, name: string): Promise<Found[]> {
  const key = `${dir}\u0000${name}`;
  const known = ctx.scriptMemo.get(key);
  if (known !== undefined) return known;
  if (ctx.scriptMemo.size >= MAX_SCRIPTS) return [];
  ctx.scriptMemo.set(key, []); // being worked out: a script that calls itself (directly or not) adds nothing
  const text = (await packageScripts(ctx, dir))?.get(name);
  if (text === undefined) return [];
  const inner = gated(await resolveScripts(ctx, scanShell(text, dir, ctx.sigs, ctx.budget, NPM_SCRIPT_SHELL)), gateOf([text], [], undefined, ctx.sigs.softEnv, ctx.sigs.configFiles));
  const out = inner.flatMap((g) => {
    const categories = g.categories.filter((x) => SCRIPT_CATEGORIES.has(x.startsWith(UNKNOWN_PREFIX) ? x.slice(UNKNOWN_PREFIX.length) : x));
    return categories.length === 0 ? [] : [{ ...g, categories, hookRun: false }];
  });
  ctx.scriptMemo.set(key, out);
  return out;
}

/**
 * Own-script candidates (`npm run <name>` for a name not counted by name) become what their script runs, under the
 * caller's phrase, in the directory the script's tool runs in; the caller's reason (an `||`, a pipe, …) comes first. A candidate whose script runs
 * nothing that counts is dropped.
 */
export async function resolveScripts(ctx: Ctx, found: Found[]): Promise<Found[]> {
  if (!found.some((f) => f.script !== undefined || f.byName !== undefined || f.scriptFile !== undefined || f.composeRun !== undefined || f.dockerBuild !== undefined || f.composeBuild !== undefined)) return found;
  const out: Found[] = [];
  for (const f0 of found) {
    // P55 (batch B): the Dockerfiles a build command builds add the checks in their RUN lines; the build itself stays as it is
    if (f0.dockerBuild !== undefined || f0.composeBuild !== undefined) out.push(...(await buildRuns(ctx, f0, resolveScripts)));
    // `docker compose run|exec <service> <command>` counts in the service's build folder
    const f = f0.composeRun === undefined ? f0 : await placeComposeRun(ctx, f0);
    if (f === null) continue;
    if (f.byName !== undefined) {
      const lowered0 = await byNameRun(ctx, f);
      const langs = lowered0 === null || f.dir === null ? undefined : byNameLangs(lowered0, await scriptRuns(ctx, f.dir, f.byName));
      const lowered = lowered0 === null ? null : { ...lowered0, ...(langs === undefined ? {} : { langs }) };
      if (lowered !== null) out.push(lowered);
      // Plan P Task 3 (PS11): what the script's text runs for the Plan P categories (`npm run test:coverage` →
      // coverage) counts through that text only, as for any other own script (the older ones keep the by-name rule)
      if (f.dir !== null && lowered !== null && !lowered.categories.some((c) => c.startsWith(UNKNOWN_PREFIX))) {
        for (const g of await scriptRuns(ctx, f.dir, f.byName)) {
          // P55 (batch B): a linter in a script counted by another name (`test: xo && … && ava`) counts for lint too; the
          // `lint` script itself already counts for lint by its name
          const extra = g.categories.filter((c) => {
            const bare = c.startsWith(UNKNOWN_PREFIX) ? c.slice(UNKNOWN_PREFIX.length) : c;
            return PLAN_P_SCRIPT_CATEGORIES.has(bare) || (bare === 'lint' && !f.categories.includes('lint'));
          });
          if (extra.length > 0) {
            out.push({
              categories: extra, by: f.by, subject: f.subject, dir: g.dir, reason: f.reason ?? g.reason,
              ...(f.reason === null && g.partialWhy !== undefined ? { partialWhy: g.partialWhy } : {}), ...carriedConfig(g),
            });
          }
        }
      }
      continue;
    }
    if (f.scriptFile !== undefined) {
      for (const g of await scriptFileRuns(ctx, f)) out.push(g);
      continue;
    }
    if (f.script === undefined) {
      out.push(f);
      continue;
    }
    if (f.dir === null) continue;
    const names = expandScripts(ctx, f.dir, [f.script], true, await packageScripts(ctx, f.dir));
    if (names === 'capped') { // fix round 4 (N8): never covered, never missing
      out.push({ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: f.dir, reason: null, partialWhy: globCappedWhy(f.subject) });
      continue;
    }
    for (const name of names) for (const g of await scriptRuns(ctx, f.dir, name)) {
      out.push({ // the script's own `cd` counts: `cd api && jest` tests the api service only
        categories: g.categories, by: f.by, subject: f.subject, dir: g.dir, reason: f.reason ?? g.reason,
        ...(f.reason === null && g.partialWhy !== undefined ? { partialWhy: g.partialWhy } : {}),
        ...(g.envGate === undefined ? {} : { envGate: g.envGate }), ...carriedConfig(g),
      });
    }
  }
  return out;
}

/** How bash runs a script file (`bash x.sh`, `./x.sh`): no -e unless the file sets it (`set -e`, read by scanShell). */
const SCRIPT_FILE_SHELL: ShellMode = { errexit: false, pipefail: false, script: true };

/**
 * DoD run (fastapi/full-stack-fastapi-template: `uv run bash scripts/tests-start.sh` → `bash scripts/test.sh` →
 * `coverage run -m pytest`): what a repo shell script file runs that counts for an own script (tests, lint, format,
 * type-check, coverage, dead-code, …), under the caller's phrase. The file is read through the coverage Reader (no
 * symbolic link at any level, real path inside the repo, the read limits), its text read like a step's (`set -e` and
 * `cd` count; the script runs in the caller's folder, so paths inside it are taken from there), and the script files
 * and own package scripts it calls in turn are followed the same way: each (folder, file) once, a cycle adding
 * nothing. Script files have their own Reader and bound (MAX_SCRIPT_FILES, every file tried counts, read or not;
 * P50 C2). A file pipegen can't read, one past that bound, or a run inside it in a folder pipegen can't place (P50
 * I4: it sits at the root as unknown, see Firsts) is never covered and never missing: unknown, saying why.
 */
async function scriptFileRuns(ctx: Ctx, f: Found): Promise<Found[]> {
  const unknown = (why: string): Found[] => [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: f.dir, reason: null, partialWhy: why }];
  const cantRead = `${f.subject} runs a script file pipegen couldn't read (missing, a symbolic link, too large or outside the repo), so it can't tell what it runs.`;
  if (f.dir === null) return unknown(`${f.subject} runs in a folder pipegen can't place, so it can't tell which script file runs.`);
  const path = posix.normalize(f.dir === '.' ? f.scriptFile as string : `${f.dir}/${f.scriptFile as string}`);
  if (path.startsWith('../') || path === '..') return unknown(cantRead);
  const key = `file\u0000${f.scriptDirect === true ? 1 : 0}\u0000${f.dir}\u0000${path}`;
  let runs = ctx.scriptMemo.get(key);
  if (runs === undefined) {
    // P50 (C2): script files have their own reader and their own bound, and every file tried counts, read or not, so a
    // repo can't spend the package.json reader (U23 needs it) or slip past the bound with files that don't exist
    if (ctx.scriptFileReads >= MAX_SCRIPT_FILES || ctx.scriptMemo.size >= MAX_SCRIPTS) {
      return unknown(`There are more script files than pipegen follows (${MAX_SCRIPT_FILES}), so it can't tell what ${f.subject.charAt(0).toLowerCase()}${f.subject.slice(1)} runs.`);
    }
    ctx.scriptFileReads++;
    ctx.scriptMemo.set(key, []); // being worked out: a script that calls itself (directly or not) adds nothing
    const t = await ctx.scriptRead.text(path);
    if (!('ok' in t)) {
      runs = unknown(cantRead);
      ctx.scriptMemo.set(key, runs);
      return runs;
    }
    // P52 (e): run directly, the shebang decides what runs: only bash or sh with allowlisted flags is read
    if (f.scriptDirect === true && !shebangOk(t.ok)) {
      ctx.scriptMemo.set(key, []);
      return [];
    }
    const inner = gated(await resolveScripts(ctx, scanShell(t.ok, f.dir, ctx.sigs, ctx.budget, SCRIPT_FILE_SHELL)), gateOf([t.ok], [], undefined, ctx.sigs.softEnv, ctx.sigs.configFiles));
    runs = inner.flatMap((g): Found[] => {
      const categories = g.categories.filter((x) => SCRIPT_CATEGORIES.has(x.startsWith(UNKNOWN_PREFIX) ? x.slice(UNKNOWN_PREFIX.length) : x));
      if (categories.length === 0) return [];
      // P50 (I4): a run in a folder pipegen can't place (`cd "$(dirname "$0")"`) could be any service's: unknown
      if (g.dir === null && categories.some((c) => !c.startsWith(UNKNOWN_PREFIX))) {
        return [{ categories: categories.map((c) => (c.startsWith(UNKNOWN_PREFIX) ? c : `${UNKNOWN_PREFIX}${c}`)), by: g.by, subject: g.subject, dir: null, reason: null,
          partialWhy: `${f.subject} changes to a folder pipegen can't place before it runs ${g.subject.charAt(0).toLowerCase()}${g.subject.slice(1)}, so it can't tell which service that checks.` }];
      }
      return [{ ...g, categories, hookRun: false }];
    });
    ctx.scriptMemo.set(key, runs);
  }
  return runs.map((g) => ({ // the script's own `cd` counts, as for a package script
    categories: g.categories, by: f.by, subject: f.subject, dir: g.dir, reason: f.reason ?? g.reason,
    ...(f.reason === null && g.partialWhy !== undefined ? { partialWhy: g.partialWhy } : {}),
    ...(g.envGate === undefined ? {} : { envGate: g.envGate }), ...carriedConfig(g),
  }));
}

export type Targets = string[] | 'capped';

/**
 * Script names a call's patterns name: a plain name as is; with `glob`, a pattern with `*` against this package.json's
 * scripts (globScripts). The names of all the patterns together are at most MAX_SCRIPT_TARGETS - 1, else 'capped'.
 */
function expandScripts(ctx: Ctx, dir: string, patterns: readonly string[], glob: boolean, scripts: ReadonlyMap<string, string> | null | undefined): Targets {
  const out = new Set<string>();
  for (const p of patterns) {
    const names = glob && p.includes('*') ? globScripts(ctx, dir, p, scripts) : [p];
    if (names === 'capped') return 'capped';
    for (const name of names) {
      out.add(name);
      if (out.size >= MAX_SCRIPT_TARGETS) return 'capped';
    }
  }
  return [...out];
}

/** The script names one glob matches in `<dir>/package.json` (npm-run-all: `:` separates parts like `/`), worked out once per (dir, glob). */
function globScripts(ctx: Ctx, dir: string, pattern: string, scripts: ReadonlyMap<string, string> | null | undefined): Targets {
  const key = `${dir}\u0000${pattern}`;
  const known = ctx.globMemo.get(key);
  if (known !== undefined) return known;
  const result = ((): Targets => {
    if (scripts === null || scripts === undefined) return [];
    const match = compileGlob(asPath(pattern));
    const out: string[] = [];
    for (const name of scripts.keys()) {
      ctx.globWork += pattern.length * Math.max(1, Math.min(name.length, MAX_GLOB_NAME));
      if (ctx.globWork > MAX_GLOB_WORK) {
        ctx.budget.truncated = true;
        return 'capped';
      }
      if (name.length > MAX_GLOB_NAME || !match(asPath(name))) continue;
      out.push(name);
      if (out.length >= MAX_SCRIPT_TARGETS) return 'capped';
    }
    return out;
  })();
  ctx.globMemo.set(key, result);
  return result;
}
const asPath = (s: string) => s.replace(/\//g, '\u0001').replace(/:/g, '/');

/** What a script really runs, for ruling U23: `real` = something other than no-ops; `soft` = a reason when none of those runs can fail it; `capped` = more scripts than pipegen follows ('scripts'), or globs past their bounds ('globs', fix round 4). */
export interface ScriptClass { real: boolean; soft: Reason | null; capped?: 'scripts' | 'globs' }

/** A known tool called in a mode that runs nothing: a version/help probe, a `notWithFlags` flag, or a pytest collect-only flag. */
function runsNothing(c: CmdInfo, sigs: Compiled): boolean {
  if (probeCall(c.args)) return true;
  const afterDash = c.args.indexOf('--');
  if ((c.name === 'tox' || c.name === 'nox') && afterDash >= 0 && c.args.slice(afterDash + 1).some((a) => PYTEST_NO_RUN.has(a))) return true;
  if ((c.name === 'pytest' || ((c.name === 'python' || c.name === 'python3') && c.args[0] === '-m' && c.args[1] === 'pytest')) && c.args.some((a) => PYTEST_NO_RUN.has(a))) return true;
  return (sigs.byFirstWord.get(c.name) ?? []).some((r) => r.rest.every((x, i) => c.args[i] === x) && (r.tool.notWithFlags ?? []).some((f) => flagGiven(f, c.args)));
}

/**
 * Fix round 2 (N1, N3) and 3 (N7; ruling U23): every top-level command of a package script, read as npm runs it (sh -c,
 * no -e), is (a) a no-op (echo, printf, true, :, false, an exit or return of 0, a bare exit), (b) dead (after a
 * top-level exit, right of `true ||` / `false &&`, also with the no-op in a `( … )` / `{ …; }` group), (c) a known tool
 * in a mode that runs nothing (--version, --help, jest --listTests, pytest --co…), (d) a call to other own scripts
 * (scriptCall: npm run/run-script/rum/urn, npm test/t/tst, yarn|pnpm|bun run X, yarn|pnpm X for a script that exists,
 * npm-run-all/run-s/run-p and concurrently `npm:` arguments, globs matched) that all do nothing by this same rule
 * (followed with no depth limit; each (dir, script) worked out once, a cycle doing nothing, at most MAX_SCRIPTS), or
 * (e) anything else. `real` when some command is (e); `soft` when every (e) has a reason that keeps it from failing
 * the script (`x || true`, `x; exit 0`: under sh -c only the last list can fail it). An unreadable script is unknown
 * and counts as real; past MAX_SCRIPTS the answer is `capped` (the row becomes unknown).
 */
async function classifyScript(ctx: Ctx, dir: string, name: string): Promise<ScriptClass> {
  const key = `${dir}\u0000${name}`;
  const known = ctx.scriptClass.get(key);
  if (known !== undefined) return known;
  const scripts = await packageScripts(ctx, dir);
  const text = scripts?.get(name);
  if (text === undefined || scripts === null || scripts === undefined) return { real: true, soft: null };
  if (ctx.scriptClass.size >= MAX_SCRIPTS) return { real: true, soft: null, capped: 'scripts' };
  ctx.scriptClass.set(key, { real: false, soft: null }); // being worked out: a cycle does nothing
  const cmds: CmdInfo[] = [];
  scanShell(text, dir, ctx.sigs, ctx.budget, NPM_SCRIPT_SHELL, (c) => { cmds.push(c); });
  let real = false;
  let capped: ScriptClass['capped'] | false = false;
  let soft: Reason | null = null;
  let allSoft = true;
  const realRun = (reason: Reason | null) => {
    real = true;
    if (reason === null) allSoft = false;
    else soft ??= reason;
  };
  let scriptBin = false; // the previous command was `yarn|pnpm <script>`: its next word is that script, not a binary
  for (const c of cmds) {
    const call = scriptCall(c.name, c.args, scripts);
    const skip = scriptBin && c.afterBin;
    scriptBin = call !== null && c.wrapper;
    if (skip || c.dead || (c.wrapper && call === null)) continue;
    // no-ops: they run no check (`false` only fails the script, it tests nothing)
    if (OK_COMMANDS.has(c.name) || c.name === 'false' || ((c.name === 'exit' || c.name === 'return') && (c.args.length === 0 || /^0+$/.test(c.args[0] as string)))) continue;
    if (runsNothing(c, ctx.sigs)) continue;
    if (call?.capped === true) { // fix round 4 (N8): globs pipegen doesn't follow; the row is unknown
      capped ||= 'globs';
      realRun(c.reason);
      continue;
    }
    if (call !== null && c.dir !== null && !call.unknown) {
      const targets = expandScripts(ctx, c.dir, call.patterns, call.glob, c.dir === dir ? scripts : await packageScripts(ctx, c.dir));
      if (targets === 'capped') {
        capped ||= 'globs';
        realRun(c.reason);
        continue;
      }
      let innerReal = false;
      let innerAllSoft = true;
      let innerSoft: Reason | null = null;
      for (const t of targets) {
        const inner = await classifyScript(ctx, c.dir, t);
        if (inner.capped !== undefined) capped ||= inner.capped;
        if (!inner.real) continue;
        innerReal = true;
        if (inner.soft === null) innerAllSoft = false;
        else innerSoft ??= inner.soft;
      }
      if (targets.length === 0) realRun(c.reason); // nothing matched: the runner fails, pipegen can't tell more
      else if (innerReal) realRun(c.reason ?? (call.soft ? 'soft' : innerAllSoft ? innerSoft : null));
      continue;
    }
    realRun(c.reason);
  }
  const out: ScriptClass = { real, soft: real && allSoft ? soft : null, ...(capped ? { capped } : {}) };
  ctx.scriptClass.set(key, out);
  return out;
}

/**
 * Ruling U23: a script counted by name (S5) whose text can be read may only be LOWERED by it: no text (no package.json,
 * no such script) keeps it; a script that runs nothing (classifyScript) drops it (missing); one whose real runs all
 * can't fail it is partial; one whose runs of a known tool for this need all have a reason (|| true, a soft flag, …) is
 * partial with that reason; anything else keeps it (an unknown runner such as `node test.js` or tape stays counted).
 */
async function byNameRun(ctx: Ctx, f: Found): Promise<Found | null> {
  if (f.dir === null || f.byName === undefined) return f;
  const text = (await packageScripts(ctx, f.dir))?.get(f.byName);
  if (text === undefined) return f;
  const cls = await classifyScript(ctx, f.dir, f.byName);
  if (cls.capped === 'globs') return { ...f, categories: f.categories.map((c) => `${UNKNOWN_PREFIX}${c}`), reason: null, partialWhy: globCappedWhy(f.subject) };
  if (cls.capped === 'scripts') {
    return { ...f, categories: f.categories.map((c) => `${UNKNOWN_PREFIX}${c}`), reason: null, partialWhy: `There are more package scripts than pipegen follows (${MAX_SCRIPTS.toLocaleString('en-US')}), so it can't tell what ${f.subject.charAt(0).toLowerCase()}${f.subject.slice(1)} runs.` };
  }
  if (!cls.real) return null;
  if (cls.soft !== null) return { ...f, reason: f.reason ?? cls.soft };
  const runs = (await scriptRuns(ctx, f.dir, f.byName)).filter((g) => g.categories.some((c) => f.categories.includes(c)));
  const first = runs[0];
  if (first !== undefined && runs.every((g) => g.reason !== null)) return { ...f, reason: f.reason ?? first.reason };
  return f;
}
