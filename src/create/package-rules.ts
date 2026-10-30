// The package.json and package-lock.json rules of ruling B2 (v0.2 Plan D, D1), as pure functions over text. The guard (src/create/guard.ts)
// applies them to every edit of these two files, and D6's referee judges call the same functions, so the producer and the checks can not drift.
//
// package.json: a SEMANTIC diff against the original. The only changes allowed:
//   - `scripts.test`, when the original has none or still npm's default, and then only to `vitest run`;
//   - `devDependencies` gains entries from the B2 table (B2_DEVDEPS) at exactly the table's version, each only when the package is absent
//     from the repo's dependencies. An existing devDependency is never changed, removed or re-pinned.
//   Every other key is compared whole: `scripts.build`, any other script (lifecycle ones by name), `dependencies`, and the gate's
//   `c8`, `prettier` and `renovate` sections included. Formatting and key order are not changes. A repeated key anywhere is refused
//   (npm keeps the last, a reviewer reading the diff sees the first).
// package-lock.json (lockfileVersion 3): EVERY change must be explained by the added devDependencies and their closure.
//   - every top-level key but `packages` is equal; the root entry is equal but for devDependencies, which follow the package.json rule;
//   - every pre-existing entry is present and deep-equal (nothing removed, nothing changed);
//   - every new entry is a plain registry package (lockEntryProblems: exact version, the registry tarball, sha512, no link or bundle,
//     registry ranges only), AND is reachable from an added package through dependencies, optionalDependencies and peerDependencies
//     (npm's own lookup: the nearest node_modules folder up the tree). An entry nobody reaches is refused;
//   - every added package sits at `node_modules/<name>` at the table's version; the reviewed integrity is checked when given.
import { isDeepStrictEqual } from 'node:util';
import { lockEntryProblems } from '../engine/npm-closure.js';

/** The only devDependencies pipegen adds (B2): the reviewed repo-code pins. */
export const B2_DEVDEPS: Readonly<Record<string, string>> = Object.freeze({ vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5', c8: '12.0.0' });
/** npm's default `scripts.test` (what `npm init` writes). */
export const NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1';
/** The value `scripts.test` may be set to (B2). */
export const VITEST_TEST_SCRIPT = 'vitest run';
/** The gate's sections of package.json (types.ts configSections): changing one weakens a pinned check. */
const GATE_SECTIONS: readonly string[] = ['c8', 'prettier', 'renovate'];
const MAX_DEPTH = 64;
const MAX_LOCK_ENTRIES = 20_000;

type Rec = Record<string, unknown>;
const isObj = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v);
const has = (o: Rec, k: string): boolean => Object.hasOwn(o, k);
const same = (a: unknown, b: unknown): boolean => isDeepStrictEqual(a, b);
const show = (s: string): string => (s.length > 60 ? `${s.slice(0, 57)}...` : s);

/**
 * JSON.parse that also refuses a repeated key at any depth and nesting over 64 levels. Objects have no prototype, so a `__proto__` key
 * is a plain own property. Throws an Error with a short plain message.
 */
export function parseJsonStrict(text: string): unknown {
  let i = 0;
  const fail = (m: string): never => { throw new Error(m); };
  const ws = (): void => { while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++; };
  const str = (): string => {
    let j = i + 1;
    while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
    if (j >= text.length) return fail('a string is not closed');
    const lit = text.slice(i, j + 1);
    i = j + 1;
    try { return JSON.parse(lit) as string; } catch { return fail('a string is not valid JSON'); }
  };
  const value = (depth: number): unknown => {
    if (depth > MAX_DEPTH) return fail('the nesting is too deep');
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      const o: Rec = Object.create(null) as Rec;
      ws();
      if (text[i] === '}') { i++; return o; }
      for (;;) {
        ws();
        if (text[i] !== '"') return fail('an object key is not a string');
        const k = str();
        if (Object.hasOwn(o, k)) return fail(`the key ${JSON.stringify(show(k))} is repeated`);
        ws();
        if (text[i++] !== ':') return fail('a colon is missing');
        o[k] = value(depth + 1);
        ws();
        const d = text[i++];
        if (d === '}') return o;
        if (d !== ',') return fail('a comma or } is missing');
      }
    }
    if (c === '[') {
      i++;
      const a: unknown[] = [];
      ws();
      if (text[i] === ']') { i++; return a; }
      for (;;) {
        a.push(value(depth + 1));
        ws();
        const d = text[i++];
        if (d === ']') return a;
        if (d !== ',') return fail('a comma or ] is missing');
      }
    }
    if (c === '"') return str();
    const m = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y;
    m.lastIndex = i;
    const t = m.exec(text);
    if (t === null) return fail('this is not JSON');
    i += t[0].length;
    return JSON.parse(t[0]) as unknown;
  };
  const v = value(0);
  ws();
  if (i !== text.length) fail('there is text after the JSON value');
  return v;
}

const parseObj = (text: string, what: string): { v: Rec } | { problem: string } => {
  let v: unknown;
  try { v = parseJsonStrict(text); } catch (e) { return { problem: `${what} can not be read as JSON (${e instanceof Error ? e.message : 'unreadable'})` }; }
  return isObj(v) ? { v } : { problem: `${what} is not a JSON object` };
};

const LIFECYCLE = new Set(['install', 'uninstall', 'prepare', 'publish', 'version', 'dependencies', 'shrinkwrap', 'restart']);
/** An npm lifecycle script name: runs by itself during install, publish, pack, version or around any other script. */
const isLifecycle = (name: string): boolean => /^(?:pre|post)/.test(name) || LIFECYCLE.has(name);

/** The rule for `devDependencies` (package.json and the lock's root entry): additions from the B2 table only, existing entries untouched. */
function devDependencyProblems(oldDev: unknown, newDev: unknown, owner: Rec, where: string): string[] {
  const out: string[] = [];
  if (oldDev !== undefined && !isObj(oldDev)) return [`${where} devDependencies of the original is not an object`];
  if (newDev !== undefined && !isObj(newDev)) return [`${where} devDependencies is not an object, so it is refused`];
  const o: Rec = oldDev ?? {};
  const n: Rec = newDev ?? {};
  for (const k of Object.keys(o)) {
    if (!has(n, k)) out.push(`${where} removes devDependencies.${show(k)}; an existing devDependency is never removed`);
    else if (!same(o[k], n[k])) out.push(`${where} changes devDependencies.${show(k)}; an existing version is never changed`);
  }
  for (const k of Object.keys(n)) {
    if (has(o, k)) continue;
    if (!has(B2_DEVDEPS, k)) out.push(`${where} adds devDependencies.${show(k)}, which is not one of pipegen's reviewed packages (${Object.keys(B2_DEVDEPS).join(', ')})`);
    else if (n[k] !== B2_DEVDEPS[k]) out.push(`${where} adds devDependencies.${k} at ${JSON.stringify(show(String(n[k])))}; only the exact reviewed version ${B2_DEVDEPS[k]} is allowed`);
    else if (['dependencies', 'optionalDependencies', 'peerDependencies'].some((f) => isObj(owner[f]) && has(owner[f] as Rec, k))) out.push(`${where} adds devDependencies.${k}, but the repository already lists it in dependencies, optionalDependencies or peerDependencies`);
  }
  return out;
}

/**
 * The reasons a change of a package.json (`original` to `content`) is refused (B2); empty = it only adds what pipegen may add.
 * Both texts are parsed strictly. Pure.
 */
export function packageJsonProblems(original: string, content: string): string[] {
  const o = parseObj(original, 'the original package.json');
  if ('problem' in o) return [o.problem];
  const n = parseObj(content, 'the new package.json');
  if ('problem' in n) return [n.problem];
  const out: string[] = [];
  for (const k of new Set([...Object.keys(o.v), ...Object.keys(n.v)])) {
    if (k === 'scripts' || k === 'devDependencies' || same(o.v[k], n.v[k])) continue;
    out.push(GATE_SECTIONS.includes(k)
      ? `pipegen changes \`${k}\` in package.json, a section the gate protects (a tool's own settings); pipegen never edits it`
      : `pipegen changes \`${show(k)}\` in package.json; its edit is limited to scripts.test and the reviewed devDependencies`);
  }
  const os = o.v.scripts;
  const ns = n.v.scripts;
  if ((os !== undefined && !isObj(os)) || (ns !== undefined && !isObj(ns))) out.push('scripts in package.json is not an object, so pipegen can not judge a change to it');
  else {
    const so: Rec = os ?? {};
    const sn: Rec = ns ?? {};
    for (const k of new Set([...Object.keys(so), ...Object.keys(sn)])) {
      if (k === 'test' || same(so[k], sn[k])) continue;
      out.push(isLifecycle(k)
        ? `pipegen changes the lifecycle script \`${show(k)}\` (scripts.${show(k)}); a lifecycle script runs by itself during install or publish`
        : `pipegen changes scripts.${show(k)}; the only script it may touch is scripts.test`);
    }
    if (!same(so.test, sn.test)) {
      const allowed = (so.test === undefined || so.test === NPM_DEFAULT_TEST) && sn.test === VITEST_TEST_SCRIPT;
      if (!allowed) out.push(`pipegen changes scripts.test; it may set it to \`${VITEST_TEST_SCRIPT}\` only when it is absent or still npm's default`);
    }
  }
  out.push(...devDependencyProblems(o.v.devDependencies, n.v.devDependencies, o.v, 'pipegen'));
  return out;
}

// ---------- the lock ----------

export interface LockOpts {
  /** The NEW package.json text of the same folder: the lock's root devDependencies must equal its devDependencies. */
  packageJson?: string;
  /** The reviewed integrity of a pinned package (name to `sha512-...`): when given, the lock entry must carry exactly it. */
  integrity?: Readonly<Record<string, string>>;
}

/** The `node_modules/<name>` key where npm looks for `dep` when `from` (a lock key) requires it: the nearest folder up the tree, else null. */
function resolveKey(packages: Rec, from: string, dep: string): string | null {
  let scope = from;
  for (;;) {
    const cand = `${scope === '' ? '' : `${scope}/`}node_modules/${dep}`;
    if (has(packages, cand)) return cand;
    if (scope === '') return null;
    const m = /^(.*)\/node_modules\/(?:@[^/]+\/)?[^/]+$/.exec(scope);
    scope = m === null ? '' : (m[1] as string);
  }
}

/**
 * The reasons a change of a package-lock.json (`original` to `content`) is refused (B2); empty = every change is explained by the added
 * devDependencies and their closure. Pure; the caller bounds the text size.
 */
export function lockProblems(original: string, content: string, opts: LockOpts = {}): string[] {
  const o = parseObj(original, 'the original package-lock.json');
  if ('problem' in o) return [o.problem];
  const n = parseObj(content, 'the new package-lock.json');
  if ('problem' in n) return [n.problem];
  for (const [what, l] of [['original', o.v], ['new', n.v]] as const) {
    if (l.lockfileVersion !== 3) return [`the ${what} package-lock.json is not lockfileVersion 3; pipegen edits only that format`];
    if (!isObj(l.packages) || !isObj(l.packages['']) || Object.keys(l.packages).length > MAX_LOCK_ENTRIES) return [`the ${what} package-lock.json has no usable \`packages\` section with a root entry`];
  }
  const out: string[] = [];
  for (const k of new Set([...Object.keys(o.v), ...Object.keys(n.v)])) if (k !== 'packages' && !same(o.v[k], n.v[k])) out.push(`the lock changes \`${show(k)}\` at the top level; only package entries may change`);
  const op = o.v.packages as Rec;
  const np = n.v.packages as Rec;
  const oroot = op[''] as Rec;
  const nroot = np[''] as Rec;
  if (!isObj(oroot) || !isObj(nroot)) return [...out, 'the root entry of the lock is not an object'];
  for (const k of new Set([...Object.keys(oroot), ...Object.keys(nroot)])) if (k !== 'devDependencies' && !same(oroot[k], nroot[k])) out.push(`the lock changes the root entry (\`${show(k)}\`); only its devDependencies may gain the reviewed packages`);
  const devProblems = devDependencyProblems(oroot.devDependencies, nroot.devDependencies, oroot, 'the lock');
  out.push(...devProblems);
  const added = isObj(nroot.devDependencies) ? Object.keys(nroot.devDependencies).filter((k) => !(isObj(oroot.devDependencies) && has(oroot.devDependencies, k))) : [];
  const addedOk = devProblems.length === 0 ? added : added.filter((k) => has(B2_DEVDEPS, k));

  for (const key of Object.keys(op)) {
    if (key === '') continue;
    if (!has(np, key)) out.push(`the lock removes ${show(key)}; an existing entry is never removed`);
    else if (!same(op[key], np[key])) out.push(`the lock changes ${show(key)}; an existing entry is never changed`);
  }
  const fresh = Object.keys(np).filter((k) => k !== '' && !has(op, k));
  for (const key of fresh) out.push(...lockEntryProblems(key, np[key]));

  for (const name of addedOk) {
    const e = np[`node_modules/${name}`];
    if (!isObj(e)) { out.push(`the lock does not hold ${name} at node_modules/${name}`); continue; }
    if (e.version !== B2_DEVDEPS[name]) out.push(`the lock holds ${name} ${show(String(e.version))}, not the reviewed ${B2_DEVDEPS[name]}`);
    const want = opts.integrity?.[name];
    if (want !== undefined && e.integrity !== want) out.push(`the lock holds ${name} with another integrity than the reviewed one`);
  }

  // closure: a new entry must be reached from an added package through new entries only
  const reached = new Set<string>();
  const queue: string[] = [];
  const reach = (key: string): void => { if (!has(op, key) && has(np, key) && !reached.has(key)) { reached.add(key); queue.push(key); } };
  for (const name of addedOk) reach(`node_modules/${name}`);
  while (queue.length > 0) {
    const key = queue.pop() as string;
    const e = np[key];
    if (!isObj(e)) continue;
    const meta = isObj(e.peerDependenciesMeta) ? e.peerDependenciesMeta : {};
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies'] as const) {
      const deps = e[field];
      if (!isObj(deps)) continue;
      for (const d of Object.keys(deps)) {
        const at = resolveKey(np, key, d);
        if (at !== null) { reach(at); continue; }
        const optional = field === 'optionalDependencies' || (field === 'peerDependencies' && isObj(meta[d]) && (meta[d] as Rec).optional === true);
        if (!optional) out.push(`${show(key)} needs ${show(d)}, which the lock does not hold, so the closure of the added packages is incomplete`);
      }
    }
  }
  for (const key of fresh) if (!reached.has(key)) out.push(`${show(key)} is not part of the closure of the added devDependencies (${Object.keys(B2_DEVDEPS).join(', ')}), so pipegen does not add it`);

  if (opts.packageJson !== undefined) {
    const p = parseObj(opts.packageJson, 'the new package.json');
    if ('problem' in p) out.push(`the lock can not be compared with package.json: ${p.problem}`);
    else if (!same(p.v.devDependencies ?? {}, nroot.devDependencies ?? {})) out.push('the root devDependencies of the lock differ from the devDependencies of the new package.json, so the two files do not agree');
  }
  return out;
}
