// Reads a tool's argv the way the tool itself does (Plan P Task 5, fix round 1), so a loader rule sees which flags are
// really in effect: a value-taking flag swallows the next word (`--template --disable-telemetry` sets no telemetry
// flag), `--` ends the flags, `--flag=false` turns a bool off, and a flag the grammar doesn't know is an error (fail
// closed). Two dialects:
// - pflag (cobra: Trivy, betterleaks): `--long[=v]`, `-s v`, `-sv`, `-s=v`, combined bool shorthands (`-dq`); words
//   that aren't flags may sit between flags. An optional-value flag (NoOptDefVal) takes a value only as `--flag=v`;
//   alone it never swallows the next word.
// - goflags (Go's flag package: Nuclei): `-name[=v]` or `--name[=v]`, short names are just other names; parsing stops
//   at the first word that isn't a flag.
import type { FlagGrammar } from './tool-grammar.js';

export interface ParsedArgv {
  /** Every flag in order, by long name; `value` is the bool as 'true'/'false', the flag's value, or '' for an optional-value flag given alone. */
  flags: { name: string; value: string; raw: string }[];
  positionals: string[];
  /** Why the argv can't be read (unknown flag, a value missing, a bad bool); empty when it reads cleanly. */
  errors: string[];
}

const BOOL_TRUE = new Set(['1', 't', 'true']);
const BOOL_FALSE = new Set(['0', 'f', 'false']);

function boolValue(v: string): string | null {
  const l = v.toLowerCase();
  return BOOL_TRUE.has(l) ? 'true' : BOOL_FALSE.has(l) ? 'false' : null;
}

export function parseArgv(argv: readonly string[], g: FlagGrammar, dialect: 'pflag' | 'goflags'): ParsedArgv {
  const out: ParsedArgv = { flags: [], positionals: [], errors: [] };
  const take = (name: string, raw: string, inline: string | undefined, i: number): number => {
    if (g.optional.has(name)) out.flags.push({ name, value: inline ?? '', raw });
    else if (g.value.has(name)) {
      if (inline !== undefined) out.flags.push({ name, value: inline, raw });
      else if (i + 1 < argv.length) {
        out.flags.push({ name, value: argv[i + 1] as string, raw });
        return i + 1;
      } else out.errors.push(`${raw} needs a value`);
    } else {
      const v = inline === undefined ? 'true' : boolValue(inline);
      if (v === null) out.errors.push(`${raw} is a switch, not "${inline}"`);
      else out.flags.push({ name, value: v, raw });
    }
    return i;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === '--') {
      out.positionals.push(...argv.slice(i + 1));
      break;
    }
    if (!a.startsWith('-') || a === '-') {
      if (dialect === 'goflags') {
        out.positionals.push(...argv.slice(i));
        break;
      }
      out.positionals.push(a);
      continue;
    }
    if (dialect === 'goflags' || a.startsWith('--')) {
      const body = a.replace(/^--?/, '');
      const eq = body.indexOf('=');
      const key = eq < 0 ? body : body.slice(0, eq);
      const inline = eq < 0 ? undefined : body.slice(eq + 1);
      const name = dialect === 'goflags' ? (g.shorts[key] ?? key) : key;
      if (key === '' || key.startsWith('-') || !(g.value.has(name) || g.bool.has(name) || g.optional.has(name)) || (dialect === 'pflag' && key.length === 1)) {
        out.errors.push(`unknown flag ${a}`);
        continue;
      }
      i = take(name, a, inline, i);
      continue;
    }
    // pflag shorthands: -abc (bools), -fVALUE, -f=VALUE, -f VALUE
    for (let j = 1; j < a.length; j++) {
      const name = g.shorts[a[j] as string];
      if (name === undefined) {
        out.errors.push(`unknown flag -${a[j]} (in ${a})`);
        break;
      }
      const rest = a.slice(j + 1);
      if (g.value.has(name) || g.optional.has(name)) {
        i = take(name, a, rest === '' ? undefined : rest.replace(/^=/, ''), i);
        break;
      }
      if (rest.startsWith('=')) {
        take(name, a, rest.slice(1), i);
        break;
      }
      take(name, a, undefined, i);
    }
  }
  return out;
}

/** The value a flag ends up with (the last one given wins), or undefined when it isn't given. */
export function lastValue(p: ParsedArgv, name: string): string | undefined {
  for (let i = p.flags.length - 1; i >= 0; i--) if (p.flags[i]?.name === name) return p.flags[i]?.value;
  return undefined;
}
