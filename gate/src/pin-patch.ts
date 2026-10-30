// The pin patcher of the nightly update issue (Plan C Task C7), split out of nightly.ts (final review minor 10) so Plan G can reuse it alone.
// updatePatch swaps ONLY the exact rendered pin line of pipegen's gate in pipegen.yml and gives a unified diff of that swap; pinnedShas reads
// which commits pin the gate at a version. The bundle has no YAML parser, so the rarer YAML forms near a pin-shaped line refuse the patch
// (PatchRefused); `pipegen update` re-derives the patch with a real parser. Pure: no I/O.

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const SHA_RE = /^[0-9a-f]{40}$/;
/** x.y.z with no leading zeros and at most 6 digits a part (no overflow, no `1e3`, no prerelease). */
const SEMVER_RE = /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/;

// ---------- updatePatch ----------

/** Thrown when the lines a patch would show could carry text into the issue format (see updatePatch). */
export class PatchRefused extends Error {}
const CONTEXT = 3;
const MAX_SHOWN_LINE = 400;
const PATCH_PATH_RE = /^[A-Za-z0-9._/-]{1,200}$/;
/** Control characters (a tab is fine), DEL and C1, every format, separator, private-use and surrogate character, the default-ignorable ones (soft hyphen, joiners, variation selectors, tag characters) and the bidi controls. */
const UNSAFE_CHAR_RE = new RegExp('[\\u0000-\\u0008\\u000a-\\u001f\\u007f-\\u009f\\p{Cf}\\p{Zl}\\p{Zp}\\p{Co}\\p{Cs}\\p{Default_Ignorable_Code_Point}\\u202a-\\u202e\\u2066-\\u2069\\u061c\\ufeff\\ufff9-\\ufffb]', 'u');

/** The lines that belong to a YAML block scalar (`run: |`, `>`, `|-`, `>-`, `|2`): their text is a script or a string, never a step. */
function blockScalarLines(lines: readonly string[]): Set<number> {
  const inside = new Set<number>();
  let col: number | undefined;
  lines.forEach((raw, i) => {
    const line = raw.replace(/\r$/, '');
    if (col !== undefined) {
      if (line.trim() === '') { inside.add(i); return; }
      if ((/^ */.exec(line) as RegExpExecArray)[0].length > col) { inside.add(i); return; }
      col = undefined;
    }
    if (/^\s*#/.test(line)) return;
    const m = /^( *)((?:- +)?)[^\s#:][^#]*?:[ \t]+[|>][+-]?[1-9]?[+-]?[ \t]*(?:#.*)?$/.exec(line);
    if (m !== null) col = (m[1] as string).length + (m[2] as string).length;
  });
  return inside;
}
/**
 * Rarer YAML forms whose text can hold a pin-shaped line without being a step, which the block-scalar skip does not know: an anchor or a tag on a
 * block scalar header (`run: &a |`, `run: !!str |`), a block scalar as a list item (`- |`), an explicit key (`? run`), and a quoted scalar that
 * runs over several lines. They are NOT parsed (the bundle has no YAML parser): a file with one of them within RARE_WINDOW lines above a
 * pin-shaped line gets no patch. `pipegen update` re-derives the patch with a real parser.
 */
const RARE_WINDOW = 50;
const RARE_FORMS: readonly RegExp[] = [
  /:[ \t]+(?:[&!]\S*[ \t]+)+[|>]/,
  /^\s*-\s+(?:[&!]\S*\s+)*[|>][+-]?[0-9]?[+-]?\s*(?:#.*)?$/,
  /^\s*\?(?:\s|$)/,
  /(?:^\s*-\s+|:[ \t]+)"(?:[^"\\]|\\.)*$/,
  /(?:^\s*-\s+|:[ \t]+)'(?:[^']|'')*$/,
];
function refuseRareForms(lines: readonly string[], pinRe: RegExp, path: string): void {
  lines.forEach((line, i) => {
    if (!pinRe.test(line)) return;
    for (let k = Math.max(0, i - RARE_WINDOW); k < i; k++) {
      const above = (lines[k] as string).replace(/\r$/, '');
      if (/^\s*#/.test(above)) continue;
      if (RARE_FORMS.some((f) => f.test(above))) throw new PatchRefused(`Refused: ${path} uses a YAML form (an anchor or tag on a block scalar, a block scalar as a list item, an explicit key, or a quoted scalar over several lines) near line ${i + 1}, which this patch maker does not parse.`);
    }
  });
}
const pinLineRe = (sha: string, version: string): RegExp => new RegExp(`^(\\s*(?:-\\s+)?uses:\\s+)crisworking/pipegen/gate@${sha} # gate-v${version.replace(/\./g, '\\.')}(\\s*)$`);
/** The shas the gate is pinned at, for `version`, on real step lines (not inside a block scalar). */
export function pinnedShas(text: string, version: string): string[] {
  const lines = text.split('\n');
  const block = blockScalarLines(lines);
  const re = pinLineRe('([0-9a-f]{40})', version);
  return [...new Set(lines.map((l, i) => (block.has(i) ? undefined : re.exec(l)?.[2])).filter((x): x is string => x !== undefined))];
}

/** The diff of one file: only the lines that are exactly the pinned gate `uses:` of `from` change, to `to`. Empty when none does. */
function filePatch(file: { path: string; text: string }, from: { sha: string; version: string }, to: { sha: string; version: string }): string {
  if (!PATCH_PATH_RE.test(file.path) || file.path.split('/').some((p) => p === '' || p === '.' || p === '..')) throw new PatchRefused('Refused: the file path is not a plain repository path.');
  const parts = file.text.split('\n');
  const endsWithNewline = parts[parts.length - 1] === '';
  const lines = endsWithNewline ? parts.slice(0, -1) : parts;
  const re = pinLineRe(from.sha, from.version);
  const block = blockScalarLines(lines);
  refuseRareForms(lines, re, file.path);
  const at: number[] = [];
  const replaced = new Map<number, string>();
  lines.forEach((line, i) => {
    const m = block.has(i) ? null : re.exec(line);
    if (m === null) return;
    at.push(i);
    replaced.set(i, `${m[1] as string}crisworking/pipegen/gate@${to.sha} # gate-v${to.version}${m[2] as string}`);
  });
  if (at.length === 0) return '';
  const ranges: { start: number; end: number }[] = [];
  for (const i of at) {
    const start = Math.max(0, i - CONTEXT);
    const end = Math.min(lines.length - 1, i + CONTEXT);
    const last = ranges[ranges.length - 1];
    if (last !== undefined && start <= last.end + 1) last.end = end; else ranges.push({ start, end });
  }
  const out: string[] = [`--- a/${file.path}`, `+++ b/${file.path}`];
  const noNewlineAtEnd = (i: number): boolean => !endsWithNewline && i === lines.length - 1;
  for (const r of ranges) {
    const count = r.end - r.start + 1;
    out.push(`@@ -${r.start + 1},${count} +${r.start + 1},${count} @@`);
    for (let i = r.start; i <= r.end; i++) {
      const line = lines[i] as string;
      const shown = (text: string): void => {
        // a single trailing CR belongs to a CRLF line end; anything else odd in a shown line could forge or hide text in the issue
        const bare = text.endsWith('\r') ? text.slice(0, -1) : text;
        if (UNSAFE_CHAR_RE.test(bare) || bare.length > MAX_SHOWN_LINE || bare.includes('<!--') || bare.includes('-->') || bare.includes('\r')) {
          throw new PatchRefused(`Refused: line ${i + 1} of ${file.path} holds text the issue format can not carry safely (a control or invisible character, a very long line, or an HTML comment marker).`);
        }
      };
      shown(line);
      const mark = noNewlineAtEnd(i) ? ['\\ No newline at end of file'] : [];
      const swap = replaced.get(i);
      if (swap === undefined) { out.push(` ${line}`, ...mark); continue; }
      shown(swap);
      out.push(`-${line}`, ...mark, `+${swap}`, ...mark);
    }
  }
  return `${out.join('\n')}\n`;
}

function checkPin(p: { sha: string; version: string }, which: string): void {
  if (!isPlain(p) || typeof p.sha !== 'string' || !SHA_RE.test(p.sha) || typeof p.version !== 'string' || !SEMVER_RE.test(p.version)) {
    throw new PatchRefused(`Refused: the ${which} pin is not a 40-character lower-case commit and a plain x.y.z version.`);
  }
}

/**
 * A unified diff that swaps ONLY the exact rendered pin of pipegen's gate, `uses: crisworking/pipegen/gate@<from.sha> # gate-v<from.version>`
 * (the form the renderer writes), for `to`. Every other byte of every file stays identical (a test applies the patch with `git apply` and
 * diffs the result against the input). A line in another form (another sha, another version, other spacing, quotes, a comment, another
 * action) is left alone. The empty string when nothing swaps. Throws PatchRefused when `from` or `to` is not a sha and a version, or when a
 * shown line could carry text into the issue (a control or invisible character, an HTML comment marker, a very long line).
 */
export function updatePatch(files: readonly { path: string; text: string }[], from: { sha: string; version: string }, to: { sha: string; version: string }): string {
  checkPin(from, 'old');
  checkPin(to, 'new');
  return files.map((f) => filePatch(f, from, to)).join('');
}
