// The PIPEGEN.md judge (v0.2 Plan D, D0b; preflight 4.2). The file is documentation Plan G writes into the user's repository; a wrong one
// could carry a link to anywhere, a notification to a stranger, raw HTML, an image beacon, a workflow expression or a secret.
// pipegen writes this file itself, so the judge accepts a RESTRICTED MARKDOWN SUBSET by a line allowlist and fails closed on all else
// (a denylist always leaks: Markdown renderers differ on fences, reference definitions and HTML). Outside a fence every line is exactly one of:
//   empty | heading `#{1,4} text` | list item `- text` or `  - text` | table row `| ... |` or a separator row of `| - :` and spaces |
//   a fence opener (exactly three backticks at column 0, then nothing or one of yaml sh bash json text) | plain text.
// `text` has only letters, digits, space and  . , ; : ! ? ' " ( ) / - _ + = % * ~  (no `&`: character references can decode into forbidden
// characters), plus inline code (`...`, same characters) and inline links [label](url) whose url is this repository, docs.github.com or
// pipegen's repository. A bare URL (any scheme:// , found as "://" so the scan is linear, or www.) is refused: a link is always inline. `<` `>` `[` `]` `\` `@` `${{` `#` `|` `$` and
// every other character are refused.
// Inside a fence a line is free text, except one that starts 3+ backticks or tildes and is not exactly three backticks; the fence closes only on an
// exact three-backtick line, and an unclosed fence is refused. Also: size, control and invisible characters, the vault's values and findSecretLike.
// Plan G must produce the file with a pure builder, and the referee must recompute it and require equality (this judge is the net under that).
import { findSecretLike } from '../../ai/redact-core.js';
import type { CreatedFile } from '../../types.js';
import type { CreatedCtx } from '../created-files.js';

export const PIPEGEN_DOC_MAX_BYTES = 256 * 1024;
/** pipegen's own repository, lower case (package.json `repository`). */
export const PIPEGEN_REPO = 'crisworking/pipegen';

const SHA_RE = /^[0-9a-f]{40}$/;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^(?!\.+$)[A-Za-z0-9._-]{1,100}$/;
// C0 controls except tab, LF and CR; DEL and C1 (Cc); every format character (Cf: zero-width, bidirectional, soft hyphen, BOM, the tag characters,
// U+061C), line and paragraph separators (Zl, Zp), private use (Co), and the blank-looking Hangul fillers (Lo). All of them also inside fences.
const INVISIBLE_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}\p{Co}\u3164\u115f\u1160\uffa0]/u;

const TEXT_CH = /^[\p{L}\p{N} .,;:!?'"()/\-_+=%*~]$/u;
const URL_CH = /^[A-Za-z0-9._~:/?#&=%+-]+$/;
const FENCE_START_RE = /^\s*(?:`{3,}|~{3,})/;
/** The only info strings: GitHub renders mermaid, math, geojson, topojson, stl and others as active content. */
const OPENER_RE = /^```(?:yaml|sh|bash|json|text)?$/;
const LINK_RE = /^\[([^[\]`]*)\]\(([^\s()<>[\]`]*)\)/;

/** The reason a character may not appear in text (`null` if it may). */
function charProblem(c: string): string | null {
  if (c === '<') return 'raw HTML (a <)';
  if (c === '>') return 'a > (HTML or a quote)';
  if (c === '@') return 'an @ (a mention would notify someone)';
  if (c === '\\') return 'a backslash';
  if (c === '[' || c === ']') return 'a [ or ] that is not an inline link to an allowed address (a link, image or reference definition)';
  return TEXT_CH.test(c) ? null : `a character that is not allowed (${JSON.stringify(c)})`;
}

/** Whether `text` (one line, or one table cell) is made only of the allowed pieces; the reason if not. */
function textProblem(t: string, o: PipegenDocOpts): string | null {
  if (t === '') return 'an empty heading, list item or text';
  if (t.startsWith(' ')) return 'text that starts with a space (an indented line)';
  if (/\p{Mn}/u.test(t)) return 'a combining mark or variation selector (not allowed outside code fences)';
  if (/~{3,}/.test(t)) return 'a run of three tildes (a code fence in a form pipegen does not write)';
  let outside = '';   // the text outside inline-link urls: no scheme:// or www. may appear there
  for (let i = 0; i < t.length;) {
    const c = t[i] as string;
    if (c === '`') {
      let n = 0;
      while (t[i + n] === '`') n++;
      if (n !== 1) return 'a run of backticks (a code fence or span in a form pipegen does not write)';
      const j = t.indexOf('`', i + 1);
      if (j < 0 || t[j + 1] === '`') return 'an inline code span that is not closed';
      for (const ch of t.slice(i + 1, j)) { const bad = charProblem(ch); if (bad !== null) return bad; }
      outside += ` ${t.slice(i + 1, j)} `;
      i = j + 1;
      continue;
    }
    if (c === '[') {
      if (t[i - 1] === '!') return 'an image (![), which could load a remote file';
      const m = LINK_RE.exec(t.slice(i));
      if (m === null) return charProblem(c);
      const label = m[1] as string, url = m[2] as string;
      for (const ch of label) { const bad = charProblem(ch); if (bad !== null) return bad; }
      if (label === '' || !URL_CH.test(url) || !allowedUrl(url, o.owner, o.repo)) return 'a link that is not this repository, docs.github.com or pipegen\'s own repository';
      outside += ` ${label} `;
      i += m[0].length;
      continue;
    }
    const bad = charProblem(c);
    if (bad !== null) return bad;
    outside += c;
    i++;
  }
  if (/:[A-Za-z0-9_+-]+:/.test(outside)) return 'an emoji shortcode (:name:), which GitHub renders as an image';
  if (outside.includes('://') || /www\./i.test(outside)) return 'a bare URL (a link must be an inline [label](url) to this repository, docs.github.com or pipegen\'s own repository)';
  return null;
}

/** The problems of the whole text under the line grammar (one entry per distinct reason). */
function grammarProblems(text: string, o: PipegenDocOpts): string[] {
  const found = new Set<string>();
  const say = (m: string) => found.add(`PIPEGEN.md holds ${m}`);
  let inFence = false;
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (inFence) {
      if (line === '```') inFence = false;
      else if (FENCE_START_RE.test(line)) say('a line inside a code fence that looks like a fence marker but is not exactly three backticks (a renderer may close the fence there)');
      continue;
    }
    if (line === '') continue;
    if (OPENER_RE.test(line)) { inFence = true; continue; }
    if (FENCE_START_RE.test(line)) { say('a code fence in a form pipegen does not write (it must be exactly three backticks at the start of a line, with no info string or one of yaml, sh, bash, json, text)'); continue; }
    let why: string | null;
    const h = /^#{1,4} (.*)$/.exec(line);
    const li = /^(?:- |  - )(.*)$/.exec(line);
    if (h !== null) why = textProblem(h[1] as string, o);
    else if (li !== null) why = textProblem(li[1] as string, o);
    else if (line.startsWith('|')) {
      if (/^[|\-: ]+$/.test(line)) why = null;
      else if (line.length >= 2 && line.endsWith('|')) {
        why = null;
        for (const cell of line.slice(1, -1).split('|')) {
          const c = cell.replace(/^ +| +$/g, '');
          if (c !== '' && (why = textProblem(c, o)) !== null) break;
        }
      } else why = 'a table row that is not closed with |';
    } else why = textProblem(line, o);
    if (why !== null) say(why);
  }
  if (inFence) say('a code fence that is never closed, so what follows it can not be checked');
  return [...found];
}

/** An https URL to docs.github.com, to this repository or to pipegen's own, by the parsed URL (dot segments and %2e resolved, no credentials, no port). */
function allowedUrl(raw: string, owner: string, repo: string): boolean {
  // exactly `https://`, and the text is its own normal form: `https:/x`, `https:x`, an upper-case scheme or host, dot segments and %2e would be
  // read by a browser differently from `new URL` without a base (D0b review finding 1)
  if (!raw.startsWith('https://')) return false;
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (u.href !== raw) return false;
  if (u.protocol !== 'https:' || u.username !== '' || u.password !== '' || u.port !== '') return false;
  if (u.hostname === 'docs.github.com') return true;
  if (u.hostname !== 'github.com') return false;
  const path = u.pathname.toLowerCase();
  return [`${owner}/${repo}`.toLowerCase(), PIPEGEN_REPO].some((r) => path === `/${r}` || path.startsWith(`/${r}/`));
}

export interface PipegenDocOpts { owner: string; repo: string; containsKnownValue: (text: string) => boolean }

export function pipegenDocProblems(text: string, o: PipegenDocOpts): string[] {
  const out: string[] = [];
  if (Buffer.byteLength(text, 'utf8') > PIPEGEN_DOC_MAX_BYTES) out.push('PIPEGEN.md is over 256 KiB');
  if (INVISIBLE_RE.test(text)) out.push('PIPEGEN.md holds a control or invisible character (NUL, escape, zero-width or bidirectional control)');
  if (text.includes('${{')) out.push('PIPEGEN.md holds ${{, a workflow expression');
  out.push(...grammarProblems(text, o));
  try { if (o.containsKnownValue(text)) out.push('PIPEGEN.md holds a secret value the user typed (or its encoded form)'); } catch { out.push('the check for typed secret values failed, so PIPEGEN.md is not written'); }
  const found = findSecretLike(text);
  if (found.length > 0) out.push(`PIPEGEN.md holds text that looks like a secret (${found.slice(0, 3).join(', ')})`);
  return out;
}

export function pipegenDocJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  const doc = ctx.inputs.pipegenDoc;
  if (doc === undefined) return ['the install record and the base commit were not given to the referee, so it can not tell whether PIPEGEN.md is new or owned by pipegen'];
  if (ctx.inputs.containsKnownValue === undefined) return ['the check for typed secret values (the vault) was not given to the referee, so PIPEGEN.md is not written'];
  if ((doc.baseSha !== null && !SHA_RE.test(doc.baseSha)) || (doc.recordSha !== null && !SHA_RE.test(doc.recordSha))) return ['a blob sha given for PIPEGEN.md is not a 40-character sha'];
  if (doc.baseSha !== null && doc.baseSha !== doc.recordSha) return ['a PIPEGEN.md already exists and the install record does not own it at this version (the user changed it, or pipegen did not write it), so it is kept and not replaced'];
  const { owner, repo } = ctx.draft.profile;
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo)) return ['the repository name is not a plain GitHub name'];
  if (typeof file.content !== 'string') return ['the content is not text'];
  return pipegenDocProblems(file.content, { owner, repo, containsKnownValue: ctx.inputs.containsKnownValue });
}
