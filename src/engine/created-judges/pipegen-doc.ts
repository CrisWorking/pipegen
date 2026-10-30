// The PIPEGEN.md judge (v0.2 Plan D, D0b; preflight 4.2). The file is documentation Plan G writes into the user's repository; a wrong one
// could carry a link to anywhere, a notification to a stranger, raw HTML, an image beacon, a workflow expression or a secret. So:
// the path is exactly PIPEGEN.md at the root; it is a new file, or one the install record owns at an unchanged blob sha; at most
// 256 KiB; no raw HTML, no image, no `@mention` outside code, no `${{`, no control or invisible character; links only to this
// repository, docs.github.com and pipegen's own repository; none of the vault's values; and nothing findSecretLike reports.
// Restricted Markdown (the file is pipegen's own): one fence form, no reference definitions, an empty link target is foreign.
// Fenced code is exempt from the HTML, image, link and mention rules (it renders as text); inline code only from the mention rule.
// Every ambiguity is resolved toward refusing: a construct this scanner does not understand is treated as prose.
import { findSecretLike } from '../../ai/redact-core.js';
import type { CreatedFile } from '../../types.js';
import type { CreatedCtx } from '../created-files.js';

export const PIPEGEN_DOC_MAX_BYTES = 256 * 1024;
/** pipegen's own repository, lower case (package.json `repository`). */
export const PIPEGEN_REPO = 'crisworking/pipegen';

const SHA_RE = /^[0-9a-f]{40}$/;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^(?!\.+$)[A-Za-z0-9._-]{1,100}$/;
// C0 controls except tab, LF and CR; DEL and C1; zero-width, bidirectional and word-joiner controls; the BOM
const INVISIBLE_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

/** Anything after optional indentation, quote and list markers that starts 3+ backticks or tildes: a fence in a form pipegen never writes. */
const FENCE_LOOKALIKE_RE = /^[\s>\-+*]*(?:\d+[.)][\s>\-+*]*)?(?:`{3,}|~{3,})/;

/**
 * Restricted Markdown: pipegen writes this file itself, so only one fence form is accepted. A fence opens on a line that is exactly three
 * backticks at column 0 (an info string without backticks may follow) and closes on a line that is exactly three backticks at column 0.
 * Indented, tilde, longer, quoted or listed fences, a line outside a fence that looks like one, and a fence never closed are problems.
 * Returns the lines outside fences (each fenced block, with its fence lines, becomes one blank line).
 */
function proseLines(text: string): { lines: string[]; problems: string[] } {
  const lines: string[] = [];
  const problems: string[] = [];
  let inFence = false;
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (inFence) { if (line === '```') { inFence = false; lines.push(''); } continue; }
    if (/^```[^`]*$/.test(line)) { inFence = true; continue; }
    if (FENCE_LOOKALIKE_RE.test(line)) problems.push('PIPEGEN.md holds a code fence in a form pipegen does not write (it must open and close at the start of a line with exactly three backticks), so what it hides can not be checked');
    lines.push(line);
  }
  if (inFence) problems.push('PIPEGEN.md has a code fence that is never closed, so what follows it can not be checked');
  return { lines, problems: [...new Set(problems)] };
}

/** One line without its inline code spans: a backtick run closes at the next run of exactly its length on the same line; a backslash escapes the next character. */
function withoutCodeSpans(line: string): string {
  let out = '';
  for (let i = 0; i < line.length;) {
    const c = line[i] as string;
    if (c === '\\') { out += line.slice(i, i + 2); i += 2; continue; }
    if (c !== '`') { out += c; i++; continue; }
    let n = 0;
    while (line[i + n] === '`') n++;
    let j = i + n;
    let close = -1;
    while (j < line.length) {
      if (line[j] !== '`') { j++; continue; }
      let m = 0;
      while (line[j + m] === '`') m++;
      if (m === n) { close = j; break; }
      j += m;
    }
    if (close < 0) { out += line.slice(i, i + n); i += n; } else i = close + n;
  }
  return out;
}

/** An https URL to docs.github.com, to this repository or to pipegen's own, by the parsed URL (dot segments and %2e resolved, no credentials, no port). */
function allowedUrl(raw: string, owner: string, repo: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
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
  const fenced = proseLines(text);
  out.push(...fenced.problems);
  const prose = fenced.lines;
  const body = prose.join('\n');
  if (/<[A-Za-z/!?]/.test(body)) out.push('PIPEGEN.md holds raw HTML outside fenced code (a < followed by a letter, /, ! or ?)');
  if (/!\[/.test(body)) out.push('PIPEGEN.md holds an image (![), which could load a remote file');
  const dests: string[] = [];
  for (const m of body.matchAll(/\]\(\s*(<[^>\n]*>|[^\s)]*)/g)) dests.push((m[1] as string).replace(/^<|>$/g, ''));
  if (/^ {0,3}\[[^\]]*\]:/m.test(body)) out.push('PIPEGEN.md holds a link reference definition ([name]: url), which pipegen never writes; use an inline link');
  for (const m of body.matchAll(/(?:https?:\/\/|www\.)[^\s<>]*/gi)) dests.push((m[0] as string).replace(/[.,;:!?)*_~'"\]]+$/, ''));
  const foreign = dests.filter((d) => !d.startsWith('#') && !allowedUrl(d, o.owner, o.repo));
  if (foreign.length > 0) out.push(`PIPEGEN.md links to somewhere that is not this repository, docs.github.com or pipegen's own repository (for example ${JSON.stringify(foreign[0]?.slice(0, 60))})`);
  if (prose.some((l) => /@[\p{L}\p{N}_]/u.test(withoutCodeSpans(l)))) out.push('PIPEGEN.md holds an @mention outside code, which would notify someone');
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
