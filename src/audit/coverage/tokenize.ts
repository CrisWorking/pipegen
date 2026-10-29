// Coverage mapper (see ../coverage.ts for the rules): the quote-aware shell tokenizer. A leaf: it imports no other coverage
// module, so shell.ts, settings.ts, walk.ts and hooks.ts can all use it.
import { READ_LIMITS } from '../../read/limits.js';

// ---------- reading shell text (review M2: command position only; round 2: quotes, lists, groups, pipes) ----------

/**
 * One shell token: an operator (incl. '\n' between commands) or a word (`w`: quotes and escapes removed). `kw` marks a
 * reserved word that opens (if, while, until, for, select, case) or closes (fi, done, esac) a compound command.
 */
export interface Tk { op: string | null; w: string; kw: 'open' | 'close' | null } // every token has all three (one object shape)
/** Characters that end a word and are operators of their own (`&` only when not part of a redirection). */
const BREAK_CHARS = ';|&()`';
/** After these, a newline doesn't end the command list (`a ||⏎ b`, `{⏎`). */
const JOINERS = new Set(['&&', '||', '|', '(', '{', '$(', '\n']);
/** Reserved words bash reads only where a command starts, and where the next word starts a command again ('any'). */
const LEAD_WORDS: ReadonlyMap<string, Pos> = new Map([['if', 'any'], ['while', 'any'], ['until', 'any'], ['!', 'any'], ['time', 'any'], ['for', 'none'], ['select', 'none'], ['case', 'none']]);
/** Reserved words bash also reads right after a compound command ends (`} fi`, `done }`). */
const FOLLOW_WORDS: ReadonlyMap<string, Pos> = new Map([['then', 'any'], ['do', 'any'], ['else', 'any'], ['elif', 'any'], ['fi', 'close'], ['done', 'close'], ['esac', 'close']]);
const OPEN_KW = new Set(['if', 'while', 'until', 'for', 'select', 'case']);
const CLOSE_KW = new Set(['fi', 'done', 'esac']);
const MAX_WORD = READ_LIMITS.maxRegexLineBytes;
const isBlank = (ch: string | undefined) => ch === undefined || ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';
/**
 * Where the tokenizer is: 'any' = a command can start (every reserved word, `{` and `}` count); 'close' = right after a
 * compound command or a subshell ended (only `}`, `)` and the FOLLOW_WORDS count); 'none' = inside a command.
 */
type Pos = 'any' | 'close' | 'none';
/** An open parenthesis: a subshell, a `$(` substitution, `$((` / `((` arithmetic, or a parenthesis inside arithmetic. */
type Paren = 'sub' | 'cmd' | 'arith$' | 'arithcmd' | 'arith';
/** Inside `case WORD in … esac`: before `in`, at a pattern, or in an arm's commands. */
type CaseState = 'subject' | 'pattern' | 'body';

/**
 * Shell text → tokens, in one linear pass.
 * - Quoted text ('…', "…") stays inside its word, so a separator in quotes never starts a command; `${…}` / `${{ … }}`
 *   stay inside the word too; `#` at a word start comments out the rest of the line; `\` + newline joins lines.
 * - `&` is part of a redirection word after `>`/`<` or before `>` (`2>&1`, `>&2`, `<&0`, `&>`, `&>>`); `|&` is a pipe;
 *   any other single `&` runs the command in the background.
 * - `{` opens a group only where a command starts and when a blank follows it; `}` closes one only where a command
 *   starts or right after a compound command (`done }`, `fi }`, `esac }`, `) }`, `} }`). Elsewhere both are plain
 *   characters (`echo {a`, `xargs -I {}`). Unquoted reserved words count only where bash reads them.
 * - A backtick substitution `` `…` `` becomes `$(` … `)`.
 * - Here-document bodies (`<<WORD`, `<<-WORD`, quoted or not) are skipped up to the line holding WORD alone; an
 *   unterminated one skips the rest of the text. Inside `$(( … ))` and `(( … ))` a `<<` is a shift and `#` is not a
 *   comment.
 * - In `case … in`, each pattern up to its `)` is skipped and becomes a `;` (the arm's commands follow); `;;`, `;&` and
 *   `;;&` end an arm.
 * A word longer than MAX_WORD keeps an empty value (it can't name a tool).
 */
export function tokenize(text: string): Tk[] {
  const toks: Tk[] = [];
  const n = text.length;
  let i = 0;
  let pos: Pos = 'any';
  let afterFunction = false; // `function name {`: the `{` after the name opens the body
  let inBacktick = false;
  const heredocs: { delim: string; tabs: boolean }[] = [];
  let delimNext: boolean | null = null; // `<< WORD`: the next word is the delimiter (value: strip tabs)
  const parens: Paren[] = [];
  const cases: CaseState[] = [];
  const pushOp = (op: string, after: Pos = 'any') => {
    toks.push({ op, w: '', kw: null });
    pos = after;
    afterFunction = false;
  };
  /** Skips the bodies of the here-documents opened on the line that just ended; returns where the text goes on. */
  const skipHeredocs = (from: number) => {
    let at = from;
    for (const h of heredocs) {
      while (at < n) {
        const nl = text.indexOf('\n', at);
        const stop = nl < 0 ? n : nl;
        let a = at;
        if (h.tabs) while (a < stop && text[a] === '\t') a++;
        const b = stop > a && text[stop - 1] === '\r' ? stop - 1 : stop;
        const done = text.slice(a, b) === h.delim;
        at = nl < 0 ? n : nl + 1;
        if (done) break;
      }
    }
    heredocs.length = 0;
    return at;
  };
  /** Skips a case pattern (`a|b)`, `(a)`, `@(x|y))`) up to the `)` that ends it; returns the index after that `)`. */
  const skipPattern = (from: number) => {
    let j = text[from] === '(' ? from + 1 : from;
    let depth = 0;
    while (j < n) {
      const ch = text[j] as string;
      if (ch === '\\') j += 2;
      else if (ch === "'") {
        const e = text.indexOf("'", j + 1);
        j = e < 0 ? n : e + 1;
      } else if (ch === '"') {
        j++;
        while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
        j++;
      } else if (ch === '(') {
        depth++;
        j++;
      } else if (ch === ')') {
        if (depth === 0) return j + 1;
        depth--;
        j++;
      } else j++;
    }
    return n;
  };
  while (i < n) {
    const c = text[i] as string;
    const next = text[i + 1];
    // (length checks first: reading index -1 of an empty array is a slow lookup in V8)
    const top = parens.length > 0 ? parens[parens.length - 1] : undefined;
    const arith = top === 'arith$' || top === 'arithcmd' || top === 'arith';
    const inCase = arith || cases.length === 0 ? undefined : cases[cases.length - 1];
    if (c === '\n') {
      const last = toks[toks.length - 1];
      if (last !== undefined && !(last.op !== null && JOINERS.has(last.op))) toks.push({ op: '\n', w: '', kw: null });
      pos = 'any';
      i = heredocs.length > 0 ? skipHeredocs(i + 1) : i + 1;
    } else if (c === ' ' || c === '\t' || c === '\r') {
      i++;
    } else if (c === '\\' && (next === '\n' || (next === '\r' && text[i + 2] === '\n'))) {
      i += next === '\n' ? 2 : 3;
    } else if (c === '#' && !arith) {
      while (i < n && text[i] !== '\n') i++;
    } else if (inCase === 'pattern') {
      if (text.startsWith('esac', i) && (isBlank(text[i + 4]) || BREAK_CHARS.includes(text[i + 4] as string))) {
        cases.pop();
        toks.push({ op: null, w: 'esac', kw: 'close' });
        pos = 'close';
        afterFunction = false;
        i += 4;
      } else {
        i = skipPattern(i);
        cases[cases.length - 1] = 'body';
        pushOp(';');
      }
    } else if (c === ';' && inCase === 'body' && (next === ';' || next === '&')) { // ;; ;& ;;& end a case arm
      i += next === ';' && text[i + 2] === '&' ? 3 : 2;
      cases[cases.length - 1] = 'pattern';
      pushOp(';');
    } else if (c === '$' && next === '(') {
      parens.push(text[i + 2] === '(' ? 'arith$' : 'cmd'); // a $( … ) inside arithmetic is a command again
      pushOp('$(');
      i += 2;
    } else if (c === '`') {
      pushOp(inBacktick ? ')' : '$(', inBacktick ? 'none' : 'any');
      inBacktick = !inBacktick;
      i++;
    } else if ((c === '&' || c === '|') && next === c) {
      pushOp(c + c);
      i += 2;
    } else if (c === '|' && next === '&') { // |& pipes stderr too
      pushOp('|');
      i += 2;
    } else if (c === '&' && next !== '>') {
      pushOp('&');
      i++;
    } else if (c === ';' || c === '|') {
      pushOp(c);
      i++;
    } else if (c === '(') {
      // `((` where a command starts, or after `for`, is arithmetic (bash reads it so first)
      const prev = toks[toks.length - 1];
      const arithCmd = next === '(' && (pos === 'any' || (prev !== undefined && prev.kw === 'open' && prev.w === 'for'));
      parens.push(arith ? 'arith' : arithCmd ? 'arithcmd' : 'sub');
      pushOp('(');
      i++;
    } else if (c === ')') {
      const p = parens.pop();
      const fnParens = toks[toks.length - 1]?.op === '('; // `name()`: a function body (a compound command) follows
      pushOp(')', fnParens ? 'any' : p === 'cmd' || p === 'arith$' || p === 'arith' ? 'none' : 'close');
      i++;
    } else if (c === '{' && (pos === 'any' || afterFunction) && isBlank(next)) {
      pushOp('{');
      i++;
    } else if (c === '}' && pos !== 'none') {
      pushOp('}', 'close');
      i++;
    } else {
      let w = '';
      let quote = '';
      let quoted = false;
      let brace = ''; // '}' or '}}' while inside ${…} / ${{ … }}
      const add = (ch: string) => {
        if (w.length <= MAX_WORD) w += ch;
      };
      const start = i;
      while (i < n) {
        const ch = text[i] as string;
        if (brace !== '') {
          if (text.startsWith(brace, i)) {
            i += brace.length;
            brace = '';
          } else i++;
          add(ch);
          continue;
        }
        if (quote !== '') {
          if (ch === quote) quote = '';
          else if (ch === '\\' && quote === '"' && i + 1 < n) add(text[++i] as string);
          else add(ch);
          i++;
          continue;
        }
        if (ch === '"' || ch === "'") {
          quote = ch;
          quoted = true;
          i++;
          continue;
        }
        if (ch === '\\' && i + 1 < n) {
          if (text[i + 1] === '\n') break;
          add(text[i + 1] as string);
          quoted = true;
          i += 2;
          continue;
        }
        if (ch === '$' && text[i + 1] === '{') {
          brace = text[i + 2] === '{' ? '}}' : '}';
          add(ch);
          i++;
          continue;
        }
        if (ch === '&' && (text[i + 1] === '>' || text[i - 1] === '>' || text[i - 1] === '<')) { // a redirection: 2>&1, &>
          add(ch);
          i++;
          continue;
        }
        if (ch === '<' && text[i + 1] === '<' && i > start && text[i - 1] !== '<') break; // cat<<EOF: `<<` starts a word
        if (isBlank(ch) || BREAK_CHARS.includes(ch) || (ch === '$' && text[i + 1] === '(')) break;
        add(ch);
        i++;
      }
      const value = w.length > MAX_WORD ? '' : w;
      const tk: Tk = { op: null, w: value, kw: null };
      toks.push(tk);
      // A reserved word counts only unquoted, outside arithmetic, and where bash reads it.
      const reserved = !quoted && !arith;
      const at = pos as Pos; // pushOp (a closure) also sets pos, so TypeScript's narrowing doesn't apply here
      const lead = reserved && at === 'any' ? LEAD_WORDS.get(value) : undefined;
      const follow = reserved && at !== 'none' ? FOLLOW_WORDS.get(value) : undefined;
      if (lead !== undefined || follow !== undefined) {
        if (OPEN_KW.has(value)) tk.kw = 'open';
        if (CLOSE_KW.has(value)) tk.kw = 'close';
        if (value === 'case') cases.push('subject');
        if (value === 'esac' && inCase !== undefined) cases.pop();
      } else if (reserved && value === 'in' && inCase === 'subject') {
        cases[cases.length - 1] = 'pattern';
      }
      pos = lead ?? follow ?? 'none';
      const prev = toks[toks.length - 2];
      afterFunction = prev !== undefined && prev.op === null && prev.w === 'function'; // this word names the function
      if (delimNext !== null) {
        heredocs.push({ delim: value, tabs: delimNext });
        delimNext = null;
      } else if (!arith && value.startsWith('<<') && !value.startsWith('<<<')) {
        const tabs = value[2] === '-';
        const delim = value.slice(tabs ? 3 : 2);
        if (delim === '') delimNext = tabs;
        else heredocs.push({ delim, tabs });
      }
    }
  }
  return toks;
}
