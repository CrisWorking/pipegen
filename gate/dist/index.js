var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// node_modules/picomatch/lib/constants.js
var require_constants = __commonJS({
  "node_modules/picomatch/lib/constants.js"(exports, module) {
    "use strict";
    var WIN_SLASH = "\\\\/";
    var WIN_NO_SLASH = `[^${WIN_SLASH}]`;
    var DEFAULT_MAX_EXTGLOB_RECURSION = 0;
    var DOT_LITERAL = "\\.";
    var PLUS_LITERAL = "\\+";
    var QMARK_LITERAL = "\\?";
    var SLASH_LITERAL = "\\/";
    var ONE_CHAR = "(?=.)";
    var QMARK = "[^/]";
    var END_ANCHOR = `(?:${SLASH_LITERAL}|$)`;
    var START_ANCHOR = `(?:^|${SLASH_LITERAL})`;
    var DOTS_SLASH = `${DOT_LITERAL}{1,2}${END_ANCHOR}`;
    var NO_DOT = `(?!${DOT_LITERAL})`;
    var NO_DOTS = `(?!${START_ANCHOR}${DOTS_SLASH})`;
    var NO_DOT_SLASH = `(?!${DOT_LITERAL}{0,1}${END_ANCHOR})`;
    var NO_DOTS_SLASH = `(?!${DOTS_SLASH})`;
    var QMARK_NO_DOT = `[^.${SLASH_LITERAL}]`;
    var STAR = `${QMARK}*?`;
    var SEP = "/";
    var POSIX_CHARS = {
      DOT_LITERAL,
      PLUS_LITERAL,
      QMARK_LITERAL,
      SLASH_LITERAL,
      ONE_CHAR,
      QMARK,
      END_ANCHOR,
      DOTS_SLASH,
      NO_DOT,
      NO_DOTS,
      NO_DOT_SLASH,
      NO_DOTS_SLASH,
      QMARK_NO_DOT,
      STAR,
      START_ANCHOR,
      SEP
    };
    var WINDOWS_CHARS = {
      ...POSIX_CHARS,
      SLASH_LITERAL: `[${WIN_SLASH}]`,
      QMARK: WIN_NO_SLASH,
      STAR: `${WIN_NO_SLASH}*?`,
      DOTS_SLASH: `${DOT_LITERAL}{1,2}(?:[${WIN_SLASH}]|$)`,
      NO_DOT: `(?!${DOT_LITERAL})`,
      NO_DOTS: `(?!(?:^|[${WIN_SLASH}])${DOT_LITERAL}{1,2}(?:[${WIN_SLASH}]|$))`,
      NO_DOT_SLASH: `(?!${DOT_LITERAL}{0,1}(?:[${WIN_SLASH}]|$))`,
      NO_DOTS_SLASH: `(?!${DOT_LITERAL}{1,2}(?:[${WIN_SLASH}]|$))`,
      QMARK_NO_DOT: `[^.${WIN_SLASH}]`,
      START_ANCHOR: `(?:^|[${WIN_SLASH}])`,
      END_ANCHOR: `(?:[${WIN_SLASH}]|$)`,
      SEP: "\\"
    };
    var POSIX_REGEX_SOURCE = {
      __proto__: null,
      alnum: "a-zA-Z0-9",
      alpha: "a-zA-Z",
      ascii: "\\x00-\\x7F",
      blank: " \\t",
      cntrl: "\\x00-\\x1F\\x7F",
      digit: "0-9",
      graph: "\\x21-\\x7E",
      lower: "a-z",
      print: "\\x20-\\x7E ",
      punct: "\\-!\"#$%&'()\\*+,./:;<=>?@[\\]^_`{|}~",
      space: " \\t\\r\\n\\v\\f",
      upper: "A-Z",
      word: "A-Za-z0-9_",
      xdigit: "A-Fa-f0-9"
    };
    module.exports = {
      DEFAULT_MAX_EXTGLOB_RECURSION,
      MAX_LENGTH: 1024 * 64,
      POSIX_REGEX_SOURCE,
      // regular expressions
      REGEX_BACKSLASH: /\\(?![*+?^${}(|)[\]])/g,
      REGEX_NON_SPECIAL_CHARS: /^[^@![\].,$*+?^{}()|\\/]+/,
      REGEX_SPECIAL_CHARS: /[-*+?.^${}(|)[\]]/,
      REGEX_SPECIAL_CHARS_BACKREF: /(\\?)((\W)(\3*))/g,
      REGEX_SPECIAL_CHARS_GLOBAL: /([-*+?.^${}(|)[\]])/g,
      REGEX_REMOVE_BACKSLASH: /(?:\[.*?[^\\]\]|\\(?=.))/g,
      // Replace globs with equivalent patterns to reduce parsing time.
      REPLACEMENTS: {
        __proto__: null,
        "***": "*",
        "**/**": "**",
        "**/**/**": "**"
      },
      // Digits
      CHAR_0: 48,
      /* 0 */
      CHAR_9: 57,
      /* 9 */
      // Alphabet chars.
      CHAR_UPPERCASE_A: 65,
      /* A */
      CHAR_LOWERCASE_A: 97,
      /* a */
      CHAR_UPPERCASE_Z: 90,
      /* Z */
      CHAR_LOWERCASE_Z: 122,
      /* z */
      CHAR_LEFT_PARENTHESES: 40,
      /* ( */
      CHAR_RIGHT_PARENTHESES: 41,
      /* ) */
      CHAR_ASTERISK: 42,
      /* * */
      // Non-alphabetic chars.
      CHAR_AMPERSAND: 38,
      /* & */
      CHAR_AT: 64,
      /* @ */
      CHAR_BACKWARD_SLASH: 92,
      /* \ */
      CHAR_CARRIAGE_RETURN: 13,
      /* \r */
      CHAR_CIRCUMFLEX_ACCENT: 94,
      /* ^ */
      CHAR_COLON: 58,
      /* : */
      CHAR_COMMA: 44,
      /* , */
      CHAR_DOT: 46,
      /* . */
      CHAR_DOUBLE_QUOTE: 34,
      /* " */
      CHAR_EQUAL: 61,
      /* = */
      CHAR_EXCLAMATION_MARK: 33,
      /* ! */
      CHAR_FORM_FEED: 12,
      /* \f */
      CHAR_FORWARD_SLASH: 47,
      /* / */
      CHAR_GRAVE_ACCENT: 96,
      /* ` */
      CHAR_HASH: 35,
      /* # */
      CHAR_HYPHEN_MINUS: 45,
      /* - */
      CHAR_LEFT_ANGLE_BRACKET: 60,
      /* < */
      CHAR_LEFT_CURLY_BRACE: 123,
      /* { */
      CHAR_LEFT_SQUARE_BRACKET: 91,
      /* [ */
      CHAR_LINE_FEED: 10,
      /* \n */
      CHAR_NO_BREAK_SPACE: 160,
      /* \u00A0 */
      CHAR_PERCENT: 37,
      /* % */
      CHAR_PLUS: 43,
      /* + */
      CHAR_QUESTION_MARK: 63,
      /* ? */
      CHAR_RIGHT_ANGLE_BRACKET: 62,
      /* > */
      CHAR_RIGHT_CURLY_BRACE: 125,
      /* } */
      CHAR_RIGHT_SQUARE_BRACKET: 93,
      /* ] */
      CHAR_SEMICOLON: 59,
      /* ; */
      CHAR_SINGLE_QUOTE: 39,
      /* ' */
      CHAR_SPACE: 32,
      /*   */
      CHAR_TAB: 9,
      /* \t */
      CHAR_UNDERSCORE: 95,
      /* _ */
      CHAR_VERTICAL_LINE: 124,
      /* | */
      CHAR_ZERO_WIDTH_NOBREAK_SPACE: 65279,
      /* \uFEFF */
      /**
       * Create EXTGLOB_CHARS
       */
      extglobChars(chars) {
        return {
          "!": { type: "negate", open: "(?:(?!(?:", close: `))${chars.STAR})` },
          "?": { type: "qmark", open: "(?:", close: ")?" },
          "+": { type: "plus", open: "(?:", close: ")+" },
          "*": { type: "star", open: "(?:", close: ")*" },
          "@": { type: "at", open: "(?:", close: ")" }
        };
      },
      /**
       * Create GLOB_CHARS
       */
      globChars(win32) {
        return win32 === true ? WINDOWS_CHARS : POSIX_CHARS;
      }
    };
  }
});

// node_modules/picomatch/lib/utils.js
var require_utils = __commonJS({
  "node_modules/picomatch/lib/utils.js"(exports) {
    "use strict";
    var {
      REGEX_BACKSLASH,
      REGEX_REMOVE_BACKSLASH,
      REGEX_SPECIAL_CHARS,
      REGEX_SPECIAL_CHARS_GLOBAL
    } = require_constants();
    exports.isObject = (val) => val !== null && typeof val === "object" && !Array.isArray(val);
    exports.hasRegexChars = (str2) => REGEX_SPECIAL_CHARS.test(str2);
    exports.isRegexChar = (str2) => str2.length === 1 && exports.hasRegexChars(str2);
    exports.escapeRegex = (str2) => str2.replace(REGEX_SPECIAL_CHARS_GLOBAL, "\\$1");
    exports.toPosixSlashes = (str2) => str2.replace(REGEX_BACKSLASH, "/");
    exports.isWindows = () => {
      if (typeof navigator !== "undefined" && navigator.platform) {
        const platform = navigator.platform.toLowerCase();
        return platform === "win32" || platform === "windows";
      }
      if (typeof process !== "undefined" && process.platform) {
        return process.platform === "win32";
      }
      return false;
    };
    exports.removeBackslashes = (str2) => {
      return str2.replace(REGEX_REMOVE_BACKSLASH, (match) => {
        return match === "\\" ? "" : match;
      });
    };
    exports.escapeLast = (input, char, lastIdx) => {
      const idx = input.lastIndexOf(char, lastIdx);
      if (idx === -1) return input;
      if (input[idx - 1] === "\\") return exports.escapeLast(input, char, idx - 1);
      return `${input.slice(0, idx)}\\${input.slice(idx)}`;
    };
    exports.removePrefix = (input, state = {}) => {
      let output = input;
      if (output.startsWith("./")) {
        output = output.slice(2);
        state.prefix = "./";
      }
      return output;
    };
    exports.wrapOutput = (input, state = {}, options = {}) => {
      const prepend = options.contains ? "" : "^";
      const append = options.contains ? "" : "$";
      let output = `${prepend}(?:${input})${append}`;
      if (state.negated === true) {
        output = `(?:^(?!${output}).*$)`;
      }
      return output;
    };
    exports.basename = (path, { windows } = {}) => {
      const segs = path.split(windows ? /[\\/]/ : "/");
      const last = segs[segs.length - 1];
      if (last === "") {
        return segs[segs.length - 2];
      }
      return last;
    };
  }
});

// node_modules/picomatch/lib/scan.js
var require_scan = __commonJS({
  "node_modules/picomatch/lib/scan.js"(exports, module) {
    "use strict";
    var utils = require_utils();
    var {
      CHAR_ASTERISK,
      /* * */
      CHAR_AT,
      /* @ */
      CHAR_BACKWARD_SLASH,
      /* \ */
      CHAR_COMMA,
      /* , */
      CHAR_DOT,
      /* . */
      CHAR_EXCLAMATION_MARK,
      /* ! */
      CHAR_FORWARD_SLASH,
      /* / */
      CHAR_LEFT_CURLY_BRACE,
      /* { */
      CHAR_LEFT_PARENTHESES,
      /* ( */
      CHAR_LEFT_SQUARE_BRACKET,
      /* [ */
      CHAR_PLUS,
      /* + */
      CHAR_QUESTION_MARK,
      /* ? */
      CHAR_RIGHT_CURLY_BRACE,
      /* } */
      CHAR_RIGHT_PARENTHESES,
      /* ) */
      CHAR_RIGHT_SQUARE_BRACKET
      /* ] */
    } = require_constants();
    var isPathSeparator = (code3) => {
      return code3 === CHAR_FORWARD_SLASH || code3 === CHAR_BACKWARD_SLASH;
    };
    var depth = (token) => {
      if (token.isPrefix !== true) {
        token.depth = token.isGlobstar ? Infinity : 1;
      }
    };
    var scan = (input, options) => {
      const opts = options || {};
      const length = input.length - 1;
      const scanToEnd = opts.parts === true || opts.tokens === true || opts.scanToEnd === true;
      const slashes = [];
      const tokens2 = [];
      const parts = [];
      let str2 = input;
      let index = -1;
      let start = 0;
      let lastIndex = 0;
      let isBrace = false;
      let isBracket = false;
      let isGlob = false;
      let isExtglob = false;
      let isGlobstar = false;
      let braceEscaped = false;
      let backslashes = false;
      let negated = false;
      let negatedExtglob = false;
      let finished = false;
      let braces = 0;
      let prev;
      let code3;
      let token = { value: "", depth: 0, isGlob: false };
      const eos = () => index >= length;
      const peek = () => str2.charCodeAt(index + 1);
      const advance = () => {
        prev = code3;
        return str2.charCodeAt(++index);
      };
      while (index < length) {
        code3 = advance();
        let next;
        if (code3 === CHAR_BACKWARD_SLASH) {
          backslashes = token.backslashes = true;
          code3 = advance();
          if (code3 === CHAR_LEFT_CURLY_BRACE) {
            braceEscaped = true;
          }
          continue;
        }
        if (braceEscaped === true || code3 === CHAR_LEFT_CURLY_BRACE) {
          braces++;
          while (eos() !== true && (code3 = advance())) {
            if (code3 === CHAR_BACKWARD_SLASH) {
              backslashes = token.backslashes = true;
              advance();
              continue;
            }
            if (code3 === CHAR_LEFT_CURLY_BRACE) {
              braces++;
              continue;
            }
            if (braceEscaped !== true && code3 === CHAR_DOT && (code3 = advance()) === CHAR_DOT) {
              isBrace = token.isBrace = true;
              isGlob = token.isGlob = true;
              finished = true;
              if (scanToEnd === true) {
                continue;
              }
              break;
            }
            if (braceEscaped !== true && code3 === CHAR_COMMA) {
              isBrace = token.isBrace = true;
              isGlob = token.isGlob = true;
              finished = true;
              if (scanToEnd === true) {
                continue;
              }
              break;
            }
            if (code3 === CHAR_RIGHT_CURLY_BRACE) {
              braces--;
              if (braces === 0) {
                braceEscaped = false;
                isBrace = token.isBrace = true;
                finished = true;
                break;
              }
            }
          }
          if (scanToEnd === true) {
            continue;
          }
          break;
        }
        if (code3 === CHAR_FORWARD_SLASH) {
          slashes.push(index);
          tokens2.push(token);
          token = { value: "", depth: 0, isGlob: false };
          if (finished === true) continue;
          if (prev === CHAR_DOT && index === start + 1) {
            start += 2;
            continue;
          }
          lastIndex = index + 1;
          continue;
        }
        if (opts.noext !== true) {
          const isExtglobChar = code3 === CHAR_PLUS || code3 === CHAR_AT || code3 === CHAR_ASTERISK || code3 === CHAR_QUESTION_MARK || code3 === CHAR_EXCLAMATION_MARK;
          if (isExtglobChar === true && peek() === CHAR_LEFT_PARENTHESES) {
            isGlob = token.isGlob = true;
            isExtglob = token.isExtglob = true;
            finished = true;
            if (code3 === CHAR_EXCLAMATION_MARK && index === start) {
              negatedExtglob = true;
            }
            if (scanToEnd === true) {
              let parens = 0;
              while (eos() !== true && (code3 = advance())) {
                if (code3 === CHAR_BACKWARD_SLASH) {
                  backslashes = token.backslashes = true;
                  advance();
                  continue;
                }
                if (code3 === CHAR_LEFT_PARENTHESES) {
                  parens++;
                  continue;
                }
                if (code3 === CHAR_RIGHT_PARENTHESES && --parens === 0) {
                  finished = true;
                  break;
                }
              }
              continue;
            }
            break;
          }
        }
        if (code3 === CHAR_ASTERISK) {
          if (prev === CHAR_ASTERISK) isGlobstar = token.isGlobstar = true;
          isGlob = token.isGlob = true;
          finished = true;
          if (scanToEnd === true) {
            continue;
          }
          break;
        }
        if (code3 === CHAR_QUESTION_MARK) {
          isGlob = token.isGlob = true;
          finished = true;
          if (scanToEnd === true) {
            continue;
          }
          break;
        }
        if (code3 === CHAR_LEFT_SQUARE_BRACKET) {
          while (eos() !== true && (next = advance())) {
            if (next === CHAR_BACKWARD_SLASH) {
              backslashes = token.backslashes = true;
              advance();
              continue;
            }
            if (next === CHAR_RIGHT_SQUARE_BRACKET) {
              isBracket = token.isBracket = true;
              isGlob = token.isGlob = true;
              finished = true;
              break;
            }
          }
          if (scanToEnd === true) {
            continue;
          }
          break;
        }
        if (opts.nonegate !== true && code3 === CHAR_EXCLAMATION_MARK && index === start) {
          negated = token.negated = true;
          start++;
          continue;
        }
        if (opts.noparen !== true && code3 === CHAR_LEFT_PARENTHESES) {
          isGlob = token.isGlob = true;
          if (scanToEnd === true) {
            let parens = 1;
            while (eos() !== true && (code3 = advance())) {
              if (code3 === CHAR_BACKWARD_SLASH) {
                backslashes = token.backslashes = true;
                advance();
                continue;
              }
              if (code3 === CHAR_LEFT_PARENTHESES) {
                parens++;
                continue;
              }
              if (code3 === CHAR_RIGHT_PARENTHESES && --parens === 0) {
                finished = true;
                break;
              }
            }
            continue;
          }
          break;
        }
        if (isGlob === true) {
          finished = true;
          if (scanToEnd === true) {
            continue;
          }
          break;
        }
      }
      if (opts.noext === true) {
        isExtglob = false;
        isGlob = false;
      }
      let base = str2;
      let prefix = "";
      let glob = "";
      if (start > 0) {
        prefix = str2.slice(0, start);
        str2 = str2.slice(start);
        lastIndex -= start;
      }
      if (base && isGlob === true && lastIndex > 0) {
        base = str2.slice(0, lastIndex);
        glob = str2.slice(lastIndex);
      } else if (isGlob === true) {
        base = "";
        glob = str2;
      } else {
        base = str2;
      }
      if (base && base !== "" && base !== "/" && base !== str2) {
        if (isPathSeparator(base.charCodeAt(base.length - 1))) {
          base = base.slice(0, -1);
        }
      }
      if (opts.unescape === true) {
        if (glob) glob = utils.removeBackslashes(glob);
        if (base && backslashes === true) {
          base = utils.removeBackslashes(base);
        }
      }
      const state = {
        prefix,
        input,
        start,
        base,
        glob,
        isBrace,
        isBracket,
        isGlob,
        isExtglob,
        isGlobstar,
        negated,
        negatedExtglob
      };
      if (opts.tokens === true) {
        state.maxDepth = 0;
        if (!isPathSeparator(code3)) {
          tokens2.push(token);
        }
        state.tokens = tokens2;
      }
      if (opts.parts === true || opts.tokens === true) {
        let prevIndex;
        for (let idx = 0; idx < slashes.length; idx++) {
          const n2 = prevIndex !== void 0 ? prevIndex + 1 : start;
          const i = slashes[idx];
          const value2 = input.slice(n2, i);
          if (opts.tokens) {
            if (idx === 0 && start !== 0) {
              tokens2[idx].isPrefix = true;
              tokens2[idx].value = prefix;
            } else {
              tokens2[idx].value = value2;
            }
            depth(tokens2[idx]);
            state.maxDepth += tokens2[idx].depth;
          }
          if (i >= start) {
            parts.push(value2);
            prevIndex = i;
          }
        }
        const n = prevIndex !== void 0 ? prevIndex + 1 : start;
        const value = input.slice(n);
        parts.push(value);
        if (opts.tokens && prevIndex && prevIndex + 1 < input.length) {
          tokens2[tokens2.length - 1].value = value;
          depth(tokens2[tokens2.length - 1]);
          state.maxDepth += tokens2[tokens2.length - 1].depth;
        }
        state.slashes = slashes;
        state.parts = parts;
      }
      return state;
    };
    module.exports = scan;
  }
});

// node_modules/picomatch/lib/parse.js
var require_parse = __commonJS({
  "node_modules/picomatch/lib/parse.js"(exports, module) {
    "use strict";
    var constants6 = require_constants();
    var utils = require_utils();
    var {
      MAX_LENGTH,
      POSIX_REGEX_SOURCE,
      REGEX_NON_SPECIAL_CHARS,
      REGEX_SPECIAL_CHARS_BACKREF,
      REPLACEMENTS
    } = constants6;
    var expandRange = (args, options) => {
      if (typeof options.expandRange === "function") {
        return options.expandRange(...args, options);
      }
      args.sort();
      const value = `[${args.join("-")}]`;
      try {
        new RegExp(value);
      } catch (ex) {
        return args.map((v) => utils.escapeRegex(v)).join("..");
      }
      return value;
    };
    var syntaxError = (type, char) => {
      return `Missing ${type}: "${char}" - use "\\\\${char}" to match literal characters`;
    };
    var splitTopLevel = (input) => {
      const parts = [];
      let bracket = 0;
      let paren = 0;
      let quote = 0;
      let value = "";
      let escaped = false;
      for (const ch of input) {
        if (escaped === true) {
          value += ch;
          escaped = false;
          continue;
        }
        if (ch === "\\") {
          value += ch;
          escaped = true;
          continue;
        }
        if (ch === '"') {
          quote = quote === 1 ? 0 : 1;
          value += ch;
          continue;
        }
        if (quote === 0) {
          if (ch === "[") {
            bracket++;
          } else if (ch === "]" && bracket > 0) {
            bracket--;
          } else if (bracket === 0) {
            if (ch === "(") {
              paren++;
            } else if (ch === ")" && paren > 0) {
              paren--;
            } else if (ch === "|" && paren === 0) {
              parts.push(value);
              value = "";
              continue;
            }
          }
        }
        value += ch;
      }
      parts.push(value);
      return parts;
    };
    var isPlainBranch = (branch) => {
      let escaped = false;
      for (const ch of branch) {
        if (escaped === true) {
          escaped = false;
          continue;
        }
        if (ch === "\\") {
          escaped = true;
          continue;
        }
        if (/[?*+@!()[\]{}]/.test(ch)) {
          return false;
        }
      }
      return true;
    };
    var normalizeSimpleBranch = (branch) => {
      let value = branch.trim();
      let changed = true;
      while (changed === true) {
        changed = false;
        if (/^@\([^\\()[\]{}|]+\)$/.test(value)) {
          value = value.slice(2, -1);
          changed = true;
        }
      }
      if (!isPlainBranch(value)) {
        return;
      }
      return value.replace(/\\(.)/g, "$1");
    };
    var hasRepeatedCharPrefixOverlap = (branches) => {
      const values = branches.map(normalizeSimpleBranch).filter(Boolean);
      for (let i = 0; i < values.length; i++) {
        for (let j = i + 1; j < values.length; j++) {
          const a = values[i];
          const b = values[j];
          const char = a[0];
          if (!char || a !== char.repeat(a.length) || b !== char.repeat(b.length)) {
            continue;
          }
          if (a === b || a.startsWith(b) || b.startsWith(a)) {
            return true;
          }
        }
      }
      return false;
    };
    var parseRepeatedExtglob = (pattern, requireEnd = true) => {
      if (pattern[0] !== "+" && pattern[0] !== "*" || pattern[1] !== "(") {
        return;
      }
      let bracket = 0;
      let paren = 0;
      let quote = 0;
      let escaped = false;
      for (let i = 1; i < pattern.length; i++) {
        const ch = pattern[i];
        if (escaped === true) {
          escaped = false;
          continue;
        }
        if (ch === "\\") {
          escaped = true;
          continue;
        }
        if (ch === '"') {
          quote = quote === 1 ? 0 : 1;
          continue;
        }
        if (quote === 1) {
          continue;
        }
        if (ch === "[") {
          bracket++;
          continue;
        }
        if (ch === "]" && bracket > 0) {
          bracket--;
          continue;
        }
        if (bracket > 0) {
          continue;
        }
        if (ch === "(") {
          paren++;
          continue;
        }
        if (ch === ")") {
          paren--;
          if (paren === 0) {
            if (requireEnd === true && i !== pattern.length - 1) {
              return;
            }
            return {
              type: pattern[0],
              body: pattern.slice(2, i),
              end: i
            };
          }
        }
      }
    };
    var buildCharClassStar = (chars) => {
      const source = chars.length === 1 ? utils.escapeRegex(chars[0]) : `[${chars.map((ch) => utils.escapeRegex(ch)).join("")}]`;
      return `${source}*`;
    };
    var getStarExtglobSequenceChars = (pattern) => {
      let index = 0;
      const chars = [];
      while (index < pattern.length) {
        const match = parseRepeatedExtglob(pattern.slice(index), false);
        if (!match || match.type !== "*") {
          return;
        }
        const branches = splitTopLevel(match.body).map((branch2) => branch2.trim());
        if (branches.length !== 1) {
          return;
        }
        const branch = normalizeSimpleBranch(branches[0]);
        if (!branch || branch.length !== 1) {
          return;
        }
        chars.push(branch);
        index += match.end + 1;
      }
      if (chars.length < 1) {
        return;
      }
      return chars;
    };
    var repeatedExtglobRecursion = (pattern) => {
      let depth = 0;
      let value = pattern.trim();
      let match = parseRepeatedExtglob(value);
      while (match) {
        depth++;
        value = match.body.trim();
        match = parseRepeatedExtglob(value);
      }
      return depth;
    };
    var analyzeRepeatedExtglob = (body, options) => {
      if (options.maxExtglobRecursion === false) {
        return { risky: false };
      }
      const max = typeof options.maxExtglobRecursion === "number" ? options.maxExtglobRecursion : constants6.DEFAULT_MAX_EXTGLOB_RECURSION;
      const branches = splitTopLevel(body).map((branch) => branch.trim());
      if (branches.length > 1) {
        if (branches.some((branch) => branch === "") || branches.some((branch) => /^[*?]+$/.test(branch)) || hasRepeatedCharPrefixOverlap(branches)) {
          return { risky: true };
        }
      }
      const safeChars = [];
      let sawStarSequence = false;
      let combinable = true;
      for (const branch of branches) {
        const chars = getStarExtglobSequenceChars(branch);
        if (chars) {
          sawStarSequence = true;
          safeChars.push(...chars);
          continue;
        }
        const literal = normalizeSimpleBranch(branch);
        if (literal && literal.length === 1) {
          safeChars.push(literal);
          continue;
        }
        combinable = false;
        if (repeatedExtglobRecursion(branch) > max) {
          return { risky: true };
        }
      }
      if (sawStarSequence) {
        return combinable ? { risky: true, safeOutput: buildCharClassStar([...new Set(safeChars)]) } : { risky: true };
      }
      return { risky: false };
    };
    var parse3 = (input, options) => {
      if (typeof input !== "string") {
        throw new TypeError("Expected a string");
      }
      input = REPLACEMENTS[input] || input;
      const opts = { ...options };
      const max = typeof opts.maxLength === "number" ? Math.min(MAX_LENGTH, opts.maxLength) : MAX_LENGTH;
      let len = input.length;
      if (len > max) {
        throw new SyntaxError(`Input length: ${len}, exceeds maximum allowed length: ${max}`);
      }
      const bos = { type: "bos", value: "", output: opts.prepend || "" };
      const tokens2 = [bos];
      const capture = opts.capture ? "" : "?:";
      const PLATFORM_CHARS = constants6.globChars(opts.windows);
      const EXTGLOB_CHARS = constants6.extglobChars(PLATFORM_CHARS);
      const {
        DOT_LITERAL,
        PLUS_LITERAL,
        SLASH_LITERAL,
        ONE_CHAR,
        DOTS_SLASH,
        NO_DOT,
        NO_DOT_SLASH,
        NO_DOTS_SLASH,
        QMARK,
        QMARK_NO_DOT,
        STAR,
        START_ANCHOR
      } = PLATFORM_CHARS;
      const globstar = (opts2) => {
        return `(${capture}(?:(?!${START_ANCHOR}${opts2.dot ? DOTS_SLASH : DOT_LITERAL}).)*?)`;
      };
      const nodot = opts.dot ? "" : NO_DOT;
      const qmarkNoDot = opts.dot ? QMARK : QMARK_NO_DOT;
      let star = opts.bash === true ? globstar(opts) : STAR;
      if (opts.capture) {
        star = `(${star})`;
      }
      if (typeof opts.noext === "boolean") {
        opts.noextglob = opts.noext;
      }
      const state = {
        input,
        index: -1,
        start: 0,
        dot: opts.dot === true,
        consumed: "",
        output: "",
        prefix: "",
        backtrack: false,
        negated: false,
        brackets: 0,
        braces: 0,
        parens: 0,
        quotes: 0,
        globstar: false,
        tokens: tokens2
      };
      input = utils.removePrefix(input, state);
      len = input.length;
      const extglobs = [];
      const braces = [];
      const stack = [];
      let prev = bos;
      let value;
      const eos = () => state.index === len - 1;
      const peek = state.peek = (n = 1) => input[state.index + n];
      const advance = state.advance = () => input[++state.index] || "";
      const remaining = () => input.slice(state.index + 1);
      const consume = (value2 = "", num2 = 0) => {
        state.consumed += value2;
        state.index += num2;
      };
      const append = (token) => {
        state.output += token.output != null ? token.output : token.value;
        consume(token.value);
      };
      const negate = () => {
        let count = 1;
        while (peek() === "!" && (peek(2) !== "(" || peek(3) === "?")) {
          advance();
          state.start++;
          count++;
        }
        if (count % 2 === 0) {
          return false;
        }
        state.negated = true;
        state.start++;
        return true;
      };
      const increment = (type) => {
        state[type]++;
        stack.push(type);
      };
      const decrement = (type) => {
        state[type]--;
        stack.pop();
      };
      const push = (tok) => {
        if (prev.type === "globstar") {
          const isBrace = state.braces > 0 && (tok.type === "comma" || tok.type === "brace");
          const isExtglob = tok.extglob === true || extglobs.length && (tok.type === "pipe" || tok.type === "paren");
          if (tok.type !== "slash" && tok.type !== "paren" && !isBrace && !isExtglob) {
            state.output = state.output.slice(0, -prev.output.length);
            prev.type = "star";
            prev.value = "*";
            prev.output = star;
            state.output += prev.output;
          }
        }
        if (extglobs.length && tok.type !== "paren") {
          extglobs[extglobs.length - 1].inner += tok.value;
        }
        if (tok.value || tok.output) append(tok);
        if (prev && prev.type === "text" && tok.type === "text") {
          prev.output = (prev.output || prev.value) + tok.value;
          prev.value += tok.value;
          return;
        }
        tok.prev = prev;
        tokens2.push(tok);
        prev = tok;
      };
      const extglobOpen = (type, value2) => {
        const token = { ...EXTGLOB_CHARS[value2], conditions: 1, inner: "" };
        token.prev = prev;
        token.parens = state.parens;
        token.output = state.output;
        token.startIndex = state.index;
        token.tokensIndex = tokens2.length;
        const output = (opts.capture ? "(" : "") + token.open;
        increment("parens");
        push({ type, value: value2, output: state.output ? "" : ONE_CHAR });
        push({ type: "paren", extglob: true, value: advance(), output });
        extglobs.push(token);
      };
      const extglobClose = (token) => {
        const literal = input.slice(token.startIndex, state.index + 1);
        const body = input.slice(token.startIndex + 2, state.index);
        const analysis = analyzeRepeatedExtglob(body, opts);
        if ((token.type === "plus" || token.type === "star") && analysis.risky) {
          const safeOutput = analysis.safeOutput ? (token.output ? "" : ONE_CHAR) + (opts.capture ? `(${analysis.safeOutput})` : analysis.safeOutput) : void 0;
          const open = tokens2[token.tokensIndex];
          open.type = "text";
          open.value = literal;
          open.output = safeOutput || utils.escapeRegex(literal);
          for (let i = token.tokensIndex + 1; i < tokens2.length; i++) {
            tokens2[i].value = "";
            tokens2[i].output = "";
            delete tokens2[i].suffix;
          }
          state.output = token.output + open.output;
          state.backtrack = true;
          push({ type: "paren", extglob: true, value, output: "" });
          decrement("parens");
          return;
        }
        let output = token.close + (opts.capture ? ")" : "");
        let rest;
        if (token.type === "negate") {
          let extglobStar = star;
          if (token.inner && token.inner.length > 1 && token.inner.includes("/")) {
            extglobStar = globstar(opts);
          }
          if (extglobStar !== star || eos() || /^\)+$/.test(remaining())) {
            output = token.close = `)$))${extglobStar}`;
          }
          if (token.inner.includes("*") && (rest = remaining()) && /^\.[^\\/.]+$/.test(rest)) {
            const expression = parse3(rest, { ...options, fastpaths: false }).output;
            output = token.close = `)${expression})${extglobStar})`;
          }
          if (token.prev.type === "bos") {
            state.negatedExtglob = true;
          }
        }
        push({ type: "paren", extglob: true, value, output });
        decrement("parens");
      };
      if (opts.fastpaths !== false && !/(^[*!]|[/()[\]{}"])/.test(input)) {
        let backslashes = false;
        let output = input.replace(REGEX_SPECIAL_CHARS_BACKREF, (m, esc, chars, first, rest, index) => {
          if (first === "\\") {
            backslashes = true;
            return m;
          }
          if (first === "?") {
            if (esc) {
              return esc + first + (rest ? QMARK.repeat(rest.length) : "");
            }
            if (index === 0) {
              return qmarkNoDot + (rest ? QMARK.repeat(rest.length) : "");
            }
            return QMARK.repeat(chars.length);
          }
          if (first === ".") {
            return DOT_LITERAL.repeat(chars.length);
          }
          if (first === "*") {
            if (esc) {
              return esc + first + (rest ? star : "");
            }
            return star;
          }
          return esc ? m : `\\${m}`;
        });
        if (backslashes === true) {
          if (opts.unescape === true) {
            output = output.replace(/\\/g, "");
          } else {
            output = output.replace(/\\+/g, (m) => {
              return m.length % 2 === 0 ? "\\\\" : m ? "\\" : "";
            });
          }
        }
        if (output === input && opts.contains === true) {
          state.output = input;
          return state;
        }
        state.output = utils.wrapOutput(output, state, options);
        return state;
      }
      while (!eos()) {
        value = advance();
        if (value === "\0") {
          continue;
        }
        if (value === "\\") {
          const next = peek();
          if (next === "/" && opts.bash !== true) {
            continue;
          }
          if (next === "." || next === ";") {
            continue;
          }
          if (!next) {
            value += "\\";
            push({ type: "text", value });
            continue;
          }
          const match = /^\\+/.exec(remaining());
          let slashes = 0;
          if (match && match[0].length > 2) {
            slashes = match[0].length;
            state.index += slashes;
            if (slashes % 2 !== 0) {
              value += "\\";
            }
          }
          if (opts.unescape === true) {
            value = advance();
          } else {
            value += advance();
          }
          if (state.brackets === 0) {
            push({ type: "text", value });
            continue;
          }
        }
        if (state.brackets > 0 && (value !== "]" || prev.value === "[" || prev.value === "[^")) {
          if (opts.posix !== false && value === ":") {
            const inner = prev.value.slice(1);
            if (inner.includes("[")) {
              prev.posix = true;
              if (inner.includes(":")) {
                const idx = prev.value.lastIndexOf("[");
                const pre = prev.value.slice(0, idx);
                const rest2 = prev.value.slice(idx + 2);
                const posix = POSIX_REGEX_SOURCE[rest2];
                if (posix) {
                  prev.value = pre + posix;
                  state.backtrack = true;
                  advance();
                  if (!bos.output && tokens2.indexOf(prev) === 1) {
                    bos.output = ONE_CHAR;
                  }
                  continue;
                }
              }
            }
          }
          if (value === "[" && peek() !== ":" || value === "-" && peek() === "]") {
            value = `\\${value}`;
          }
          if (value === "]" && (prev.value === "[" || prev.value === "[^")) {
            value = `\\${value}`;
          }
          if (opts.posix === true && value === "!" && prev.value === "[") {
            value = "^";
          }
          prev.value += value;
          append({ value });
          continue;
        }
        if (state.quotes === 1 && value !== '"') {
          value = utils.escapeRegex(value);
          prev.value += value;
          append({ value });
          continue;
        }
        if (value === '"') {
          state.quotes = state.quotes === 1 ? 0 : 1;
          if (opts.keepQuotes === true) {
            push({ type: "text", value });
          }
          continue;
        }
        if (value === "(") {
          increment("parens");
          push({ type: "paren", value });
          continue;
        }
        if (value === ")") {
          if (state.parens === 0 && opts.strictBrackets === true) {
            throw new SyntaxError(syntaxError("opening", "("));
          }
          const extglob = extglobs[extglobs.length - 1];
          if (extglob && state.parens === extglob.parens + 1) {
            extglobClose(extglobs.pop());
            continue;
          }
          push({ type: "paren", value, output: state.parens ? ")" : "\\)" });
          decrement("parens");
          continue;
        }
        if (value === "[") {
          if (opts.nobracket === true || !remaining().includes("]")) {
            if (opts.nobracket !== true && opts.strictBrackets === true) {
              throw new SyntaxError(syntaxError("closing", "]"));
            }
            value = `\\${value}`;
          } else {
            increment("brackets");
          }
          push({ type: "bracket", value });
          continue;
        }
        if (value === "]") {
          if (opts.nobracket === true || prev && prev.type === "bracket" && prev.value.length === 1) {
            push({ type: "text", value, output: `\\${value}` });
            continue;
          }
          if (state.brackets === 0) {
            if (opts.strictBrackets === true) {
              throw new SyntaxError(syntaxError("opening", "["));
            }
            push({ type: "text", value, output: `\\${value}` });
            continue;
          }
          decrement("brackets");
          const prevValue = prev.value.slice(1);
          if (prev.posix !== true && prevValue[0] === "^" && !prevValue.includes("/")) {
            value = `/${value}`;
          }
          prev.value += value;
          append({ value });
          if (opts.literalBrackets === false || utils.hasRegexChars(prevValue)) {
            continue;
          }
          const escaped = utils.escapeRegex(prev.value);
          state.output = state.output.slice(0, -prev.value.length);
          if (opts.literalBrackets === true) {
            state.output += escaped;
            prev.value = escaped;
            continue;
          }
          prev.value = `(${capture}${escaped}|${prev.value})`;
          state.output += prev.value;
          continue;
        }
        if (value === "{" && opts.nobrace !== true) {
          increment("braces");
          const open = {
            type: "brace",
            value,
            output: "(",
            outputIndex: state.output.length,
            tokensIndex: state.tokens.length
          };
          braces.push(open);
          push(open);
          continue;
        }
        if (value === "}") {
          const brace = braces[braces.length - 1];
          if (opts.nobrace === true || !brace) {
            push({ type: "text", value, output: value });
            continue;
          }
          let output = ")";
          if (brace.dots === true) {
            const arr = tokens2.slice();
            const range = [];
            for (let i = arr.length - 1; i >= 0; i--) {
              tokens2.pop();
              if (arr[i].type === "brace") {
                break;
              }
              if (arr[i].type !== "dots") {
                range.unshift(arr[i].value);
              }
            }
            output = expandRange(range, opts);
            state.backtrack = true;
          }
          if (brace.comma !== true && brace.dots !== true) {
            const out = state.output.slice(0, brace.outputIndex);
            const toks = state.tokens.slice(brace.tokensIndex);
            brace.value = brace.output = "\\{";
            value = output = "\\}";
            state.output = out;
            for (const t of toks) {
              state.output += t.output || t.value;
            }
          }
          push({ type: "brace", value, output });
          decrement("braces");
          braces.pop();
          continue;
        }
        if (value === "|") {
          if (extglobs.length > 0) {
            extglobs[extglobs.length - 1].conditions++;
          }
          push({ type: "text", value });
          continue;
        }
        if (value === ",") {
          let output = value;
          const brace = braces[braces.length - 1];
          if (brace && stack[stack.length - 1] === "braces") {
            brace.comma = true;
            output = "|";
          }
          push({ type: "comma", value, output });
          continue;
        }
        if (value === "/") {
          if (prev.type === "dot" && state.index === state.start + 1) {
            state.start = state.index + 1;
            state.consumed = "";
            state.output = "";
            tokens2.pop();
            prev = bos;
            continue;
          }
          push({ type: "slash", value, output: SLASH_LITERAL });
          continue;
        }
        if (value === ".") {
          if (state.braces > 0 && prev.type === "dot") {
            if (prev.value === ".") prev.output = DOT_LITERAL;
            const brace = braces[braces.length - 1];
            prev.type = "dots";
            prev.output += value;
            prev.value += value;
            brace.dots = true;
            continue;
          }
          if (state.braces + state.parens === 0 && prev.type !== "bos" && prev.type !== "slash") {
            push({ type: "text", value, output: DOT_LITERAL });
            continue;
          }
          push({ type: "dot", value, output: DOT_LITERAL });
          continue;
        }
        if (value === "?") {
          const isGroup = prev && prev.value === "(";
          if (!isGroup && opts.noextglob !== true && peek() === "(" && peek(2) !== "?") {
            extglobOpen("qmark", value);
            continue;
          }
          if (prev && prev.type === "paren") {
            const next = peek();
            let output = value;
            if (prev.value === "(" && !/[!=<:]/.test(next) || next === "<" && !/<([!=]|\w+>)/.test(remaining())) {
              output = `\\${value}`;
            }
            push({ type: "text", value, output });
            continue;
          }
          if (opts.dot !== true && (prev.type === "slash" || prev.type === "bos")) {
            push({ type: "qmark", value, output: QMARK_NO_DOT });
            continue;
          }
          push({ type: "qmark", value, output: QMARK });
          continue;
        }
        if (value === "!") {
          if (opts.noextglob !== true && peek() === "(") {
            if (peek(2) !== "?" || !/[!=<:]/.test(peek(3))) {
              extglobOpen("negate", value);
              continue;
            }
          }
          if (opts.nonegate !== true && state.index === 0) {
            negate();
            continue;
          }
        }
        if (value === "+") {
          if (opts.noextglob !== true && peek() === "(" && peek(2) !== "?") {
            extglobOpen("plus", value);
            continue;
          }
          if (prev && prev.value === "(" || opts.regex === false) {
            push({ type: "plus", value, output: PLUS_LITERAL });
            continue;
          }
          if (prev && (prev.type === "bracket" || prev.type === "paren" || prev.type === "brace") || state.parens > 0) {
            push({ type: "plus", value });
            continue;
          }
          push({ type: "plus", value: PLUS_LITERAL });
          continue;
        }
        if (value === "@") {
          if (opts.noextglob !== true && peek() === "(" && peek(2) !== "?") {
            push({ type: "at", extglob: true, value, output: "" });
            continue;
          }
          push({ type: "text", value });
          continue;
        }
        if (value !== "*") {
          if (value === "$" || value === "^") {
            value = `\\${value}`;
          }
          const match = REGEX_NON_SPECIAL_CHARS.exec(remaining());
          if (match) {
            value += match[0];
            state.index += match[0].length;
          }
          push({ type: "text", value });
          continue;
        }
        if (prev && (prev.type === "globstar" || prev.star === true)) {
          prev.type = "star";
          prev.star = true;
          prev.value += value;
          prev.output = star;
          state.backtrack = true;
          state.globstar = true;
          consume(value);
          continue;
        }
        let rest = remaining();
        if (opts.noextglob !== true && /^\([^?]/.test(rest)) {
          extglobOpen("star", value);
          continue;
        }
        if (prev.type === "star") {
          if (opts.noglobstar === true) {
            consume(value);
            continue;
          }
          const prior = prev.prev;
          const before = prior.prev;
          const isStart = prior.type === "slash" || prior.type === "bos";
          const afterStar = before && (before.type === "star" || before.type === "globstar");
          if (opts.bash === true && (!isStart || rest[0] && rest[0] !== "/")) {
            push({ type: "star", value, output: "" });
            continue;
          }
          const isBrace = state.braces > 0 && (prior.type === "comma" || prior.type === "brace");
          const isExtglob = extglobs.length && (prior.type === "pipe" || prior.type === "paren");
          if (!isStart && prior.type !== "paren" && !isBrace && !isExtglob) {
            push({ type: "star", value, output: "" });
            continue;
          }
          while (rest.slice(0, 3) === "/**") {
            const after = input[state.index + 4];
            if (after && after !== "/") {
              break;
            }
            rest = rest.slice(3);
            consume("/**", 3);
          }
          const isEnd = eos() || state.parens > 0 && rest === ")".repeat(state.parens) && !extglobs.some((extglob) => extglob.type === "negate");
          if (prior.type === "bos" && eos()) {
            prev.type = "globstar";
            prev.value += value;
            prev.output = globstar(opts);
            state.output = prev.output;
            state.globstar = true;
            consume(value);
            continue;
          }
          if (prior.type === "slash" && prior.prev.type !== "bos" && !afterStar && isEnd) {
            state.output = state.output.slice(0, -(prior.output + prev.output).length);
            prior.output = `(?:${prior.output}`;
            prev.type = "globstar";
            prev.output = globstar(opts) + (opts.strictSlashes ? ")" : "|$)");
            prev.value += value;
            state.globstar = true;
            state.output += prior.output + prev.output;
            consume(value);
            continue;
          }
          if (prior.type === "slash" && prior.prev.type !== "bos" && rest[0] === "/") {
            const end = rest[1] !== void 0 ? "|$" : "";
            state.output = state.output.slice(0, -(prior.output + prev.output).length);
            prior.output = `(?:${prior.output}`;
            prev.type = "globstar";
            prev.output = `${globstar(opts)}${SLASH_LITERAL}|${SLASH_LITERAL}${end})`;
            prev.value += value;
            state.output += prior.output + prev.output;
            state.globstar = true;
            consume(value + advance());
            push({ type: "slash", value: "/", output: "" });
            continue;
          }
          if (prior.type === "bos" && rest[0] === "/") {
            prev.type = "globstar";
            prev.value += value;
            prev.output = `(?:^|${SLASH_LITERAL}|${globstar(opts)}${SLASH_LITERAL})`;
            state.output = prev.output;
            state.globstar = true;
            consume(value + advance());
            push({ type: "slash", value: "/", output: "" });
            continue;
          }
          state.output = state.output.slice(0, -prev.output.length);
          prev.type = "globstar";
          prev.output = globstar(opts);
          prev.value += value;
          state.output += prev.output;
          state.globstar = true;
          consume(value);
          continue;
        }
        const token = { type: "star", value, output: star };
        if (opts.bash === true) {
          token.output = ".*?";
          if (prev.type === "bos" || prev.type === "slash") {
            token.output = nodot + token.output;
          }
          push(token);
          continue;
        }
        if (prev && (prev.type === "bracket" || prev.type === "paren") && opts.regex === true) {
          token.output = value;
          push(token);
          continue;
        }
        if (state.index === state.start || prev.type === "slash" || prev.type === "dot") {
          if (prev.type === "dot") {
            state.output += NO_DOT_SLASH;
            prev.output += NO_DOT_SLASH;
          } else if (opts.dot === true) {
            state.output += NO_DOTS_SLASH;
            prev.output += NO_DOTS_SLASH;
          } else {
            state.output += nodot;
            prev.output += nodot;
          }
          if (peek() !== "*") {
            state.output += ONE_CHAR;
            prev.output += ONE_CHAR;
          }
        }
        push(token);
      }
      while (state.brackets > 0) {
        if (opts.strictBrackets === true) throw new SyntaxError(syntaxError("closing", "]"));
        state.output = utils.escapeLast(state.output, "[");
        decrement("brackets");
      }
      while (state.parens > 0) {
        if (opts.strictBrackets === true) throw new SyntaxError(syntaxError("closing", ")"));
        state.output = utils.escapeLast(state.output, "(");
        decrement("parens");
      }
      while (state.braces > 0) {
        if (opts.strictBrackets === true) throw new SyntaxError(syntaxError("closing", "}"));
        state.output = utils.escapeLast(state.output, "{");
        decrement("braces");
      }
      if (opts.strictSlashes !== true && (prev.type === "star" || prev.type === "bracket")) {
        push({ type: "maybe_slash", value: "", output: `${SLASH_LITERAL}?` });
      }
      if (state.backtrack === true) {
        state.output = "";
        for (const token of state.tokens) {
          state.output += token.output != null ? token.output : token.value;
          if (token.suffix) {
            state.output += token.suffix;
          }
        }
      }
      return state;
    };
    parse3.fastpaths = (input, options) => {
      const opts = { ...options };
      const max = typeof opts.maxLength === "number" ? Math.min(MAX_LENGTH, opts.maxLength) : MAX_LENGTH;
      const len = input.length;
      if (len > max) {
        throw new SyntaxError(`Input length: ${len}, exceeds maximum allowed length: ${max}`);
      }
      input = REPLACEMENTS[input] || input;
      const {
        DOT_LITERAL,
        SLASH_LITERAL,
        ONE_CHAR,
        DOTS_SLASH,
        NO_DOT,
        NO_DOTS,
        NO_DOTS_SLASH,
        STAR,
        START_ANCHOR
      } = constants6.globChars(opts.windows);
      const nodot = opts.dot ? NO_DOTS : NO_DOT;
      const slashDot = opts.dot ? NO_DOTS_SLASH : NO_DOT;
      const capture = opts.capture ? "" : "?:";
      const state = { negated: false, prefix: "" };
      let star = opts.bash === true ? ".*?" : STAR;
      if (opts.capture) {
        star = `(${star})`;
      }
      const globstar = (opts2) => {
        if (opts2.noglobstar === true) return star;
        return `(${capture}(?:(?!${START_ANCHOR}${opts2.dot ? DOTS_SLASH : DOT_LITERAL}).)*?)`;
      };
      const create = (str2) => {
        switch (str2) {
          case "*":
            return `${nodot}${ONE_CHAR}${star}`;
          case ".*":
            return `${DOT_LITERAL}${ONE_CHAR}${star}`;
          case "*.*":
            return `${nodot}${star}${DOT_LITERAL}${ONE_CHAR}${star}`;
          case "*/*":
            return `${nodot}${star}${SLASH_LITERAL}${ONE_CHAR}${slashDot}${star}`;
          case "**":
            return nodot + globstar(opts);
          case "**/*":
            return `(?:${nodot}${globstar(opts)}${SLASH_LITERAL})?${slashDot}${ONE_CHAR}${star}`;
          case "**/*.*":
            return `(?:${nodot}${globstar(opts)}${SLASH_LITERAL})?${slashDot}${star}${DOT_LITERAL}${ONE_CHAR}${star}`;
          case "**/.*":
            return `(?:${nodot}${globstar(opts)}${SLASH_LITERAL})?${DOT_LITERAL}${ONE_CHAR}${star}`;
          default: {
            const match = /^(.*?)\.(\w+)$/.exec(str2);
            if (!match) return;
            const source2 = create(match[1]);
            if (!source2) return;
            return source2 + DOT_LITERAL + match[2];
          }
        }
      };
      const output = utils.removePrefix(input, state);
      let source = create(output);
      if (source && opts.strictSlashes !== true) {
        source += `${SLASH_LITERAL}?`;
      }
      return source;
    };
    module.exports = parse3;
  }
});

// node_modules/picomatch/lib/picomatch.js
var require_picomatch = __commonJS({
  "node_modules/picomatch/lib/picomatch.js"(exports, module) {
    "use strict";
    var scan = require_scan();
    var parse3 = require_parse();
    var utils = require_utils();
    var constants6 = require_constants();
    var isObject = (val) => val && typeof val === "object" && !Array.isArray(val);
    var picomatch2 = (glob, options, returnState = false) => {
      if (Array.isArray(glob)) {
        const fns = glob.map((input) => picomatch2(input, options, returnState));
        const arrayMatcher = (str2) => {
          for (const isMatch of fns) {
            const state2 = isMatch(str2);
            if (state2) return state2;
          }
          return false;
        };
        return arrayMatcher;
      }
      const isState = isObject(glob) && glob.tokens && glob.input;
      if (glob === "" || typeof glob !== "string" && !isState) {
        throw new TypeError("Expected pattern to be a non-empty string");
      }
      const opts = options || {};
      const posix = opts.windows;
      const regex = isState ? picomatch2.compileRe(glob, options) : picomatch2.makeRe(glob, options, false, true);
      const state = regex.state;
      delete regex.state;
      let isIgnored = () => false;
      if (opts.ignore) {
        const ignoreOpts = { ...options, ignore: null, onMatch: null, onResult: null };
        isIgnored = picomatch2(opts.ignore, ignoreOpts, returnState);
      }
      const matcher = (input, returnObject = false) => {
        const { isMatch, match, output } = picomatch2.test(input, regex, options, { glob, posix });
        const result = { glob, state, regex, posix, input, output, match, isMatch };
        if (typeof opts.onResult === "function") {
          opts.onResult(result);
        }
        if (isMatch === false) {
          result.isMatch = false;
          return returnObject ? result : false;
        }
        if (isIgnored(input)) {
          if (typeof opts.onIgnore === "function") {
            opts.onIgnore(result);
          }
          result.isMatch = false;
          return returnObject ? result : false;
        }
        if (typeof opts.onMatch === "function") {
          opts.onMatch(result);
        }
        return returnObject ? result : true;
      };
      if (returnState) {
        matcher.state = state;
      }
      return matcher;
    };
    picomatch2.test = (input, regex, options, { glob, posix } = {}) => {
      if (typeof input !== "string") {
        throw new TypeError("Expected input to be a string");
      }
      if (input === "") {
        return { isMatch: false, output: "" };
      }
      const opts = options || {};
      const format = opts.format || (posix ? utils.toPosixSlashes : null);
      let match = input === glob;
      let output = match && format ? format(input) : input;
      if (match === false) {
        output = format ? format(input) : input;
        match = output === glob;
      }
      if (match === false || opts.capture === true) {
        if (opts.matchBase === true || opts.basename === true) {
          match = picomatch2.matchBase(input, regex, options, posix);
        } else {
          match = regex.exec(output);
        }
      }
      return { isMatch: Boolean(match), match, output };
    };
    picomatch2.matchBase = (input, glob, options, posix = options && options.windows) => {
      const regex = glob instanceof RegExp ? glob : picomatch2.makeRe(glob, options);
      return regex.test(utils.basename(input, { windows: posix }));
    };
    picomatch2.isMatch = (str2, patterns, options) => picomatch2(patterns, options)(str2);
    picomatch2.parse = (pattern, options) => {
      if (Array.isArray(pattern)) return pattern.map((p) => picomatch2.parse(p, options));
      return parse3(pattern, { ...options, fastpaths: false });
    };
    picomatch2.scan = (input, options) => scan(input, options);
    picomatch2.compileRe = (state, options, returnOutput = false, returnState = false) => {
      if (returnOutput === true) {
        return state.output;
      }
      const opts = options || {};
      const prepend = opts.contains ? "" : "^";
      const append = opts.contains ? "" : "$";
      let source = `${prepend}(?:${state.output})${append}`;
      if (state && state.negated === true) {
        source = `^(?!${source}).*$`;
      }
      const regex = picomatch2.toRegex(source, options);
      if (returnState === true) {
        regex.state = state;
      }
      return regex;
    };
    picomatch2.makeRe = (input, options = {}, returnOutput = false, returnState = false) => {
      if (!input || typeof input !== "string") {
        throw new TypeError("Expected a non-empty string");
      }
      let parsed = { negated: false, fastpaths: true };
      if (options.fastpaths !== false && (input[0] === "." || input[0] === "*")) {
        parsed.output = parse3.fastpaths(input, options);
      }
      if (!parsed.output) {
        parsed = parse3(input, options);
      }
      return picomatch2.compileRe(parsed, options, returnOutput, returnState);
    };
    picomatch2.toRegex = (source, options) => {
      try {
        const opts = options || {};
        return new RegExp(source, opts.flags || (opts.nocase ? "i" : ""));
      } catch (err) {
        if (options && options.debug === true) throw err;
        return /$^/;
      }
    };
    picomatch2.constants = constants6;
    module.exports = picomatch2;
  }
});

// node_modules/picomatch/index.js
var require_picomatch2 = __commonJS({
  "node_modules/picomatch/index.js"(exports, module) {
    "use strict";
    var pico = require_picomatch();
    var utils = require_utils();
    function picomatch2(glob, options, returnState = false) {
      if (options && (options.windows === null || options.windows === void 0)) {
        options = { ...options, windows: utils.isWindows() };
      }
      return pico(glob, options, returnState);
    }
    Object.assign(picomatch2, pico);
    module.exports = picomatch2;
  }
});

// gate/src/main.ts
import { randomUUID } from "node:crypto";
import { accessSync, chmodSync as chmodSync2, closeSync as closeSync5, constants as constants5, fstatSync as fstatSync5, lstatSync as lstatSync5, mkdirSync as mkdirSync3, openSync as openSync5, readSync as readSync5, renameSync, unlinkSync as unlinkSync2, writeFileSync, writeSync as writeSync3 } from "node:fs";
import { basename as basename2, dirname as dirname3, isAbsolute as isAbsolute3, join as join4 } from "node:path";

// src/engine/tool-flags.ts
import { createHash } from "node:crypto";

// src/types.ts
var NEED_CATEGORIES = [
  "secrets",
  "sast",
  "deps",
  "unit-tests",
  "full-tests",
  "lint",
  "format-lint",
  "hooks",
  "hooks-ci",
  "image-build",
  "image-scan",
  "dast",
  "iac",
  "sbom",
  "signing",
  "attestation",
  "deploy-verify",
  "gate",
  // Plan P Task 2 (table in src/engine/needs.ts): quality, supply-chain and scheduled checks
  "format",
  "type-check",
  "coverage",
  "dead-code",
  "duplication",
  "dockerfile-lint",
  "workflow-lint",
  "workflow-pin-check",
  "dependency-review",
  "licences",
  "api-dast",
  "publishing",
  "egress",
  "update-config",
  "scorecard",
  "fuzzing"
];
var GATE_CHECK_NAME = "pipegen / gate";
var RESULT_ARTIFACT_PREFIX = "pipegen-out-";
var FLOOR_NEEDS = ["secrets", "sast", "deps", "unit-tests", "full-tests", "gate"];
var PROTECTED_PATHS_BASE = [
  ".github/workflows/**",
  ".github/CODEOWNERS",
  "CODEOWNERS",
  ".pre-commit-config.yaml",
  ".husky/**",
  "lefthook.yml",
  "docker-compose.pipegen.yml",
  ".gitleaksignore",
  ".semgrepignore",
  ".trivyignore",
  ".zap/**",
  ".github/actions/**",
  "docs/CODEOWNERS",
  ".github/dependabot.yml",
  // Renovate (Plan P carry-forward; C4 review 15): its config decides which dependency updates land
  "renovate.json",
  "renovate.json5",
  ".renovaterc",
  ".renovaterc.json",
  ".renovaterc.json5",
  ".github/renovate.json",
  ".github/renovate.json5"
];
var PROTECTED_SECTIONS_BASE = ["package.json:renovate"];

// src/engine/artifact-names.ts
var ArtifactNameError = class extends Error {
};
var NEED_ID_RE = /^(?!base-)(?!.*--)[a-z0-9][a-z0-9-]{0,63}$/;
var MAX_SLUG = 40;
function slug(s) {
  const out = s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+/, "").slice(0, MAX_SLUG).replace(/-+$/, "");
  if (out === "") throw new ArtifactNameError("A name has no letters or digits left after cleaning, so it can not name an artifact.");
  return out;
}
function resultArtifactName(needId, service, opts) {
  if (!NEED_ID_RE.test(needId)) throw new ArtifactNameError("A need id for an artifact name must be lower case letters, digits and dashes.");
  return `${RESULT_ARTIFACT_PREFIX}${opts?.base === true ? "base-" : ""}${needId}${service === void 0 ? "" : `--${slug(service)}`}`;
}
var SECRETS_RANGE_ID = "secrets-range";
var SECRETS_RANGE_ARTIFACT = resultArtifactName(SECRETS_RANGE_ID);
var SECRETS_RANGE_TOOL = "betterleaks";
var RANGE_FACTS_FILE = "range.json";
var RANGE_CANARY_FILES = ["pipegen-range-canary-1.txt", "pipegen-range-canary-2.txt"];
var GATE_RESULT_ARTIFACT = "pipegen-gate-result";
var BASELINE_ARTIFACT = "pipegen-baseline";
var CLEAN_RUN_ARTIFACT = "pipegen-clean-run";

// src/engine/licence-lockfiles.ts
var TRIVY_LICENCE_LOCKFILES = Object.freeze({
  npm: { file: "package-lock.json", licences: "lockfile" },
  yarn: { file: "yarn.lock", licences: "installed" },
  pnpm: { file: "pnpm-lock.yaml", licences: "installed" },
  bun: { file: "bun.lock", licences: "installed" },
  pip: { file: "requirements.txt", licences: "installed" },
  poetry: { file: "poetry.lock", licences: "never" },
  uv: { file: "uv.lock", licences: "never" },
  go: { file: "go.mod", licences: "installed" },
  other: { file: "(a lockfile pipegen does not know)", licences: "never" }
});
var LOCKFILE_KINDS = Object.keys(TRIVY_LICENCE_LOCKFILES);
var isLockfileKind = (k) => typeof k === "string" && Object.hasOwn(TRIVY_LICENCE_LOCKFILES, k);

// gate/src/policy-default.ts
var SEVERITIES = Object.freeze(["critical", "high", "medium", "low", "info"]);
var POLICY_FLOOR = Object.freeze(["critical", "high"]);
var DEFAULT_POLICY = Object.freeze({
  block: Object.freeze(["critical", "high"]),
  warn: Object.freeze(["medium"])
});
var isPlain = (v) => typeof v === "object" && v !== null && !Array.isArray(v) && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
function policyProblem(v) {
  if (!isPlain(v) || Object.keys(v).sort().join() !== "block,warn") return "a JSON object with exactly block and warn";
  const lists = [v.block, v.warn];
  if (!lists.every((l) => Array.isArray(l) && l.length <= SEVERITIES.length && l.every((x) => typeof x === "string" && SEVERITIES.includes(x)))) return "block and warn lists of severities";
  const block = v.block;
  const warn = v.warn;
  if (!POLICY_FLOOR.every((s) => block.includes(s))) return "a policy whose block list includes at least critical and high";
  if (new Set(block).size !== block.length || new Set(warn).size !== warn.length || warn.some((x) => block.includes(x))) return "a policy with no duplicate and no severity in both lists";
  return null;
}

// gate/src/date.ts
function validDate(text) {
  if (typeof text !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return void 0;
  const [y, m, d] = text.split("-").map(Number);
  if (y < 1) return void 0;
  const t = new Date(Date.UTC(y, m - 1, d));
  t.setUTCFullYear(y);
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d ? text : void 0;
}

// src/engine/tool-flags.ts
var OXLINT_EXTENSIONS = ["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx", "vue", "astro", "svelte"];
var TRIVY_PINNED_CONFIG = `# pipegen's pinned trivy config: no cache kept between runs, and no repository trivy-secret.yaml (an empty path loads none)
cache:
  backend: memory
secret:
  config: ""
`;
var DEDICATED = (exe, pkg, config) => ({ method: "github-release", package: pkg, exe, dialect: "long", sub: [], flags: {}, dedicated: true, ...config === void 0 ? {} : { config } });
var FOUND_1 = [1];
var FOUND_10 = [10];
var TRIVY_CONFIG = { flag: "--config", content: TRIVY_PINNED_CONFIG, fileName: "trivy.yaml" };
var SECRETS_SCAN_CONFIG = `[extend]
useDefault = true

[[rules]]
id = "pipegen-canary"
description = "pipegen scan marker (proves the file was read)"
regex = '''(?m)^pipegen-canary-[0-9a-f]{32}$'''
keywords = ["pipegen-canary-"]
`;
var SECRETS_IGNORE_FILES = [".gitleaksignore", ".betterleaksignore"];
var STAGED = { ignoreFiles: SECRETS_IGNORE_FILES };
var GH = "github-release";
var TRIVY_ASSET = "trivy_0.76.0_Linux-64bit.tar.gz";
var RUFF_ASSET = "ruff-x86_64-unknown-linux-gnu.tar.gz";
var COVERAGE_MINIMUMS = ["60", "70", "80", "90"];
var TEST_COMMANDS = Object.freeze({
  npm: Object.freeze({ exe: "npm", args: Object.freeze(["test"]) })
});
var ESLINT_FILES = "files: ['**/*.{js,mjs,cjs,jsx,vue,svelte,astro}']";
var ESLINT_TS_FILES = "files: ['**/*.{js,mjs,cjs,jsx,ts,mts,cts,tsx,vue,svelte,astro}']";
var POLICIES = {
  "trivy-config": { ...DEDICATED("trivy", TRIVY_ASSET, TRIVY_CONFIG), findingsExit: FOUND_10 },
  "trivy-image": { ...DEDICATED("trivy", TRIVY_ASSET, TRIVY_CONFIG), slots: { "": "image-digest" }, findingsExit: FOUND_10 },
  "trivy-licence": { ...DEDICATED("trivy", TRIVY_ASSET, TRIVY_CONFIG), findingsExit: FOUND_10 },
  betterleaks: { ...DEDICATED("betterleaks", "betterleaks_1.9.0_linux_x64.tar.gz", { flag: "--config", content: SECRETS_SCAN_CONFIG, fileName: "betterleaks.toml" }), findingsExit: FOUND_10, staged: STAGED },
  nuclei: {
    ...DEDICATED("nuclei", "nuclei_3.11.1_linux_amd64.zip"),
    slots: { "-target": "local-url" },
    findingsExit: [],
    archive: { repo: "projectdiscovery/nuclei-templates", commitEnv: "PIPEGEN_NUCLEI_TEMPLATES_COMMIT", treeEnv: "PIPEGEN_NUCLEI_TEMPLATES_TREE", dir: "/pipegen-nuclei-templates" }
  },
  // ruling P28: the image entries too. registry runs the image's own entrypoint, nothing else
  registry: { method: "docker", package: "registry", exe: "", entrypoint: true, dialect: "long", sub: [], flags: {} },
  // ZAP baseline (zaproxy/zap-stable): getopt short options, read as Go-style words; no -I (warnings that never fail)
  "zap-baseline": {
    slots: { "-t": "local-url" },
    network: "host",
    asImageUser: true,
    method: "docker",
    package: "zaproxy/zap-stable",
    exe: "zap-baseline.py",
    dialect: "goflags",
    sub: [],
    flags: { J: "output", z: { values: ["-silent"] } },
    findingsExit: [1, 2],
    // 1: a FAIL alert, 2: a WARN alert (0 is a clean run)
    required: { J: null, z: "-silent" },
    mount: { at: "/zap/wrk", source: "work" },
    config: { flag: "-c", content: "# pipegen's pinned ZAP baseline rules: the defaults, nothing ignored\n", fileName: "zap-baseline.conf" }
  },
  // Semgrep CE 1.181.0: rules only from the verified archive (semgrepProblems), no metrics, no version check, and no file-size skip
  // (--max-target-bytes=0: by default semgrep silently skips every file over 1 MB, so padding a file would hide it from SAST; DECISIONS #108)
  semgrep: {
    method: "docker",
    package: "semgrep/semgrep",
    exe: "semgrep",
    dialect: "long",
    sub: ["scan"],
    findingsExit: [],
    flags: { metrics: { values: ["off"] }, "disable-version-check": "bool", "max-target-bytes": { values: ["0"] }, config: { values: ["/pipegen-rules"] }, sarif: "bool", output: "output" },
    required: { metrics: "off", "disable-version-check": "true", "max-target-bytes": "0", config: "/pipegen-rules" },
    scopeIgnore: { file: ".semgrepignore", lines: ["node_modules"] },
    env: ["PIPEGEN_RULES_URL", "PIPEGEN_RULES_SHA256", "PIPEGEN_RULES_TREE"],
    extraChoices: { rules: ["javascript", "typescript", "python"] },
    mount: { at: "/src", source: "repo", workdir: true },
    network: "none",
    archive: { repo: "semgrep/semgrep-rules", urlEnv: "PIPEGEN_RULES_URL", treeEnv: "PIPEGEN_RULES_TREE", dir: "/pipegen-rules", subChoice: "rules" }
  },
  // gitleaks 8.30.1 (`gitleaks dir --help`; dir mode since C1b fix round 1, so the scanner reads the bytes the scrub reads), the secrets fallback (P21): the same locks as betterleaks
  gitleaks: {
    method: GH,
    package: "gitleaks_8.30.1_linux_x64.tar.gz",
    exe: "gitleaks",
    dialect: "long",
    sub: ["dir"],
    positionals: ["."],
    findingsExit: FOUND_10,
    staged: STAGED,
    flags: { "no-banner": "bool", "ignore-gitleaks-allow": "bool", redact: { values: ["", "100"], optional: true }, "report-format": { values: ["sarif"] }, "report-path": "output", "exit-code": { values: ["10"] }, "max-archive-depth": { values: ["0"] } },
    required: { "ignore-gitleaks-allow": "true", redact: "", "report-format": "sarif", "report-path": null, "exit-code": "10", "max-archive-depth": "0" },
    config: { flag: "--config", content: SECRETS_SCAN_CONFIG, fileName: "gitleaks.toml" }
  },
  // osv-scanner v2.7.0
  "osv-scanner": {
    method: GH,
    package: "osv-scanner_linux_amd64",
    exe: "osv-scanner",
    dialect: "long",
    sub: ["scan", "source"],
    positionals: ["."],
    findingsExit: FOUND_1,
    flags: { recursive: "bool", "no-ignore": "bool", format: { values: ["sarif"] }, output: "output" },
    required: { "no-ignore": "true", format: "sarif", output: null },
    config: { flag: "--config", content: "# pipegen's pinned osv-scanner config: no ignored vulnerabilities\n", fileName: "osv-scanner.toml" }
  },
  lefthook: { method: GH, runsRepoCode: true, package: "lefthook_2.2.2_Linux_x86_64", exe: "lefthook", dialect: "long", sub: ["run", "pre-commit"], flags: { "all-files": "bool" }, required: { "all-files": "true" } },
  syft: {
    method: GH,
    slots: { "": "image-digest" },
    package: "syft_1.55.0_linux_amd64.tar.gz",
    exe: "syft",
    dialect: "long",
    sub: ["scan"],
    flags: { output: { values: ["spdx-json=sbom.spdx.json"] } },
    required: { output: "spdx-json=sbom.spdx.json" },
    config: { flag: "--config", content: "check-for-app-update: false\n", fileName: "syft.yaml" }
  },
  cosign: { method: GH, needsSlot: "is run by Plan G's sign job, which adds its own reviewed flags", package: "cosign-linux-amd64", exe: "cosign", dialect: "long", sub: ["sign"], flags: { yes: "bool" }, required: { yes: "true" } },
  actionlint: {
    method: GH,
    package: "actionlint_1.7.12_linux_amd64.tar.gz",
    exe: "actionlint",
    dialect: "goflags",
    sub: [],
    flags: { "no-color": "bool", shellcheck: { values: [""] }, pyflakes: { values: [""] } },
    required: { shellcheck: "", pyflakes: "" },
    config: { flag: "-config-file", content: `self-hosted-runner:
  labels: []
paths:
  .github/workflows/**/*.{yml,yaml}:
    ignore:
      - 'unexpected key "cache-mode" for "job" section'
`, fileName: "actionlint.yaml" }
  },
  zizmor: { method: GH, package: "zizmor-x86_64-unknown-linux-gnu.tar.gz", exe: "zizmor", dialect: "long", sub: [], positionals: [".github/workflows"], flags: { offline: "bool" }, required: { offline: "true" }, config: { flag: "--config", content: "rules: {}\n", fileName: "zizmor.yml" } },
  // Biome 2.5.15: `biome ci` (lint + format check, never writes)
  biome: {
    method: "npm",
    package: "@biomejs/biome",
    npmBin: "bin/biome",
    exe: "biome",
    dialect: "long",
    sub: ["ci"],
    flags: {},
    config: { flag: "--config-path", content: '{\n  "linter": {\n    "rules": {\n      "complexity": {\n        "noExcessiveCognitiveComplexity": { "level": "error", "options": { "maxAllowedComplexity": 15 } }\n      }\n    }\n  }\n}\n', fileName: "biome.json" }
  },
  // ESLint 10.13.0: no warnings allowed; the pinned flat config lints the framework files too (P25)
  eslint: {
    method: "npm",
    package: "eslint",
    npmBin: "bin/eslint.js",
    exe: "eslint",
    dialect: "long",
    sub: [],
    positionals: ["."],
    flags: { "max-warnings": { values: ["0"] } },
    required: { "max-warnings": "0" },
    config: { flag: "--config", content: [`import js from`, `'@eslint/js';
export default [js.configs.recommended, { ${ESLINT_FILES}, languageOptions: { parserOptions: { ecmaFeatures: { jsx: true } } }, rules: { complexity: ['error', 15] } }];
`].join(" "), fileName: "eslint.config.mjs" }
  },
  "eslint-typescript": {
    method: "npm",
    package: "eslint",
    npmBin: "bin/eslint.js",
    exe: "eslint",
    dialect: "long",
    sub: [],
    positionals: ["."],
    flags: { "max-warnings": { values: ["0"] } },
    required: { "max-warnings": "0" },
    // built in parts so the bundled CLI holds no import statement of a non-node module (test/package.test.ts)
    config: { flag: "--config", content: [`import js from`, `'@eslint/js';
import tseslint from`, `'typescript-eslint';
export default [js.configs.recommended, ...tseslint.configs.recommended, { ${ESLINT_TS_FILES}, rules: { complexity: ['error', 15] } }];
`].join(" "), fileName: "eslint.config.mjs" }
  },
  // Oxlint 1.89.0
  "oxlint-typeaware": {
    method: "npm",
    package: "oxlint",
    npmBin: "bin/oxlint",
    closureEnv: { OXLINT_TSGOLINT_PATH: "node_modules/.bin/tsgolint" },
    exe: "oxlint",
    dialect: "long",
    sub: [],
    flags: { "type-aware": "bool", "deny-warnings": "bool", "no-ignore": "bool" },
    required: { "type-aware": "true", "deny-warnings": "true", "no-ignore": "true" },
    fileList: { extensions: OXLINT_EXTENSIONS },
    config: { flag: "--config", content: '{ "categories": { "correctness": "error" } }\n', fileName: "oxlintrc.json" }
  },
  // Prettier 3.9.10: check only (never --write); the repo's own Prettier config is used (catalogue §2)
  prettier: {
    method: "npm",
    package: "prettier",
    npmBin: "bin/prettier.cjs",
    loadsRepoConfig: true,
    exe: "prettier",
    dialect: "long",
    sub: [],
    positionals: ["."],
    flags: { check: "bool", "ignore-path": { values: [".prettierignore"] } },
    required: { check: "true", "ignore-path": ".prettierignore" },
    // the checkout's .prettierignore stays; the pinned (empty) ignore file is the second --ignore-path, so no .gitignore is read (C4 fix round 1; prettier 3.9.10 reads .gitignore and .prettierignore by default)
    config: { flag: "--ignore-path", content: "# pipegen's pinned prettier ignore file: nothing is ignored here, so a .gitignore in the checkout hides no file\n", fileName: "prettierignore" }
  },
  // Vitest 5.0.5: coverage on, with a minimum the AI chooses (P24)
  "vitest-coverage": {
    method: "npm",
    package: "vitest",
    npmBin: "vitest.mjs",
    runsRepoCode: true,
    exe: "vitest",
    dialect: "long",
    sub: ["run"],
    flags: { coverage: "bool", "coverage.thresholds.lines": { values: COVERAGE_MINIMUMS } },
    required: { coverage: "true", "coverage.thresholds.lines": null }
  },
  // c8 12.0.0: the service's tests (TEST_COMMANDS, after `--`) with a line minimum pipegen's code fills (D9, ruling B5); with no command c8 12.0.0
  // refuses every run ("Not enough non-option arguments", measured), and without --lines its default minimum is 90
  c8: {
    method: "npm",
    package: "c8",
    npmBin: "bin/c8.js",
    runsRepoCode: true,
    testCommand: true,
    exe: "c8",
    dialect: "long",
    sub: [],
    flags: { "check-coverage": "bool", lines: { values: COVERAGE_MINIMUMS } },
    required: { "check-coverage": "true", lines: null }
  },
  // Knip 6.42.1
  knip: { method: "npm", package: "knip", npmBin: "bin/knip.js", loadsRepoConfig: true, exe: "knip", dialect: "long", sub: [], flags: { "no-progress": "bool", "no-gitignore": "bool" }, required: { "no-gitignore": "true" } },
  // jscpd 5.4.2 (the release binary): new copy-paste against the base only; no semantic mode (jscpdProblems)
  jscpd: {
    method: GH,
    slots: { "--baseline-from-ref": "git-ref" },
    package: "jscpd-linux-x64-gnu.tar.gz",
    exe: "jscpd",
    dialect: "long",
    sub: [],
    positionals: ["."],
    flags: { "baseline-from-ref": { values: ["origin/main"] }, "fail-on-new-clones": { values: [""], optional: true }, "no-gitignore": "bool", reporters: { values: ["sarif"] }, output: { values: ["jscpd-report"] } },
    required: { "baseline-from-ref": "origin/main", "fail-on-new-clones": "", "no-gitignore": "true" },
    config: { flag: "--config", content: "{}\n", fileName: "jscpd.json" }
  },
  // hadolint 2.15.1: fails on warnings and errors (never --no-fail or a lower threshold)
  hadolint: {
    method: GH,
    slots: { "": "repo-path" },
    repoPathFrom: "dockerfile",
    package: "hadolint-linux-x86_64",
    exe: "hadolint",
    dialect: "long",
    sub: [],
    findingsExit: FOUND_1,
    flags: { "no-color": "bool", "failure-threshold": { values: ["warning"] }, format: { values: ["sarif"] }, output: "output" },
    required: { "failure-threshold": "warning", format: "sarif", output: null },
    config: { flag: "--config", content: "# pipegen's pinned hadolint config: every rule at its default level, nothing ignored\nignored: []\n", fileName: "hadolint.yaml" }
  },
  // kube-linter 0.8.3: an unrenderable chart, a bad path or YAML it can't parse fails the check (P25)
  "kube-linter": {
    method: GH,
    slots: { "": "repo-path" },
    repoPathFrom: "k8s-dir",
    package: "kube-linter-linux",
    exe: "kube-linter",
    dialect: "long",
    sub: ["lint"],
    findingsExit: FOUND_1,
    flags: { "fail-if-no-objects-found": "bool", "fail-on-invalid-resource": "bool", format: { values: ["sarif"] }, output: "output" },
    required: { "fail-if-no-objects-found": "true", "fail-on-invalid-resource": "true", format: "sarif", output: null },
    config: { flag: "--config", content: "# pipegen's pinned kube-linter config: the default checks\nchecks:\n  doNotAutoAddDefaults: false\n", fileName: "kube-linter.yaml" }
  },
  // Schemathesis 4.32.2: exactly 25 examples per operation, JUnit report
  schemathesis: {
    method: "pip",
    package: "schemathesis",
    exe: "schemathesis",
    dialect: "long",
    sub: ["run"],
    flags: { "max-examples": { values: ["25"] }, report: { values: ["junit"] }, "report-junit-path": "output" },
    required: { "max-examples": "25", report: "junit", "report-junit-path": null }
  },
  // pinact 5.0.0: check only (never rewrites the workflows), and every version comment checked
  pinact: { method: GH, package: "pinact_linux_amd64.tar.gz", exe: "pinact", dialect: "long", sub: ["run"], flags: { check: "bool", "verify-comment": "bool" }, required: { check: "true", "verify-comment": "true" } },
  // poutine 1.1.6
  poutine: {
    method: GH,
    package: "poutine_Linux_x86_64.tar.gz",
    exe: "poutine",
    dialect: "long",
    sub: ["analyze_local"],
    positionals: ["."],
    flags: { "disable-version-check": "bool", "fail-on-violation": "bool", quiet: "bool" },
    required: { "disable-version-check": "true", "fail-on-violation": "true" },
    config: { flag: "--config", content: "# pipegen's pinned poutine config: no skipped rules\nskip: []\n", fileName: "poutine.yml" }
  },
  // gosec 2.29.0 (Go flags): never -no-fail; every #nosec suppression is reported in the SARIF (P27)
  gosec: {
    method: GH,
    needsSlot: "is for Go: Go is not supported in v0.2 (a permanent refusal until Go setup is added)",
    package: "gosec_2.29.0_linux_amd64.tar.gz",
    exe: "gosec",
    dialect: "goflags",
    sub: [],
    positionals: ["./..."],
    findingsExit: FOUND_1,
    flags: { fmt: { values: ["sarif"] }, out: "output", "track-suppressions": "bool" },
    required: { fmt: "sarif", out: null, "track-suppressions": "true" }
  },
  // Ruff 0.17.1 (never --exit-zero, --fix or a format without --check)
  ruff: {
    method: GH,
    package: RUFF_ASSET,
    exe: "ruff",
    dialect: "long",
    sub: ["check"],
    findingsExit: FOUND_1,
    flags: { "no-cache": "bool", "output-format": { values: ["sarif"] }, "output-file": "output" },
    required: { "no-cache": "true", "output-format": "sarif", "output-file": null },
    config: { flag: "--config", content: 'respect-gitignore = false\n\n[lint]\nextend-select = ["C901"]\n\n[lint.mccabe]\nmax-complexity = 15\n', fileName: "ruff.toml" }
  },
  "ruff-format": {
    method: GH,
    package: RUFF_ASSET,
    exe: "ruff",
    dialect: "long",
    sub: ["format"],
    flags: { check: "bool", "no-cache": "bool" },
    required: { check: "true", "no-cache": "true" },
    config: { flag: "--config", content: "# pipegen's pinned ruff config: the default format, and files hidden by a .gitignore are still checked\nrespect-gitignore = false\n", fileName: "ruff.toml" }
  },
  // mypy 2.4.0 (never --install-types: it installs unpinned stub packages)
  mypy: { method: "pip", package: "mypy", exe: "mypy", dialect: "long", sub: [], positionals: ["."], flags: { "no-incremental": "bool" } },
  // coverage.py 7.16.2: pytest under coverage, then the minimum (P24)
  "coverage-py": {
    method: "pip",
    package: "coverage",
    exe: "coverage",
    dialect: "long",
    sub: ["run"],
    positionals: ["pytest"],
    flags: { module: "bool" },
    required: { module: "true" },
    then: [{ sub: ["report"], flags: { "fail-under": { values: COVERAGE_MINIMUMS } }, required: { "fail-under": null } }]
  },
  creosote: { method: "pip", package: "creosote", exe: "creosote", dialect: "long", sub: [], flags: {} },
  vulture: { method: "pip", package: "vulture", exe: "vulture", dialect: "long", sub: [], positionals: ["."], flags: { "min-confidence": { values: ["80"] } }, required: { "min-confidence": "80" } },
  // Bandit 1.9.4 (never --exit-zero)
  bandit: {
    method: "pip",
    package: "bandit",
    exe: "bandit",
    dialect: "long",
    sub: [],
    positionals: ["."],
    findingsExit: FOUND_1,
    flags: { recursive: "bool", format: { values: ["sarif"] }, output: "output" },
    required: { recursive: "true", format: "sarif", output: null },
    // pipegen's own (empty) .bandit: without --ini bandit walks the targets and loads the only `.bandit` it finds, wherever it is (C4 review 1; bandit 1.9.4 cli/main.py)
    config: { flag: "--ini", content: "[bandit]\n", fileName: "bandit.ini" }
  }
};
var READS_ONLY = [
  // pinned config passed by flag
  "trivy-config",
  "trivy-image",
  "trivy-licence",
  "betterleaks",
  "gitleaks",
  "osv-scanner",
  "syft",
  "actionlint",
  "zizmor",
  "biome",
  "eslint",
  "eslint-typescript",
  "oxlint-typeaware",
  "jscpd",
  "hadolint",
  "kube-linter",
  "poutine",
  "ruff",
  "ruff-format",
  "zap-baseline",
  // no config file, but verified rules/templates only, no repo plugin mechanism on the allowlist
  "semgrep",
  "nuclei"
];
var ARGV_POLICIES = Object.freeze(Object.fromEntries(
  Object.entries(POLICIES).map(([id, pol]) => [id, READS_ONLY.includes(id) ? { ...pol, readsOnly: true } : pol])
));
var sha16 = (text) => createHash("sha256").update(text).digest("hex").slice(0, 16);
var stagePath = (artifact) => `\${{ runner.temp }}/pipegen-stage/${artifact}`;
var isStagedTool = (tool2) => tool2 !== void 0 && Object.hasOwn(ARGV_POLICIES, tool2) && ARGV_POLICIES[tool2]?.staged !== void 0;
var PIPEGEN_GATE_USES = "crisworking/pipegen/gate";
var GATE_USES_RE = new RegExp(`^${PIPEGEN_GATE_USES.replace(/[/.]/g, "\\$&")}@[0-9a-f]{40}$`);
var PIP_CLOSURES = Object.freeze({});
var PLATFORM_USES = Object.freeze({
  checkout: "actions/checkout",
  "setup-node": "actions/setup-node",
  "setup-python": "actions/setup-python",
  "upload-artifact": "actions/upload-artifact",
  "download-artifact": "actions/download-artifact",
  "docker-login": "docker/login-action",
  "setup-buildx": "docker/setup-buildx-action",
  "build-push": "docker/build-push-action",
  "upload-sarif": "github/codeql-action/upload-sarif",
  attest: "actions/attest"
});
var PLATFORM_LOCKS = Object.freeze({
  "actions/checkout": { "persist-credentials": "false", "allow-unsafe-pr-checkout": "false" },
  "actions/setup-node": { "package-manager-cache": "false" },
  // archive (v7.0.0+, pinned v7.0.2 action.yml): 'false' uploads one file unzipped under its own name; the gate reads only a zip (C5a fix round 1)
  "actions/upload-artifact": { "include-hidden-files": "false", "if-no-files-found": "error", archive: "true" },
  // the docker actions' cache and credential locks (6b, review R1-5): checked here, not only by the loader
  "docker/build-push-action": { "no-cache": "true", "github-token": "", context: "." },
  "docker/setup-buildx-action": { "cache-binary": "false" },
  "docker/login-action": { logout: "true" }
});
var CACHE_LOCKS = Object.freeze(Object.fromEntries(
  Object.values(PLATFORM_LOCKS).flatMap((locks) => Object.entries(locks)).filter(([k]) => /(?:^|[-_])cache(?:$|[-_])/i.test(k))
));
var ACTION_POLICIES = Object.freeze({
  "actions/checkout": {
    "persist-credentials": { values: ["false"], as: "fixed", required: true },
    "allow-unsafe-pr-checkout": { values: ["false"], as: "fixed", required: true },
    "fetch-depth": { values: ["1", "0"], as: "choice" }
  },
  "actions/setup-node": {
    "package-manager-cache": { values: ["false"], as: "fixed", required: true },
    "node-version": { values: ["22", "24", "26"], as: "choice" }
    // 22 (maintenance until 2027-04-30), 24, 26; the renderer maps the repo's own version onto these (render-step.ts mapNodeVersion)
  },
  "actions/setup-python": { "python-version": { values: ["3.11", "3.12", "3.13", "3.14"], as: "choice" } },
  // hidden files (.env and the like) are never uploaded; a missing file is an error. `path` is set by the renderer
  // from the scanning entries' own output paths, never by the template
  "actions/upload-artifact": {
    "include-hidden-files": { values: ["false"], as: "fixed" },
    "if-no-files-found": { values: ["error"], as: "fixed" },
    archive: { values: ["true"], as: "fixed", required: true }
  },
  "actions/download-artifact": {},
  "docker/login-action": { logout: { values: ["true"], as: "fixed", required: true }, registry: { values: ["ghcr.io"], as: "choice" } },
  // ghcr.io only: the login sends the workflow token, which must never go to another registry (review 6a)
  "docker/setup-buildx-action": { "cache-binary": { values: ["false"], as: "fixed", required: true } },
  "docker/build-push-action": {
    context: { values: ["."], as: "fixed", required: true },
    "github-token": { values: [""], as: "fixed", required: true },
    "no-cache": { values: ["true"], as: "fixed", required: true },
    push: { values: ["false", "true"], as: "choice" }
  },
  "github/codeql-action/upload-sarif": {},
  "actions/attest": {},
  // pipegen's own gate action: no inputs of its own to fix or choose; every one is the renderer's (RENDERER_INPUTS below)
  [PIPEGEN_GATE_USES]: {},
  "bullfrogsec/bullfrog": {
    "egress-policy": { values: ["block"], as: "fixed", required: true },
    "dns-policy": { values: ["allowed-domains-only"], as: "fixed", required: true },
    "enable-sudo": { values: ["false"], as: "fixed", required: true },
    "allowed-domains": { values: ["github-core", "npm", "pypi", "dockerhub", "ghcr"], as: "choice" },
    "allowed-ips": { values: ["172.16.0.0/12"], as: "choice" }
  },
  // dependency review checks vulnerabilities (never off), blocks on low, moderate or high, never only warns, and never
  // compares a ref pipegen didn't choose (base-ref/head-ref: an empty diff passes; T3)
  "actions/dependency-review-action": {
    "comment-summary-in-pr": { values: ["never"], as: "fixed", required: true },
    "vulnerability-check": { values: ["true"], as: "fixed" },
    "fail-on-severity": { values: ["low", "moderate", "high"], as: "either" },
    "warn-only": { values: ["false"], as: "fixed" }
  },
  "ossf/scorecard-action": {
    publish_results: { values: ["false"], as: "fixed", required: true },
    results_format: { values: ["sarif"], as: "fixed" },
    results_file: { values: ["scorecard.sarif"], as: "fixed" }
  },
  // trusted publishing with attestations, to PyPI or TestPyPI only (P22)
  "pypa/gh-action-pypi-publish": {
    attestations: { values: ["true"], as: "fixed", required: true },
    "repository-url": { values: ["https://upload.pypi.org/legacy/", "https://test.pypi.org/legacy/"], as: "fixed" },
    "packages-dir": { values: ["dist"], as: "fixed" },
    "skip-existing": { values: ["false", "true"], as: "fixed" },
    "print-hash": { values: ["true", "false"], as: "fixed" },
    verbose: { values: ["true", "false"], as: "fixed" }
  }
});
var rx = (re, describe, whenWith) => ({ describe, check: (v) => re.test(v), ...whenWith === void 0 ? {} : { whenWith } });
var TIMEOUT_MINUTES_RE = /^(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|360)$/;
var PLAIN_REL_RE = /^(?![-/])(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,200}$/;
var GHCR_ONLY = { check: (all) => all.registry === "ghcr.io", describe: "only when the registry is ghcr.io" };
var RUNNER_TEMP_PATH = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-out\/[a-z0-9][a-z0-9-]{0,120}(?:\/[A-Za-z0-9_][A-Za-z0-9._-]{0,100}){0,3}$/, "a path under ${{ runner.temp }}/pipegen-out/<artifact>");
var OWN_ARTIFACT_FOLDER = {
  check: (all) => {
    const folder = `\${{ runner.temp }}/pipegen-out/${all.name ?? ""}`;
    return typeof all.name === "string" && typeof all.path === "string" && (all.path === folder || all.path.startsWith(`${folder}/`));
  },
  describe: "only inside its own artifact folder (${{ runner.temp }}/pipegen-out/<name>)"
};
var OWN_FOLDER_PATH = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-out\/[a-z0-9][a-z0-9-]{0,120}(?:\/[A-Za-z0-9_][A-Za-z0-9._-]{0,100}){0,3}$/, "a path under ${{ runner.temp }}/pipegen-out/<artifact>", OWN_ARTIFACT_FOLDER);
var ARTIFACT_NAME = rx(new RegExp(`^${RESULT_ARTIFACT_PREFIX}[a-z0-9][a-z0-9-]{0,120}$`), `a result artifact name (${RESULT_ARTIFACT_PREFIX}\u2026)`);
var GATE_FILES_FOLDER = "pipegen-gate";
var GATE_FILES_DIR = `\${{ runner.temp }}/${GATE_FILES_FOLDER}`;
var GATE_UPLOAD_FILES = Object.freeze({
  [GATE_RESULT_ARTIFACT]: "result.json",
  [BASELINE_ARTIFACT]: "baseline.json",
  [CLEAN_RUN_ARTIFACT]: "marker.json"
});
var isGateUploadName = (name) => typeof name === "string" && Object.hasOwn(GATE_UPLOAD_FILES, name);
var gateUploadPath = (name) => `${GATE_FILES_DIR}/${GATE_UPLOAD_FILES[name]}`;
var UPLOAD_NAME = {
  describe: `a result artifact name (${RESULT_ARTIFACT_PREFIX}\u2026) or one of the gate's own (${Object.keys(GATE_UPLOAD_FILES).join(", ")})`,
  check: (v) => ARTIFACT_NAME.check(v) || isGateUploadName(v)
};
var TEMP = "${{ runner.temp }}";
var RESULT_FILE = "[A-Za-z0-9_][A-Za-z0-9._-]{0,100}";
var RAW_PATH_RE = new RegExp(`^\\$\\{\\{ runner\\.temp \\}\\}/pipegen-raw/(${RESULT_ARTIFACT_PREFIX}[a-z0-9][a-z0-9-]{0,120})/(${RESULT_FILE})$`);
function rawResultParts(path) {
  const m = RAW_PATH_RE.exec(path);
  return m === null ? null : { artifact: m[1], file: m[2] };
}
function scrubbedResultPath(rawPath) {
  const parts = rawResultParts(rawPath);
  return parts === null ? null : `${TEMP}/pipegen-out/${parts.artifact}/${parts.file}`;
}
var MODE_SCRUB = { check: (all) => all.mode === "scrub", describe: "only in mode scrub" };
var SCRUB_RAW = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-raw\//, "a path ${{ runner.temp }}/pipegen-raw/<artifact>/<file>", {
  check: (all) => MODE_SCRUB.check(all) && rawResultParts(all.raw ?? "")?.artifact === all.artifact,
  describe: "only in mode scrub, inside the folder of the artifact it names (${{ runner.temp }}/pipegen-raw/<artifact>/<file>)"
});
var SCRUB_OUT = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-out\//, "a path ${{ runner.temp }}/pipegen-out/<artifact>/<file>", {
  check: (all) => MODE_SCRUB.check(all) && scrubbedResultPath(all.raw ?? "") === all.out && rawResultParts(all.raw ?? "")?.artifact === all.artifact,
  describe: "only in mode scrub, at the same file as raw, in the folder of the artifact it names (${{ runner.temp }}/pipegen-out/<artifact>/<file>)"
});
var inScrubMode = (input) => ({ ...input, whenWith: input.whenWith ?? MODE_SCRUB });
var GATE_MODES = ["scrub", "stage", "gate", "find-run", "nightly", "baseline-check"];
var inModes = (modes) => ({
  check: (all) => modes.some((m) => all.mode === m),
  describe: `only in mode ${modes.join(" or ")}`
});
var modeInput = (modes, re, describe) => rx(re, describe, inModes(modes));
var literalInput = (modes, problem, describe) => ({
  describe,
  check: (v) => problem(v) === null,
  whenWith: inModes(modes)
});
var ID_LIST_MAX = 50;
function idListProblem(text) {
  const list = parseJson(text);
  if (!Array.isArray(list) || list.length > ID_LIST_MAX) return `a JSON list of at most ${ID_LIST_MAX} need ids`;
  return list.every((x) => typeof x === "string" && NEED_ID_TEXT_RE.test(x)) ? null : "a JSON list of need ids (lower case letters, digits and dashes)";
}
function policyProblem2(text) {
  return policyProblem(parseJson(text));
}
var GLOB_RE = /^(?![-/])(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/*?-]{1,200}$/;
function pathListProblem(text) {
  const list = parseJson(text);
  if (!Array.isArray(list) || list.length > 100) return "a JSON list of at most 100 path globs";
  return list.every((x) => typeof x === "string" && GLOB_RE.test(x)) ? null : "a JSON list of plain relative path globs (no .., no leading /)";
}
var SERVICE_ROOT_RE = /^(?:\.|(?![-/])(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,200})$/;
function serviceRootsProblem(text) {
  const list = parseJson(text);
  if (!Array.isArray(list) || list.length > 100) return "a JSON list of at most 100 service folders";
  return list.every((x) => typeof x === "string" && SERVICE_ROOT_RE.test(x) && !x.includes("//")) ? null : "a JSON list of plain relative folders (or .), no glob, no .., no leading /";
}
function licenceLockfilesProblem(text) {
  const list = parseJson(text);
  const shape = 'a JSON list of at most 100 { "service", "lockfiles": [{ "kind", "read" }] } entries';
  if (!Array.isArray(list) || list.length > 100) return shape;
  for (const e of list) {
    if (!isPlainObject(e) || Object.keys(e).sort().join() !== "lockfiles,service") return shape;
    if (typeof e.service !== "string" || e.service.length > 40 || !SERVICE_SLUG_RE.test(e.service)) return `${shape}, each service a service slug`;
    if (!Array.isArray(e.lockfiles) || e.lockfiles.length > 4) return `${shape}, at most 4 lockfiles each`;
    for (const l of e.lockfiles) {
      if (!isPlainObject(l) || Object.keys(l).sort().join() !== "kind,read" || !isLockfileKind(l.kind) || typeof l.read !== "boolean") return `${shape}, each lockfile a known kind (${Object.keys(TRIVY_LICENCE_LOCKFILES).join(", ")}) with read true or false`;
      if (l.read && TRIVY_LICENCE_LOCKFILES[l.kind].licences === "never") return `${shape}; a ${l.kind} lockfile is never read by the licence scan`;
    }
  }
  return null;
}
function warnFirstListProblem(text) {
  const list = parseJson(text);
  const shape = 'a JSON list of at most 50 { "needId", "since": "YYYY-MM-DD" } entries, each need once';
  if (!Array.isArray(list) || list.length > ID_LIST_MAX) return shape;
  const seen = /* @__PURE__ */ new Set();
  for (const e of list) {
    if (!isPlainObject(e) || Object.keys(e).sort().join() !== "needId,since" || typeof e.needId !== "string" || !NEED_ID_TEXT_RE.test(e.needId) || typeof e.since !== "string" || validDate(e.since) !== e.since || seen.has(e.needId)) return shape;
    seen.add(e.needId);
  }
  return null;
}
var NEED_ID_TEXT_RE = /^(?!base-)(?!.*--)[a-z0-9][a-z0-9-]{0,63}$/;
var JOB_ID_TEXT_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,99}$/;
var SERVICE_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
var TOOL_ID_TEXT_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
var RESULT_ARTIFACT_NAME_RE = new RegExp(`^${RESULT_ARTIFACT_PREFIX}[a-z0-9][a-z0-9-]{0,120}$`);
var RESULT_NAME_TEXT_RE = RESULT_ARTIFACT_NAME_RE;
var DATE_TEXT_RE = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/;
var JOB_LIST_KEYS = ["needId", "service", "job", "category", "tool", "format", "artifact", "baseArtifact", "blocking", "needsSecrets", "warnFirst", "range"];
var JOB_LIST_MAX = 500;
var JOB_LIST_MAX_TEXT = 2e5;
var isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function parseJson(text) {
  if (typeof text !== "string" || text.length > JOB_LIST_MAX_TEXT) return void 0;
  try {
    return JSON.parse(text);
  } catch {
    return void 0;
  }
}
var FIELD_CHECKS = {
  needId: (v) => typeof v === "string" && NEED_ID_TEXT_RE.test(v),
  service: (v) => typeof v === "string" && v.length <= 40 && SERVICE_SLUG_RE.test(v) && !v.includes("--"),
  job: (v) => typeof v === "string" && JOB_ID_TEXT_RE.test(v),
  category: (v) => typeof v === "string" && NEED_CATEGORIES.includes(v),
  tool: (v) => typeof v === "string" && TOOL_ID_TEXT_RE.test(v),
  format: (v) => v === "sarif" || v === "zap-json" || v === "junit" || v === "none",
  artifact: (v) => typeof v === "string" && RESULT_NAME_TEXT_RE.test(v),
  baseArtifact: (v) => typeof v === "string" && RESULT_NAME_TEXT_RE.test(v),
  blocking: (v) => typeof v === "boolean",
  needsSecrets: (v) => typeof v === "boolean",
  warnFirst: (v) => isPlainObject(v) && Object.keys(v).join() === "since" && typeof v.since === "string" && DATE_TEXT_RE.test(v.since),
  range: (v) => v === true
};
var RANGE_TOOL = SECRETS_RANGE_TOOL;
function rangeEntryProblem(e) {
  const want = { needId: "secrets", category: "secrets", tool: RANGE_TOOL, format: "sarif", artifact: SECRETS_RANGE_ARTIFACT, blocking: true };
  for (const [k, v] of Object.entries(want)) if (e[k] !== v) return `its ${k} is not the one of the commit-range scan`;
  if (Object.hasOwn(e, "baseArtifact") || Object.hasOwn(e, "service") || Object.hasOwn(e, "warnFirst")) return "it names a base artifact, a service or warn-first, which the commit-range scan never has";
  return null;
}
var JOB_LIST_REQUIRED = ["needId", "job", "category", "format", "blocking", "needsSecrets"];
function jobListLiteralProblem(text) {
  const list = parseJson(text);
  if (!Array.isArray(list)) return "it is not a JSON list";
  if (list.length > JOB_LIST_MAX) return `it has more than ${JOB_LIST_MAX} entries`;
  const jobs = /* @__PURE__ */ new Set();
  const secretsJobs = /* @__PURE__ */ new Set();
  const ranges = [];
  for (const [i, e] of list.entries()) {
    if (!isPlainObject(e)) return `entry ${i + 1} is not an object`;
    for (const k of Object.keys(e)) if (!JOB_LIST_KEYS.includes(k)) return `entry ${i + 1} has the key ${JSON.stringify(k.slice(0, 40))}, which a job list entry never has`;
    for (const k of JOB_LIST_REQUIRED) if (!Object.hasOwn(e, k)) return `entry ${i + 1} has no ${k}`;
    for (const k of JOB_LIST_KEYS) if (Object.hasOwn(e, k) && !FIELD_CHECKS[k](e[k])) return `entry ${i + 1} has a ${k} that is not in the form pipegen writes`;
    if (e.range === true) {
      const p = rangeEntryProblem(e);
      if (p !== null) return `entry ${i + 1} is marked range, but ${p}`;
      ranges.push(e.job);
      continue;
    }
    if (jobs.has(e.job)) return `the job ${JSON.stringify(e.job)} is listed twice`;
    jobs.add(e.job);
    if (e.needId === "secrets" && e.category === "secrets") secretsJobs.add(e.job);
  }
  if (ranges.length > 1) return "it has more than one commit-range entry";
  for (const job of ranges) if (!secretsJobs.has(job)) return `its commit-range entry names the job ${JSON.stringify(job)}, which is not the job of its secrets check`;
  return null;
}
var BASE_CHECKOUT_REF = `\${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event_name == 'pull_request_review' && github.event.pull_request.base.sha || github.event_name == 'merge_group' && github.event.merge_group.base_sha || github.event_name == 'push' && github.event.before || '${"0".repeat(40)}' }}`;
var RANGE_HEAD_REF = `\${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.event_name == 'pull_request_review' && github.event.pull_request.head.sha || github.event_name == 'merge_group' && github.event.merge_group.head_sha || github.event_name == 'push' && github.event.after || '${"0".repeat(40)}' }}`;
var RANGE_BEFORE_REF = `\${{ github.event_name == 'pull_request' && github.event.action == 'synchronize' && github.event.before || '${"0".repeat(40)}' }}`;
var RANGE_EVENT_REF = "${{ github.event_name }}";
var RANGE_STEP_ENV = Object.freeze({ PIPEGEN_RANGE_BASE: BASE_CHECKOUT_REF, PIPEGEN_RANGE_HEAD: RANGE_HEAD_REF, PIPEGEN_RANGE_BEFORE: RANGE_BEFORE_REF, PIPEGEN_RANGE_EVENT: RANGE_EVENT_REF });
var rangeScanStepId = `checker-run-${sha16(SECRETS_RANGE_ARTIFACT)}`;
var RENDERER_INPUTS = Object.freeze({
  // the base commit, for the base-scan job only (the job rule is in job-rules.ts); no other ref is ever set
  "actions/checkout": { ref: { describe: "the event-switched base commit (BASE_CHECKOUT_REF) and nothing else", check: (v) => v === BASE_CHECKOUT_REF } },
  // a result upload sits in its own pipegen-out folder; the gate's reserved names only at their own pipegen-gate file (C5b)
  "actions/upload-artifact": {
    name: UPLOAD_NAME,
    path: {
      describe: `${OWN_FOLDER_PATH.describe}, or for the gate's own artifacts their file in ${GATE_FILES_DIR}`,
      check: (v) => OWN_FOLDER_PATH.check(v) || Object.keys(GATE_UPLOAD_FILES).some((n) => v === gateUploadPath(n)),
      whenWith: {
        check: (all) => isGateUploadName(all.name) ? all.path === gateUploadPath(all.name) : OWN_ARTIFACT_FOLDER.check(all),
        describe: `only inside its own artifact folder (\${{ runner.temp }}/pipegen-out/<name>), or for a gate artifact at its own file in ${GATE_FILES_DIR}`
      }
    }
  },
  "actions/download-artifact": { name: ARTIFACT_NAME, path: OWN_FOLDER_PATH },
  "github/codeql-action/upload-sarif": { sarif_file: RUNNER_TEMP_PATH, category: rx(/^pipegen-[a-z0-9][a-z0-9-]{0,100}$/, "a category starting pipegen-") },
  "actions/attest": {
    "subject-name": rx(/^(?:ghcr\.io|docker\.io)\/[a-z0-9][a-z0-9._/-]{0,200}$/, "an image name on ghcr.io or docker.io, with no tag"),
    "subject-digest": rx(/^sha256:[0-9a-f]{64}$/, "a sha256 digest")
  },
  "docker/build-push-action": {
    file: rx(PLAIN_REL_RE, "a repo-relative file path"),
    tags: rx(/^[a-z0-9][a-z0-9._/-]{0,200}:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/, "one image reference with a tag")
  },
  "docker/login-action": {
    username: rx(/^\$\{\{ github\.actor \}\}$/, "${{ github.actor }}"),
    password: rx(/^\$\{\{ secrets\.GITHUB_TOKEN \}\}$/, "${{ secrets.GITHUB_TOKEN }}", GHCR_ONLY)
  },
  // pipegen's own gate action. Every input is the renderer's (the entry fixes none and offers no choice); each mode has its
  // own inputs, checked with `whenWith` on `mode`, so a mode's input is refused under another mode (Plan C rulings B1 and B3).
  [PIPEGEN_GATE_USES]: {
    mode: rx(new RegExp(`^(?:${GATE_MODES.join("|")})$`), `one of ${GATE_MODES.join(", ")}`),
    // scrub (ruling B1) and stage (C1c)
    artifact: { ...ARTIFACT_NAME, whenWith: inModes(["scrub", "stage"]) },
    tool: rx(/^[a-z0-9][a-z0-9-]{0,63}$/, "a reviewed tool id", {
      check: (all) => all.mode === "scrub" || all.mode === "stage" && isStagedTool(all.tool),
      describe: "only in mode scrub, or in mode stage for a tool that scans a stage folder (betterleaks, gitleaks)"
    }),
    // stage (C1c): the stage folder of the artifact named, in mode stage, and in mode scrub for a tool that scans one
    stage: rx(/^\$\{\{ runner\.temp \}\}\/pipegen-stage\/[a-z0-9][a-z0-9-]{0,120}$/, "the stage folder ${{ runner.temp }}/pipegen-stage/<artifact>", {
      check: (all) => (all.mode === "stage" || all.mode === "scrub") && isStagedTool(all.tool) && typeof all.artifact === "string" && all.stage === stagePath(all.artifact),
      describe: "only in mode stage or scrub, for a tool that scans a stage folder, as the stage folder of the artifact it names"
    }),
    format: inScrubMode(rx(/^(?:sarif|zap-json)$/, "sarif or zap-json")),
    raw: SCRUB_RAW,
    out: SCRUB_OUT,
    // the fingerprint key: the scrub hashes with it, the gate checks the baseline's MAC with it (ruling B6)
    "fp-key": modeInput(["scrub", "gate", "baseline-check", "nightly"], /^\$\{\{ secrets\.PIPEGEN_FP_KEY \}\}$/, "${{ secrets.PIPEGEN_FP_KEY }}"),
    // gate (ruling B3)
    jobs: modeInput(["gate"], /^\$\{\{ toJSON\(needs\) \}\}$/, "${{ toJSON(needs) }}"),
    "job-list": literalInput(["gate"], jobListLiteralProblem, "a job list literal (a JSON list of entries)"),
    "not-proven": literalInput(["gate"], idListProblem, "a JSON list of need ids"),
    skipped: literalInput(["gate"], idListProblem, "a JSON list of need ids"),
    policy: literalInput(["gate"], policyProblem2, 'a JSON policy { "block": [...], "warn": [...] }'),
    "protected-paths": literalInput(["gate"], pathListProblem, "a JSON list of plain relative path globs"),
    // the service folders (C5a CF3): the root-scoped config names are protected at each of them too (effectiveProtectedPaths)
    "service-roots": literalInput(["gate"], serviceRootsProblem, "a JSON list of plain relative service folders"),
    // the lockfile kinds per service and whether the licence scan reads them (final review fix round A, ruling 2): the licence check's coverage
    "licence-lockfiles": literalInput(["gate"], licenceLockfilesProblem, "a JSON list of { service, lockfiles: [{ kind, read }] }"),
    // gate and nightly
    "block-from": modeInput(["gate", "nightly"], /^\$\{\{ vars\.PIPEGEN_BLOCK_FROM \}\}$/, "${{ vars.PIPEGEN_BLOCK_FROM }}"),
    "block-from-recorded": literalInput(["gate", "nightly"], (v) => validDate(v) === v ? null : "a real calendar date", "a real calendar date YYYY-MM-DD"),
    // gate, find-run, nightly and baseline-check: the workflow token, nothing else
    "github-token": modeInput(["gate", "find-run", "nightly", "baseline-check"], /^\$\{\{ secrets\.GITHUB_TOKEN \}\}$/, "${{ secrets.GITHUB_TOKEN }}"),
    // baseline-check (C3): github-token and fp-key only, above
    // find-run
    sha: modeInput(["find-run"], /^\$\{\{ (?:github\.sha|github\.event\.workflow_run\.head_sha) \}\}$/, "${{ github.sha }} or ${{ github.event.workflow_run.head_sha }}"),
    "central-workflow": modeInput(["find-run"], PLAIN_REL_RE, "a plain relative path of the central workflow"),
    "central-sha": modeInput(["find-run"], /^[0-9a-f]{40}$/, "a 40-character commit"),
    // how long find-run waits for a run in progress (C8): whole minutes, 1 to 360 (a job's own limit)
    "timeout-minutes": modeInput(["find-run"], TIMEOUT_MINUTES_RE, "whole minutes, 1 to 360"),
    // where the gate runs (C8 fix round 1): `inline` (the gate job is in pipegen.yml) or `central` (the per-project central workflow); the renderer
    // knows it from the draft and the referee checks it. find-run never guesses it from the repository's visibility.
    layout: modeInput(["find-run"], /^(?:inline|central)$/, "inline or central"),
    // nightly (C7): block-from, block-from-recorded, github-token and fp-key (to verify the baseline) above; the setup merge time is read from the API, which proves it
    // the warn-first checks and their dates (final review fix round A, ruling 3): the nightly's "switch to blocking" issues
    "warn-first": literalInput(["nightly"], warnFirstListProblem, "a JSON list of { needId, since }")
  }
});

// src/util/safe-text.ts
var DEFAULT_MAX = 200;
var PATH_SHOWN_MAX = 4096;
var OSC = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)/g;
var CSI = /\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]/g;
var ESC_OTHER = /\x1b[\x20-\x2f]*[\x30-\x7e]?/g;
var CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
var BIDI = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/g;
function clean(s) {
  return String(s).replace(OSC, "").replace(CSI, "").replace(ESC_OTHER, "").replace(CONTROL, "").replace(BIDI, "");
}
function cut(s, max) {
  const chars = Array.from(s);
  if (chars.length <= max) return s;
  if (max <= 0) return "";
  return chars.slice(0, max - 1).join("") + "\u2026";
}
var INVISIBLE = /[\p{Default_Ignorable_Code_Point}\ufff9-\ufffb]/gu;
var LINE_SEP = /[\u2028\u2029]/g;
function safeText(s, max = DEFAULT_MAX) {
  return cut(clean(s).replace(INVISIBLE, "").replace(LINE_SEP, " "), max);
}
var ZWSP = "\u200B";
function safeMarkdown(s, max = DEFAULT_MAX) {
  const escaped = clean(s).replace(INVISIBLE, "").replace(LINE_SEP, " ").trim().replace(/\\/g, "\\\\").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/[`*_|~[\]]/g, "\\$&").replace(/\$/g, `${ZWSP}\\$$`).replace(/[!^](?=\\\[|$)/g, "\\$&").replace(/#$/, "\\#").replace(/^(?:[#+=:-]|(\d+)([.)]))/, (m, digits, mark) => digits === void 0 ? `\\${m}` : `${digits}\\${mark}`).replace(/^\\\[/, `${ZWSP}\\[`).replace(/\/(?=\/)/g, `/${ZWSP}`).replace(/(www)\./gi, `$1${ZWSP}.`).replace(/@/g, `${ZWSP}@${ZWSP}`).replace(/#(?=\d)/g, `#${ZWSP}`).replace(/\b(GH)-(?=\d)/gi, `$1${ZWSP}-`);
  const cutText2 = cut(escaped, max);
  if (cutText2 === escaped) return cutText2;
  if (cutText2 === "") return "";
  return `${dropHalfEscape(cutText2.slice(0, -1))}\u2026`;
}
function dropHalfEscape(body) {
  let n = 0;
  while (n < body.length && body[body.length - 1 - n] === "\\") n++;
  if (n % 2 === 1) return body.slice(0, -1);
  return body.replace(/&[a-z]{0,3}$/, "");
}

// gate/src/fingerprint.ts
import { createHash as createHash2, createHmac } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync, realpathSync } from "node:fs";
import { join, sep } from "node:path";

// src/ai/redact-core.ts
var R = "[REDACTED]";
var LONG_LINE = "[REDACTED: line too long]";
var MAX_REGEX_LINE_BYTES = 4096;
function regexSafe(s) {
  return Buffer.byteLength(s) <= MAX_REGEX_LINE_BYTES;
}
var TOKEN_RULES = [
  // AKIA long-term keys, ASIA temporary (STS) keys, and the other documented access-key id prefixes; the body is the old [0-9A-Z] class (a superset of base32)
  ["aws-access-key", /(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[0-9A-Z]{16}/g],
  ["github-token", /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ["github-fine-grained-token", /github_pat_[A-Za-z0-9_]{20,}/g],
  ["slack-token", /xox[abpr]-[A-Za-z0-9-]+/g],
  ["stripe-key", /sk_(?:live|test)_[A-Za-z0-9]{10,}/g],
  ["sk-api-key", /sk-[A-Za-z0-9_-]{20,}/g],
  ["slack-webhook", /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]+/g],
  ["google-api-key", /AIza[0-9A-Za-z_-]{35}/g],
  ["npm-token", /npm_[A-Za-z0-9]{36}/g]
];
function replaceSpans(s, spans) {
  if (spans.length === 0) return s;
  const sorted = spans.filter(([a, b]) => b > a).sort((x, y) => x[0] - y[0]);
  let out = "";
  let pos = 0;
  for (const [a, b] of sorted) {
    if (b <= pos) continue;
    out += s.slice(pos, Math.max(a, pos)) + (a >= pos ? R : "");
    pos = b;
  }
  return out + s.slice(pos);
}
var code = (s, i) => s.charCodeAt(i);
var isLetter = (c) => c >= 65 && c <= 90 || c >= 97 && c <= 122;
var isDigit = (c) => c >= 48 && c <= 57;
var isB64Url = (c) => isLetter(c) || isDigit(c) || c === 95 || c === 45;
var isSchemeChar = (c) => isLetter(c) || isDigit(c) || c === 43 || c === 46 || c === 45;
var isSpace = (c) => c === 32 || c === 9 || c === 13 || c === 10 || c === 12 || c === 11;
var isNameChar = (c) => isLetter(c) || isDigit(c) || c === 95 || c === 46 || c === 45;
function jwtSpans(s) {
  const spans = [];
  let from = 0;
  for (let i = s.indexOf("eyJ", from); i >= 0; i = s.indexOf("eyJ", from)) {
    let j = i + 3;
    while (j < s.length && isB64Url(code(s, j))) j++;
    const seg1End = j;
    let ok = seg1End - i >= 4 && code(s, j) === 46;
    let k = j + 1;
    if (ok) {
      while (k < s.length && isB64Url(code(s, k))) k++;
      ok = k - (j + 1) >= 4 && code(s, k) === 46;
    }
    let m = k + 1;
    if (ok) {
      while (m < s.length && isB64Url(code(s, m))) m++;
    }
    if (ok) {
      spans.push([i, m]);
      from = m;
    } else {
      from = Math.max(seg1End, i + 1);
    }
  }
  return spans;
}
function connectionSpans(s) {
  const spans = [];
  const n = s.length;
  let lastHostAt = null;
  const lastHostAtFrom = (i) => {
    if (lastHostAt === null) {
      lastHostAt = new Int32Array(n + 1).fill(-1);
      let cur = -1;
      for (let p = n - 1; p >= 0; p--) {
        const c = code(s, p);
        if (isSpace(c)) cur = -1;
        else if (c === 64 && cur === -1 && p + 1 < n && (isLetter(code(s, p + 1)) || isDigit(code(s, p + 1)) || code(s, p + 1) === 91)) cur = p;
        lastHostAt[p] = cur;
      }
    }
    return i < n ? lastHostAt[i] : -1;
  };
  let from = 0;
  for (let sep3 = s.indexOf("://", from); sep3 >= 0; sep3 = s.indexOf("://", from)) {
    from = sep3 + 1;
    if (sep3 === 0 || !isSchemeChar(code(s, sep3 - 1))) continue;
    const start = sep3 + 3;
    let authEnd = start;
    while (authEnd < n) {
      const c = code(s, authEnd);
      if (c === 47 || c === 63 || c === 35 || isSpace(c)) break;
      authEnd++;
    }
    while (authEnd < n && code(s, authEnd) === 47) {
      let segEnd = authEnd + 1;
      let hasAt = false;
      while (segEnd < n) {
        const c = code(s, segEnd);
        if (c === 47 || c === 63 || c === 35 || isSpace(c)) break;
        if (c === 64) hasAt = true;
        segEnd++;
      }
      if (!hasAt) break;
      authEnd = segEnd;
    }
    let at3 = -1;
    for (let p = authEnd - 1; p >= start; p--) if (code(s, p) === 64) {
      at3 = p;
      break;
    }
    let colon = -1;
    const colonLimit = at3 >= 0 ? at3 : authEnd;
    for (let p = start; p < colonLimit; p++) if (code(s, p) === 58) {
      colon = p;
      break;
    }
    if (at3 >= 0 && colon >= 0) {
      if (at3 > colon + 1) spans.push([colon + 1, at3]);
    } else {
      const tokAt = lastHostAtFrom(start);
      if (tokAt > start) {
        let c2 = -1;
        const limit = Math.min(authEnd, tokAt);
        for (let p = start; p < limit; p++) if (code(s, p) === 58) {
          c2 = p;
          break;
        }
        if (c2 >= 0 && tokAt > c2 + 1) spans.push([c2 + 1, tokAt]);
      }
    }
    const last = spans.length > 0 ? spans[spans.length - 1][1] : 0;
    from = Math.max(sep3 + 1, last);
  }
  return spans;
}
function regexSpans(s, re) {
  const spans = [];
  re.lastIndex = 0;
  for (let m = re.exec(s); m !== null; m = re.exec(s)) {
    spans.push([m.index, m.index + m[0].length]);
    if (m[0].length === 0) re.lastIndex++;
  }
  return spans;
}
var KEYWORD = /password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret/i;
var AUTH_SCHEMES = /* @__PURE__ */ new Set(["bearer", "basic", "token", "digest"]);
var SAFE_AUTH_WORDS = ["authoritative", "authorities", "authenticity", "authorship", "authoring", "authority", "authentic", "authored", "authors", "author"];
function isSecretName(name) {
  if (KEYWORD.test(name)) return true;
  const lower = name.toLowerCase();
  for (let i = lower.indexOf("auth"); i >= 0; i = lower.indexOf("auth", i + 1)) {
    if (lower.startsWith("authorization", i)) return true;
    if (i > 0 && lower[i - 1] === "o") continue;
    if (SAFE_AUTH_WORDS.some((w) => lower.startsWith(w, i))) continue;
    return true;
  }
  return false;
}
var isQuote = (c) => c === 34 || c === 39 || c === 96;
function closingQuote(s, open, limit = s.length, doubled = false) {
  const q = code(s, open);
  for (let j = open + 1; j < limit; j++) {
    const c = code(s, j);
    if (c === 92) j++;
    else if (c === q) {
      if (doubled && j > open + 1 && j + 1 < limit && code(s, j + 1) === q) j++;
      else return j;
    }
  }
  return -1;
}
var skipBlanks = (s, i) => {
  while (i < s.length && (code(s, i) === 32 || code(s, i) === 9)) i++;
  return i;
};
function assignmentSpans(s, workflow = false) {
  const spans = [];
  const n = s.length;
  let block = false;
  const tags = tagTables(s);
  let handledTag = -1;
  let handledBlockable = false;
  const hideElementText = (qname, tagEnd, blockable) => {
    const close = tags.closerAfter(qname, tagEnd);
    if (close > tagEnd + 1) spans.push([tagEnd + 1, close]);
    else if (close < 0) {
      const lt = s.indexOf("<", tagEnd + 1);
      const stop = lt < 0 ? n : lt;
      if (stop > tagEnd + 1) spans.push([tagEnd + 1, stop]);
      if (blockable && skipBlanks(s, tagEnd + 1) >= n) block = true;
    }
  };
  const handleTag = (open, blockable) => {
    if (open < handledTag || open === handledTag && (handledBlockable || !blockable)) return;
    handledBlockable = open === handledTag ? handledBlockable || blockable : blockable;
    handledTag = open;
    const tag = tags.tagAt(open);
    spans.push(...valueAttributeSpans(s, open, tag.end));
    if (tag.closed && code(s, tag.end - 1) !== 47) {
      let e = open + 1;
      while (e < n && (isNameChar(code(s, e)) || code(s, e) === 58)) e++;
      if (e > open + 1) hideElementText(s.slice(open + 1, e), tag.end, blockable);
    }
  };
  let runA = -1;
  let runB = -1;
  const newAttributeRun = (from, to) => {
    if (from >= runA && from < runB) return null;
    let a = from;
    while (a > 0 && isAttributeRunChar(code(s, a - 1))) a--;
    let b = to;
    while (b < n && isAttributeRunChar(code(s, b))) b++;
    runA = a;
    runB = b;
    return [a, b];
  };
  let i = 0;
  while (i < n) {
    if (!isNameChar(code(s, i))) {
      i++;
      continue;
    }
    const start = i;
    while (i < n && isNameChar(code(s, i))) i++;
    const name = s.slice(start, i);
    if (!isSecretName(name)) continue;
    const before = start > 0 ? code(s, start - 1) : -1;
    let p = i;
    let lt = -1;
    if (before === 60) lt = start - 1;
    else if (before === 58) {
      let b = start - 2;
      while (b >= 0 && isNameChar(code(s, b))) b--;
      if (b >= 0 && b < start - 2 && code(s, b) === 60) lt = b;
    }
    if (lt >= 0 && (p >= n || code(s, p) === 62 || code(s, p) === 32 || code(s, p) === 9 || code(s, p) === 47)) handleTag(lt, true);
    const run = name.startsWith("--") ? null : newAttributeRun(start, i);
    if (run !== null) {
      const [a, b] = run;
      const q = b < n ? code(s, b) : -1;
      if ((q === 34 || q === 39) && a > 0 && code(s, a - 1) === q) {
        const eq = skipBlanksBack(s, a - 2);
        if (eq >= 0 && code(s, eq) === 61) {
          const open = tags.enclosing(start);
          if (open >= 0) {
            const attrEnd = skipBlanksBack(s, eq - 1) + 1;
            let attrStart = attrEnd;
            while (attrStart > open && isNameChar(code(s, attrStart - 1))) attrStart--;
            const attr = s.slice(attrStart, attrEnd).toLowerCase();
            handleTag(open, attr === "name" || attr === "key");
          }
        }
      }
    }
    if (name.startsWith("--")) {
      let q = skipBlanks(s, p);
      if (s.startsWith(":=", q)) q += 2;
      else if (code(s, q) === 61 || code(s, q) === 58) q++;
      const v2 = skipBlanks(s, q);
      if (v2 === p || v2 >= n) continue;
      if (isQuote(code(s, v2))) {
        const close = closingQuote(s, v2);
        const end = close < 0 ? n : close;
        if (end > v2 + 1) spans.push([v2 + 1, end]);
        i = close < 0 ? n : close + 1;
      } else {
        let e = v2;
        while (e < n && !isSpace(code(s, e))) e++;
        spans.push([v2, e]);
        i = e;
      }
      continue;
    }
    if (p < n && isQuote(code(s, p))) p++;
    if (p < n && code(s, p) === 93) p++;
    p = skipBlanks(s, p);
    if (s.startsWith("=>", p) || s.startsWith(":=", p)) p += 2;
    else if (p < n && (code(s, p) === 58 || code(s, p) === 61)) p++;
    else continue;
    const v = skipBlanks(s, p);
    if (v >= n) {
      block = true;
      break;
    }
    if ((code(s, v) === 123 || code(s, v) === 91) && skipBlanks(s, v + 1) >= n) {
      block = true;
      break;
    }
    const header = blockHeader(s, v);
    if (header !== null) {
      block = true;
      if (header.comment >= 0) spans.push([header.comment, n]);
      break;
    }
    if (workflow && isAllowedWorkflowValue(name, s, v)) {
      block = true;
      break;
    }
    const c = code(s, v);
    if (name.toLowerCase().includes("authorization")) {
      const inner = isQuote(c) ? v + 1 : v;
      let w = inner;
      while (w < n && isLetter(code(s, w))) w++;
      if (AUTH_SCHEMES.has(s.slice(inner, w).toLowerCase()) && (code(s, w) === 32 || code(s, w) === 9)) {
        const credStart = skipBlanks(s, w);
        const close = isQuote(c) ? closingQuote(s, v) : -1;
        const end = close < 0 ? n : close;
        if (end > credStart) spans.push([credStart, end]);
        if (close < 0) {
          block = true;
          break;
        }
        i = close + 1;
        continue;
      }
    }
    if (isQuote(c)) {
      const triple = c !== 96 && s.startsWith(s[v].repeat(3), v);
      if (triple) {
        const close2 = s.indexOf(s[v].repeat(3), v + 3);
        const end2 = close2 < 0 ? n : close2;
        if (end2 > v + 3) spans.push([v + 3, end2]);
        if (close2 < 0) {
          block = true;
          break;
        }
        i = close2 + 3;
        continue;
      }
      const close = closingQuote(s, v);
      const far = close < 0 || c === 96 ? close : closingQuote(s, v, n, true);
      const end = far < 0 ? n : far;
      if (end > v + 1) spans.push([v + 1, end]);
      if (far < 0) {
        block = true;
        break;
      }
      i = close + 1;
      continue;
    }
    spans.push([v, n]);
    block = true;
    break;
  }
  return { spans, block };
}
var skipBlanksBack = (s, i) => {
  while (i >= 0 && (code(s, i) === 32 || code(s, i) === 9)) i--;
  return i;
};
var isAttributeRunChar = (c) => isNameChar(c) || c === 58 || c === 47 || c === 32 || c === 9;
function tagTables(s) {
  const n = s.length;
  let lastLt = null;
  let lastGt = null;
  let nextStop = null;
  let closers = null;
  const build = () => {
    lastLt = new Int32Array(n);
    lastGt = new Int32Array(n);
    nextStop = new Int32Array(n + 1);
    let lt = -1;
    let gt = -1;
    for (let p = 0; p < n; p++) {
      if (code(s, p) === 60) lt = p;
      if (code(s, p) === 62) gt = p;
      lastLt[p] = lt;
      lastGt[p] = gt;
    }
    nextStop[n] = n;
    for (let p = n - 1; p >= 0; p--) nextStop[p] = code(s, p) === 60 || code(s, p) === 62 ? p : nextStop[p + 1];
  };
  return {
    enclosing(i) {
      if (lastLt === null || lastGt === null) build();
      const open = lastLt[i];
      return open < 0 || lastGt[i] > open ? -1 : open;
    },
    tagAt(open) {
      if (nextStop === null) build();
      const end = nextStop[open + 1];
      return { end, closed: end < n && code(s, end) === 62 };
    },
    closerAfter(name, from) {
      if (closers === null) {
        closers = /* @__PURE__ */ new Map();
        for (let k = s.indexOf("</"); k >= 0; k = s.indexOf("</", k + 2)) {
          let e = k + 2;
          while (e < n && (isNameChar(code(s, e)) || code(s, e) === 58)) e++;
          if (e === k + 2 || e < n && code(s, e) !== 62 && code(s, e) !== 32 && code(s, e) !== 9) continue;
          const key = s.slice(k + 2, e).toLowerCase();
          const list2 = closers.get(key);
          if (list2 === void 0) closers.set(key, [k]);
          else list2.push(k);
        }
      }
      const list = closers.get(name.toLowerCase());
      if (list === void 0) return -1;
      let lo = 0;
      let hi = list.length;
      while (lo < hi) {
        const mid = lo + hi >> 1;
        if (list[mid] > from) hi = mid;
        else lo = mid + 1;
      }
      return lo < list.length ? list[lo] : -1;
    }
  };
}
function valueAttributeSpans(s, start, end) {
  const spans = [];
  const lower = s.slice(start, end).toLowerCase();
  for (let k = lower.indexOf("value"); k >= 0; k = lower.indexOf("value", k + 5)) {
    const at3 = start + k;
    if (!isSpace(code(s, at3 - 1))) continue;
    let q = skipBlanks(s, at3 + 5);
    if (q >= end || code(s, q) !== 61) continue;
    q = skipBlanks(s, q + 1);
    if (q >= end || code(s, q) !== 34 && code(s, q) !== 39) continue;
    const close = closingQuote(s, q, end);
    const stop = close < 0 ? end : close;
    if (stop > q + 1) spans.push([q + 1, stop]);
  }
  return spans;
}
function blockHeader(s, v) {
  const n = s.length;
  let q = v;
  let consumed = false;
  while (q < n && (code(s, q) === 38 || code(s, q) === 33)) {
    let e = q + 1;
    while (e < n && !isSpace(code(s, e))) e++;
    q = skipBlanks(s, e);
    consumed = true;
  }
  if (q < n && (code(s, q) === 124 || code(s, q) === 62)) {
    let e = q + 1;
    for (let k = 0; k < 2 && e < n; k++) {
      const c = code(s, e);
      if (c >= 49 && c <= 57 || c === 43 || c === 45) e++;
      else break;
    }
    if (e < n && !isSpace(code(s, e)) && code(s, e) !== 35) return null;
    q = skipBlanks(s, e);
    consumed = true;
  }
  if (q >= n) return consumed ? { comment: -1 } : null;
  if (code(s, q) === 35) return { comment: q };
  return null;
}
var MARK_START = "-----";
var KEY_TAILS = ["PRIVATE KEY", "PRIVATE KEY BLOCK"];
function findKeyMarker(line, kind, from) {
  const head = `${MARK_START}${kind} `;
  for (let i = line.indexOf(head, from); i >= 0; i = line.indexOf(head, i + 1)) {
    let j = i + head.length;
    while (j < line.length && (line[j] === " " || line[j] >= "A" && line[j] <= "Z")) j++;
    const label = line.slice(i + head.length, j);
    if (KEY_TAILS.some((t) => label.endsWith(t)) && line.startsWith(MARK_START, j)) return { start: i, end: j + MARK_START.length };
  }
  return null;
}
function isWorkflowPath(path) {
  if (path.includes("\\")) return false;
  const parts = path.split("/");
  if (parts[0] === "") parts.shift();
  if (parts.some((p) => p === "" || p === "." || p === "..")) return false;
  const base = parts[parts.length - 1];
  if (base === "action.yml" || base === "action.yaml") return true;
  const yaml = base.endsWith(".yml") && base.length > 4 || base.endsWith(".yaml") && base.length > 5;
  return yaml && parts.length >= 3 && parts[parts.length - 2] === "workflows" && parts[parts.length - 3] === ".github";
}
var WORKFLOW_REF = /(["']?)\$\{\{ *(?:secrets|vars|github|env|inputs|steps|needs|matrix)\.[A-Za-z0-9_.-]+ *\}\}\1[ \t]*$/y;
var ID_TOKEN_VALUE = /(["']?)(?:write|read|none)\1[ \t]*$/y;
var INHERIT_VALUE = /(["']?)inherit\1[ \t]*$/y;
var stickyTest = (re, s, at3) => {
  re.lastIndex = at3;
  return re.test(s);
};
function isAllowedWorkflowValue(name, s, v) {
  if (stickyTest(WORKFLOW_REF, s, v)) return true;
  if (name === "id-token") return stickyTest(ID_TOKEN_VALUE, s, v);
  if (name === "secrets") return stickyTest(INHERIT_VALUE, s, v);
  return false;
}
function redactSegment(s, workflow = false) {
  let out = s;
  for (const [, re] of TOKEN_RULES) out = replaceSpans(out, regexSpans(out, re));
  out = replaceSpans(out, jwtSpans(out));
  out = replaceSpans(out, connectionSpans(out));
  const a = assignmentSpans(out, workflow);
  return { text: replaceSpans(out, a.spans), block: a.block };
}
var indentOf = (line) => {
  let i = 0;
  let cols = 0;
  for (; i < line.length; i++) {
    if (line[i] === " ") cols++;
    else if (line[i] === "	") cols = (Math.floor(cols / 8) + 1) * 8;
    else break;
  }
  return { chars: i, cols };
};
var CODE_EXTENSIONS = /* @__PURE__ */ new Set([
  ".py",
  ".js",
  ".mjs",
  ".cjs",
  ".jsx",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".go",
  ".rb",
  ".java",
  ".kt",
  ".kts",
  ".scala",
  ".cs",
  ".php",
  ".rs",
  ".swift",
  ".c",
  ".h",
  ".cpp",
  ".hpp",
  ".m",
  ".sh",
  ".bash",
  ".zsh",
  ".ps1",
  ".lua",
  ".pl",
  ".r",
  ".dart",
  ".ex",
  ".exs",
  ".clj",
  ".groovy"
]);
var WRAPPER_SUFFIXES = /* @__PURE__ */ new Set([".example", ".sample", ".dist", ".tpl", ".tmpl", ".template", ".j2", ".jinja", ".jinja2", ".bak", ".orig", ".old", ".default", ".local"]);
function isCodePath(path) {
  let base = path.slice(Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\")) + 1).toLowerCase();
  for (; ; ) {
    const dot2 = base.lastIndexOf(".");
    if (dot2 <= 0 || !WRAPPER_SUFFIXES.has(base.slice(dot2))) break;
    base = base.slice(0, dot2);
  }
  const dot = base.lastIndexOf(".");
  return dot > 0 && CODE_EXTENSIONS.has(base.slice(dot));
}
function sectionName(line) {
  const open = skipBlanks(line, 0);
  if (code(line, open) !== 91) return null;
  const from = code(line, open + 1) === 91 ? open + 2 : open + 1;
  const close = line.indexOf("]", from);
  if (close < 0) return null;
  let after = from === open + 2 && code(line, close + 1) === 93 ? close + 2 : close + 1;
  after = skipBlanks(line, after);
  if (after < line.length && code(line, after) !== 35 && code(line, after) !== 59) return null;
  return line.slice(from, close);
}
function isPlainKey(s) {
  const a = skipBlanks(s, 0);
  let b = a;
  while (b < s.length && (isNameChar(code(s, b)) || code(s, b) === 34 || code(s, b) === 39)) b++;
  return b > a && skipBlanks(s, b) >= s.length;
}
var isSecretSection = (section) => section.split(/[^A-Za-z0-9_.-]+/).some((part) => part !== "" && (isSecretName(part) || part.toLowerCase().includes("credential")));
function hideSectionValue(line) {
  let sep3 = -1;
  for (let j = 0; j < line.length; j++) {
    const c = code(line, j);
    if (c === 61 || c === 58) {
      sep3 = j;
      break;
    }
  }
  if (sep3 < 0 || !regexSafe(line) || !isPlainKey(line.slice(0, sep3))) return line.slice(0, indentOf(line).chars) + R;
  const key = redactSegment(line.slice(0, sep3)).text;
  const v = skipBlanks(line, sep3 + 1);
  return v >= line.length ? key + line.slice(sep3) : key + line.slice(sep3, v) + R;
}
function redact(text, hint) {
  const blockRule = hint?.path === void 0 || !isCodePath(hint.path);
  const workflow = hint?.path !== void 0 && isWorkflowPath(hint.path);
  const out = [];
  let inKey = false;
  let blockCols = -1;
  let secretSection = false;
  for (const raw of text.split("\n")) {
    let lineEnd = raw.length;
    while (lineEnd > 0 && raw.charCodeAt(lineEnd - 1) === 13) lineEnd--;
    const cr = raw.slice(lineEnd);
    const line = raw.slice(0, lineEnd);
    const startedInKey = inKey;
    const pieces = [];
    const plain = [];
    let pos = 0;
    for (; ; ) {
      if (inKey) {
        const end = findKeyMarker(line, "END", pos);
        if (!end) break;
        pos = end.end;
        inKey = false;
      } else {
        const begin = findKeyMarker(line, "BEGIN", pos);
        const seg = line.slice(pos, begin ? begin.start : line.length);
        pieces.push(seg);
        plain.push(seg);
        if (!begin) break;
        pieces.push(R);
        pos = begin.end;
        inKey = true;
      }
    }
    const startsBlock = pieces.includes(R);
    if (startedInKey && !startsBlock && plain.every((p) => p === "")) continue;
    if (blockCols >= 0) {
      if (line.trim() === "") {
        out.push(raw);
        continue;
      }
      const ind = indentOf(line);
      if (ind.cols > blockCols) {
        if (blockRule && !startedInKey && !startsBlock && !secretSection) {
          const section = sectionName(line);
          if (section !== null) secretSection = isSecretSection(section);
        }
        out.push(line.slice(0, ind.chars) + R + cr);
        continue;
      }
      blockCols = -1;
    }
    if (blockRule && !startedInKey && !startsBlock) {
      const section = sectionName(line);
      if (section !== null) secretSection = isSecretSection(section);
      else if (secretSection && line.trim() !== "") {
        out.push(hideSectionValue(line) + cr);
        if (!regexSafe(line) || redactSegment(line, workflow).block) blockCols = indentOf(line).cols;
        continue;
      }
    }
    if (!regexSafe(line)) {
      out.push(LONG_LINE + cr);
      blockCols = indentOf(line).cols;
      continue;
    }
    let block = false;
    out.push(pieces.map((p) => {
      if (p === R) return R;
      const r = redactSegment(p, workflow);
      block ||= r.block;
      return r.text;
    }).join("") + cr);
    if (block && blockRule) blockCols = indentOf(line).cols;
  }
  return out.join("\n");
}
function findSecretLike(text) {
  const found = /* @__PURE__ */ new Set();
  for (const line of text.split("\n")) {
    if (findKeyMarker(line, "BEGIN", 0)) found.add("private-key");
    if (!regexSafe(line)) continue;
    for (const [name, re] of TOKEN_RULES) if (regexSpans(line, re).length > 0) found.add(name);
    if (jwtSpans(line).length > 0) found.add("jwt");
    if (connectionSpans(line).length > 0) found.add("connection-string-password");
  }
  return [...found];
}
var MIN_DECODED_PIECE = 8;
function readablePieces(bytes) {
  return bytes.toString("latin1").match(new RegExp(`[\\x20-\\x7e]{${MIN_DECODED_PIECE},}`, "g")) ?? [];
}
function decodedNamePieces(name) {
  const out = /* @__PURE__ */ new Set();
  for (const run of name.match(/[A-Za-z0-9+/_=-]{12,}/g) ?? []) {
    for (let k = 0; k < 4 && k < run.length; k++) for (const p of readablePieces(Buffer.from(run.slice(k), "base64"))) out.add(p);
  }
  for (const run of name.match(/[0-9a-fA-F]{16,}/g) ?? []) {
    for (let k = 0; k < 2; k++) {
      const even = run.slice(k, k + Math.floor((run.length - k) / 2) * 2);
      for (const p of readablePieces(Buffer.from(even, "hex"))) out.add(p);
    }
  }
  if (/%[0-9a-fA-F]{2}/.test(name)) {
    const decoded = name.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return Buffer.from(m.replaceAll("%", ""), "hex").toString("latin1");
      }
    });
    if (decoded !== name) out.add(decoded);
  }
  for (const p of [...out]) if (name.includes(p)) out.delete(p);
  return [...out];
}
function entropy(s) {
  const counts = /* @__PURE__ */ new Map();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
function highEntropyRuns(name) {
  const hits = [];
  for (const seg of name.split("/")) {
    for (const run of seg.match(/[A-Za-z0-9+=]{20,}/g) ?? []) {
      if (!/\d/.test(run) || !/[A-Za-z]/.test(run)) continue;
      if (entropy(run) >= (/^[0-9a-fA-F]+$/.test(run) ? 3 : 3.5)) hits.push(run);
    }
  }
  return hits;
}
var RUN = /[A-Za-z0-9+=]{20,}/g;
function maskText(text) {
  return redact(text).replace(RUN, (run) => highEntropyRuns(run).length > 0 ? R : run);
}
var MAX_NAME_CHARS = 4096;
var looksSecret = (text) => redact(text) !== text || findSecretLike(text).length > 0 || highEntropyRuns(text).length > 0;
function secretShapedName(name) {
  if (name.length > MAX_NAME_CHARS) return true;
  if (looksSecret(name)) return true;
  return decodedNamePieces(name).some(looksSecret);
}

// gate/src/fingerprint.ts
var FP_KEY_MIN = 32;
var REGION_MAX_BYTES = 64 * 1024;
var FILE_SCAN_MAX = 16 * 1024 * 1024;
var CONTENT_FORMS = Object.freeze(["hash", "region", "quoted", "file"]);
var POSITION_FORMS = Object.freeze(["line", "nokey", "quoted-nokey"]);
var sha = (s) => createHash2("sha256").update(s).digest("hex");
var hmac = (key, data) => createHmac("sha256", key).update(data).digest("hex");
var field = (s) => s === void 0 ? "" : String(s).replaceAll("\0", "\uFFFD");
function keyId(key) {
  return hmac(key, "pipegen-key-id").slice(0, 16);
}
function keyProblem(key, fork, needed) {
  if (!needed) return void 0;
  if (key === void 0 || key === "") {
    return fork ? void 0 : "PIPEGEN_FP_KEY is missing (an empty key is only allowed on a fork pull request), so secret fingerprints cannot be made";
  }
  if (key.length < FP_KEY_MIN) return `PIPEGEN_FP_KEY is too short: it needs at least ${FP_KEY_MIN} characters`;
  return /^[\x20-\x7e]*$/.test(key) && !/["\\]/.test(key) ? void 0 : "PIPEGEN_FP_KEY must be printable ASCII without a double quote or a backslash";
}
var maskSecretShapes = (text) => maskText(text);
function normaliseMessage(message, lines) {
  const own7 = new Set(lines);
  return message.replace(/(?<![\w.])\d+(?!\w|\.\d)/g, (m) => own7.has(Number(m)) ? "" : m).replace(/\s+/g, " ").trim();
}
var COLUMN_RULES = Object.freeze(Object.assign(/* @__PURE__ */ Object.create(null), {
  betterleaks: { shiftAfterFirstLine: 0 },
  gitleaks: { shiftAfterFirstLine: 1 }
}));
var no = (reason) => ({ ok: false, reason });
var CACHE_MAX_BYTES = 128 * 1024 * 1024;
var RegionCache = class {
  files = /* @__PURE__ */ new Map();
  bytes = 0;
  get(file, load) {
    const known = this.files.get(file);
    if (known !== void 0) return known;
    const made = load();
    if (made.ok) {
      if (this.bytes + made.buf.length > CACHE_MAX_BYTES) {
        this.files.clear();
        this.bytes = 0;
      }
      this.bytes += made.buf.length;
    }
    this.files.set(file, made);
    return made;
  }
};
function loadWorkspaceFile(workspace, file) {
  const bad = (reason) => ({ ok: false, reason });
  let fd;
  try {
    const wsReal = realpathSync(workspace);
    let cur = workspace;
    const parts = file.split("/").filter((x) => x !== "" && x !== ".");
    if (parts.length === 0) return bad("the path is not inside the workspace");
    let last = lstatSync(cur);
    for (const [i, part] of parts.entries()) {
      cur = join(cur, part);
      try {
        last = lstatSync(cur);
      } catch (e) {
        return bad(e.code === "ENOENT" ? "the file is missing" : "the file cannot be read");
      }
      if (last.isSymbolicLink()) return bad("the file or a folder on its path is a link");
      if (i < parts.length - 1 && !last.isDirectory()) return bad("a folder on the path is not a folder");
    }
    if (!last.isFile()) return bad("the path is not a regular file");
    try {
      fd = openSync(cur, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    } catch (e) {
      return bad(e.code === "ELOOP" ? "the file or a folder on its path is a link" : "the file cannot be opened");
    }
    const opened = fstatSync(fd);
    if (!opened.isFile()) return bad("the path is not a regular file");
    if (opened.dev !== last.dev || opened.ino !== last.ino) return bad("the file changed while it was opened");
    let real;
    try {
      real = readlinkSync(`/proc/self/fd/${fd}`).replace(/ \(deleted\)$/, "");
    } catch {
    }
    if (real !== void 0 && !real.startsWith(wsReal + sep)) return bad("the opened file is outside the workspace");
    const want = Math.min(opened.size, FILE_SCAN_MAX);
    const buf = Buffer.alloc(want);
    let got = 0;
    while (got < want) {
      const n = readSync(fd, buf, got, want - got, got);
      if (n === 0) break;
      got += n;
    }
    return { ok: true, buf, got, size: opened.size, starts: [0], atEnd: false };
  } catch {
    return bad("the file cannot be read");
  } finally {
    if (fd !== void 0) try {
      closeSync(fd);
    } catch {
    }
  }
}
function lineStart(f, n) {
  while (f.starts.length < n && !f.atEnd) {
    const nl = f.buf.indexOf(10, f.starts[f.starts.length - 1]);
    if (nl === -1 || nl >= f.got) f.atEnd = true;
    else f.starts.push(nl + 1);
  }
  const at3 = f.starts[n - 1];
  return at3 === void 0 || at3 >= f.got ? void 0 : at3;
}
function readRegion(workspace, f, cache) {
  const span = regionSpan(workspace, f, cache);
  return span.ok ? { ok: true, bytes: span.bytes } : span;
}
function regionSpan(workspace, f, cache) {
  const rule = Object.hasOwn(COLUMN_RULES, f.tool) ? COLUMN_RULES[f.tool] : void 0;
  if (rule === void 0) return no(`the columns of ${f.tool} are not known (they are placeholders there), so the region is not read`);
  const { line, startColumn, endColumn } = f;
  const endLine = f.endLine ?? line;
  if (line === void 0 || startColumn === void 0 || endColumn === void 0 || endLine === void 0) return no("the finding has no complete region");
  const startCol = startColumn - (line >= 2 ? rule.shiftAfterFirstLine : 0);
  const endCol = endColumn - (endLine >= 2 ? rule.shiftAfterFirstLine : 0);
  if (endLine < line || startCol < 1 || endCol < 1 || endLine === line && endCol < startCol) return no("the region is empty or its end is before its start");
  const file = f.file;
  if (file === void 0 || file === "" || file.startsWith("/") || file.includes("\0") || file.includes("\\") || file.split("/").some((x) => x === "..")) return no("the path is not inside the workspace");
  try {
    const read = (cache ?? new RegionCache()).get(file, () => loadWorkspaceFile(workspace, file));
    if (!read.ok) return no(read.reason);
    const first = lineStart(read, line);
    const last = lineStart(read, endLine);
    if (first === void 0 || last === void 0) return no(read.got < read.size ? "the region is too far into a large file" : "the region is outside the file");
    const lineEnd = (at3) => {
      const nl = read.buf.indexOf(10, at3);
      return nl === -1 || nl >= read.got ? read.got : nl;
    };
    const from = first + startCol - 1;
    const to = last + endCol;
    if (from >= lineEnd(first) || to > lineEnd(last)) return no("the region is outside the file");
    if (to - from > REGION_MAX_BYTES) return no("the region is over 64 KiB");
    if (to - from < 1) return no("the region is empty or its end is before its start");
    const bytes = Buffer.from(read.buf.subarray(from, to));
    if (bytes.includes(0)) return no("the region holds a NUL byte");
    return { ok: true, bytes, from, to };
  } catch {
    return no("the file cannot be read");
  }
}
var PROFILES = Object.freeze(Object.assign(/* @__PURE__ */ Object.create(null), { "trivy-image": "image", nuclei: "web", "zap-baseline": "zap" }));
var profileOf = (tool2) => Object.hasOwn(PROFILES, tool2) ? PROFILES[tool2] : "file";
function uriSlot(f) {
  if (f.file !== void 0) return field(f.file);
  return f.uriUnmapped ? `unmapped:${field(f.uriId)}` : "";
}
function profileMessage(f, profile) {
  let m = f.message;
  if (profile === "image") m = m.replace(/@?\bsha256:[0-9a-fA-F]{16,}/g, "");
  if (profile === "web") m = m.replace(/\bhttps?:\/\/[^\s/]+/gi, "").replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, "");
  return m;
}
var ownLines = (f) => [f.line, f.endLine].filter((n) => n !== void 0);
function nonSecretMessage(f, profile) {
  return normaliseMessage(maskSecretShapes(profileMessage(f, profile)), ownLines(f));
}
var QUOTING_RULES = Object.freeze(Object.assign(/* @__PURE__ */ Object.create(null), { bandit: ["B105", "B106", "B107"] }));
function isQuotingFinding(f) {
  return Object.hasOwn(QUOTING_RULES, f.tool) && QUOTING_RULES[f.tool].includes(f.ruleId);
}
function fingerprintFinding(f, ctx) {
  const profile = profileOf(f.tool);
  if (profile === "zap") return { fingerprint: sha([field(f.ruleId), field(f.method), uriSlotZap(f)].join("\0")), by: "hash" };
  if (!f.secret && isQuotingFinding(f)) {
    const base = [field(f.tool), field(f.ruleId), uriSlot(f)];
    const key2 = ctx.fpKey ?? "";
    return key2 === "" ? { fingerprint: `quoted-nokey:${sha([...base, field(f.line)].join("\0"))}`, by: "quoted-nokey" } : { fingerprint: `quoted:${hmac(key2, [...base, field(normaliseMessage(profileMessage(f, profile), ownLines(f)))].join("\0"))}`, by: "quoted" };
  }
  if (!f.secret) {
    return { fingerprint: sha([field(f.tool), field(f.ruleId), profile === "file" ? uriSlot(f) : "", field(nonSecretMessage(f, profile))].join("\0")), by: "hash" };
  }
  const key = ctx.fpKey ?? "";
  const where = [field(f.tool), field(f.ruleId)];
  if (key === "") return { fingerprint: `secret-nokey:${sha([...where, uriSlot(f), field(f.line)].join("\0"))}`, by: "nokey" };
  const fileHash = ctx.fileHashOf?.(f);
  if (fileHash !== void 0) return { fingerprint: `secret:${hmac(key, ["file", ...where, field(fileHash)].join("\0"))}`, by: "file" };
  const staged = ctx.regionOf?.(f);
  let why2;
  if (staged !== void 0) {
    if (staged.ok) {
      ctx.onRegion?.(staged.bytes);
      return { fingerprint: `secret:${hmac(key, Buffer.concat([Buffer.from(`${where.join("\0")}\0`), staged.bytes]))}`, by: "region" };
    }
    why2 = staged.reason;
  } else if (f.file === void 0) why2 = "the finding has no file in the workspace";
  else if (ctx.workspace === void 0 || ctx.workspace === "") why2 = "no workspace to read the region from";
  else {
    const region = readRegion(ctx.workspace, f, ctx.cache);
    if (region.ok) {
      ctx.onRegion?.(region.bytes);
      return { fingerprint: `secret:${hmac(key, Buffer.concat([Buffer.from(`${where.join("\0")}\0`), region.bytes]))}`, by: "region" };
    }
    why2 = region.reason;
  }
  return { fingerprint: `secret:${hmac(key, ["line", ...where, uriSlot(f), field(f.line)].join("\0"))}`, by: "line", note: `fingerprint by line: ${why2}` };
}
function uriSlotZap(f) {
  return f.file !== void 0 ? field(f.file) : f.uriUnmapped ? `unmapped:${field(f.uriId)}` : "";
}
function fingerprintAll(findings, ctx) {
  const shared = { ...ctx, cache: ctx.cache ?? new RegionCache() };
  return findings.map((f) => {
    const r = fingerprintFinding(f, shared);
    return { ...f, fingerprint: r.fingerprint, fpBy: r.by, ...r.note === void 0 ? {} : { fpNote: r.note } };
  });
}

// gate/src/baseline.ts
import { createHmac as createHmac2, timingSafeEqual } from "node:crypto";

// src/engine/need-ids.ts
var AI_ONLY_IDS = ["migration-check"];
var NEED_IDS = [...NEED_CATEGORIES, ...AI_ONLY_IDS];
var NEED_ID_CATEGORY = Object.freeze({
  ...Object.fromEntries(NEED_CATEGORIES.map((c) => [c, c])),
  "migration-check": "full-tests"
});

// gate/src/parse-common.ts
var MAX_RAW_BYTES = 64 * 1024 * 1024;
var MAX_RESULTS_PER_RUN = 5e4;
var MAX_RUNS = 20;
var MAX_MESSAGE_CHARS = 2e3;
var MAX_ID_CHARS = 1024;
var MAX_URI_CHARS = 4096;
var DEFAULT_LIMITS = Object.freeze({ maxBytes: MAX_RAW_BYTES, maxResults: MAX_RESULTS_PER_RUN, maxRuns: MAX_RUNS });
function limitsFrom(partial) {
  return { ...DEFAULT_LIMITS, ...partial };
}
var ReadError = class extends Error {
};
function fail(message) {
  throw new ReadError(message);
}
function guarded(read) {
  const notes = [];
  try {
    return { findings: read(notes), notes };
  } catch (e) {
    return { findings: [], toolError: e instanceof ReadError ? e.message : "the result could not be read (unexpected shape)", notes };
  }
}
function readText(input, maxBytes) {
  if (typeof input === "string") {
    const size = input.length > maxBytes ? input.length : input.length * 3 <= maxBytes ? 0 : new TextEncoder().encode(input).byteLength;
    if (size > maxBytes) fail(`the result is over the size cap (${maxBytes} bytes)`);
    return input;
  }
  if (input.byteLength > maxBytes) fail(`the result is over the size cap (${maxBytes} bytes)`);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    fail("the result is not valid UTF-8");
  }
}
function parseJsonOnce(text) {
  try {
    return JSON.parse(text);
  } catch {
    fail("the result is not valid JSON");
  }
}
function readJson(input, maxBytes) {
  try {
    return { json: parseJsonOnce(readText(input, maxBytes)) };
  } catch (e) {
    return { toolError: e instanceof ReadError ? e.message : "the result could not be read" };
  }
}
function isObj(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function getOwn(o, key) {
  return Object.hasOwn(o, key) ? o[key] : void 0;
}
function shown(v, max = 40) {
  return typeof v === "string" ? JSON.stringify(safeText(v, max)) : typeof v;
}
function optStr(o, key, where) {
  const v = getOwn(o, key);
  if (v === void 0) return void 0;
  if (typeof v !== "string") fail(`${where}: ${key} is not a string`);
  return v;
}
function optObj(o, key, where) {
  const v = getOwn(o, key);
  if (v === void 0) return void 0;
  if (!isObj(v)) fail(`${where}: ${key} is not an object`);
  return v;
}
function optList(o, key, where) {
  const v = getOwn(o, key);
  if (v === void 0) return void 0;
  if (!Array.isArray(v)) fail(`${where}: ${key} is not a list`);
  return v;
}
function optStrList(o, key, where) {
  const list = optList(o, key, where);
  if (list === void 0) return void 0;
  for (const item of list) if (typeof item !== "string") fail(`${where}: ${key} holds a value that is not a string`);
  return list;
}
function cutText(s, max = MAX_MESSAGE_CHARS) {
  if (s.length <= max) return s;
  const cut2 = s.slice(0, max);
  const last = cut2.charCodeAt(cut2.length - 1);
  return last >= 55296 && last <= 56319 ? cut2.slice(0, -1) : cut2;
}
function lineOf(v, where) {
  if (v === void 0) return void 0;
  if (typeof v !== "number") fail(`${where}: the line is not a number`);
  return Number.isInteger(v) && v >= 1 && v <= 2 ** 31 - 1 ? v : void 0;
}
var K = Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const padded = new Uint8Array(data.length + 9 + 63 >> 6 << 6);
  padded.set(data);
  padded[data.length] = 128;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(data.length * 8 / 2 ** 32));
  view.setUint32(padded.length - 4, data.length * 8 >>> 0);
  const h = Uint32Array.from([1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]);
  const w = new Uint32Array(64);
  const rotr = (x, n) => x >>> n | x << 32 - n;
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3;
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
      w[i] = w[i - 16] + s0 + w[i - 7] + s1 >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + (e & f ^ ~e & g) + K[i] + w[i] >>> 0;
      const t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + (a & b ^ a & c ^ b & c) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = d + t1 >>> 0;
      d = c;
      c = b;
      b = a;
      a = t1 + t2 >>> 0;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
  return Array.from(h, (x) => x.toString(16).padStart(8, "0")).join("");
}
function uriIdOf(uri) {
  return sha256Hex(uri.slice(0, MAX_URI_CHARS)).slice(0, 32);
}

// gate/src/sarif.ts
var tool = (driver, severity, over = {}) => ({ driver, severity, secrets: false, fileMode: "repo", executionSuccessfulFalse: "error", errorRules: [], zeroScoreIsUnknown: false, uriEncoding: "unmeasured", messageFrom: "result", ...over });
var SARIF_TOOLS = Object.freeze(Object.assign(/* @__PURE__ */ Object.create(null), {
  betterleaks: tool("betterleaks", "secret", { secrets: true, uriEncoding: "raw" }),
  gitleaks: tool("gitleaks", "secret", { secrets: true, uriEncoding: "raw", note: "completeness not provable (gitleaks)" }),
  semgrep: tool("Semgrep OSS", "level", { messageFrom: "rule-template" }),
  "osv-scanner": tool("osv-scanner", "security-severity"),
  "trivy-config": tool("Trivy", "security-severity", { zeroScoreIsUnknown: true }),
  "trivy-image": tool("Trivy", "security-severity", { fileMode: "none", zeroScoreIsUnknown: true }),
  "trivy-licence": tool("Trivy", "security-severity"),
  hadolint: tool("Hadolint", "level", { errorRules: ["DL1000"] }),
  "kube-linter": tool("kube-linter", "level", { executionSuccessfulFalse: "findings", errorRules: ["failed-to-load-object"] }),
  nuclei: tool("Nuclei", "security-severity", { fileMode: "none", executionSuccessfulFalse: "ignored" }),
  ruff: tool("ruff", "level", { errorRules: ["invalid-syntax", "E999", "E902", "panic"] }),
  gosec: tool("gosec", "tag-word"),
  bandit: tool("Bandit", "issue-severity")
}));
var SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
var CONTROL2 = /[\u0000-\u001f\u007f]/;
function decodeOnce(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return void 0;
  }
}
function normaliseUri(uri, opts = {}) {
  if (typeof uri !== "string" || uri.trim() === "" || uri.length > MAX_URI_CHARS) return void 0;
  const encoding = opts.encoding ?? "unmeasured";
  if (uri.includes("\uFFFD")) return void 0;
  let p = uri;
  if (/^file:\/\//i.test(p)) {
    p = p.slice(7);
    if (!p.startsWith("/")) return void 0;
  } else if (SCHEME.test(p)) {
    return void 0;
  }
  const ws = opts.workspace === void 0 ? "" : opts.workspace.replace(/\/+$/, "");
  if (ws.startsWith("/") && p.startsWith(`${ws}/`)) p = p.slice(ws.length + 1);
  else if (p.startsWith("/src/")) p = p.slice(5);
  else if (p.startsWith("/zap/wrk/")) p = p.slice(9);
  let once = p;
  if (encoding === "unmeasured") {
    if (p.includes("%")) return void 0;
  } else if (encoding === "percent") {
    const decoded = decodeOnce(p);
    if (decoded === void 0 || decoded.includes("\uFFFD")) return void 0;
    once = decoded;
    const twice = decodeOnce(once);
    if (twice !== once) return void 0;
  }
  if (CONTROL2.test(once) || once.includes("\\") || once.startsWith("/") || SCHEME.test(once)) return void 0;
  const kept = [];
  for (const segment of once.split("/")) {
    if (segment === "..") return void 0;
    if (segment !== "" && segment !== ".") kept.push(segment);
  }
  return kept.length === 0 ? void 0 : kept.join("/");
}
var LEVELS = Object.freeze(Object.assign(/* @__PURE__ */ Object.create(null), { error: "high", warning: "medium", note: "low", none: "info" }));
var WORDS = Object.freeze(Object.assign(/* @__PURE__ */ Object.create(null), { HIGH: "high", MEDIUM: "medium", LOW: "low" }));
var RANK = ["critical", "high", "medium", "low", "info"];
function fromScore(v) {
  const n = typeof v === "number" ? v : typeof v === "string" && /^\s*\d+(\.\d+)?\s*$/.test(v) ? Number(v) : NaN;
  if (!Number.isFinite(n) || n < 0 || n > 10) return void 0;
  return n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : n > 0 ? "low" : "info";
}
function fromLevel(v) {
  return v === void 0 ? void 0 : LEVELS[v];
}
var MAX_TAGS = 256;
var MAX_ADVISORY_IDS = 64;
var SAME = (a, b) => a.level === b.level && String(a.score) === String(b.score) && a.tags.join("\0") === b.tags.join("\0") && a.template === b.template && a.aliases.join("\0") === b.aliases.join("\0");
function readAliases(lists, where) {
  const out = [];
  for (const list of lists) {
    for (const id of list ?? []) {
      if (id.length > MAX_ID_CHARS) fail(`${where}: an advisory id is longer than ${MAX_ID_CHARS}`);
      if (!out.includes(id)) out.push(id);
      if (out.length > MAX_ADVISORY_IDS) fail(`${where}: more than ${MAX_ADVISORY_IDS} advisory ids and aliases`);
    }
  }
  return out;
}
function tagFacts(tags) {
  let secret = false;
  let word;
  for (const t of tags) {
    if (t.toLowerCase() === "secret") secret = true;
    const w = WORDS[t];
    if (w !== void 0 && (word === void 0 || RANK.indexOf(w) < RANK.indexOf(word))) word = w;
  }
  return { secret, word };
}
function readTags(o, where) {
  const tags = optStrList(o, "tags", where) ?? [];
  if (tags.length > MAX_TAGS) fail(`${where}: more than ${MAX_TAGS} tags`);
  return tags;
}
function readRules(driver, where) {
  const list = [];
  const byId = /* @__PURE__ */ new Map();
  const raw = optList(driver, "rules", where);
  for (const [i, r] of (raw ?? []).entries()) {
    const at3 = `${where} rule ${i}`;
    if (!isObj(r)) fail(`${at3} is not an object`);
    const id = getOwn(r, "id");
    if (typeof id !== "string") fail(`${at3} has no id`);
    const level = optStr(optObj(r, "defaultConfiguration", at3) ?? {}, "level", `${at3} defaultConfiguration`);
    const props = optObj(r, "properties", at3) ?? {};
    const score = getOwn(props, "security-severity");
    if (score !== void 0 && typeof score !== "string" && typeof score !== "number") fail(`${at3}: security-severity is not a string or a number`);
    const tags = readTags(props, `${at3} properties`);
    const template = optStr(optObj(r, "fullDescription", at3) ?? {}, "text", `${at3} fullDescription`);
    const aliases = readAliases([optStrList(r, "deprecatedIds", at3), optStrList(props, "aliases", `${at3} properties`)], at3);
    const rule = { id, level, score, tags, ...tagFacts(tags), ...template === void 0 ? {} : { template }, aliases };
    list.push(rule);
    const same = byId.get(id);
    if (same === void 0) byId.set(id, rule);
    else if (!SAME(same, rule)) fail(`${at3}: two rules have the same id (${shown(id)}) and different severity data`);
  }
  return { list, byId };
}
function readInvocations(run, info, where) {
  let executionFailed = false;
  for (const [i, inv] of (optList(run, "invocations", where) ?? []).entries()) {
    const at3 = `${where} invocation ${i}`;
    if (!isObj(inv)) fail(`${at3} is not an object`);
    const exec = getOwn(inv, "executionSuccessful");
    if (typeof exec !== "boolean") fail(`${at3}: executionSuccessful is missing or not a boolean (SARIF requires it)`);
    if (exec === false && info.executionSuccessfulFalse !== "ignored") executionFailed = true;
    const notes = optList(inv, "toolExecutionNotifications", at3);
    if (notes !== void 0 && notes.length > 0) {
      const first = notes[0];
      const descriptor = isObj(first) ? getOwn(first, "descriptor") : void 0;
      const id = isObj(descriptor) ? getOwn(descriptor, "id") : void 0;
      fail(`${at3}: the tool reported ${notes.length} execution notification(s) (toolExecutionNotifications), first: ${typeof id === "string" ? safeText(id, 40) : "no id"}; the scan may have covered less than it should`);
    }
    for (const [j, n] of (optList(inv, "toolConfigurationNotifications", at3) ?? []).entries()) {
      if (!isObj(n)) fail(`${at3}: configuration notification ${j} is not an object`);
      const level = getOwn(n, "level");
      if (level !== void 0 && (typeof level !== "string" || !["none", "note", "warning", "error"].includes(level))) fail(`${at3}: configuration notification ${j} has a level that is not a SARIF level`);
      if (level === "error") fail(`${at3}: toolConfigurationNotifications has an error-level entry`);
    }
  }
  return { executionFailed };
}
function templateMessage(rule, ruleId) {
  return rule?.template !== void 0 && rule.template !== "" ? cutText(rule.template, MAX_MESSAGE_CHARS) : cutText(`finding of rule ${ruleId}`, MAX_MESSAGE_CHARS);
}
function secretMessage(ruleId) {
  return cutText(`secret detected by rule ${ruleId}`);
}
function baseFolder(baseId, run, workspace, encoding, where) {
  const table = optObj(run, "originalUriBaseIds", where);
  const entry = table === void 0 ? void 0 : getOwn(table, baseId);
  if (entry === void 0) return baseId === "%SRCROOT%" ? "" : void 0;
  if (!isObj(entry)) fail(`${where}: originalUriBaseIds entry ${shown(baseId)} is not an object`);
  const uri = optStr(entry, "uri", `${where} originalUriBaseIds entry`);
  const ws = workspace === void 0 ? "" : workspace.replace(/\/+$/, "");
  if (uri === void 0 || !ws.startsWith("/") || !/^file:\/\/\//i.test(uri)) return void 0;
  const path = uri.slice(7).replace(/\/+$/, "");
  if (path === ws) return "";
  return path.startsWith(`${ws}/`) ? normaliseUri(path.slice(ws.length + 1), { encoding }) : void 0;
}
function mapUri(uri, baseId, run, bases, workspace, encoding, where) {
  const own7 = normaliseUri(uri, { workspace, encoding });
  if (baseId === void 0 || uri.startsWith("/") || SCHEME.test(uri)) return own7;
  if (!bases.has(baseId)) bases.set(baseId, baseFolder(baseId, run, workspace, encoding, where));
  const base = bases.get(baseId);
  if (base === void 0 || own7 === void 0) return void 0;
  return base === "" ? own7 : `${base}/${own7}`;
}
function readRun(run, index, toolId, info, opts, limits, notes) {
  const where = `run ${index}`;
  if (!isObj(run)) fail(`${where} is not an object`);
  const driver = getOwn(optObj(run, "tool", where) ?? {}, "driver");
  const name = isObj(driver) ? getOwn(driver, "name") : void 0;
  if (!isObj(driver) || name !== info.driver) fail(`${where}: the driver name is ${shown(name)}, not the "${info.driver}" expected for ${toolId}`);
  const { executionFailed } = readInvocations(run, info, where);
  const results = getOwn(run, "results");
  if (!Array.isArray(results)) fail(`${where} has no results list`);
  if (results.length > limits.maxResults) fail(`${where} has more than ${limits.maxResults} results`);
  if (executionFailed && !(info.executionSuccessfulFalse === "findings" && results.length > 0)) fail(`${where}: executionSuccessful is false`);
  const { list: rules, byId } = readRules(driver, where);
  const secretsTool = info.secrets || opts.secretsTool === true;
  const findings = [];
  let noSeverity = 0;
  let unmapped = 0;
  const unreadable = /* @__PURE__ */ new Map();
  const bases = /* @__PURE__ */ new Map();
  for (const [i, r] of results.entries()) {
    const at3 = `${where} result ${i}`;
    if (!isObj(r)) fail(`${at3} is not an object`);
    const ref2 = optObj(r, "rule", at3);
    const rawId = getOwn(r, "ruleId") ?? (ref2 === void 0 ? void 0 : getOwn(ref2, "id"));
    if (typeof rawId !== "string" || rawId === "") fail(`${at3} has no ruleId`);
    if (rawId.length > MAX_ID_CHARS) fail(`${at3}: the ruleId is longer than ${MAX_ID_CHARS}`);
    const idx = getOwn(r, "ruleIndex");
    if (idx !== void 0 && typeof idx !== "number") fail(`${at3}: ruleIndex is not a number`);
    const indexed = typeof idx === "number" && Number.isInteger(idx) && idx >= 0 && idx < rules.length && rules[idx].id === rawId ? rules[idx] : void 0;
    const rule = indexed ?? byId.get(rawId);
    const msg = optObj(r, "message", at3);
    const text = msg === void 0 ? void 0 : optStr(msg, "text", `${at3} message`);
    const level = optStr(r, "level", at3);
    const props = optObj(r, "properties", at3) ?? {};
    const resultTags = readTags(props, `${at3} properties`);
    const score = getOwn(props, "security-severity");
    if (score !== void 0 && typeof score !== "string" && typeof score !== "number") fail(`${at3}: security-severity is not a string or a number`);
    const issue = getOwn(props, "issue_severity");
    if (issue !== void 0 && typeof issue !== "string") fail(`${at3}: issue_severity is not a string`);
    const resultAliases = optStrList(props, "aliases", `${at3} properties`);
    let commit;
    if (opts.commits === true) {
      const pf = optObj(r, "partialFingerprints", at3);
      const c = pf === void 0 ? void 0 : getOwn(pf, "commitSha");
      if (typeof c !== "string" || !/^[0-9a-f]{40}$/.test(c)) fail(`${at3} has no commit (partialFingerprints.commitSha of 40 hex digits), so its place in the commit range is not known`);
      commit = c;
    }
    let uri;
    let baseId;
    let line;
    let startColumn;
    let endLine;
    let endColumn;
    const locations = optList(r, "locations", at3);
    if (locations !== void 0 && locations.length > 0) {
      const loc = locations[0];
      if (!isObj(loc)) fail(`${at3}: the first location is not an object`);
      const physical = optObj(loc, "physicalLocation", `${at3} location`);
      if (physical !== void 0) {
        const artifact = optObj(physical, "artifactLocation", `${at3} location`) ?? {};
        uri = optStr(artifact, "uri", `${at3} artifactLocation`);
        baseId = optStr(artifact, "uriBaseId", `${at3} artifactLocation`);
        const region = optObj(physical, "region", `${at3} location`);
        if (region !== void 0) {
          line = lineOf(getOwn(region, "startLine"), `${at3} region`);
          startColumn = lineOf(getOwn(region, "startColumn"), `${at3} region`);
          endLine = lineOf(getOwn(region, "endLine"), `${at3} region`);
          endColumn = lineOf(getOwn(region, "endColumn"), `${at3} region`);
        }
      }
    }
    let file;
    let uriUnmapped = false;
    if (uri !== void 0) {
      if (info.fileMode === "none") {
        uriUnmapped = true;
      } else {
        file = opts.exactNames !== void 0 ? baseId === void 0 && opts.exactNames.test(uri) ? uri : void 0 : info.secrets && uri.includes("!") ? void 0 : mapUri(uri, baseId, run, bases, opts.workspace, info.uriEncoding, at3);
        uriUnmapped = file === void 0;
        if (uriUnmapped) unmapped++;
      }
    }
    if (info.errorRules.includes(rawId)) unreadable.set(rawId, (unreadable.get(rawId) ?? 0) + 1);
    const fromResult = tagFacts(resultTags);
    const isSecret = secretsTool || rule?.secret === true || fromResult.secret;
    let severity;
    if (isSecret) {
      severity = "critical";
    } else {
      switch (info.severity) {
        case "security-severity":
          severity = fromScore(score !== void 0 ? score : rule?.score);
          if (severity === "info" && info.zeroScoreIsUnknown) severity = void 0;
          break;
        case "level":
          severity = fromLevel(level ?? rule?.level);
          break;
        case "issue-severity":
          severity = typeof issue === "string" ? WORDS[issue] : void 0;
          break;
        case "tag-word":
          severity = RANK.find((s) => s === rule?.word || s === fromResult.word);
          break;
        case "secret":
          severity = "critical";
          break;
      }
    }
    if (severity === void 0) {
      severity = "high";
      noSeverity++;
    }
    const advisoryIds = isSecret ? [] : readAliases([[rawId], rule?.aliases, resultAliases], at3);
    findings.push({
      tool: toolId,
      ruleId: isSecret ? `secret:${rawId}` : rawId,
      severity,
      file,
      line,
      message: isSecret ? secretMessage(rawId) : info.messageFrom === "rule-template" ? templateMessage(rule, rawId) : cutText(text ?? "", MAX_MESSAGE_CHARS),
      uriUnmapped,
      secret: isSecret,
      ...startColumn === void 0 ? {} : { startColumn },
      ...endLine === void 0 ? {} : { endLine },
      ...endColumn === void 0 ? {} : { endColumn },
      ...uriUnmapped && uri !== void 0 ? { uriId: uriIdOf(uri) } : {},
      ...advisoryIds.length > 1 ? { advisoryIds } : {},
      ...commit === void 0 ? {} : { commit }
    });
  }
  if (unreadable.size > 0) {
    const total = [...unreadable.values()].reduce((a, b) => a + b, 0);
    fail(`${where}: ${toolId} could not read ${total} target(s) (${[...unreadable.keys()].map((k) => safeText(k, 40)).join(", ")}); the scan covered less than it should`);
  }
  if (noSeverity > 0) notes.push(`${where}: ${noSeverity} finding(s) had no severity value at ${toolId}'s own source and are counted as high`);
  if (unmapped > 0) notes.push(`${where}: ${unmapped} finding(s) had a path that could not be mapped to a repository file`);
  return findings;
}
var NOTHING_REPORTED_NUCLEI = "nothing reported (nuclei run with no result)";
var SYNTHESIZED_NUCLEI = Object.freeze({ driver: "pipegen-empty-nuclei", mark: "nuclei-no-file" });
function isSynthesizedNuclei(json) {
  const keys = (o) => Object.keys(o).sort().join(",");
  const runs = getOwn(json, "runs");
  if (getOwn(json, "version") !== "2.1.0" || keys(json) !== "runs,version" || !Array.isArray(runs) || runs.length !== 1) return false;
  const run = runs[0];
  if (!isObj(run) || keys(run) !== "properties,results,tool") return false;
  const results = getOwn(run, "results");
  const props = getOwn(run, "properties");
  const tool2 = getOwn(run, "tool");
  const driver = isObj(tool2) && keys(tool2) === "driver" ? getOwn(tool2, "driver") : void 0;
  return Array.isArray(results) && results.length === 0 && isObj(props) && keys(props) === "pipegenSynthesized" && getOwn(props, "pipegenSynthesized") === SYNTHESIZED_NUCLEI.mark && isObj(driver) && keys(driver) === "name" && getOwn(driver, "name") === SYNTHESIZED_NUCLEI.driver;
}
function parseSarif(json, toolId, opts = {}) {
  return guarded((notes) => {
    const info = Object.hasOwn(SARIF_TOOLS, toolId) ? SARIF_TOOLS[toolId] : void 0;
    if (info === void 0) fail(`${JSON.stringify(safeText(toolId, 60))} is not a tool whose SARIF the gate reads`);
    if (!isObj(json)) fail("the result is not a SARIF document (the top level is not an object)");
    if (toolId === "nuclei" && isSynthesizedNuclei(json)) {
      notes.push("nothing reported (synthesized empty result)");
      return [];
    }
    const version = getOwn(json, "version");
    if (version !== "2.1.0") fail(`the SARIF version is ${shown(version, 20)}, not 2.1.0`);
    const runs = getOwn(json, "runs");
    if (!Array.isArray(runs)) fail("the result has no runs list");
    if (runs.length === 0) fail("the result has no runs");
    const limits = limitsFrom(opts.limits);
    if (runs.length > limits.maxRuns) fail(`the result has more than ${limits.maxRuns} runs`);
    const findings = runs.flatMap((run, i) => readRun(run, i, toolId, info, opts, limits, notes));
    if (toolId === "nuclei" && findings.length === 0) notes.push(NOTHING_REPORTED_NUCLEI);
    if (info.note !== void 0 && opts.exactNames === void 0) notes.push(info.note);
    return findings;
  });
}
function parseSarifText(input, toolId, opts = {}) {
  const read = readJson(input, limitsFrom(opts.limits).maxBytes);
  return read.toolError === void 0 ? parseSarif(read.json, toolId, opts) : { findings: [], toolError: read.toolError, notes: [] };
}

// gate/src/zap.ts
var ZAP_TOOL = "zap-baseline";
var ZAP_JSON_VERIFIED = false;
var UNVERIFIED_NOTE = "zap-json parsing is unverified against a real zap-baseline -J report";
var MAX_PLUGIN_ID = 256;
var MAX_URL_PATH = 2048;
var MAX_SITES = 1e3;
var METHOD = /^[A-Za-z]{1,16}$/;
function severityOf(v) {
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d$/.test(v) ? Number(v) : NaN;
  return n === 3 ? "high" : n === 2 ? "medium" : n === 1 ? "low" : n === 0 ? "info" : void 0;
}
function urlPath(uri) {
  let url;
  try {
    url = new URL(uri);
  } catch {
    return void 0;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return void 0;
  return url.pathname.length > MAX_URL_PATH ? void 0 : url.pathname;
}
function optString(o, key, where, nullOk = false) {
  const v = getOwn(o, key);
  if (v === void 0 || nullOk && v === null) return void 0;
  if (typeof v !== "string") fail(`${where}: ${key} is not a string`);
  return v;
}
function parseZapJson(json, toolId, opts = {}) {
  return guarded((notes) => {
    if (toolId !== ZAP_TOOL) fail(`${JSON.stringify(safeText(toolId, 60))} is not a tool whose ZAP report the gate reads`);
    if (!isObj(json)) fail("the result is not a ZAP report (the top level is not an object)");
    if (getOwn(json, "@programName") !== "ZAP") fail("the report is not from ZAP (@programName)");
    const limits = limitsFrom(opts.limits);
    const sites = getOwn(json, "site");
    if (!Array.isArray(sites)) fail("the report has no site list");
    if (sites.length === 0) fail("the report lists no site, so nothing was scanned");
    if (sites.length > MAX_SITES) fail(`the report lists more than ${MAX_SITES} sites`);
    const findings = [];
    let unknownRisk = 0;
    for (const [s, site] of sites.entries()) {
      const at3 = `site ${s}`;
      if (!isObj(site)) fail(`${at3} is not an object`);
      const alerts = getOwn(site, "alerts");
      if (!Array.isArray(alerts)) fail(`${at3} has no alerts list`);
      for (const [a, alert] of alerts.entries()) {
        const where = `${at3} alert ${a}`;
        if (!isObj(alert)) fail(`${where} is not an object`);
        const pluginid = getOwn(alert, "pluginid");
        if (typeof pluginid !== "string" || pluginid === "" || pluginid.length > MAX_PLUGIN_ID) fail(`${where} has no usable pluginid (${shown(pluginid)})`);
        const name = optString(alert, "name", where);
        const title = optString(alert, "alert", where);
        const risk = getOwn(alert, "riskcode");
        if (risk !== void 0 && typeof risk !== "string" && typeof risk !== "number") fail(`${where}: riskcode is not a string or a number`);
        let severity = severityOf(risk);
        if (severity === void 0) {
          severity = "high";
          unknownRisk++;
        }
        const message = cutText(name ?? title ?? "", MAX_MESSAGE_CHARS);
        const instances = optList(alert, "instances", where) ?? [];
        const make = (file, method, uriUnmapped, uriId) => {
          if (findings.length >= limits.maxResults) fail(`the report has more than ${limits.maxResults} findings`);
          findings.push({ tool: toolId, ruleId: pluginid, severity, file, message, method, uriUnmapped, secret: false, ...uriId === void 0 ? {} : { uriId } });
        };
        if (instances.length === 0) make(void 0, void 0, false);
        for (const [n, inst] of instances.entries()) {
          const w = `${where} instance ${n}`;
          if (!isObj(inst)) fail(`${w} is not an object`);
          const uri = optString(inst, "uri", w, true);
          const method = optString(inst, "method", w, true);
          const file = uri === void 0 ? void 0 : urlPath(uri);
          make(file, method !== void 0 && METHOD.test(method) ? method.toUpperCase() : void 0, file === void 0, file === void 0 && uri !== void 0 ? uriIdOf(uri) : void 0);
        }
      }
    }
    notes.push(UNVERIFIED_NOTE);
    if (unknownRisk > 0) notes.push(`${unknownRisk} alert(s) had an unknown riskcode and are counted as high`);
    return findings;
  });
}
function parseZapJsonText(input, toolId, opts = {}) {
  const read = readJson(input, limitsFrom(opts.limits).maxBytes);
  return read.toolError === void 0 ? parseZapJson(read.json, toolId, opts) : { findings: [], toolError: read.toolError, notes: [] };
}

// gate/src/decide.ts
var NOT_RUN_FORK = "not run on a fork PR (no secrets): a maintainer must run it from a branch of this repository";
var NOT_SCANNED_RULE_ID = "secret:not-scanned";
var FORM_OF = Object.freeze({
  hash: "content",
  region: "content",
  quoted: "content",
  file: "content",
  line: "position",
  nokey: "position",
  "quoted-nokey": "position"
});
var FLOOR = new Set(FLOOR_NEEDS);
var NEVER_SKIPPED = /* @__PURE__ */ new Set(["secrets", "sast", "deps", "gate"]);
var SHA_RE = /^[0-9a-f]{40}$/;
var ZERO_SHA = "0".repeat(40);
var GITLEAKS_NOTE = SARIF_TOOLS.gitleaks?.note ?? "completeness not provable (gitleaks)";
var NOTHING_REPORTED = "nothing reported";
var SHOWN_PER_TOOL = 10;
function countKeyOf(job, f) {
  return f.uriUnmapped && !f.secret ? `unmapped\0${job}\0${f.tool}\0${f.ruleId}` : `fp\0${job}\0${f.tool}\0${f.fingerprint}`;
}
function at(o, ...path) {
  let v = o;
  for (const k of path) {
    if (typeof v !== "object" || v === null || Array.isArray(v) || !Object.hasOwn(v, k)) return void 0;
    v = v[k];
  }
  return v;
}
var sha40 = (v) => typeof v === "string" && SHA_RE.test(v) ? v : void 0;
function expectedBaseOf(ev) {
  const p = ev.payload;
  const pair = ev.name === "pull_request" || ev.name === "pull_request_review" ? [at(p, "pull_request", "base", "sha"), at(p, "pull_request", "head", "sha")] : ev.name === "merge_group" ? [at(p, "merge_group", "base_sha"), at(p, "merge_group", "head_sha")] : ev.name === "push" ? [at(p, "before"), at(p, "after")] : void 0;
  const heads = [...new Set([sha40(pair?.[1]), sha40(ev.sha)].filter((x) => x !== void 0))];
  if (pair === void 0) return { heads, why: `a ${ev.name} event has no base commit` };
  const base = sha40(pair[0]);
  if (base === void 0) return { heads, why: "the event payload has no base commit" };
  if (base === ZERO_SHA) return { heads, why: "the base commit is all zeros (a new branch)" };
  if (heads.includes(base)) return { heads, why: "the base commit is the head" };
  return { base, heads };
}
function isFork(payload) {
  const head = at(payload, "pull_request", "head", "repo", "id");
  const repo2 = at(payload, "repository", "id");
  return typeof head === "number" && typeof repo2 === "number" && head !== repo2;
}
function verifyBase(i) {
  if (i.baseScan === null) return { kind: "absent", why: "this run has no base-scan job" };
  const exp = expectedBaseOf(i.event);
  if (exp.base === void 0) return { kind: "unverified", why: exp.why ?? "no base commit" };
  if (i.baseScan.commit !== exp.base) return { kind: "unverified", why: "the base-scan job did not check out the base commit of this event" };
  const a = i.ancestry;
  if (a === null || a.base !== exp.base || !exp.heads.includes(a.head)) return { kind: "unverified", why: "the base commit could not be verified as an ancestor of the head" };
  if (!a.isAncestor) return { kind: "unverified", why: "the base commit is not an ancestor of the head" };
  return { kind: "verified" };
}
var isFindingsEntry = (e) => e.format === "sarif" || e.format === "zap-json";
var isFloorNeed = (needId) => FLOOR.has(needId) || Object.hasOwn(NEED_ID_CATEGORY, needId) && FLOOR.has(NEED_ID_CATEGORY[needId]);
var isFloorEntry = (e) => isFloorNeed(e.needId) || FLOOR.has(e.category);
var serious = (f) => f.severity === "critical" || f.severity === "high" || f.secret;
var isMalicious = (f) => [f.ruleId, ...f.advisoryIds ?? []].some((id) => /^MAL-/i.test(id.trim()));
var isPosition = (f) => FORM_OF[f.fpBy] === "position" || f.secret && f.tool.startsWith("trivy");
function fileState(outputs, file) {
  const st = outputs?.status;
  if (st === void 0) return { kind: "absent" };
  if (st === "tool-error") return { kind: "tool-error", why: outputs?.error ?? "no detail" };
  if (st !== "ok") return { kind: "tampered", why: "its status output is neither ok nor tool-error" };
  if (outputs?.sha256 === void 0) return { kind: "tampered", why: "it has no sha256 output" };
  if (file === void 0) return { kind: "missing-file" };
  if (file.problem !== void 0) return { kind: "tampered", why: file.problem };
  if (file.sha256 !== outputs.sha256) return { kind: "tampered", why: "its sha256 does not equal the job's output" };
  if (file.read.toolError !== void 0) return { kind: "tool-error", why: `the result could not be read back: ${file.read.toolError}` };
  return { kind: "ok", read: file.read };
}
function countsOf(job, fs) {
  const m = /* @__PURE__ */ new Map();
  for (const f of fs) {
    const k = countKeyOf(job, f);
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return m;
}
function touched(diff, f) {
  const set = f.file === void 0 ? void 0 : diff.added.get(f.file);
  if (set === void 0 || set.size === 0) return false;
  if (f.line === void 0) return true;
  const from = f.line;
  const to = Math.max(f.endLine ?? f.line, from);
  if (to - from + 1 <= set.size) {
    for (let n = from; n <= to; n++) if (set.has(n)) return true;
    return false;
  }
  for (const n of set) if (n >= from && n <= to) return true;
  return false;
}
function decideGate(i) {
  const blocking = [];
  const warnings = [];
  const counted = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const blockReasons = [];
  const warnReasons = [];
  const failedJobs = [];
  const notRun = [];
  const toolErrors = [];
  const noCoverage = [];
  const notScanned = [];
  const notProven = [];
  const checks = [];
  const notes = [];
  const note = (n) => {
    if (!notes.includes(n)) notes.push(n);
  };
  const block = (r) => {
    if (!blockReasons.includes(r)) blockReasons.push(r);
  };
  const warn = (r) => {
    if (!warnReasons.includes(r)) warnReasons.push(r);
  };
  for (const n of i.notes ?? []) note(n);
  const coverageOf = (job) => (i.coverage ?? []).filter((c) => c.job === job).map((c) => c.text);
  for (const c of i.coverage ?? []) note(`${c.job}: ${c.text}`);
  for (const s of i.settingsErrors) block(s);
  const pp = policyProblem(i.policy);
  const policy = pp === null ? i.policy : DEFAULT_POLICY;
  if (pp !== null) block(`the policy is refused (it must be ${pp}), so the default policy is used`);
  const notProvenSet = new Set(i.notProvenNeeds);
  for (const n of notProvenSet) if (isFloorNeed(n)) block(`not-proven can't include floor need ${n}`);
  const skippedBy = /* @__PURE__ */ new Map();
  for (const s of i.skipped) {
    if (NEVER_SKIPPED.has(s.needId)) block(`${s.needId} can never be skipped`);
    else if (!skippedBy.has(s.needId)) skippedBy.set(s.needId, s.reason);
  }
  for (const c of i.checks) if (c.entry.warnFirst !== void 0 && isFloorEntry(c.entry)) block(`warn-first can't be set on floor need ${c.entry.needId}`);
  const fork = isFork(i.event.payload);
  const baseState = verifyBase(i);
  if (baseState.kind === "unverified") note(`no base: ${baseState.why}, so every finding compared with the base scan is new`);
  let diff;
  if (i.diff === null && i.event.name === "push") {
    diff = null;
    note("no diff on this push: position-based fingerprints are compared by count only");
  } else if (i.diff === null) {
    diff = { added: /* @__PURE__ */ new Map(), complete: false };
    note(`the pull request's diff is missing on this ${i.event.name} event, so every position-based fingerprint is new`);
  } else if (i.diff.commit !== i.event.sha) {
    diff = { added: i.diff.added, complete: false };
    note("the diff's line numbers are of a commit that is not the scanned commit (github.sha), so every position-based fingerprint is new");
  } else diff = i.diff;
  const baselineValid = i.baseline === null || [...i.baseline.counts.values()].every((v) => Number.isSafeInteger(v) && v >= 0);
  if (!baselineValid) note("the baseline is invalid (a count that is not a whole number of at least 0): there is no base for the tools it covers, so their findings are new");
  if (i.checks.length === 0) block("the job list is empty: no check ran, so nothing is proven");
  for (const n of new Set(i.floorNeeds)) {
    if (n === "gate" || i.checks.some((c) => c.entry.needId === n)) continue;
    if (skippedBy.has(n)) continue;
    failedJobs.push({ needId: n, job: n, reason: "missing" });
    block(`required check ${n} is not in the job list (missing)`);
  }
  const ranSkipped = /* @__PURE__ */ new Set();
  const headFindings = [];
  for (const c of i.checks) {
    const e = c.entry;
    const floor = isFloorEntry(e);
    const zapUnverified = e.tool === ZAP_TOOL && !ZAP_JSON_VERIFIED;
    const level = !floor && (notProvenSet.has(e.needId) || zapUnverified) ? "not-proven" : !e.blocking && !floor ? "advisory" : "required";
    const findings = isFindingsEntry(e);
    const tool2 = e.tool ?? e.needId;
    const name = `${tool2} (${e.job})`;
    const ref2 = (reason) => ({ needId: e.needId, job: e.job, ...e.tool === void 0 ? {} : { tool: e.tool }, reason });
    const uncovered = coverageOf(e.job);
    const state = (s) => {
      checks.push({ needId: e.needId, job: e.job, ...e.tool === void 0 ? {} : { tool: e.tool }, judgedBy: findings ? "findings" : "job status", state: uncovered.length === 0 ? s : `${s}; ${uncovered.join("; ")}` });
    };
    if (level === "not-proven") notProven.push(ref2(zapUnverified && !notProvenSet.has(e.needId) ? "ZAP results are not verified yet, so this DAST check is judged as not proven (warnings only)" : "not proven: warnings only"));
    const toolError2 = (why2, base) => {
      const blocks = level === "required";
      toolErrors.push({ ...ref2(why2), base, blocks });
      const text = `tool error in ${name}${base ? " on the base commit" : ""}: re-run the job`;
      if (blocks) block(text);
      else if (level === "not-proven") warn(`${text} (not proven: a warning only)`);
      else note(`${text} (a non-blocking check)`);
    };
    const tampered = (what, why2) => {
      block(`result tampered or missing: ${e.job} (${what}: ${why2})`);
    };
    const didNotReport = () => {
      const text = `scanner ${name} did not report`;
      if (level === "required") block(text);
      else if (level === "not-proven") warn(`${text} (not proven: a warning only)`);
      else note(`${text} (a non-blocking check)`);
    };
    if (c.result !== "success") {
      const skip = skippedBy.get(e.needId);
      if (skip !== void 0) {
        state("skipped");
        continue;
      }
      if (fork && e.needsSecrets) {
        if (level === "required") {
          notRun.push(ref2(NOT_RUN_FORK));
          block(`${name}: ${NOT_RUN_FORK}`);
        } else warn(`${name}: ${NOT_RUN_FORK} (${level === "advisory" ? "a non-blocking check" : "not proven"})`);
        state("not run (fork PR)");
        continue;
      }
      if (findings && c.outputs.status === "tool-error") {
        toolError2(c.outputs.error ?? "no detail", false);
        state("tool error");
        continue;
      }
      const text = `${name} did not succeed (${c.result})`;
      if (level === "not-proven") warn(`not-proven check ${text}: a warning only`);
      else if (level === "advisory") note(`non-blocking check ${text}`);
      else if (e.warnFirst !== void 0 && !findings && c.result === "failure") warn(`warn-first check ${text}: a warning until a reviewed pull request makes it blocking`);
      else {
        failedJobs.push(ref2(c.result));
        block(`required check ${text}`);
      }
      state(`failed (${c.result})`);
      continue;
    }
    ranSkipped.add(e.needId);
    if (!findings) {
      state("passed");
      continue;
    }
    const head = fileState(c.outputs, c.file);
    if (head.kind === "absent") {
      didNotReport();
      state("did not report");
      continue;
    }
    if (head.kind === "tool-error") {
      toolError2(head.why, false);
      state("tool error");
      continue;
    }
    if (head.kind === "tampered") {
      tampered(e.artifact ?? e.job, head.why);
      state("tampered");
      continue;
    }
    if (head.kind === "missing-file") {
      if (level === "advisory") {
        note(`the result of non-blocking check ${name} is missing`);
        state("did not report");
      } else {
        tampered(e.artifact ?? e.job, "the artifact is missing");
        state("tampered");
      }
      continue;
    }
    const fs = head.read.findings;
    for (const n of head.read.notes) note(`${e.job}: ${n}`);
    for (const f of fs) headFindings.push({ job: e.job, f });
    const nothing = fs.length === 0 && (head.read.notes.some((n) => n.startsWith(NOTHING_REPORTED)) || e.tool === "nuclei" || e.tool === "gitleaks" && head.read.notes.includes(GITLEAKS_NOTE));
    if (nothing) {
      noCoverage.push(ref2("nothing reported, so completeness is not provable: never counted as covered"));
      if (level === "required") block(`no coverage for ${name}: completeness not provable, and a required check can't pass without it`);
      state("no coverage (completeness not provable)");
      continue;
    }
    const bf = c.base === void 0 ? { kind: "absent" } : fileState(c.base.outputs, c.base.file);
    if (bf.kind === "tool-error") toolError2(bf.why, true);
    if (bf.kind === "tampered") tampered(e.baseArtifact ?? `${e.job} base`, bf.why);
    if (bf.kind === "missing-file") tampered(e.baseArtifact ?? `${e.job} base`, "the base artifact is missing");
    const sameRun = e.tool !== void 0 && i.sameRunTools.includes(e.tool);
    let counts;
    let noBase;
    if (!sameRun && i.baseline !== null && e.tool !== void 0 && i.baseline.tools.includes(e.tool)) {
      if (baselineValid) counts = i.baseline.counts;
      else noBase = "new";
    } else if (bf.kind === "ok" && baseState.kind === "verified") counts = countsOf(e.job, bf.read.findings);
    else if (bf.kind === "absent" && baseState.kind !== "unverified") {
      noBase = i.installing ? "installing" : "new";
      note(`scanner ${name} couldn't run on the base commit: ${i.installing ? "its findings are warnings (installing pipegen)" : "all its findings are new"}`);
    } else noBase = "new";
    const odd = fs.filter((f) => !SEVERITIES.includes(f.severity)).length;
    if (odd > 0) note(`${e.job}: ${odd} finding(s) had an unknown severity and are counted as high`);
    const decided = fs.map((f) => ({ ...f, severity: SEVERITIES.includes(f.severity) ? f.severity : "high", needId: e.needId, job: e.job, isNew: void 0, reason: "" }));
    const groups = /* @__PURE__ */ new Map();
    for (const d of decided) {
      const set = (isNew, reason) => {
        d.isNew = isNew;
        d.reason = reason;
      };
      if (d.ruleId === NOT_SCANNED_RULE_ID && d.fpBy !== "file") {
        set(true, "new: not scanned, and without a key its file can not be matched with the base");
        continue;
      }
      if (d.secret && d.uriUnmapped) {
        set(true, "new: a secret in a file whose path could not be mapped to a repository path; it blocks every run until the file is renamed or the secret removed");
        continue;
      }
      if (noBase === "installing" && d.ruleId !== NOT_SCANNED_RULE_ID && !d.secret && e.category !== "secrets") {
        set(void 0, "no base: the scanner couldn't run on the base commit (installing pipegen)");
        continue;
      }
      if (counts === void 0) {
        set(true, "new: no base to compare with");
        continue;
      }
      if (isPosition(d) && diff !== null) {
        if (d.file === void 0) {
          set(true, "new: a position-based fingerprint with no repository file");
          continue;
        }
        if (!diff.complete) {
          set(true, "new: the pull request's diff is missing, incomplete or of another commit");
          continue;
        }
        if (touched(diff, d)) {
          set(true, "new: on a changed line of this pull request");
          continue;
        }
      }
      const k = countKeyOf(e.job, d);
      const g = groups.get(k);
      if (g === void 0) groups.set(k, [d]);
      else g.push(d);
    }
    for (const [k, g] of groups) {
      const inBase = counts?.get(k) ?? 0;
      g.forEach((d, n) => {
        d.isNew = n >= inBase;
        d.reason = n >= inBase ? inBase === 0 ? "new: not in the base" : "new: more than in the base" : "old: also in the base";
      });
    }
    for (const d of decided) {
      if (d.ruleId === NOT_SCANNED_RULE_ID) notScanned.push(d);
      const licenceUnknown = e.category === "licences" && d.severity === "info";
      const shown2 = serious(d) || d.severity === "medium" || licenceUnknown;
      const put = (to, why2) => {
        if (why2 !== void 0) d.reason = `${d.reason}; ${why2}`;
        if (to === "block") blocking.push(d);
        else if (to === "warn") warnings.push(d);
        else counted[d.severity]++;
      };
      if (level !== "required") {
        put(shown2 ? "warn" : "count", level === "advisory" ? "a non-blocking check: never blocks" : "not proven: never blocks");
        continue;
      }
      if (isMalicious(d)) {
        put("block", "a malicious package advisory (MAL-): blocks even when old");
        continue;
      }
      if (d.isNew === void 0) {
        put(shown2 ? "warn" : "count");
        continue;
      }
      if (d.isNew && serious(d)) {
        put("block", "a new critical, high or secret finding blocks in any mode");
        continue;
      }
      if (e.warnFirst !== void 0) {
        put(shown2 ? "warn" : "count", "warn-first: a warning until a reviewed pull request makes the check blocking");
        continue;
      }
      if (d.isNew && e.category === "dependency-review") {
        put("block", "a new vulnerability in dependency review");
        continue;
      }
      if (licenceUnknown) {
        put("warn", "an unknown licence: needs a human, never blocks");
        continue;
      }
      if (i.mode === "block") put(policy.block.includes(d.severity) ? "block" : policy.warn.includes(d.severity) ? "warn" : "count");
      else put(shown2 ? "warn" : "count");
    }
    state(fs.length === 0 ? "no findings" : `${fs.length} finding(s)`);
  }
  const informational = i.event.name === "push";
  const onMain = "on the default branch the commit range is informational";
  for (const rs of i.rangeScans) {
    const name = `${rs.tool} (the pull request's commit range)`;
    if (rs.toolError !== void 0) {
      toolErrors.push({ needId: "secrets", job: "commit range", tool: rs.tool, reason: rs.toolError, base: false, blocks: !informational });
      if (informational) warn(`tool error in ${name}; ${onMain}`);
      else block(`tool error in ${name}: the pull request's commits are not proven free of secrets; re-run the job`);
      continue;
    }
    if (rs.findings === void 0) {
      if (informational) warn(`scanner ${name} did not report; ${onMain}`);
      else block(`scanner ${name} did not report, so the pull request's commits are not proven free of secrets`);
      continue;
    }
    for (const f of rs.findings) {
      const reason = rangeReason(f.commit);
      if (informational) warnings.push({ ...f, needId: "secrets", job: "commit range", isNew: true, reason: `${reason}; ${onMain}` });
      else blocking.push({ ...f, needId: "secrets", job: "commit range", isNew: true, reason });
    }
  }
  const integrityBlocks = i.integrity.length > 0 && !i.installing;
  if (i.integrity.length > 0) {
    if (i.installing) warn("installing pipegen: review these files");
    else block("pipeline files changed or suppressions added without code-owner approval on the current commit");
  }
  const skipped = i.skipped.filter((s) => skippedBy.get(s.needId) === s.reason && !ranSkipped.has(s.needId)).map((s) => {
    const job = i.checks.find((c) => c.entry.needId === s.needId)?.entry.job;
    return { needId: s.needId, ...job === void 0 ? {} : { job }, reason: s.reason };
  });
  const pass = blockReasons.length === 0 && blocking.length === 0;
  const result = {
    pass,
    mode: i.mode,
    blocking,
    warnings,
    counted,
    blockReasons,
    warnReasons,
    failedJobs,
    notRun,
    toolErrors,
    noCoverage,
    notScanned,
    skipped,
    notProven,
    integrity: { blocks: integrityBlocks, findings: [...i.integrity] },
    checks,
    notes
  };
  return { ...result, summary: renderSummary(result, i.installing) };
}
var rangeReason = (commit) => `secret added in this PR's history (commit ${commit !== void 0 && /^[0-9a-f]{40}$/.test(commit) ? commit.slice(0, 12) : "not known"}): rotate it now, even if a later commit removed it`;
var md = (s, max) => {
  const v = safeMarkdown(s, max);
  return v === "" ? "(empty)" : v;
};
function findingLines(fs) {
  const out = [];
  const byTool = /* @__PURE__ */ new Map();
  for (const f of fs) {
    const g = byTool.get(f.tool);
    if (g === void 0) byTool.set(f.tool, [f]);
    else g.push(f);
  }
  for (const [tool2, g] of byTool) {
    out.push(`#### ${md(tool2)}`);
    const lines = /* @__PURE__ */ new Map();
    for (const f of g) {
      const k = JSON.stringify([f.severity, f.isNew, f.ruleId, f.file ?? f.displayPath ?? "", f.message, f.reason]);
      const l = lines.get(k);
      if (l === void 0) lines.set(k, { f, n: 1 });
      else l.n++;
    }
    const all = [...lines.values()];
    for (const { f, n } of all.slice(0, SHOWN_PER_TOOL)) {
      const where = f.file !== void 0 ? `${md(f.file, 300)}${n === 1 && f.line !== void 0 ? `:${f.line}` : ""}` : f.displayPath !== void 0 ? md(f.displayPath, 300) : f.uriUnmapped ? "(a path that could not be mapped)" : "(no repository file)";
      const age = f.isNew === true ? "new" : f.isNew === false ? "old" : "no base";
      out.push(`- ${f.severity} \xB7 ${age} \xB7 ${md(f.ruleId)} \xB7 ${where} \xB7 ${md(f.message)} \xB7 ${md(f.reason, 300)}${n > 1 ? ` (\xD7${n})` : ""}`);
    }
    if (all.length > SHOWN_PER_TOOL) out.push(`- +${all.length - SHOWN_PER_TOOL} more`);
  }
  return out;
}
function renderSummary(r, installing) {
  const out = [];
  const section = (title, lines) => {
    if (lines.length > 0) out.push("", `### ${title}`, ...lines);
  };
  out.push(`## pipegen gate: ${r.pass ? "passed" : "blocked"} (${r.mode} mode)`);
  const countedText = SEVERITIES.filter((s) => r.counted[s] > 0).map((s) => `${r.counted[s]} ${s}`).join(", ");
  out.push("", [
    `${r.blocking.length} blocking findings`,
    `${r.blockReasons.length} other reasons to block`,
    `${r.warnings.length} warnings`,
    `${r.warnReasons.length} other warnings`,
    `${r.toolErrors.length} tool errors`,
    `${r.failedJobs.length} failed checks`,
    `${r.notRun.length} not run`,
    ...countedText === "" ? [] : [`only counted: ${countedText}`]
  ].join(" \xB7 "));
  section("Blocking", [...r.blockReasons.map((b) => `- ${md(b, 400)}`), ...findingLines(r.blocking)]);
  section("Warnings", [...r.warnReasons.map((w) => `- ${md(w, 400)}`), ...findingLines(r.warnings)]);
  section("Tool errors", r.toolErrors.map((t) => `- ${md(t.tool ?? t.needId)} (${md(t.job)})${t.base ? " on the base commit" : ""}: ${md(t.reason, 300)} \xB7 ${t.blocks ? "blocks" : "does not block"}`));
  section("Failed checks", r.failedJobs.map((f) => `- ${md(f.job)}: ${md(f.reason)}`));
  section("Not run (fork PR)", r.notRun.map((f) => `- ${md(f.job)}: ${NOT_RUN_FORK}`));
  section("No coverage (completeness not provable)", r.noCoverage.map((f) => `- ${md(f.job)}: nothing reported, so completeness is not provable; never counted as covered`));
  section("Not scanned", r.notScanned.map((f) => `- ${f.file !== void 0 ? md(f.file, 300) : f.displayPath !== void 0 ? md(f.displayPath, 300) : "(a path that could not be mapped)"}${f.line !== void 0 ? ` lines ${f.line}-${f.endLine ?? f.line}` : ""} \xB7 ${f.isNew === false ? "old" : "new"}`));
  section("Skipped", r.skipped.map((s) => `- ${md(s.job ?? s.needId)}: skipped, ${md(s.reason)}; not checked, never counted as clean`));
  section("Not proven", r.notProven.map((n) => `- ${md(n.job)}: ${md(n.reason, 300)}`));
  if (r.integrity.findings.length > 0) {
    section("Integrity", [
      installing ? "installing pipegen: review these files" : "pipeline files changed or suppressions added without code-owner approval on the current commit",
      ...r.integrity.findings.slice(0, 50).map((f) => `- ${md(f.ruleId)} \xB7 ${f.file === void 0 ? "(no file)" : md(f.file, 300)} \xB7 ${md(f.message)}`),
      ...r.integrity.findings.length > 50 ? [`- +${r.integrity.findings.length - 50} more`] : []
    ]);
  }
  section("Checks", r.checks.map((c) => `- ${md(c.job)}: ${md(c.state)} (judged by ${c.judgedBy})`));
  section("Notes", r.notes.slice(0, 100).map((n) => `- ${md(n, 400)}`));
  return `${out.join("\n")}
`;
}

// gate/src/baseline.ts
var WORKFLOW_PATH = ".github/workflows/pipegen.yml";
var BASELINE_RETENTION_DAYS = 90;
var MAX_RUN_PAGES = 5;
var RUNS_PER_PAGE = 100;
var MAX_TRUSTED_RUNS = 15;
var HISTORY_CHECK_CAP = 20;
var MARKER_WINDOW = 10;
var HISTORY_FAIL_CAP = 3;
var MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
var MAX_COUNT_ENTRIES = 2e5;
var MAX_COUNT_KEY = 4096;
var BASELINE_FORMAT = "pipegen-baseline-v1";
var CLEAN_RUN_FORMAT = "pipegen-clean-run-v1";
var SHA_RE2 = /^[0-9a-f]{40}$/;
var KEY_ID_RE = /^[0-9a-f]{16}$/;
var MAC_RE = /^[0-9a-f]{64}$/;
var isPlain2 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var own = (o, k) => Object.hasOwn(o, k) ? o[k] : void 0;
var posInt = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
async function resolveTip(gh, repo2) {
  try {
    const ref2 = await gh.branchHead(repo2.owner, repo2.name, repo2.defaultBranch);
    if (!isPlain2(ref2) || own(ref2, "ref") !== `refs/heads/${repo2.defaultBranch}`) return void 0;
    const obj = own(ref2, "object");
    const tip = isPlain2(obj) && own(obj, "type") === "commit" ? own(obj, "sha") : void 0;
    return typeof tip === "string" && SHA_RE2.test(tip) ? tip : void 0;
  } catch {
    return void 0;
  }
}
async function historyState(gh, repo2, sha3, lk) {
  if (typeof sha3 !== "string" || !SHA_RE2.test(sha3)) return "out";
  try {
    const tipP = lk === void 0 ? resolveTip(gh, repo2) : lk.tip ??= resolveTip(gh, repo2);
    const tip = await tipP;
    if (tip === void 0) return "error";
    const answer = await gh.compare(repo2.owner, repo2.name, sha3, tip);
    const status = isPlain2(answer) ? own(answer, "status") : void 0;
    if (typeof status !== "string") return "error";
    return status === "ahead" || status === "identical" ? "in" : "out";
  } catch {
    return "error";
  }
}
function runFieldsTrusted(run, repo2) {
  if (!isPlain2(run)) return false;
  if (!posInt(own(run, "id"))) return false;
  if (own(run, "event") !== "push") return false;
  if (own(run, "path") !== WORKFLOW_PATH) return false;
  const head = own(run, "head_repository");
  if (!isPlain2(head) || own(head, "id") !== repo2.id) return false;
  if (own(run, "head_branch") !== repo2.defaultBranch) return false;
  const sha3 = own(run, "head_sha");
  return typeof sha3 === "string" && SHA_RE2.test(sha3);
}
async function judgeRun(gh, run, repo2, budget, lk) {
  if (!runFieldsTrusted(run, repo2)) return { ok: false, why: "untrusted" };
  const sha3 = own(run, "head_sha");
  if (budget !== void 0) {
    if (budget.left <= 0) return { ok: false, why: "cap" };
    budget.left--;
  }
  const askTag = async () => {
    try {
      const t = await gh.tagExists(repo2.owner, repo2.name, repo2.defaultBranch);
      return t === false ? "none" : t === true ? "tag" : "error";
    } catch {
      return "error";
    }
  };
  const tag = await (lk === void 0 ? askTag() : lk.tag ??= askTag());
  if (tag === "tag") return { ok: false, why: "tag" };
  if (tag === "error") return { ok: false, why: "error" };
  const h = await historyState(gh, repo2, sha3, lk);
  return h === "in" ? { ok: true } : { ok: false, why: h === "out" ? "history" : "error" };
}
function expiryProblem(meta, now) {
  if (meta.expired !== false) return "the artifact has expired";
  const t = typeof meta.expiresAt === "string" && /^\d{4}-\d{2}-\d{2}T/.test(meta.expiresAt) ? Date.parse(meta.expiresAt) : Number.NaN;
  if (Number.isNaN(t) || !(now instanceof Date) || Number.isNaN(now.getTime())) return "the artifact has no usable expiry time, so it is treated as expired";
  return t <= now.getTime() ? "the artifact has expired" : void 0;
}
function metaProblem(meta, ctx, name) {
  if (!isPlain2(meta) || meta.name !== name) return `the artifact is not named ${name}`;
  if (!posInt(meta.runId)) return "the artifact has no valid run id";
  const exp = expiryProblem(meta, ctx.now);
  if (exp !== void 0) return exp;
  return keyNote(ctx.key);
}
function keyNote(key) {
  if (key === void 0 || key === "") return "PIPEGEN_FP_KEY is not available (a fork pull request has no secrets), so the file can not be verified";
  return keyProblem(key, false, true) === void 0 ? void 0 : "PIPEGEN_FP_KEY can not be used, so the file can not be verified";
}
function parseDoc(bytes) {
  if (!(bytes instanceof Uint8Array)) return "the artifact is not bytes";
  if (bytes.length === 0 || bytes.length > MAX_ARTIFACT_BYTES) return "the file is empty or over the size cap";
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return "the file is not valid JSON";
  }
  return isPlain2(value) ? value : "the file is not a JSON object";
}
var hmac2 = (key, text) => createHmac2("sha256", key).update(text).digest("hex");
var macKey = (key) => hmac2(key, "pipegen-artifact-mac-v1");
var sign = (key, text) => hmac2(macKey(key), text);
function macMatches(key, text, mac) {
  const a = Buffer.from(sign(key, text), "hex");
  const b = Buffer.from(mac, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
var code2 = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function canonicalBaseline(runId, kid, counts) {
  return JSON.stringify([BASELINE_FORMAT, runId, kid, [...counts].sort(([a], [b]) => code2(a, b))]);
}
var canonicalMarker = (runId, kid) => JSON.stringify([CLEAN_RUN_FORMAT, runId, kid]);
function readCounts(v) {
  if (!isPlain2(v)) return "counts is not a map";
  const entries = Object.entries(v);
  if (entries.length > MAX_COUNT_ENTRIES) return "counts has too many entries";
  const out = /* @__PURE__ */ new Map();
  for (const [k, n] of entries) {
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) return "a count is not a whole number of at least 0";
    const parts = k.split("\0");
    if (k.length > MAX_COUNT_KEY || parts.length < 4 || parts[0] !== "fp" && parts[0] !== "unmapped" || !parts[1] || !parts[2]) return "a count key is not one the gate writes";
    out.set(k, n);
  }
  return out;
}
function verifyBaselineArtifact(bytes, meta, ctx) {
  const none = (note) => ({ baseline: null, note: `no trusted baseline: ${note}` });
  const early = metaProblem(meta, ctx, BASELINE_ARTIFACT);
  if (early !== void 0) return none(early);
  const key = ctx.key;
  const doc = parseDoc(bytes);
  if (typeof doc === "string") return none(doc);
  if (Object.keys(doc).sort().join() !== "counts,keyId,mac,runId") return none("the file does not have exactly runId, keyId, counts and MAC");
  const runId = own(doc, "runId");
  if (!posInt(runId)) return none("runId is not a positive whole number");
  const kid = own(doc, "keyId");
  if (typeof kid !== "string" || !KEY_ID_RE.test(kid)) return none("keyId is not a key id");
  const mac = own(doc, "mac");
  if (typeof mac !== "string" || !MAC_RE.test(mac)) return none("the MAC is missing or not 64 lower-case hex characters");
  if (runId !== meta.runId) return none(`the file is for run ${runId}, not the run of the artifact (${meta.runId})`);
  if (kid !== keyId(key)) return none("its key id is not the current PIPEGEN_FP_KEY's (the key changed): secret fingerprints are under another key, so the base scan decides");
  const counts = readCounts(own(doc, "counts"));
  if (typeof counts === "string") return none(counts);
  if (!macMatches(key, canonicalBaseline(runId, kid, counts), mac)) return none("the MAC does not match");
  const tools = /* @__PURE__ */ new Set();
  for (const k of counts.keys()) tools.add(k.split("\0")[2]);
  return { baseline: { tools: [...tools].sort(), counts } };
}
function verifyCleanRunArtifact(bytes, meta, ctx) {
  const no2 = (note, malformed) => ({ seen: false, malformed, note: `clean-run marker not trusted: ${note}` });
  if (!isPlain2(meta) || meta.name !== CLEAN_RUN_ARTIFACT) return no2(`the artifact is not named ${CLEAN_RUN_ARTIFACT}`, true);
  if (!posInt(meta.runId)) return no2("the artifact has no valid run id", true);
  const exp = expiryProblem(meta, ctx.now);
  if (exp !== void 0) return no2(exp, false);
  const key = keyNote(ctx.key) === void 0 ? ctx.key : void 0;
  const doc = parseDoc(bytes);
  if (typeof doc === "string") return no2(doc, true);
  if (Object.keys(doc).sort().join() !== "keyId,mac,runId") return no2("the file does not have exactly runId, keyId and MAC", true);
  const runId = own(doc, "runId");
  const kid = own(doc, "keyId");
  const mac = own(doc, "mac");
  if (!posInt(runId)) return no2("runId is not a positive whole number", true);
  if (typeof kid !== "string" || !KEY_ID_RE.test(kid)) return no2("keyId is not a key id", true);
  if (typeof mac !== "string" || !MAC_RE.test(mac)) return no2("the MAC is missing or not 64 lower-case hex characters", true);
  if (runId !== meta.runId) return no2(`the file is for run ${runId}, not the run of the artifact (${meta.runId})`, true);
  if (key === void 0) return { seen: true, malformed: false };
  if (kid !== keyId(key)) return no2("its key id is not the current PIPEGEN_FP_KEY's", false);
  if (!macMatches(key, canonicalMarker(runId, kid), mac)) return no2("the MAC does not match", false);
  return { seen: true, malformed: false };
}
function candidatesOf(listing, artifactName, runId) {
  if (!isPlain2(listing)) return [];
  const list = own(listing, "artifacts");
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const a of list) {
    if (!isPlain2(a) || own(a, "name") !== artifactName || !posInt(own(a, "id"))) continue;
    const wr = own(a, "workflow_run");
    if (!isPlain2(wr) || own(wr, "id") !== runId) continue;
    const created = own(a, "created_at");
    const createdMs = typeof created === "string" && /^\d{4}-\d{2}-\d{2}T/.test(created) ? Date.parse(created) : Number.NaN;
    if (Number.isNaN(createdMs)) continue;
    const exp = own(a, "expires_at");
    const size = own(a, "size_in_bytes");
    out.push({
      id: own(a, "id"),
      createdMs,
      expired: own(a, "expired") !== false,
      expiresAt: typeof exp === "string" ? exp : null,
      size: typeof size === "number" && Number.isSafeInteger(size) && size >= 0 ? size : Number.POSITIVE_INFINITY
    });
  }
  return out.sort((x, y) => y.createdMs - x.createdMs || y.id - x.id);
}
async function walk(gh, repo2, ctx, artifactName, use, notes, st, window) {
  const budget = { left: window === void 0 ? HISTORY_CHECK_CAP : window + HISTORY_FAIL_CAP };
  const lk = {};
  let historyFails = 0;
  let windowFull = false;
  let trustedSeen = 0;
  let expired = 0;
  let notSuccess = 0;
  let exhausted = true;
  for (let page2 = 1; page2 <= MAX_RUN_PAGES; page2++) {
    let listing;
    try {
      listing = await gh.listRuns(repo2.owner, repo2.name, { workflow: "pipegen.yml", branch: repo2.defaultBranch, event: "push", status: "success", page: page2, perPage: RUNS_PER_PAGE });
    } catch {
      notes.push("the list of workflow runs could not be read");
      st.incomplete = true;
      return void 0;
    }
    const runs = isPlain2(listing) && Array.isArray(own(listing, "workflow_runs")) ? own(listing, "workflow_runs") : void 0;
    if (runs === void 0) {
      notes.push("the list of workflow runs is not a list");
      st.incomplete = true;
      return void 0;
    }
    const ordered = runs.filter((r) => isPlain2(r) && posInt(own(r, "id"))).sort((x, y) => own(y, "id") - own(x, "id"));
    for (const r of ordered) {
      if (window !== void 0 && trustedSeen >= window) {
        windowFull = true;
        break;
      }
      if (own(r, "conclusion") !== "success") {
        notSuccess++;
        continue;
      }
      const j = await judgeRun(gh, r, repo2, budget, lk);
      if (!j.ok) {
        if (j.why === "untrusted") continue;
        if (j.why === "history") {
          historyFails++;
          if (window !== void 0 && trustedSeen === 0 && historyFails >= HISTORY_FAIL_CAP) {
            notes.push(`${historyFails} runs look valid but fail the default-history check (cap ${HISTORY_FAIL_CAP})`);
            st.incomplete = true;
            return void 0;
          }
          continue;
        }
        st.incomplete = true;
        notes.push(j.why === "tag" ? `a tag named ${repo2.defaultBranch} exists; no run is trusted until it is deleted` : j.why === "cap" ? `more than ${window === void 0 ? HISTORY_CHECK_CAP : window + HISTORY_FAIL_CAP} runs needed a default-history check (cap)` : "the default history of a run could not be checked");
        if (j.why === "tag" || j.why === "cap") return void 0;
        continue;
      }
      if (++trustedSeen > (window ?? MAX_TRUSTED_RUNS)) {
        notes.push("too many runs without a usable artifact");
        st.incomplete = true;
        return void 0;
      }
      const runId = own(r, "id");
      let found;
      try {
        found = candidatesOf(await gh.listRunArtifacts(repo2.owner, repo2.name, runId, artifactName), artifactName, runId);
      } catch {
        notes.push(`the artifacts of run ${runId} could not be read`);
        st.incomplete = true;
        continue;
      }
      const live = found.filter((c2) => {
        const gone = expiryProblem({ runId, name: artifactName, expired: c2.expired, expiresAt: c2.expiresAt }, ctx.now) !== void 0;
        if (gone) expired++;
        return !gone;
      });
      const c = live[0];
      if (c === void 0) continue;
      const meta = { runId, name: artifactName, expired: false, expiresAt: c.expiresAt };
      const problem = (note) => {
        notes.push(note);
        st.incomplete = true;
        return use({ problem: note }, meta, st);
      };
      if (c.size > MAX_ARTIFACT_BYTES) {
        const x2 = problem(`the ${artifactName} artifact of run ${runId} is over the size cap`);
        if (x2 !== void 0) return x2;
        continue;
      }
      let bytes;
      try {
        bytes = await gh.downloadArtifact(repo2.owner, repo2.name, c.id);
      } catch {
        const x2 = problem(`the ${artifactName} artifact of run ${runId} could not be downloaded (deleted?)`);
        if (x2 !== void 0) return x2;
        continue;
      }
      if (!(bytes instanceof Uint8Array)) {
        const x2 = problem(`the ${artifactName} artifact of run ${runId} is not bytes`);
        if (x2 !== void 0) return x2;
        continue;
      }
      const x = use({ bytes }, meta, st);
      if (x !== void 0) return x;
    }
    if (window !== void 0 && trustedSeen >= window) windowFull = true;
    if (windowFull || runs.length < RUNS_PER_PAGE) {
      exhausted = false;
      break;
    }
  }
  if (window !== void 0 && trustedSeen === 0 && historyFails > 0) {
    notes.push(`${historyFails} run${historyFails === 1 ? "" : "s"} look valid but fail the default-history check, and none passes`);
    st.incomplete = true;
  }
  if (exhausted) {
    notes.push(`the run list was cut after ${MAX_RUN_PAGES} pages`);
    st.incomplete = true;
  }
  if (expired > 0 && notes.length === 0) notes.push(`the ${artifactName} artifact has expired`);
  if (notSuccess > 0) notes.push(`${notSuccess} run${notSuccess === 1 ? "" : "s"} did not have conclusion success (a red main does not refresh the baseline)`);
  return void 0;
}
async function loadBaseline(gh, repo2, ctx) {
  const kn = keyNote(ctx.key);
  if (kn !== void 0) return { baseline: null, note: `no trusted baseline: ${kn}; the base scan decides` };
  const notes = [];
  const st = { incomplete: false };
  const result = await walk(gh, repo2, ctx, BASELINE_ARTIFACT, (input, meta) => "problem" in input ? { baseline: null, note: `no trusted baseline: ${input.problem}` } : verifyBaselineArtifact(input.bytes, meta, ctx), notes, st);
  if (result !== void 0) return result;
  return { baseline: null, note: `no trusted baseline: ${notes.join("; ") || `no ${BASELINE_ARTIFACT} artifact from a trusted run`}; the base scan decides` };
}
async function cleanRunSeen(gh, repo2, ctx) {
  const notes = [];
  const st = { incomplete: false };
  const result = await walk(gh, repo2, ctx, CLEAN_RUN_ARTIFACT, (input, meta, s) => {
    if ("problem" in input) return void 0;
    const r = verifyCleanRunArtifact(input.bytes, meta, ctx);
    if (r.seen) return { state: "seen", seen: true };
    if (r.malformed) s.incomplete = true;
    if (r.note !== void 0) notes.push(r.note);
    return void 0;
  }, notes, st, MARKER_WINDOW);
  if (result !== void 0) return result;
  const why2 = notes.join("; ");
  return st.incomplete ? { state: "unknown", seen: false, note: `clean-run marker could not be checked: ${why2 || "unknown"}` } : { state: "none", seen: false, note: `no clean-run marker from a trusted run${why2 === "" ? "" : `: ${why2}`}` };
}
function requireKey(key) {
  const problem = key === void 0 ? "PIPEGEN_FP_KEY is missing" : keyProblem(key, false, true);
  if (problem !== void 0 || key === void 0) throw new Error(`can not sign: ${problem ?? "PIPEGEN_FP_KEY is missing"}`);
  return key;
}
function requireRunId(runId) {
  if (!posInt(runId)) throw new Error("can not sign: the run id is not a positive whole number");
  return runId;
}
var KEYED_FORMS = ["region", "quoted", "file", "line"];
function buildBaseline(input) {
  const key = requireKey(input.key);
  const runId = requireRunId(input.runId);
  const kid = keyId(key);
  const sameRun = new Set(input.sameRunTools);
  const counts = /* @__PURE__ */ new Map();
  const skipped = [];
  for (const c of input.checks) {
    const skip = (reason) => {
      skipped.push({ job: c.job, reason });
    };
    if (c.status !== "ok") {
      skip("tool error: never stored");
      continue;
    }
    if (c.noCoverage === true) {
      skip("no coverage: not proven clean, so not stored");
      continue;
    }
    if (sameRun.has(c.tool)) {
      skip("compared with the same-run base scan, never with a stored baseline");
      continue;
    }
    if (c.findings.some((f) => f.secret || KEYED_FORMS.includes(f.fpBy)) && c.keyId !== kid) {
      skip("its secret fingerprints are not under the current key id");
      continue;
    }
    for (const f of c.findings) {
      const k = countKeyOf(c.job, f);
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
  }
  if (counts.size > MAX_COUNT_ENTRIES) throw new Error(`can not write the baseline: too many distinct findings (${counts.size}; the reader takes at most ${MAX_COUNT_ENTRIES})`);
  for (const k of counts.keys()) {
    if (k.length > MAX_COUNT_KEY) throw new Error(`can not write the baseline: a count key is longer than ${MAX_COUNT_KEY} characters (the reader would refuse the file)`);
  }
  const sorted = [...counts].sort(([a], [b]) => code2(a, b));
  const mac = sign(key, canonicalBaseline(runId, kid, counts));
  const bytes = new TextEncoder().encode(JSON.stringify({ runId, keyId: kid, counts: Object.fromEntries(sorted), mac }));
  if (bytes.length > MAX_ARTIFACT_BYTES) throw new Error(`can not write the baseline: it is over the size cap (${bytes.length} bytes; the reader takes at most ${MAX_ARTIFACT_BYTES})`);
  return { bytes, counts: new Map(sorted), skipped };
}
async function saveBaseline(input, uploader) {
  const built = buildBaseline(input);
  await uploader.upload(BASELINE_ARTIFACT, built.bytes, { retentionDays: BASELINE_RETENTION_DAYS });
  return built;
}
function buildCleanRunMarker(runId, key) {
  const k = requireKey(key);
  const id = requireRunId(runId);
  const kid = keyId(k);
  return new TextEncoder().encode(JSON.stringify({ runId: id, keyId: kid, mac: sign(k, canonicalMarker(id, kid)) }));
}

// gate/src/artifacts.ts
import { createHash as createHash5 } from "node:crypto";
import { crc32, inflateRawSync } from "node:zlib";

// gate/src/scrub.ts
import { createHash as createHash4, randomBytes } from "node:crypto";
import { closeSync as closeSync4, constants as constants4, fstatSync as fstatSync4, linkSync, lstatSync as lstatSync4, mkdirSync as mkdirSync2, openSync as openSync4, readSync as readSync4, unlinkSync, writeSync as writeSync2 } from "node:fs";
import { basename, dirname as dirname2, isAbsolute as isAbsolute2, join as join3, sep as sep2 } from "node:path";

// gate/src/stage.ts
import { createHash as createHash3 } from "node:crypto";
import { chmodSync, closeSync as closeSync2, constants as constants2, fstatSync as fstatSync2, lstatSync as lstatSync2, mkdirSync, openSync as openSync2, readdirSync, readSync as readSync2, rmSync, writeSync } from "node:fs";
import { dirname, isAbsolute, join as join2 } from "node:path";

// src/ai/scan-staging.ts
var SCAN_PREFIX = "\n";
var PREFIX_LINES = 1;
var LATE_MAGIC = Object.freeze([[257, "ustar"], [128, "DICM"], [32769, "CD001"], [34817, "CD001"], [36865, "CD001"]]);
function scannersWouldSkip(written) {
  const buf = typeof written === "string" ? Buffer.from(written, "utf8") : Buffer.from(written.buffer, written.byteOffset, written.byteLength);
  return LATE_MAGIC.some(([at3, magic]) => buf.subarray(at3, at3 + magic.length).toString("latin1") === magic);
}
var CANARY_RULE = "pipegen-canary";
var CANARY_HEX = 32;
var CANARY_LENGTH = CANARY_RULE.length + 1 + CANARY_HEX;
var CANARY_RE = /^pipegen-canary-[0-9a-f]{32}$/;
function newCanary() {
  const bytes = new Uint8Array(CANARY_HEX / 2);
  globalThis.crypto.getRandomValues(bytes);
  return `${CANARY_RULE}-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}
var isCanary = (text) => CANARY_RE.test(text);
var CANARY_RULE_TOML = `[[rules]]
id = "${CANARY_RULE}"
description = "pipegen scan marker (proves the file was read)"
regex = '''(?m)^pipegen-canary-[0-9a-f]{32}$'''
keywords = ["pipegen-canary-"]
`;
function asScannedBytes(content, canary) {
  const needsNewline = content.length > 0 && content[content.length - 1] !== 10;
  return Buffer.concat([Buffer.from(SCAN_PREFIX), content, Buffer.from(`${needsNewline ? "\n" : ""}
${canary}
`)]);
}
function writtenCanaryLine(written) {
  let n = 0;
  for (const c of written) if (c === 10) n++;
  return n;
}
var SCAN_CHUNK_SAFE_BYTES = 9e4;
var SCAN_OVERHEAD_BYTES = SCAN_PREFIX.length + 1 + 1 + CANARY_LENGTH + 1;
var PIECE_BYTES = SCAN_CHUNK_SAFE_BYTES - SCAN_OVERHEAD_BYTES;
var PIECE_OVERLAP_BYTES = 16 * 1024;
function planPieces(content, opts = {}) {
  const size = content.length;
  const P = opts.pieceBytes ?? PIECE_BYTES;
  const O = opts.overlap ?? PIECE_OVERLAP_BYTES;
  if (!Number.isInteger(P) || !Number.isInteger(O) || O < 1 || P <= 2 * O) throw new Error("planPieces: the piece size must be more than twice the overlap");
  if (size <= P) return [{ offset: 0, length: size, line: 1, column: 0 }];
  const buf = Buffer.from(content.buffer, content.byteOffset, content.byteLength);
  const pieces = [];
  let start = 0;
  let line = 1;
  let lineStart2 = 0;
  for (; ; ) {
    let end = Math.min(start + P, size);
    if (end < size) {
      const nl2 = buf.lastIndexOf(10, end - 1);
      if (nl2 >= start + O) end = nl2 + 1;
    }
    pieces.push({ offset: start, length: end - start, line, column: start - lineStart2 });
    if (end >= size) return pieces;
    const limit = end - O;
    const nl = buf.lastIndexOf(10, limit - 1);
    const next = nl >= start ? nl + 1 : limit;
    for (let i = buf.indexOf(10, start); i >= 0 && i < next; i = buf.indexOf(10, i + 1)) {
      line++;
      lineStart2 = i + 1;
    }
    start = next;
  }
}
function originalLine(piece, writtenLine, contentLines) {
  const inPiece = Math.min(Math.max(writtenLine - PREFIX_LINES, 1), Math.max(contentLines, 1));
  return piece.line + inPiece - 1;
}

// gate/src/generated/secrets-path-rules.ts
var PATH_RULES = [
  {
    "tool": "betterleaks",
    "rule": "freemius-secret-key",
    "pattern": "(?i)\\.php$",
    "suffixes": [
      ".php"
    ]
  },
  {
    "tool": "betterleaks",
    "rule": "hashicorp-tf-password",
    "pattern": "(?i)\\.(?:tf|hcl)$",
    "suffixes": [
      ".tf",
      ".hcl"
    ]
  },
  {
    "tool": "betterleaks",
    "rule": "kubernetes-secret-yaml",
    "pattern": "(?i)\\.ya?ml$",
    "suffixes": [
      ".yaml",
      ".yml"
    ]
  },
  {
    "tool": "betterleaks",
    "rule": "nuget-config-password",
    "pattern": "(?i)nuget\\.config$",
    "suffixes": [
      ".nuget.config"
    ]
  },
  {
    "tool": "betterleaks",
    "rule": "pkcs12-file",
    "pattern": "(?i)(?:^|\\/)[^\\/]+\\.p(?:12|fx)$",
    "suffixes": [
      ".p12",
      ".pfx"
    ]
  },
  {
    "tool": "gitleaks",
    "rule": "freemius-secret-key",
    "pattern": "(?i)\\.php$",
    "suffixes": [
      ".php"
    ]
  },
  {
    "tool": "gitleaks",
    "rule": "hashicorp-tf-password",
    "pattern": "(?i)\\.(?:tf|hcl)$",
    "suffixes": [
      ".tf",
      ".hcl"
    ]
  },
  {
    "tool": "gitleaks",
    "rule": "kubernetes-secret-yaml",
    "pattern": "(?i)\\.ya?ml$",
    "suffixes": [
      ".yaml",
      ".yml"
    ]
  },
  {
    "tool": "gitleaks",
    "rule": "nuget-config-password",
    "pattern": "(?i)nuget\\.config$",
    "suffixes": [
      ".nuget.config"
    ]
  },
  {
    "tool": "gitleaks",
    "rule": "pkcs12-file",
    "pattern": "(?i)(?:^|\\/)[^\\/]+\\.p(?:12|fx)$",
    "suffixes": [
      ".p12",
      ".pfx"
    ]
  }
];

// gate/src/stage.ts
var MAX_STAGE_FILES = 2e5;
var MAX_STAGE_BYTES = 1024 * 1024 * 1024;
var MAX_STAGED_BYTES = 2.5 * 1024 * 1024 * 1024;
var MAX_MANIFEST_BYTES = 256 * 1024 * 1024;
var MAX_NAMES = 99999999;
var STAGE_FILES_DIR = "files";
var STAGE_MANIFEST = "manifest.json";
var MANIFEST_VERSION = 1;
var StageError = class extends Error {
};
var RULES = PATH_RULES.map((r) => ({ ...r, re: new RegExp(r.pattern.replace(/^\(\?i\)/, ""), r.pattern.startsWith("(?i)") ? "iu" : "u") }));
var STAGE_SUFFIXES = Object.freeze([".txt", ...new Set(PATH_RULES.flatMap((r) => r.suffixes))]);
var escape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
var STAGED_NAME_RE = new RegExp(`^f\\d{8}(?:${STAGE_SUFFIXES.map(escape).join("|")})$`);
function suffixFor(path) {
  const text = typeof path === "string" ? path : Buffer.from(path).toString("utf8");
  const lower = text.toLowerCase();
  const hits = /* @__PURE__ */ new Set();
  for (const r of RULES) {
    if (!r.re.test(text)) continue;
    hits.add(r.suffixes.find((s) => lower.endsWith(s)) ?? r.suffixes[0]);
  }
  if (hits.size > 1) throw new StageError("two path rules of the pinned scanners target one file with different suffixes, which the stage step can not give it");
  return [...hits][0] ?? ".txt";
}
var SLASH = Buffer.from("/");
var GIT = Buffer.from(".git");
function walk2(ws, maxFiles, maxBytes) {
  const files = [];
  let links = 0;
  let other = 0;
  let bytes = 0;
  const visit = (abs, rel) => {
    let names;
    try {
      names = readdirSync(abs, { encoding: "buffer" });
    } catch {
      throw new StageError("a folder of the checkout can not be read, so the secrets scan would not cover it: nothing was staged");
    }
    names.sort(Buffer.compare);
    for (const name of names) {
      if (rel.length === 0 && name.equals(GIT)) continue;
      const a = Buffer.concat([abs, SLASH, name]);
      const r = rel.length === 0 ? name : Buffer.concat([rel, SLASH, name]);
      const st = lstatSync2(a);
      if (st.isSymbolicLink()) links++;
      else if (st.isDirectory()) visit(a, r);
      else if (st.isFile()) {
        files.push({ abs: a, rel: r, size: st.size, dev: st.dev, ino: st.ino });
        bytes += st.size;
        if (files.length > maxFiles) throw new StageError(`the checkout has more than ${maxFiles} files, so pipegen does not stage it and the secrets scan does not run: it is not scanned (fail closed)`);
        if (bytes > maxBytes) throw new StageError(`the checkout has more than ${maxBytes} bytes of files, so pipegen does not stage it and the secrets scan does not run: it is not scanned (fail closed)`);
      } else other++;
    }
  };
  visit(ws, Buffer.alloc(0));
  return { files, links, other };
}
function readFound(f) {
  let fd;
  try {
    fd = openSync2(f.abs, constants2.O_RDONLY | constants2.O_NOFOLLOW | constants2.O_NONBLOCK | constants2.O_NOCTTY);
    const st = fstatSync2(fd);
    if (!st.isFile() || st.dev !== f.dev || st.ino !== f.ino || st.size !== f.size) throw new StageError("a file of the checkout changed while it was staged: nothing was staged");
    const buf = Buffer.alloc(st.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync2(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    if (got !== buf.length) throw new StageError("a file of the checkout changed while it was staged: nothing was staged");
    return buf;
  } catch (e) {
    if (e instanceof StageError) throw e;
    throw new StageError("a file of the checkout can not be read, so the secrets scan would not cover it: nothing was staged");
  } finally {
    if (fd !== void 0) try {
      closeSync2(fd);
    } catch {
    }
  }
}
function writeNew(path, bytes, mode) {
  const fd = openSync2(path, constants2.O_WRONLY | constants2.O_CREAT | constants2.O_EXCL | constants2.O_NOFOLLOW, mode);
  try {
    let at3 = 0;
    while (at3 < bytes.length) at3 += writeSync(fd, bytes, at3, bytes.length - at3);
  } finally {
    closeSync2(fd);
  }
}
var sha256 = (b) => createHash3("sha256").update(b).digest("hex");
var linesOf = (b) => {
  let n = 0;
  for (const c of b) if (c === 10) n++;
  return Math.max(1, n + (b.length > 0 && b[b.length - 1] !== 10 ? 1 : 0));
};
function ensureFolder(path, what) {
  let st;
  try {
    st = lstatSync2(path);
  } catch {
    try {
      mkdirSync(path, { mode: 493 });
    } catch {
      throw new StageError(`${what} can not be created`);
    }
    st = lstatSync2(path);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new StageError(`${what} is not a real folder (a link or a file), so pipegen will not stage there`);
}
function stageWorkspace(o) {
  let made = false;
  try {
    if (!isAbsolute(o.workspace) || !isAbsolute(o.stage)) throw new StageError("the workspace and the stage folder must be absolute paths");
    const wsStat = lstatSync2(o.workspace, { throwIfNoEntry: false });
    if (wsStat === void 0 || wsStat.isSymbolicLink() || !wsStat.isDirectory()) throw new StageError("the workspace is not a real folder (missing, a link or a file)");
    const found = walk2(Buffer.from(o.workspace), o.maxFiles ?? MAX_STAGE_FILES, o.maxBytes ?? MAX_STAGE_BYTES);
    ensureFolder(dirname(o.stage), "the folder of the stage folders");
    try {
      mkdirSync(o.stage, { mode: 448 });
    } catch {
      throw new StageError("the stage folder exists already or can not be created, so pipegen will not stage over it");
    }
    made = true;
    const filesDir = join2(o.stage, STAGE_FILES_DIR);
    mkdirSync(filesDir, { mode: 448 });
    const entries = [];
    let bytes = 0;
    let written = 0;
    const maxStaged = o.maxStagedBytes ?? MAX_STAGED_BYTES;
    for (const f of found.files) {
      const content = readFound(f);
      bytes += content.length;
      const suffix = suffixFor(f.rel);
      const hash = sha256(content);
      const pieces = planPieces(content, { ...o.pieceBytes === void 0 ? {} : { pieceBytes: o.pieceBytes }, ...o.overlap === void 0 ? {} : { overlap: o.overlap } });
      const parts = [...pieces.length > 1 ? [{ p: { offset: 0, length: content.length, line: 1, column: 0 }, k: 0 }] : [], ...pieces.map((p, i) => ({ p, k: i + 1 }))];
      for (const { p, k } of parts) {
        if (entries.length >= MAX_NAMES) throw new StageError("too many staged files for eight-digit names");
        const name = `f${String(entries.length + 1).padStart(8, "0")}${suffix}`;
        const canary = newCanary();
        const part = content.subarray(p.offset, p.offset + p.length);
        const out = asScannedBytes(part, canary);
        written += out.length;
        if (written > maxStaged) throw new StageError(`the stage folder would hold more than ${maxStaged} bytes (large files are staged whole and as pieces), so pipegen stops and the secrets scan does not run: it is not scanned (fail closed)`);
        writeNew(join2(filesDir, name), out, 292);
        entries.push({
          name,
          path: f.rel.toString("base64"),
          size: content.length,
          sha256: hash,
          offset: p.offset,
          length: p.length,
          line: p.line,
          column: p.column,
          lines: linesOf(part),
          canaryLine: writtenCanaryLine(out),
          canary,
          stagedSize: out.length,
          stagedSha256: sha256(out),
          piece: k,
          pieces: pieces.length,
          ...scannersWouldSkip(out) ? { lateMagic: true } : {}
        });
      }
    }
    const manifest = {
      pipegenStage: MANIFEST_VERSION,
      prefixBytes: Buffer.byteLength(SCAN_PREFIX),
      canaryRule: CANARY_RULE,
      pieceBytes: o.pieceBytes ?? PIECE_BYTES,
      overlap: o.overlap ?? PIECE_OVERLAP_BYTES,
      skipped: { links: found.links, other: found.other },
      files: entries
    };
    writeNew(join2(o.stage, STAGE_MANIFEST), Buffer.from(JSON.stringify(manifest)), 292);
    chmodSync(filesDir, 365);
    chmodSync(o.stage, 365);
    return { status: "ok", files: found.files.length, staged: entries.length, bytes, skippedLinks: found.links, skippedOther: found.other };
  } catch (e) {
    if (made) try {
      chmodTree(o.stage);
      rmSync(o.stage, { recursive: true, force: true });
    } catch {
    }
    return { status: "error", error: e instanceof StageError ? e.message : "the checkout could not be staged for the secrets scan, so it is not scanned" };
  }
}
function chmodTree(dir) {
  const st = lstatSync2(dir, { throwIfNoEntry: false });
  if (st === void 0 || st.isSymbolicLink() || !st.isDirectory()) return;
  chmodSync(dir, 448);
  for (const n of readdirSync(dir)) chmodTree(join2(dir, n));
}
function listingMatches(listed, names) {
  if (listed.length !== names.length) return false;
  const a = [...listed].sort();
  const b = [...names].sort();
  return a.every((n, i) => n === b[i]);
}
function readPlain(path, max, what) {
  const st = lstatSync2(path, { throwIfNoEntry: false });
  if (st === void 0) throw new StageError(`${what} is missing (the stage step did not finish)`);
  if (st.isSymbolicLink() || !st.isFile()) throw new StageError(`${what} is not a regular file`);
  if (st.size > max) throw new StageError(`${what} is over its size cap`);
  let fd;
  try {
    fd = openSync2(path, constants2.O_RDONLY | constants2.O_NOFOLLOW | constants2.O_NONBLOCK | constants2.O_NOCTTY);
    const o = fstatSync2(fd);
    if (!o.isFile() || o.dev !== st.dev || o.ino !== st.ino) throw new StageError(`${what} changed while it was read`);
    const buf = Buffer.alloc(o.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync2(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    return buf.subarray(0, got);
  } catch (e) {
    if (e instanceof StageError) throw e;
    throw new StageError(`${what} can not be read`);
  } finally {
    if (fd !== void 0) try {
      closeSync2(fd);
    } catch {
    }
  }
}
var isInt = (v, min = 0) => typeof v === "number" && Number.isSafeInteger(v) && v >= min;
var HEX64 = /^[0-9a-f]{64}$/;
var B64 = /^[A-Za-z0-9+/]+={0,2}$/;
function readStage(stage) {
  if (!isAbsolute(stage)) throw new StageError("the stage folder is not an absolute path");
  for (const [p, what] of [[stage, "the stage folder"], [join2(stage, STAGE_FILES_DIR), "the staged files folder"]]) {
    const st = lstatSync2(p, { throwIfNoEntry: false });
    if (st === void 0 || st.isSymbolicLink() || !st.isDirectory()) throw new StageError(`${what} is missing or not a real folder`);
  }
  let doc;
  try {
    doc = JSON.parse(readPlain(join2(stage, STAGE_MANIFEST), MAX_MANIFEST_BYTES, "the stage manifest").toString("utf8"));
  } catch (e) {
    if (e instanceof StageError) throw e;
    throw new StageError("the stage manifest is not JSON");
  }
  const bad = (m) => {
    throw new StageError(`the stage manifest ${m}`);
  };
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return bad("is not an object");
  const d = doc;
  if (d.pipegenStage !== MANIFEST_VERSION || d.prefixBytes !== Buffer.byteLength(SCAN_PREFIX) || d.canaryRule !== CANARY_RULE) bad("is not one this gate writes");
  if (!Array.isArray(d.files)) return bad("has no file list");
  const entries = d.files.map((x, i) => {
    if (typeof x !== "object" || x === null || Array.isArray(x)) return bad(`entry ${i + 1} is not an object`);
    const e = x;
    const name = e.name;
    if (typeof name !== "string" || !STAGED_NAME_RE.test(name) || name.slice(0, 9) !== `f${String(i + 1).padStart(8, "0")}`) bad(`entry ${i + 1} has a name out of order or form`);
    if (typeof e.path !== "string" || e.path === "" || !B64.test(e.path) || Buffer.from(e.path, "base64").toString("base64") !== e.path) bad(`entry ${i + 1} has a path that is not base64`);
    for (const k of ["size", "offset", "length", "column", "stagedSize"]) if (!isInt(e[k])) bad(`entry ${i + 1} has a ${k} that is not a whole number`);
    for (const k of ["line", "lines", "canaryLine", "pieces"]) if (!isInt(e[k], 1)) bad(`entry ${i + 1} has a ${k} that is not a positive whole number`);
    if (!isInt(e.piece)) bad(`entry ${i + 1} has a piece that is not a whole number`);
    if (e.piece === 0 && (e.offset !== 0 || e.length !== e.size || e.line !== 1 || e.column !== 0 || e.pieces < 2)) bad(`entry ${i + 1} is a whole copy that is not its whole file`);
    if (typeof e.sha256 !== "string" || !HEX64.test(e.sha256) || typeof e.stagedSha256 !== "string" || !HEX64.test(e.stagedSha256)) bad(`entry ${i + 1} has a hash that is not sha256`);
    if (typeof e.canary !== "string" || !isCanary(e.canary)) bad(`entry ${i + 1} has a canary that is not a canary`);
    if (e.offset + e.length > e.size || e.piece > e.pieces) bad(`entry ${i + 1} has a piece outside its file`);
    if (e.lateMagic !== void 0 && e.lateMagic !== true) bad(`entry ${i + 1} has an odd lateMagic`);
    return e;
  });
  const filesDir = join2(stage, STAGE_FILES_DIR);
  const listed = readdirSync(filesDir, { encoding: "buffer" }).map((b) => b.toString("latin1"));
  if (!listingMatches(listed, entries.map((e) => e.name))) throw new StageError("the staged files folder does not hold exactly the files of the manifest");
  for (const e of entries) {
    const b = readPlain(join2(filesDir, e.name), e.stagedSize, `the staged file ${e.name}`);
    if (b.length !== e.stagedSize || sha256(b) !== e.stagedSha256) throw new StageError(`the staged file ${e.name} is not the one the stage step wrote`);
  }
  return { dir: stage, files: filesDir, prefixBytes: d.prefixBytes, entries, byName: new Map(entries.map((e) => [e.name, e])) };
}
var NOT_SCANNED_RULE = "secret:not-scanned";
var shiftUnreliable = (tool2, e) => tool2 === "gitleaks" && e.stagedSize > SCAN_CHUNK_SAFE_BYTES;
var CANARY_RULE_ID = `secret:${CANARY_RULE}`;
function pathFields(e) {
  const raw = Buffer.from(e.path, "base64");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    text = void 0;
  }
  if (text !== void 0 && normaliseUri(text, { encoding: "raw" }) === text) return { file: text, uriUnmapped: false, uriId: void 0 };
  return { file: void 0, uriUnmapped: true, uriId: createHash3("sha256").update(Buffer.concat([Buffer.from("pipegen-path-bytes\0"), raw])).digest("hex").slice(0, 32), displayPath: displayPathOf(raw) };
}
function displayPathOf(raw) {
  const b = Buffer.from(raw);
  let out = "";
  let i = 0;
  while (i < b.length) {
    const c = b[i];
    const len = c < 128 ? 1 : c >= 194 && c <= 223 ? 2 : c >= 224 && c <= 239 ? 3 : c >= 240 && c <= 244 ? 4 : 0;
    let ch;
    if (len > 0 && i + len <= b.length) {
      try {
        ch = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(i, i + len));
      } catch {
        ch = void 0;
      }
    }
    if (ch === void 0) {
      out += `\\x${c.toString(16).padStart(2, "0")}`;
      i++;
      continue;
    }
    const cp = ch.codePointAt(0);
    if (cp < 32 || cp >= 127 && cp <= 159) out += `\\x${cp.toString(16).padStart(2, "0")}`;
    else if (cp === 65533) out += "\\u{fffd}";
    else if (ch === "\\") out += "\\\\";
    else out += ch;
    i += len;
  }
  return safeText(out, PATH_SHOWN_MAX);
}
function applyStage(parsed, stage, tool2) {
  const cache = new RegionCache();
  const proofs = /* @__PURE__ */ new Map();
  const real = [];
  for (const f of parsed) {
    const e = f.file === void 0 ? void 0 : stage.byName.get(f.file);
    if (e === void 0) throw new StageError("a finding names a file the stage step did not write, so it can not be mapped back to the checkout");
    if (f.ruleId === CANARY_RULE_ID && f.line === e.canaryLine && (f.endLine ?? f.line) === e.canaryLine) {
      const span = regionSpan(stage.files, f, cache);
      const unshifted = shiftUnreliable(tool2, e) && f.startColumn !== void 0 && f.endColumn !== void 0 ? regionSpan(stage.files, { ...f, startColumn: f.startColumn + 1, endColumn: f.endColumn + 1 }, cache) : void 0;
      if (span.ok && span.bytes.toString("latin1") === e.canary || unshifted?.ok === true && unshifted.bytes.toString("latin1") === e.canary) {
        proofs.set(e.name, (proofs.get(e.name) ?? 0) + 1);
        continue;
      }
    }
    real.push({ f, e });
  }
  real.sort((a, b) => (a.e.piece === 0 ? 1 : 0) - (b.e.piece === 0 ? 1 : 0));
  const pieceKeys = /* @__PURE__ */ new Set();
  const regions = /* @__PURE__ */ new Map();
  const hashes = /* @__PURE__ */ new Map();
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const { f, e } of real) {
    const span = regionSpan(stage.files, f, cache);
    const piece = { offset: e.offset, length: e.length, line: e.line, column: e.column };
    const line = f.line === void 0 ? void 0 : originalLine(piece, f.line, e.lines);
    const endLine = f.line === void 0 ? void 0 : originalLine(piece, f.endLine ?? f.line, e.lines);
    const at3 = (n) => e.offset + Math.min(Math.max(n - stage.prefixBytes, 0), e.length);
    const whole = f.line === void 0;
    const key = whole ? `${f.ruleId}\0${e.path}\0whole` : span.ok ? `${f.ruleId}\0${e.path}\0${at3(span.from)}\0${at3(span.to)}` : `${f.ruleId}\0${e.path}\0${e.name}\0${f.line}\0${f.startColumn}\0${f.endLine}\0${f.endColumn}`;
    const alt = !whole && shiftUnreliable(tool2, e) && f.startColumn !== void 0 && f.endColumn !== void 0 ? regionSpan(stage.files, { ...f, startColumn: f.startColumn + 1, endColumn: f.endColumn + 1 }, cache) : void 0;
    const altKey = alt?.ok === true ? `${f.ruleId}\0${e.path}\0${at3(alt.from)}\0${at3(alt.to)}` : void 0;
    if (seen.has(key) || altKey !== void 0 && pieceKeys.has(altKey)) continue;
    seen.add(key);
    if (e.piece !== 0 && !whole) pieceKeys.add(key);
    const { startColumn: _s, endColumn: _e, ...rest } = f;
    const mapped = { ...rest, ...pathFields(e), ...line === void 0 ? {} : { line }, ...endLine === void 0 ? {} : { endLine } };
    if (mapped.uriId === void 0) delete mapped.uriId;
    if (whole) hashes.set(mapped, e.sha256);
    else if (shiftUnreliable(tool2, e)) regions.set(mapped, { ok: false, reason: "gitleaks columns are not reliable in the whole copy of a large file (its +1 is dropped on the first line of each chunk)" });
    else regions.set(mapped, span.ok ? { ok: true, bytes: span.bytes } : { ok: false, reason: span.reason });
    out.push(mapped);
  }
  const unscanned = stage.entries.filter((e) => proofs.get(e.name) !== 1);
  for (const e of unscanned) {
    const f = {
      tool: tool2,
      ruleId: NOT_SCANNED_RULE,
      severity: "critical",
      secret: true,
      message: `not scanned: the secrets scanner did not report this file's canary exactly once, so it may not have read it${e.lateMagic === true ? " (it has a binary-format marker at a byte the scanners sniff)" : ""}`,
      ...pathFields(e),
      line: e.line,
      endLine: e.line + e.lines - 1
    };
    if (f.uriId === void 0) delete f.uriId;
    hashes.set(f, e.sha256);
    out.push(f);
  }
  const notes = [`staged ${new Set(stage.entries.map((e) => e.path)).size} file(s) under neutral names as ${stage.entries.length} scanned piece(s)`];
  if (unscanned.length > 0) notes.push(`${unscanned.length} staged piece(s) not scanned (no canary reported): each is a critical not-scanned finding`);
  return { findings: out, regionOf: (f) => regions.get(f), fileHashOf: (f) => hashes.get(f), notes };
}

// gate/src/range.ts
import { closeSync as closeSync3, constants as constants3, fstatSync as fstatSync3, lstatSync as lstatSync3, openSync as openSync3, readSync as readSync3 } from "node:fs";
var RangeFactsError = class extends Error {
};
var SKIP_REASONS = ["no-range", "no-merge-base"];
var isRangeSkipped = (r) => Object.hasOwn(r, "skipped");
var SHA_RE3 = /^[0-9a-f]{40}$/;
var ZERO = "0".repeat(40);
var MAX_FACTS_BYTES = 64 * 1024;
var MAX_COMMITS = 1e7;
var KEYS = ["base", "before", "canaries", "commits", "forced", "head", "pipegenRange"];
var CANARY_RULE_ID2 = `secret:${CANARY_RULE}`;
var isObj2 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function parseRangeFacts(text) {
  const bad = (why2) => {
    throw new RangeFactsError(`the commit-range facts ${why2}`);
  };
  if (typeof text !== "string" || text.length > MAX_FACTS_BYTES) bad("are over the size cap");
  let d;
  try {
    d = JSON.parse(text);
  } catch {
    return bad("are not JSON");
  }
  if (!isObj2(d)) return bad("are not in the form the range scan step writes");
  if (d.pipegenRange !== 1) bad("are of a version this gate does not read");
  if (Object.keys(d).sort().join() === "pipegenRange,skipped") {
    if (!SKIP_REASONS.includes(d.skipped)) bad("say the scan was skipped for a reason this gate does not know");
    return { skipped: d.skipped };
  }
  if (Object.keys(d).sort().join() !== KEYS.join()) return bad("are not in the form the range scan step writes");
  for (const k of ["base", "head"]) if (typeof d[k] !== "string" || !SHA_RE3.test(d[k]) || d[k] === ZERO) bad(`have a ${k} that is not a commit sha`);
  if (d.before !== null && (typeof d.before !== "string" || !SHA_RE3.test(d.before) || d.before === ZERO)) bad("have a before that is not a commit sha");
  if (typeof d.forced !== "boolean") bad("do not say whether the push rewrote the branch");
  if (typeof d.commits !== "number" || !Number.isSafeInteger(d.commits) || d.commits < 0 || d.commits > MAX_COMMITS) bad("have a commit count that is not a whole number");
  const list = d.canaries;
  if (!Array.isArray(list) || list.length !== RANGE_CANARY_FILES.length) return bad(`do not name ${RANGE_CANARY_FILES.length} canary commits`);
  const canaries = list.map((c, i) => {
    if (!isObj2(c) || Object.keys(c).sort().join() !== "commit,path") return bad("have a canary that is not { commit, path }");
    if (typeof c.commit !== "string" || !SHA_RE3.test(c.commit)) return bad("have a canary commit that is not a commit sha");
    const path = RANGE_CANARY_FILES[i];
    if (c.path !== path) return bad("have a canary file that is not the one the step writes");
    return { commit: c.commit, path };
  });
  if (new Set(canaries.map((c) => c.commit)).size !== canaries.length) bad("name one canary commit twice");
  return { base: d.base, head: d.head, before: d.before, forced: d.forced, commits: d.commits, canaries };
}
function readRangeFacts(path) {
  let st;
  try {
    st = lstatSync3(path);
  } catch {
    throw new RangeFactsError("the commit-range facts (range.json beside the raw result) are missing: the range scan step did not finish");
  }
  if (st.isSymbolicLink() || !st.isFile()) throw new RangeFactsError("the commit-range facts are a link or not a regular file");
  let fd;
  try {
    fd = openSync3(path, constants3.O_RDONLY | constants3.O_NOFOLLOW | constants3.O_NONBLOCK | constants3.O_NOCTTY);
    const opened = fstatSync3(fd);
    if (!opened.isFile() || opened.dev !== st.dev || opened.ino !== st.ino || opened.size > MAX_FACTS_BYTES) throw new RangeFactsError("the commit-range facts changed while they were opened, or are over the size cap");
    const buf = Buffer.alloc(opened.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync3(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    return parseRangeFacts(buf.subarray(0, got).toString("utf8"));
  } catch (e) {
    if (e instanceof RangeFactsError) throw e;
    throw new RangeFactsError("the commit-range facts could not be read");
  } finally {
    if (fd !== void 0) try {
      closeSync3(fd);
    } catch {
    }
  }
}
function applyRange(findings, facts) {
  const seen = facts.canaries.map(() => 0);
  const kept = [];
  for (const f of findings) {
    if (f.commit === void 0 || !SHA_RE3.test(f.commit)) throw new RangeFactsError("a finding of the commit range has no commit");
    const i = facts.canaries.findIndex((c) => f.ruleId === CANARY_RULE_ID2 && f.commit === c.commit && f.file === c.path && f.line === 1 && (f.endLine ?? 1) === 1);
    if (i >= 0) {
      seen[i] = (seen[i] ?? 0) + 1;
      continue;
    }
    kept.push(f);
  }
  const tip = facts.canaries.length - 1;
  if ((seen[tip] ?? 0) === 0) throw new RangeFactsError(`the scanner did not report the canary of the stream's last commit (${facts.canaries[tip].commit.slice(0, 12)}), so it has not read the commit range to its end`);
  const wrong = facts.canaries.filter((_, i) => seen[i] !== 1);
  if (wrong.length > 0) throw new RangeFactsError(`the scanner did not report the canary of commit ${wrong.map((c) => c.commit.slice(0, 12)).join(" and ")} exactly once, so it is not proven to have read the commit range once`);
  const dropped = facts.before === null ? "" : `, and the commits the push replaced (the head before it, ${facts.before.slice(0, 12)})`;
  return {
    findings: kept,
    notes: [
      `the commit range ${facts.base.slice(0, 12)}..${facts.head.slice(0, 12)} (${facts.commits} commit(s), merges included${dropped}) was scanned to its end; both canary commits were read`,
      ...facts.forced ? ["this push rewrote the history of the branch: the range was scanned from where its old and new heads meet"] : []
    ]
  };
}
var SKIP_NOTES = Object.freeze({
  "no-range": "no commit range on this event (a push that made the branch, workflow_dispatch or schedule), so no commit range was scanned",
  "no-merge-base": "this push rewrote the history of the branch and its old head is not in the checkout, so its commit range was not scanned"
});

// gate/src/scrub.ts
var MAX_ERROR_CHARS = 300;
var MAX_NOTES = 50;
var MAX_NOTE_CHARS = 300;
var MAX_FIELD = 1024;
var sha2562 = (b) => createHash4("sha256").update(b).digest("hex");
var LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
var SEVERITIES2 = ["critical", "high", "medium", "low", "info"];
var FP_BYS = [...CONTENT_FORMS, ...POSITION_FORMS];
function forkFromEvent(eventText) {
  if (eventText === void 0 || eventText === "") return false;
  let json;
  try {
    json = JSON.parse(eventText);
  } catch {
    return false;
  }
  if (!isObj(json)) return false;
  const pr = getOwn(json, "pull_request");
  const head = isObj(pr) ? getOwn(pr, "head") : void 0;
  const headRepo = isObj(head) ? getOwn(head, "repo") : void 0;
  const repo2 = getOwn(json, "repository");
  const headId = isObj(headRepo) ? getOwn(headRepo, "id") : void 0;
  const id = isObj(repo2) ? getOwn(repo2, "id") : void 0;
  return typeof headId === "number" && typeof id === "number" && headId !== id;
}
var clip = (s, max = MAX_FIELD) => s.length <= max ? s : s.slice(0, max);
var outText = (s) => clip(maskSecretShapes(s));
var SECRET_PREFIX = "secret:";
var ruleIdText = (id) => id.startsWith(SECRET_PREFIX) ? SECRET_PREFIX + outText(id.slice(SECRET_PREFIX.length)) : outText(id);
var withoutKey = (text, key) => key === "" ? text : text.split(key).join("[key]");
var toolError = (error, key) => ({ status: "tool-error", error: clip(maskSecretShapes(withoutKey(safeText(error, MAX_ERROR_CHARS), key)), MAX_ERROR_CHARS) });
function writtenMessage(f) {
  if (isQuotingFinding(f)) return `${f.ruleId}: message withheld (the tool quotes the string it matched)`;
  return outText(f.message);
}
function withholder() {
  const known = /* @__PURE__ */ new Map();
  return (file) => {
    if (file === void 0) return false;
    let v = known.get(file);
    if (v === void 0) {
      v = secretShapedName(file);
      known.set(file, v);
    }
    return v;
  };
}
function sarifOut(tool2, findings, notes, key, extra = {}) {
  const info = SARIF_TOOLS[tool2];
  const withheld = withholder();
  const results = findings.map((f) => {
    const hide = withheld(f.file);
    const loc = {};
    if (f.file !== void 0 && !hide) loc.artifactLocation = { uri: clip(f.file, 4096) };
    if (f.line !== void 0) loc.region = { startLine: f.line, endLine: f.endLine ?? f.line };
    return {
      ruleId: ruleIdText(f.ruleId),
      level: LEVEL[f.severity],
      message: { text: writtenMessage(f) },
      ...Object.keys(loc).length === 0 ? {} : { locations: [{ physicalLocation: loc }] },
      partialFingerprints: { pipegenFingerprint: f.fingerprint },
      properties: {
        pipegenSeverity: f.severity,
        pipegenSecret: f.secret,
        pipegenUnmapped: f.uriUnmapped || hide,
        pipegenPathWithheld: hide,
        pipegenFpBy: f.fpBy,
        // C9: the commit a finding of the commit-range scan was found in (40 hex digits, read by the parser)
        ...f.commit === void 0 ? {} : { pipegenCommit: f.commit },
        // C1c fix round 1: the display form of a staged name with no lossless text (withheld like a path when it looks like a secret)
        ...f.file === void 0 && f.displayPath !== void 0 && !withheld(f.displayPath) ? { pipegenDisplayPath: clip(f.displayPath, 4096) } : {},
        // C2 fix round 1 (review-C2 I3): the advisory ids and aliases, so the gate sees a MAL- id whichever id the tool shows
        ...f.advisoryIds === void 0 || f.secret ? {} : { pipegenAdvisoryIds: f.advisoryIds.map((id) => outText(id)) }
      }
    };
  });
  return JSON.stringify({
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: info.driver } },
      properties: { pipegenScrubbed: true, pipegenTool: tool2, ...key === void 0 ? {} : { pipegenKeyId: keyId(key) }, pipegenNotes: [...notes], ...extra },
      results
    }]
  });
}
function zapOut(findings, notes) {
  const withheld = withholder();
  return JSON.stringify({
    pipegenScrubbed: true,
    tool: ZAP_TOOL,
    notes: [...notes],
    alerts: findings.map((f) => {
      const hide = withheld(f.file);
      return {
        pluginid: outText(f.ruleId),
        name: outText(f.message),
        severity: f.severity,
        fingerprint: f.fingerprint,
        unmapped: f.uriUnmapped || hide,
        pathWithheld: hide,
        ...f.method === void 0 ? {} : { method: f.method },
        ...f.file === void 0 || hide ? {} : { path: clip(f.file, 4096) }
      };
    })
  });
}
function lineNotes(findings) {
  const counts = /* @__PURE__ */ new Map();
  for (const f of findings) if (f.fpBy === "line" && f.fpNote !== void 0) counts.set(f.fpNote, (counts.get(f.fpNote) ?? 0) + 1);
  return [...counts].map(([note, n]) => `${n} secret finding(s), ${note}`);
}
function scrubBytes(raw, opts) {
  const key = typeof opts.fpKey === "string" ? opts.fpKey : "";
  try {
    if (key !== "") opts.mask?.(key);
  } catch {
    return toolError("the key could not be masked in the logs, so the scrub did not run", key);
  }
  try {
    const maxBytes = opts.maxBytes ?? MAX_RAW_BYTES;
    let parsed;
    let secretsTool = false;
    let stage;
    if (opts.format === "sarif") {
      if (!Object.hasOwn(SARIF_TOOLS, opts.tool)) return toolError(`${JSON.stringify(safeText(opts.tool, 60))} is not a tool whose SARIF the gate reads`, key);
      secretsTool = SARIF_TOOLS[opts.tool].secrets;
      if (opts.range !== void 0 && (opts.tool !== SECRETS_RANGE_TOOL || opts.stage !== void 0)) return toolError(`the commit-range scan is ${SECRETS_RANGE_TOOL}'s, and it has no stage folder`, key);
      if (opts.range !== void 0 && isRangeSkipped(opts.range)) {
        const note = SKIP_NOTES[opts.range.skipped];
        const bytes2 = Buffer.from(sarifOut(opts.tool, [], [note], void 0, { pipegenRangeSkipped: opts.range.skipped }), "utf8");
        return { status: "ok", bytes: bytes2, sha256: sha2562(bytes2), findings: 0, notes: [note], fpBy: { hash: 0, region: 0, quoted: 0, file: 0, line: 0, nokey: 0, "quoted-nokey": 0 } };
      }
      if (opts.stage !== void 0) {
        if (!secretsTool) return toolError("a stage folder is only for the secrets tools", key);
        try {
          stage = readStage(opts.stage);
        } catch (e) {
          return toolError(e instanceof StageError ? e.message : "the stage folder could not be read", key);
        }
      }
      parsed = opts.range !== void 0 ? parseSarifText(raw, opts.tool, { commits: true, limits: { maxBytes } }) : stage === void 0 ? parseSarifText(raw, opts.tool, { workspace: opts.workspace, limits: { maxBytes } }) : parseSarifText(raw, opts.tool, { workspace: stage.files, exactNames: STAGED_NAME_RE, limits: { maxBytes } });
    } else if (opts.format === "zap-json") {
      if (opts.stage !== void 0 || opts.range !== void 0) return toolError("a stage folder or a commit range is only for the secrets tools", key);
      if (opts.tool !== ZAP_TOOL) return toolError(`${JSON.stringify(safeText(opts.tool, 60))} is not a tool whose ZAP report the gate reads`, key);
      parsed = parseZapJsonText(raw, opts.tool, { limits: { maxBytes } });
    } else {
      return toolError("the result format is not one the gate reads", key);
    }
    if (parsed.toolError !== void 0) return toolError(parsed.toolError, key);
    let staged;
    if (stage !== void 0) {
      try {
        staged = applyStage(parsed.findings, stage, opts.tool);
      } catch (e) {
        return toolError(e instanceof StageError ? e.message : "the staged findings could not be mapped back", key);
      }
      parsed = { findings: staged.findings, notes: [...parsed.notes, ...staged.notes] };
    }
    if (opts.range !== void 0 && !isRangeSkipped(opts.range)) {
      try {
        const ranged = applyRange(parsed.findings, opts.range);
        parsed = { findings: ranged.findings, notes: [...parsed.notes, ...ranged.notes] };
      } catch (e) {
        return toolError(e instanceof RangeFactsError ? e.message : "the commit-range findings could not be checked", key);
      }
    }
    const needsKey = secretsTool || parsed.findings.some((f) => f.secret || isQuotingFinding(f));
    const problem = keyProblem(key, forkFromEvent(opts.eventText), needsKey);
    if (problem !== void 0) return toolError(problem, key);
    const usedKey = needsKey && key !== "" ? key : void 0;
    const regions = [];
    const findings = fingerprintAll(parsed.findings, {
      fpKey: usedKey,
      workspace: opts.workspace,
      onRegion: (b) => {
        regions.push(b);
      },
      ...staged === void 0 ? {} : { regionOf: staged.regionOf, fileHashOf: staged.fileHashOf },
      // C9: a secret of the commit range is in a commit, not in the checkout's file of that name: never read a region for it
      ...opts.range === void 0 ? {} : { regionOf: () => ({ ok: false, reason: "a secret in a commit of the range (the checkout's file is not that commit's)" }) }
    });
    const notes = [...parsed.notes, ...lineNotes(findings)].slice(0, MAX_NOTES).map((n) => clip(maskSecretShapes(n), MAX_NOTE_CHARS));
    const bytes = Buffer.from(opts.format === "sarif" ? sarifOut(opts.tool, findings, notes, usedKey) : zapOut(findings, notes), "utf8");
    const written = bytes.toString("utf8");
    const holds = (text) => bytes.includes(text) || written.includes(JSON.stringify(text).slice(1, -1));
    if (usedKey !== void 0 && holds(usedKey)) return toolError("the output would hold the key, so it was not written", key);
    for (const region of regions) {
      if (region.length >= 8 && (bytes.includes(region) || written.includes(JSON.stringify(region.toString("utf8")).slice(1, -1)))) return toolError("the output would hold the text of a secret region, so it was not written", key);
    }
    const fpBy = { hash: 0, region: 0, quoted: 0, file: 0, line: 0, nokey: 0, "quoted-nokey": 0 };
    for (const f of findings) fpBy[f.fpBy]++;
    return { status: "ok", bytes, sha256: sha2562(bytes), findings: findings.length, ...usedKey === void 0 ? {} : { keyId: keyId(usedKey) }, notes, fpBy };
  } catch {
    return toolError("the scrub failed unexpectedly", key);
  }
}
var str = (o, k, where) => {
  const v = getOwn(o, k);
  if (typeof v !== "string") fail(`${where}: ${k} is not a string`);
  return v;
};
var bool = (o, k, where) => {
  const v = getOwn(o, k);
  if (typeof v !== "boolean") fail(`${where}: ${k} is not a boolean`);
  return v;
};
var optBool = (o, k, where) => {
  const v = getOwn(o, k);
  if (v === void 0) return false;
  if (typeof v !== "boolean") fail(`${where}: ${k} is not a boolean`);
  return v;
};
var lineNo = (v, where) => {
  if (v === void 0) return void 0;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1) fail(`${where}: a line is not a whole number`);
  return v;
};
function advisoryIdsOf(v, where) {
  if (!Array.isArray(v) || v.length > MAX_ADVISORY_IDS || !v.every((x) => typeof x === "string")) fail(`${where}: the advisory ids are not a list of at most ${MAX_ADVISORY_IDS} strings`);
  return v;
}
function commitOf(v, where) {
  if (typeof v !== "string" || !/^[0-9a-f]{40}$/.test(v)) fail(`${where}: the commit is not 40 hex digits`);
  return v;
}
function readNotes(v, where) {
  if (!Array.isArray(v)) fail(`${where}: notes is not a list`);
  return v.map((n) => {
    if (typeof n !== "string") fail(`${where}: a note is not a string`);
    return n;
  });
}
function readScrubbed(input, format, maxBytes = MAX_RAW_BYTES) {
  const read = readJson(input, maxBytes);
  if (read.toolError !== void 0) return { findings: [], notes: [], toolError: read.toolError };
  try {
    const doc = read.json;
    if (!isObj(doc)) fail("the scrubbed result is not an object");
    if (format === "sarif") {
      if (getOwn(doc, "version") !== "2.1.0") fail("the scrubbed result is not SARIF 2.1.0");
      const runs = getOwn(doc, "runs");
      if (!Array.isArray(runs) || runs.length !== 1 || !isObj(runs[0])) fail("the scrubbed result has not exactly one run");
      const run = runs[0];
      const props = getOwn(run, "properties");
      if (!isObj(props) || getOwn(props, "pipegenScrubbed") !== true) fail("the result was not written by the scrub");
      const tool2 = str(props, "pipegenTool", "properties");
      const id = getOwn(props, "pipegenKeyId");
      if (id !== void 0 && (typeof id !== "string" || !/^[0-9a-f]{16}$/.test(id))) fail("the key id is not 16 hex characters");
      const results = getOwn(run, "results");
      if (!Array.isArray(results)) fail("the scrubbed result has no results list");
      const findings2 = results.map((r, i) => {
        const at3 = `result ${i}`;
        if (!isObj(r)) fail(`${at3} is not an object`);
        const p = getOwn(r, "properties");
        const fp2 = getOwn(r, "partialFingerprints");
        const msg = getOwn(r, "message");
        if (!isObj(p) || !isObj(fp2) || !isObj(msg)) fail(`${at3} is missing a part`);
        const severity = str(p, "pipegenSeverity", at3);
        const fpBy = str(p, "pipegenFpBy", at3);
        if (!SEVERITIES2.includes(severity) || !FP_BYS.includes(fpBy)) fail(`${at3}: an unknown severity or fingerprint form`);
        const fingerprint = str(fp2, "pipegenFingerprint", at3);
        if (!/^(?:secret:|secret-nokey:|quoted:|quoted-nokey:)?[0-9a-f]{64}$/.test(fingerprint)) fail(`${at3}: the fingerprint is not a hash`);
        let file;
        let line;
        let endLine;
        const locs = getOwn(r, "locations");
        if (locs !== void 0) {
          const phys = Array.isArray(locs) && isObj(locs[0]) ? getOwn(locs[0], "physicalLocation") : void 0;
          if (!isObj(phys)) fail(`${at3}: the location is not readable`);
          const art = getOwn(phys, "artifactLocation");
          if (art !== void 0) file = isObj(art) ? str(art, "uri", at3) : fail(`${at3}: the artifact location is not an object`);
          const region = getOwn(phys, "region");
          if (region !== void 0) {
            if (!isObj(region)) fail(`${at3}: the region is not an object`);
            line = lineNo(getOwn(region, "startLine"), at3);
            endLine = lineNo(getOwn(region, "endLine"), at3);
          }
        }
        return {
          tool: tool2,
          ruleId: str(r, "ruleId", at3),
          severity,
          ...file === void 0 ? {} : { file },
          ...line === void 0 ? {} : { line },
          ...endLine === void 0 ? {} : { endLine },
          message: str(msg, "text", at3),
          fingerprint,
          secret: bool(p, "pipegenSecret", at3),
          fpBy,
          uriUnmapped: bool(p, "pipegenUnmapped", at3),
          pathWithheld: optBool(p, "pipegenPathWithheld", at3),
          ...getOwn(p, "pipegenDisplayPath") === void 0 ? {} : { displayPath: str(p, "pipegenDisplayPath", at3) },
          ...getOwn(p, "pipegenAdvisoryIds") === void 0 ? {} : { advisoryIds: advisoryIdsOf(getOwn(p, "pipegenAdvisoryIds"), at3) },
          ...getOwn(p, "pipegenCommit") === void 0 ? {} : { commit: commitOf(getOwn(p, "pipegenCommit"), at3) }
        };
      });
      const skipped = getOwn(props, "pipegenRangeSkipped");
      if (skipped !== void 0 && (!SKIP_REASONS.includes(skipped) || findings2.length > 0)) fail("the commit-range skip mark is not the scrub's (an unknown reason, or findings beside it)");
      return { findings: findings2, ...typeof id === "string" ? { keyId: id } : {}, notes: readNotes(getOwn(props, "pipegenNotes"), "properties"), ...skipped === void 0 ? {} : { rangeSkipped: skipped } };
    }
    if (getOwn(doc, "pipegenScrubbed") !== true || getOwn(doc, "tool") !== ZAP_TOOL) fail("the result was not written by the scrub for ZAP");
    const alerts = getOwn(doc, "alerts");
    if (!Array.isArray(alerts)) fail("the scrubbed ZAP result has no alerts list");
    const findings = alerts.map((a, i) => {
      const at3 = `alert ${i}`;
      if (!isObj(a)) fail(`${at3} is not an object`);
      const severity = str(a, "severity", at3);
      const fingerprint = str(a, "fingerprint", at3);
      if (!SEVERITIES2.includes(severity) || !/^[0-9a-f]{64}$/.test(fingerprint)) fail(`${at3}: an unknown severity or a fingerprint that is not a hash`);
      const method = getOwn(a, "method");
      const path = getOwn(a, "path");
      if (method !== void 0 && typeof method !== "string" || path !== void 0 && typeof path !== "string") fail(`${at3}: a method or path is not a string`);
      return {
        tool: ZAP_TOOL,
        ruleId: str(a, "pluginid", at3),
        severity,
        ...path === void 0 ? {} : { file: path },
        message: str(a, "name", at3),
        fingerprint,
        secret: false,
        fpBy: "hash",
        uriUnmapped: bool(a, "unmapped", at3),
        pathWithheld: optBool(a, "pathWithheld", at3),
        ...method === void 0 ? {} : { method }
      };
    });
    return { findings, notes: readNotes(getOwn(doc, "notes"), "report") };
  } catch (e) {
    return { findings: [], notes: [], toolError: e instanceof ReadError ? e.message : "the scrubbed result could not be read" };
  }
}
var ScrubFileError = class extends Error {
};
var ARTIFACT_RE = /^[a-z0-9][a-z0-9-]{0,120}$/;
var FILE_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;
function ensureFolder2(path, what) {
  let made = false;
  try {
    const st = lstatSync4(path);
    if (st.isSymbolicLink()) throw new ScrubFileError(`${what} is a link, so the scrub will not write there`);
    if (!st.isDirectory()) throw new ScrubFileError(`${what} is not a folder`);
  } catch (e) {
    if (e instanceof ScrubFileError) throw e;
    if (e.code !== "ENOENT") throw new ScrubFileError(`${what} cannot be checked`);
    try {
      mkdirSync2(path, { mode: 493 });
      made = true;
    } catch {
      throw new ScrubFileError(`${what} cannot be created`);
    }
  }
  if (made) {
    const st = lstatSync4(path);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new ScrubFileError(`${what} is not the folder that was just made`);
  }
}
function prepareOutFolder(out, artifact) {
  if (!ARTIFACT_RE.test(artifact)) throw new ScrubFileError("the artifact name is not a plain artifact name");
  if (!isAbsolute2(out)) throw new ScrubFileError("the out path must be absolute");
  const parts = out.split(sep2);
  const file = parts[parts.length - 1];
  if (parts.length < 4 || parts[parts.length - 2] !== artifact || parts[parts.length - 3] !== "pipegen-out" || !FILE_RE.test(file)) {
    throw new ScrubFileError("the out path is not <base>/pipegen-out/<artifact>/<file> for the artifact named");
  }
  const outDir = dirname2(dirname2(out));
  ensureFolder2(outDir, "the pipegen-out folder");
  ensureFolder2(join3(outDir, artifact), "the artifact folder in pipegen-out");
  return out;
}
function readPlainFile(path, max, what) {
  let st;
  try {
    st = lstatSync4(path);
  } catch (e) {
    throw new ScrubFileError(e.code === "ENOENT" ? `the tool left no result file (${what} is missing)` : `${what} cannot be checked`);
  }
  if (st.isSymbolicLink()) throw new ScrubFileError(`${what} is a link, so it is not read`);
  if (!st.isFile()) throw new ScrubFileError(`${what} is not a regular file`);
  let fd;
  try {
    fd = openSync4(path, constants4.O_RDONLY | constants4.O_NOFOLLOW | constants4.O_NONBLOCK | constants4.O_NOCTTY);
    const opened = fstatSync4(fd);
    if (!opened.isFile() || opened.dev !== st.dev || opened.ino !== st.ino) throw new ScrubFileError(`${what} changed while it was opened`);
    if (opened.size > max) throw new ScrubFileError(`${what} is over the size cap (${max} bytes)`);
    const buf = Buffer.alloc(opened.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync4(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    return got === buf.length ? buf : buf.subarray(0, got);
  } catch (e) {
    if (e instanceof ScrubFileError) throw e;
    throw new ScrubFileError(`${what} cannot be read`);
  } finally {
    if (fd !== void 0) try {
      closeSync4(fd);
    } catch {
    }
  }
}
function scrubFile(opts) {
  const key = typeof opts.fpKey === "string" ? opts.fpKey : "";
  const fail1 = (error) => {
    const r = toolError(error, key);
    return { status: "tool-error", error: r.status === "tool-error" ? r.error : error };
  };
  try {
    if (key !== "") opts.mask?.(key);
  } catch {
    return fail1("the key could not be masked in the logs, so the scrub did not run");
  }
  let range;
  if (opts.artifact === SECRETS_RANGE_ARTIFACT) {
    if (opts.stage !== void 0) return fail1("the commit-range scan has no stage folder");
    try {
      range = readRangeFacts(join3(dirname2(opts.raw), RANGE_FACTS_FILE));
    } catch (e) {
      return fail1(e instanceof RangeFactsError ? e.message : "the commit-range facts could not be read");
    }
  } else if (Object.hasOwn(SARIF_TOOLS, opts.tool) && SARIF_TOOLS[opts.tool].secrets && opts.stage === void 0) {
    return fail1("the secrets scan has no stage folder (the stage input): pipegen stages the checkout under neutral names before every secrets scan, and without it the scan's coverage can not be proven");
  }
  let raw;
  try {
    raw = range !== void 0 && isRangeSkipped(range) ? Buffer.alloc(0) : readPlainFile(opts.raw, opts.maxBytes ?? MAX_RAW_BYTES, "the raw result");
  } catch (e) {
    return fail1(e instanceof ScrubFileError ? e.message : "the raw result cannot be read");
  }
  let eventText = opts.eventText;
  if (eventText === void 0 && opts.eventPath !== void 0) {
    try {
      eventText = readPlainFile(opts.eventPath, 16 * 1024 * 1024, "the event payload").toString("utf8");
    } catch {
      eventText = void 0;
    }
  }
  const scrubbed = scrubBytes(raw, {
    tool: opts.tool,
    format: opts.format,
    fpKey: opts.fpKey,
    eventText,
    workspace: opts.workspace,
    maxBytes: opts.maxBytes,
    ...opts.stage === void 0 ? {} : { stage: opts.stage },
    ...range === void 0 ? {} : { range }
  });
  if (scrubbed.status !== "ok") return { status: "tool-error", error: scrubbed.error };
  let fd;
  let tmp;
  try {
    const path = prepareOutFolder(opts.out, opts.artifact);
    tmp = join3(dirname2(path), `.${basename(path)}.${randomBytes(8).toString("hex")}.tmp`);
    try {
      fd = openSync4(tmp, constants4.O_WRONLY | constants4.O_CREAT | constants4.O_EXCL | constants4.O_NOFOLLOW, 420);
    } catch {
      tmp = void 0;
      throw new ScrubFileError("the scrubbed result file cannot be created");
    }
    let at3 = 0;
    while (at3 < scrubbed.bytes.length) at3 += writeSync2(fd, scrubbed.bytes, at3, scrubbed.bytes.length - at3);
    closeSync4(fd);
    fd = void 0;
    try {
      linkSync(tmp, path);
    } catch (e) {
      throw new ScrubFileError(e.code === "EEXIST" ? "the scrubbed result file already exists, so it is not overwritten" : "the scrubbed result file cannot be created");
    }
  } catch (e) {
    return fail1(e instanceof ScrubFileError ? e.message : "the scrubbed result could not be written");
  } finally {
    if (fd !== void 0) try {
      closeSync4(fd);
    } catch {
    }
    if (tmp !== void 0) try {
      unlinkSync(tmp);
    } catch {
    }
  }
  return { status: "ok", sha256: scrubbed.sha256, findings: scrubbed.findings, ...scrubbed.keyId === void 0 ? {} : { keyId: scrubbed.keyId }, notes: scrubbed.notes };
}

// gate/src/artifacts.ts
var MAX_RESULT_ZIP_BYTES = 16 * 1024 * 1024;
var MAX_RESULT_FILE_BYTES = 16 * 1024 * 1024;
var FILE_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;
var isPlain3 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var own2 = (o, k) => Object.hasOwn(o, k) ? o[k] : void 0;
var posInt2 = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
var natInt = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
function pickArtifact(listing, want) {
  const bad = (problem) => ({ ok: false, missing: false, problem });
  const max = want.maxBytes ?? MAX_RESULT_ZIP_BYTES;
  if (!isPlain3(listing)) return bad("the artifact list is not an object");
  const list = own2(listing, "artifacts");
  if (!Array.isArray(list)) return bad("the artifact list has no artifacts");
  const total = own2(listing, "total_count");
  if (total !== void 0 && (!natInt(total) || total > list.length)) return bad("the artifact list is cut (fewer entries than its total)");
  if (!list.every(isPlain3)) return bad("an entry of the artifact list is not an object");
  const named = list.filter((a2) => own2(a2, "name") === want.name);
  if (named.length === 0) return { ok: false, missing: true, problem: `no artifact named ${want.name}` };
  if (named.length > 1) return bad(`${named.length} artifacts are named ${want.name}`);
  const a = named[0];
  const run = own2(a, "workflow_run");
  if (!isPlain3(run) || own2(run, "id") !== want.runId) return bad("the artifact is not of this workflow run");
  if (own2(a, "expired") !== false) return bad("the artifact is expired or does not say");
  const id = own2(a, "id");
  const size = own2(a, "size_in_bytes");
  if (!posInt2(id)) return bad("the artifact has no valid id");
  if (!natInt(size)) return bad("the artifact has no valid size");
  if (size > max) return bad(`the artifact is over the size cap (${max} bytes)`);
  return { ok: true, id, size };
}
var S_IFMT = 61440;
var S_IFREG = 32768;
var EOCD_SIG = 101010256;
var CEN_SIG = 33639248;
var LOC_SIG = 67324752;
var DD_SIG = 134695760;
function readZipEntry(zip, opts) {
  try {
    return readZip(zip, opts.maxBytes ?? MAX_RESULT_FILE_BYTES, opts.expectedFile);
  } catch {
    return { ok: false, problem: "the zip could not be read" };
  }
}
function readZip(zip, maxBytes, expectedFile) {
  const bad = (problem) => ({ ok: false, problem: `the zip is refused: ${problem}` });
  if (!(zip instanceof Uint8Array)) return bad("not bytes");
  const b = Buffer.from(zip.buffer, zip.byteOffset, zip.byteLength);
  if (b.length < 22 + 46 + 30) return bad("too short");
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) {
    if (b.readUInt32LE(i) === EOCD_SIG && i + 22 + b.readUInt16LE(i + 20) === b.length) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return bad("no end record");
  const disk = b.readUInt16LE(eocd + 4);
  const cdDisk = b.readUInt16LE(eocd + 6);
  const onDisk = b.readUInt16LE(eocd + 8);
  const total = b.readUInt16LE(eocd + 10);
  const cdSize = b.readUInt32LE(eocd + 12);
  const cdAt = b.readUInt32LE(eocd + 16);
  if (disk !== 0 || cdDisk !== 0) return bad("a multi-part zip");
  if (onDisk === 65535 || total === 65535 || cdSize === 4294967295 || cdAt === 4294967295) return bad("a zip64 archive");
  if (onDisk !== 1 || total !== 1) return bad(`${total} entries, not exactly one`);
  if (cdAt + cdSize !== eocd) return bad("the central directory is not where the end record says");
  const c = cdAt;
  if (b.readUInt32LE(c) !== CEN_SIG) return bad("no central directory entry");
  const madeBy = b.readUInt16LE(c + 4);
  const flags = b.readUInt16LE(c + 8);
  const method = b.readUInt16LE(c + 10);
  const crc = b.readUInt32LE(c + 16);
  const csize = b.readUInt32LE(c + 20);
  const usize = b.readUInt32LE(c + 24);
  const nameLen = b.readUInt16LE(c + 28);
  const extraLen = b.readUInt16LE(c + 30);
  const commentLen = b.readUInt16LE(c + 32);
  const diskStart = b.readUInt16LE(c + 34);
  const external = b.readUInt32LE(c + 38);
  const localAt = b.readUInt32LE(c + 42);
  if (46 + nameLen + extraLen + commentLen !== cdSize) return bad("the central directory holds more than one entry");
  if (diskStart !== 0) return bad("a multi-part zip");
  if (csize === 4294967295 || usize === 4294967295 || localAt === 4294967295) return bad("zip64 sizes");
  if ((flags & 1) !== 0 || (flags & 64) !== 0) return bad("an encrypted entry");
  if (method !== 0 && method !== 8) return bad("a compression method other than stored or deflate");
  const nameBytes = b.subarray(c + 46, c + 46 + nameLen);
  const name = nameBytes.toString("utf8");
  if (!Buffer.from(name, "utf8").equals(nameBytes)) return bad("the entry name is not UTF-8");
  if (!FILE_NAME_RE.test(name)) return bad("the entry is not a plain file name (a path, a folder, a link name or a hidden name)");
  if (expectedFile !== void 0 && name !== expectedFile) return bad("the entry is not the expected result file");
  const host = madeBy >> 8;
  const mode = external >>> 16;
  if (host === 3 && (mode & S_IFMT) !== 0 && (mode & S_IFMT) !== S_IFREG) return bad("the entry is not a regular file (a link, a folder or a device)");
  if ((external & 16) !== 0) return bad("the entry is a folder");
  if (localAt !== 0) return bad("bytes in front of the entry");
  if (b.readUInt32LE(0) !== LOC_SIG) return bad("no local header");
  const lflags = b.readUInt16LE(6);
  const lmethod = b.readUInt16LE(8);
  const lname = b.readUInt16LE(26);
  const lextra = b.readUInt16LE(28);
  if (lflags !== flags || lmethod !== method) return bad("the local header disagrees with the directory");
  if (!b.subarray(30, 30 + lname).equals(nameBytes)) return bad("the local header names another file");
  const dataAt = 30 + lname + lextra;
  const dataEnd = dataAt + csize;
  if (dataEnd > cdAt) return bad("the entry runs past the central directory");
  const descriptor = (flags & 8) !== 0;
  if (!descriptor) {
    if (b.readUInt32LE(14) !== crc || b.readUInt32LE(18) !== csize || b.readUInt32LE(22) !== usize) return bad("the local header sizes disagree with the directory");
    if (dataEnd !== cdAt) return bad("bytes between the entry and the central directory");
  } else {
    const rest = cdAt - dataEnd;
    const at3 = dataEnd;
    const withSig = rest === 16 && b.readUInt32LE(at3) === DD_SIG;
    const off = withSig ? 4 : rest === 12 ? 0 : -1;
    if (off < 0) return bad("bytes between the entry and the central directory");
    if (b.readUInt32LE(at3 + off) !== crc || b.readUInt32LE(at3 + off + 4) !== csize || b.readUInt32LE(at3 + off + 8) !== usize) return bad("the data descriptor disagrees with the directory");
  }
  if (usize > maxBytes) return bad("the file is over the size cap");
  const raw = b.subarray(dataAt, dataEnd);
  let data;
  if (method === 0) {
    if (csize !== usize) return bad("a stored entry whose sizes differ");
    data = Buffer.from(raw);
  } else {
    try {
      data = inflateRawSync(raw, { maxOutputLength: Math.max(1, Math.min(maxBytes, usize + 1)) });
    } catch {
      return bad("the file does not inflate within its declared size and the size cap (a zip bomb, or broken data)");
    }
  }
  if (data.length !== usize) return bad("the inflated size is not the declared size");
  if (crc32(data) !== crc) return bad("the CRC does not match");
  return { ok: true, name, bytes: new Uint8Array(data) };
}
var sha2563 = (b) => createHash5("sha256").update(b).digest("hex");
var tamperedFile = (problem) => ({ kind: "file", file: { sha256: "", read: { findings: [], notes: [] }, problem } });
async function downloadResult(io, want) {
  let listing;
  try {
    listing = await io.listRunArtifacts(want.owner, want.repo, want.runId, want.name);
  } catch {
    return tamperedFile("the artifact list could not be read");
  }
  const pick = pickArtifact(listing, { name: want.name, runId: want.runId });
  if (!pick.ok) return pick.missing ? { kind: "missing" } : tamperedFile(pick.problem);
  let zip;
  try {
    zip = await io.artifactZip(want.owner, want.repo, pick.id, MAX_RESULT_ZIP_BYTES);
  } catch {
    return tamperedFile("the artifact could not be downloaded");
  }
  if (!(zip instanceof Uint8Array) || zip.length > MAX_RESULT_ZIP_BYTES) return tamperedFile("the artifact download is not bytes within the size cap");
  const entry = readZipEntry(zip, want.expectedFile === void 0 ? {} : { expectedFile: want.expectedFile });
  if (!entry.ok) return tamperedFile(entry.problem);
  return { kind: "file", file: { sha256: sha2563(entry.bytes), read: readScrubbed(entry.bytes, want.format, MAX_RESULT_FILE_BYTES) } };
}

// gate/src/integrity.ts
var import_picomatch = __toESM(require_picomatch2(), 1);
import { createHash as createHash6 } from "node:crypto";

// node_modules/smol-toml/dist/error.js
function getLineColFromPtr(string, ptr) {
  let lines = string.slice(0, ptr).split(/\r?\n/);
  return [lines.length, lines.pop().length + 1];
}
function makeCodeBlock(string, line, column) {
  let lines = string.split(/\r?\n/);
  let codeblock = "";
  let numberLen = (Math.log10(line + 1) | 0) + 1;
  for (let i = line - 1; i <= line + 1; i++) {
    let l = lines[i - 1];
    if (!l)
      continue;
    codeblock += i.toString().padEnd(numberLen, " ");
    codeblock += ":  ";
    codeblock += l;
    codeblock += "\n";
    if (i === line) {
      codeblock += " ".repeat(numberLen + column + 2);
      codeblock += "^\n";
    }
  }
  return codeblock;
}
var TomlError = class _TomlError extends Error {
  line;
  column;
  codeblock;
  constructor(message, options) {
    const [line, column] = getLineColFromPtr(options.toml, options.ptr);
    const codeblock = makeCodeBlock(options.toml, line, column);
    super(`Invalid TOML document: ${message}

${codeblock}`, options);
    this.line = line;
    this.column = column;
    this.codeblock = codeblock;
  }
  /** @internal */
  static x(message, ctx, ptr) {
    throw new _TomlError(message, { toml: ctx.s, ptr: ptr ?? ctx.p });
  }
};

// node_modules/smol-toml/dist/primitive.js
function parseString(ctx) {
  let startPtr = ctx.p;
  let c = ctx.s.charCodeAt(ctx.p++);
  let first = c;
  let isLiteral = c === 39;
  let isMultiline = c === ctx.s.charCodeAt(ctx.p) && c === ctx.s.charCodeAt(ctx.p + 1);
  if (isMultiline) {
    if ((c = ctx.s.charCodeAt(ctx.p += 2)) === 10)
      ctx.p++;
    else if (c === 13 && ctx.s.charCodeAt(ctx.p + 1) === 10)
      ctx.p += 2;
  }
  let parsed = "";
  let sliceStart = ctx.p;
  let state = 0;
  for (; ctx.p < ctx.s.length; ctx.p++) {
    c = ctx.s.charCodeAt(ctx.p);
    if (isMultiline && (c === 10 || c === 13 && ctx.s.charCodeAt(ctx.p + 1) === 10)) {
      state = state && 3;
    } else if (c < 32 && c !== 9 || c === 127) {
      TomlError.x("control characters are not allowed in strings", ctx);
    } else if ((!state || state === 3) && c === first && (!isMultiline || ctx.s.charCodeAt(ctx.p + 1) === first && ctx.s.charCodeAt(ctx.p + 2) === first)) {
      if (isMultiline) {
        if (ctx.s.charCodeAt(ctx.p + 3) === first)
          ctx.p++;
        if (ctx.s.charCodeAt(ctx.p + 3) === first)
          ctx.p++;
      }
      if (!state) {
        let s = ctx.s.slice(sliceStart, ctx.p);
        parsed = parsed ? parsed + s : s;
      }
      ctx.p += isMultiline ? 3 : 1;
      return parsed;
    } else if (!state) {
      if (!isLiteral && c === 92) {
        parsed += ctx.s.slice(sliceStart, sliceStart = ctx.p);
        state = 1;
      }
    } else if (state === 1) {
      if (c === 120 || c === 117 || c === 85) {
        let errPtr = ctx.p++ - 1;
        let value = 0;
        let len = c === 120 ? 2 : c === 117 ? 4 : 8;
        for (let j = 0; j < len; j++, ctx.p++) {
          let hex = ctx.s.charCodeAt(ctx.p);
          let digit = (
            /* 0-9 */
            hex >= 48 && hex <= 57 ? hex - 48 : (
              /* A-F */
              hex >= 65 && hex <= 70 ? hex - 65 + 10 : (
                /* a-f */
                hex >= 97 && hex <= 102 ? hex - 97 + 10 : -1
              )
            )
          );
          if (digit < 0)
            TomlError.x("invalid non-hex character in unicode escape", ctx);
          value = value << 4 | digit;
        }
        if (value < 0 || value > 1114111 || value >= 55296 && value <= 57343) {
          TomlError.x("invalid unicode escape", ctx, errPtr);
        }
        parsed += String.fromCodePoint(value);
        sliceStart = ctx.p--;
        state = 0;
      } else if (isMultiline && (c === 32 || c === 9)) {
        state = 2;
      } else {
        if (c === 98)
          parsed += "\b";
        else if (c === 116)
          parsed += "	";
        else if (c === 110)
          parsed += "\n";
        else if (c === 102)
          parsed += "\f";
        else if (c === 114)
          parsed += "\r";
        else if (c === 101)
          parsed += "\x1B";
        else if (c === 34)
          parsed += '"';
        else if (c === 92)
          parsed += "\\";
        else
          TomlError.x("unrecognised escape sequence", ctx);
        sliceStart = ctx.p + 1;
        state = 0;
      }
    } else if (c !== 32 && c !== 9) {
      if (state === 2)
        TomlError.x("invalid escape: only line-ending whitespace may be escaped", ctx, sliceStart);
      state = !isLiteral && c === 92 ? 1 : 0;
      sliceStart = ctx.p;
    }
  }
  TomlError.x("unfinished string", ctx, startPtr);
}

// node_modules/smol-toml/dist/date.js
var DATE_TIME_RE = /^(\d{4}-\d{2}-\d{2})?[Tt ]?(?:(\d{2}):\d{2}(?::\d{2}(?:\.\d+)?)?)?(Z|z|[-+]\d{2}:\d{2})?$/i;
var TomlDate = class _TomlDate extends Date {
  #hasDate = false;
  #hasTime = false;
  #offset = null;
  constructor(date, fasttype, unsafeDelim) {
    let hasDate = true;
    let hasTime = true;
    let offset = "Z";
    let c;
    if (typeof date === "string") {
      if (fasttype)
        prep: {
          if (fasttype < 3) {
            if (+date.slice(11, 13) > 23) {
              date = "";
              break prep;
            }
            if (fasttype === 2) {
              offset = null;
              date += "Z";
            } else if ((c = date.charCodeAt(date.length - 1)) !== 90 && c !== 122) {
              offset = date.slice(date.length - 6);
            }
            if (unsafeDelim)
              date = date.slice(0, 10) + "T" + date.slice(11);
          } else if (fasttype === 4) {
            date = +date.slice(0, 2) > 23 ? "" : `0000-01-01T${date}Z`;
          }
          hasDate = fasttype !== 4;
          hasTime = fasttype !== 3;
        }
      else {
        let match = date.match(DATE_TIME_RE);
        if (match) {
          if (!match[1]) {
            hasDate = false;
            date = `0000-01-01T${date}`;
          }
          hasTime = !!match[2];
          hasTime && date[10] === " " && (date = date.replace(" ", "T"));
          if (match[2] && +match[2] > 23) {
            date = "";
          } else {
            offset = match[3] || null;
            if (!offset && hasTime)
              date += "Z";
          }
        } else {
          date = "";
        }
      }
    }
    super(date);
    if (!isNaN(this.getTime())) {
      this.#hasDate = hasDate;
      this.#hasTime = hasTime;
      this.#offset = offset;
    }
  }
  isDateTime() {
    return this.#hasDate && this.#hasTime;
  }
  isLocal() {
    return !this.#hasDate || !this.#hasTime || !this.#offset;
  }
  isDate() {
    return this.#hasDate && !this.#hasTime;
  }
  isTime() {
    return this.#hasTime && !this.#hasDate;
  }
  isValid() {
    return this.#hasDate || this.#hasTime;
  }
  toISOString() {
    let iso = super.toISOString();
    if (this.isDate())
      return iso.slice(0, 10);
    if (this.isTime())
      return iso.slice(11, 23);
    if (this.#offset === null)
      return iso.slice(0, -1);
    if (this.#offset === "Z" || this.#offset === "z")
      return iso;
    let offset = +this.#offset.slice(1, 3) * 60 + +this.#offset.slice(4, 6);
    offset = this.#offset[0] === "-" ? offset : -offset;
    let offsetDate = new Date(this.getTime() - offset * 6e4);
    return offsetDate.toISOString().slice(0, -1) + this.#offset;
  }
  static wrapAsOffsetDateTime(jsDate, offset = "Z") {
    let date = new _TomlDate(jsDate);
    date.#offset = offset;
    return date;
  }
  static wrapAsLocalDateTime(jsDate) {
    let date = new _TomlDate(jsDate);
    date.#offset = null;
    return date;
  }
  static wrapAsLocalDate(jsDate) {
    let date = new _TomlDate(jsDate);
    date.#hasTime = false;
    date.#offset = null;
    return date;
  }
  static wrapAsLocalTime(jsDate) {
    let date = new _TomlDate(jsDate);
    date.#hasDate = false;
    date.#offset = null;
    return date;
  }
};

// node_modules/smol-toml/dist/extract.js
function isDigit2(char, base = 10) {
  return base === 16 ? char > 47 && char < 58 || char > 64 && char < 71 || char > 96 && char < 103 : char > 47 && char < 48 + base;
}
function isEndOfValue(char, delim) {
  return char === 32 || char === 9 || char === 10 || char === 13 || // Structure end or next value delimiter
  delim && (char === delim || char === 44) || // Comment
  char === 35;
}
function extractValue(ctx, end) {
  let errPtr = ctx.p;
  let c = ctx.s.charCodeAt(ctx.p);
  if (c === 91 || c === 123) {
    ctx.d-- || TomlError.x("document contains excessively nested structures. aborting.", ctx);
    let value = c === 91 ? parseArray(ctx) : parseInlineTable(ctx);
    ctx.d++;
    return value;
  }
  if (c === 34 || c === 39) {
    return parseString(ctx);
  }
  if (c === 116) {
    if (ctx.s.charCodeAt(++ctx.p) !== 114 || ctx.s.charCodeAt(++ctx.p) !== 117 || ctx.s.charCodeAt(++ctx.p) !== 101)
      TomlError.x("invalid value", ctx, errPtr);
    return ctx.p++, true;
  }
  if (c === 102) {
    if (ctx.s.charCodeAt(++ctx.p) !== 97 || ctx.s.charCodeAt(++ctx.p) !== 108 || ctx.s.charCodeAt(++ctx.p) !== 115 || ctx.s.charCodeAt(++ctx.p) !== 101)
      TomlError.x("invalid value", ctx, errPtr);
    return ctx.p++, false;
  }
  if (c === 43 || c === 45) {
    return parseNumber(ctx, ctx.p, ctx.s.charCodeAt(++ctx.p), 44 - c, end);
  }
  if (ctx.s.charCodeAt(ctx.p + 4) === 45 && ctx.s.charCodeAt(ctx.p + 7) === 45) {
    return parseDate(ctx, c, end);
  }
  if (ctx.s.charCodeAt(ctx.p + 2) === 58) {
    return parseTime(ctx, c, end);
  }
  return parseNumber(ctx, ctx.p, c, 0, end);
}
function parseNumber(ctx, startPtr, startChr, sign2, endChr) {
  let c = startChr;
  let state = 0;
  let hasUnderscores = false;
  if (c === 105) {
    if (ctx.s.charCodeAt(++ctx.p) !== 110 || ctx.s.charCodeAt(++ctx.p) !== 102)
      TomlError.x("invalid value", ctx, startPtr);
    return ctx.p++, (sign2 || 1) / 0;
  }
  if (c === 110) {
    if (ctx.s.charCodeAt(++ctx.p) !== 97 || ctx.s.charCodeAt(++ctx.p) !== 110)
      TomlError.x("invalid value", ctx, startPtr);
    return ctx.p++, NaN;
  }
  if (c === 48) {
    if (++ctx.p >= ctx.s.length || isEndOfValue(c = ctx.s.charCodeAt(ctx.p), endChr))
      return ctx.bi === true ? 0n : 0;
    if (!sign2) {
      if (c === 120)
        return parseIntegerBaseN(ctx, startPtr, 16, endChr);
      else if (c === 98)
        return parseIntegerBaseN(ctx, startPtr, 2, endChr);
      else if (c === 111)
        return parseIntegerBaseN(ctx, startPtr, 8, endChr);
    }
    if (c === 46)
      state = 2;
    else if (c === 101 || c === 69)
      state = 4;
    else
      TomlError.x("illegal leading zero", ctx, startPtr);
  } else if (!isDigit2(c))
    TomlError.x("invalid value", ctx, startPtr);
  while (++ctx.p < ctx.s.length && (c = ctx.s.charCodeAt(ctx.p), !isEndOfValue(c, endChr))) {
    if (!state)
      state = 1;
    if (c === 95) {
      if (!(state & 1))
        TomlError.x("illegal underscore", ctx);
      state += 11;
      hasUnderscores = true;
    } else if (state === 1 && c === 46)
      state = 2;
    else if ((state === 1 || state === 3) && (c === 101 || c === 69))
      state = 4;
    else if (state === 4 && (c === 43 || c === 45)) {
      state = 6;
    } else if (!isDigit2(c))
      TomlError.x(`illegal character in numeric literal`, ctx);
    else if (state > 9)
      state -= 11;
    else if (!(state & 1))
      state++;
  }
  if (!state) {
    let val = (startChr - 48) * (sign2 || 1);
    return ctx.bi === true ? BigInt(val) : val;
  }
  if (!(state & 1))
    TomlError.x("unfinished numeric value", ctx, startPtr);
  let str2 = ctx.s.slice(startPtr, ctx.p);
  if (hasUnderscores)
    str2 = str2.replaceAll("_", "");
  return state > 1 ? parseFloat(str2) : parseInteger(ctx, str2, 10, startPtr);
}
function parseIntegerBaseN(ctx, startPtr, base, endChr) {
  let c, underscore = 1;
  while (++ctx.p < ctx.s.length && (c = ctx.s.charCodeAt(ctx.p), !isEndOfValue(c, endChr))) {
    if (c === 95) {
      if (underscore & 1)
        TomlError.x("illegal underscore", ctx);
      underscore = 3;
    } else if (!isDigit2(c, base))
      TomlError.x(`illegal character in numeric literal`, ctx);
    else if (underscore & 1)
      underscore--;
  }
  if (underscore & 1)
    TomlError.x("unfinished numeric value", ctx);
  let str2 = ctx.s.slice(startPtr + 2, ctx.p);
  if (underscore)
    str2 = str2.replaceAll("_", "");
  return parseInteger(ctx, str2, base, startPtr);
}
function parseInteger(ctx, str2, base, startPtr) {
  if (ctx.bi !== true)
    int: {
      let val = parseInt(str2, base);
      if (!Number.isSafeInteger(val)) {
        if (ctx.bi)
          break int;
        TomlError.x("integer value cannot be represented losslessly", ctx, startPtr);
      }
      return val;
    }
  return base === 10 ? BigInt(str2) : BigInt((base === 2 ? "0b" : base === 8 ? "0o" : "0x") + str2);
}
function parseDate(ctx, c, endChr) {
  let startPtr = ctx.p++, unsafeSeparator;
  if (!isDigit2(c) || !isDigit2(ctx.s.charCodeAt(ctx.p++)) || !isDigit2(ctx.s.charCodeAt(ctx.p++)) || !isDigit2(ctx.s.charCodeAt(ctx.p++))) {
    return parseNumber(ctx, ctx.p = startPtr, c, 0, endChr);
  }
  ctx.p += 5;
  if (!isDigit2(ctx.s.charCodeAt(ctx.p++)))
    TomlError.x("invalid date-time: date part is malformed", ctx, startPtr);
  if (ctx.p >= ctx.s.length || ((c = ctx.s.charCodeAt(ctx.p)) !== 32 || (unsafeSeparator = true, !isDigit2(ctx.s.charCodeAt(ctx.p + 1)))) && c !== 84 && c !== 116) {
    let t2 = ctx.s.slice(startPtr, ctx.p);
    return readDate(ctx, t2, 3, false, startPtr);
  }
  if (ctx.s.charCodeAt(ctx.p += 3) !== 58)
    TomlError.x("invalid date-time: time part is malformed", ctx, startPtr);
  if (ctx.s.charCodeAt(ctx.p += 3) === 58)
    ctx.p += 3;
  if (ctx.s.charCodeAt(ctx.p) === 46)
    while (isDigit2(ctx.s.charCodeAt(++ctx.p)))
      ;
  if (c = ctx.s.charCodeAt(ctx.p)) {
    if (c === 90 || c === 122) {
      let t2 = ctx.s.slice(startPtr, ++ctx.p);
      return readDate(ctx, t2, 1, unsafeSeparator, startPtr, "[+00:00]");
    }
    if (c === 43 || c === 45) {
      let t2 = ctx.s.slice(startPtr, ctx.p += 6);
      return readDate(ctx, t2, 1, unsafeSeparator, startPtr, !ctx.ld && "[" + ctx.s.slice(ctx.p - 6, ctx.p) + "]");
    }
  }
  let t = ctx.s.slice(startPtr, ctx.p);
  return readDate(ctx, t, 2, unsafeSeparator, startPtr);
}
function parseTime(ctx, c, endChr) {
  let start = ctx.p;
  if (!isDigit2(c) || !isDigit2(ctx.s.charCodeAt(++ctx.p))) {
    return parseNumber(ctx, --ctx.p, c, 0, endChr);
  }
  if (ctx.s.charCodeAt(ctx.p += 4) === 58)
    ctx.p += 3;
  if (ctx.s.charCodeAt(ctx.p) === 46)
    while (isDigit2(ctx.s.charCodeAt(++ctx.p)))
      ;
  let t = ctx.s.slice(start, ctx.p);
  return readDate(ctx, t, 4, false, start);
}
function readDate(ctx, str2, type, unsafeDelim, errPtr, temporalSuffix) {
  if (ctx.ld) {
    let date = new TomlDate(str2, type, unsafeDelim);
    if (!date.isValid())
      TomlError.x("invalid date", ctx, errPtr);
    return date;
  }
  try {
    if (temporalSuffix)
      str2 += temporalSuffix;
    switch (type) {
      case 1:
        return Temporal.ZonedDateTime.from(str2);
      case 2:
        return Temporal.PlainDateTime.from(str2);
      case 3:
        return Temporal.PlainDate.from(str2);
      case 4:
        return Temporal.PlainTime.from(str2);
    }
  } catch (e) {
    TomlError.x(e instanceof Error ? e.message : "" + e, ctx, errPtr);
  }
}

// node_modules/smol-toml/dist/util.js
function skipComment(ctx) {
  for (; ctx.p < ctx.s.length; ctx.p++) {
    let c = ctx.s.charCodeAt(ctx.p);
    if (c === 10)
      break;
    if (c === 13 && ctx.s.charCodeAt(ctx.p + 1) === 10) {
      ctx.p++;
      break;
    }
    if (c < 32 && c !== 9 || c === 127) {
      TomlError.x("control characters are not allowed in comments", ctx);
    }
  }
}
function skipVoid(ctx, banNewLines, banComments) {
  let c;
  while (ctx.p < ctx.s.length) {
    while (ctx.p < ctx.s.length && ((c = ctx.s.charCodeAt(ctx.p)) === 32 || c === 9 || !banNewLines && (c === 10 || c === 13 && ctx.s.charCodeAt(ctx.p + 1) === 10)))
      ctx.p++;
    if (banComments || c !== 35)
      break;
    skipComment(ctx);
  }
}

// node_modules/smol-toml/dist/struct.js
function parseKey(ctx, end = 61) {
  let startPtr;
  let state = 0;
  let parsed = [];
  let sliceStart;
  let c = ctx.s.charCodeAt(startPtr = ctx.p);
  do {
    if (c === end) {
      if (!state)
        TomlError.x("unexpected end of key", ctx);
      if (state === 1)
        parsed.push(ctx.s.slice(sliceStart, ctx.p));
      return ctx.p++, parsed;
    } else if (c === 46) {
      if (!state)
        TomlError.x("illegal empty bare key", ctx);
      if (state === 1)
        parsed.push(ctx.s.slice(sliceStart, ctx.p));
      state = 0;
    } else if (!state && (c === 34 || c === 39)) {
      if (c === ctx.s.charCodeAt(ctx.p + 1) && c === ctx.s.charCodeAt(ctx.p + 2))
        TomlError.x("illegal quoted key: multiline strings are not allowed", ctx);
      parsed.push(parseString(ctx));
      state = 2;
      ctx.p--;
    } else if (c === 32 || c === 9) {
      if (state === 1) {
        parsed.push(ctx.s.slice(sliceStart, ctx.p));
        state = 2;
      }
    } else if (state === 2 || c < 48 && c !== 45 || c > 57 && c < 65 || c > 90 && c < 97 && c !== 95 || c > 122) {
      TomlError.x("illegal character in key", ctx);
    } else if (!state) {
      state = 1;
      sliceStart = ctx.p;
    }
  } while (c = ctx.s.charCodeAt(++ctx.p));
  TomlError.x("incomplete key-value: cannot find end of key", ctx, startPtr);
}
function parseInlineTable(ctx) {
  let startPtr = ctx.p++;
  let res = /* @__PURE__ */ Object.create(null);
  let seen = /* @__PURE__ */ new Set();
  let c;
  while (ctx.p < ctx.s.length) {
    skipVoid(ctx);
    if ((c = ctx.s.charCodeAt(ctx.p)) === 125) {
      ctx.p++;
      return res;
    }
    let k;
    let t = res;
    let hasOwn = false;
    let errPtr = ctx.p;
    let key = parseKey(ctx);
    for (let i = 0; i < key.length; i++) {
      if (i)
        t = hasOwn ? t[k] : t[k] = /* @__PURE__ */ Object.create(null);
      k = key[i];
      if ((hasOwn = Object.hasOwn(t, k)) && (typeof t[k] !== "object" || seen.has(t[k]))) {
        TomlError.x("trying to redefine an already defined value", ctx, errPtr);
      }
      let unsafe = k === "__proto__";
      if (ctx.uk && (unsafe || k === "constructor")) {
        t = ctx.uk !== 1 && TomlError.x("document contains an unsafe property", ctx, errPtr);
        break;
      }
      if (!hasOwn && unsafe) {
        Object.defineProperty(t, k, { enumerable: true, configurable: true, writable: true });
      }
    }
    if (hasOwn) {
      TomlError.x("trying to redefine an already defined value", ctx, errPtr);
    }
    skipVoid(ctx, true, true);
    let value = extractValue(
      ctx,
      125
      /* } */
    );
    if (t && typeof (t[k] = value) === "object")
      seen.add(value);
    skipVoid(ctx);
    if ((c = ctx.s.charCodeAt(ctx.p++)) === 125) {
      return res;
    }
    if (c !== 44)
      TomlError.x("expected comma or end of structure", ctx, ctx.p - 1);
  }
  TomlError.x("unfinished table", ctx, startPtr);
}
function parseArray(ctx) {
  let startPtr = ctx.p++;
  let res = [];
  let c;
  while (ctx.p < ctx.s.length) {
    skipVoid(ctx);
    if ((c = ctx.s.charCodeAt(ctx.p)) === 93) {
      ctx.p++;
      return res;
    }
    res.push(extractValue(
      ctx,
      93
      /* ] */
    ));
    skipVoid(ctx);
    if ((c = ctx.s.charCodeAt(ctx.p++)) === 93) {
      return res;
    }
    if (c !== 44)
      TomlError.x("expected comma or end of structure", ctx, ctx.p - 1);
  }
  TomlError.x("unfinished array", ctx, startPtr);
}

// node_modules/smol-toml/dist/parse.js
function peekTable(ctx, key, table, meta, type) {
  let t = table;
  let m = meta;
  let k;
  let hasOwn = false;
  let state;
  for (let i = 0; i < key.length; i++) {
    if (i) {
      t = hasOwn ? t[k] : t[k] = /* @__PURE__ */ Object.create(null);
      m = (state = m[k]).c;
      if (type === 0 && (state.t === 1 || state.t === 2)) {
        return null;
      }
      if (state.t === 2) {
        let l = t.length - 1;
        t = t[l];
        m = m[l].c;
      }
    }
    k = key[i];
    if ((hasOwn = Object.hasOwn(t, k)) && m[k]?.t === 0 && m[k]?.d) {
      return null;
    }
    if (!hasOwn) {
      let unsafe = k === "__proto__";
      if (ctx.uk && (unsafe || k === "constructor"))
        return false;
      if (unsafe) {
        Object.defineProperty(t, k, { enumerable: true, configurable: true, writable: true });
        Object.defineProperty(m, k, { enumerable: true, configurable: true, writable: true });
      }
      m[k] = {
        t: i < key.length - 1 && type === 2 ? 3 : type,
        d: false,
        i: 0,
        c: /* @__PURE__ */ Object.create(null)
      };
    }
  }
  state = m[k];
  if (state.t !== type && !(type === 1 && state.t === 3)) {
    return null;
  }
  if (type === 2) {
    if (!state.d) {
      state.d = true;
      t[k] = [];
    }
    t[k].push(t = /* @__PURE__ */ Object.create(null));
    state.c[state.i++] = state = { t: 1, d: false, i: 0, c: /* @__PURE__ */ Object.create(null) };
  }
  if (state.d) {
    return null;
  }
  state.d = true;
  if (type === 1) {
    t = hasOwn ? t[k] : t[k] = /* @__PURE__ */ Object.create(null);
  } else if (type === 0 && hasOwn) {
    return null;
  }
  return [k, t, state.c];
}
function validateTablePeek(ctx, peek, ptr) {
  if (peek === null || ctx.uk === 2)
    TomlError.x(peek === null ? "trying to redefine an already defined table or value" : "document contains an unsafe property", ctx, ptr);
}
function parse(toml, options = {}) {
  let ctx = {
    s: toml,
    p: 0,
    d: options.maxDepth ?? 1e3,
    bi: options.integersAsBigInt ?? false,
    ld: options.useLegacyDate ?? true,
    uk: options.unsafeKeyBehaviour === "throw" ? 2 : options.unsafeKeyBehaviour === "drop" ? 1 : 0
  };
  let res = /* @__PURE__ */ Object.create(null);
  let meta = /* @__PURE__ */ Object.create(null);
  let tmp;
  let skipping = false;
  let tbl = res;
  let m = meta;
  if (toml.charCodeAt(0) === 65279)
    ctx.p++;
  skipVoid(ctx);
  while (ctx.p < toml.length) {
    if (toml.charCodeAt(ctx.p) === 91) {
      let isTableArray = toml.charCodeAt(++ctx.p) === 91;
      tmp = ctx.p += +isTableArray;
      skipping = false;
      let k = parseKey(
        ctx,
        93
        /* ] */
      );
      if (isTableArray) {
        if (toml.charCodeAt(ctx.p) !== 93) {
          TomlError.x("expected end of table array declaration", ctx);
        }
        ctx.p++;
      }
      let p = peekTable(
        ctx,
        k,
        res,
        meta,
        isTableArray ? 2 : 1
        /* Type.EXPLICIT */
      );
      if (!p) {
        validateTablePeek(ctx, p, tmp);
        skipping = true;
      } else {
        m = p[2];
        tbl = p[1];
      }
    } else {
      tmp = ctx.p;
      let k = parseKey(ctx);
      let p = peekTable(
        ctx,
        k,
        tbl,
        m,
        0
        /* Type.DOTTED */
      );
      if (!p && !skipping)
        validateTablePeek(ctx, p, tmp);
      skipVoid(ctx, true, true);
      let v = extractValue(ctx, void 0);
      if (p && !skipping)
        p[1][p[0]] = v;
    }
    skipVoid(ctx, true);
    if (ctx.p < toml.length && (tmp = toml.charCodeAt(ctx.p)) !== 10 && (tmp !== 13 || toml.charCodeAt(ctx.p + 1) !== 10)) {
      TomlError.x("each key-value declaration must be followed by an end-of-line", ctx);
    }
    skipVoid(ctx);
  }
  return res;
}

// node_modules/smol-toml/dist/stringify.js
var HAS_WELLFORMED = !!"".isWellFormed;

// gate/src/integrity.ts
var isPlain4 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var own3 = (o, k) => Object.hasOwn(o, k) ? o[k] : void 0;
var posInt3 = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
var natInt2 = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
var SHA_RE4 = /^[0-9a-f]{40}$/;
var API_FILE_CAP = 3e3;
var PER_PAGE = 100;
var COMPARE_FILE_CAP = 300;
var MAX_PATCH_CHARS = 2 * 1024 * 1024;
var MAX_FILE_BYTES = 1024 * 1024;
var MAX_CODEOWNERS_BYTES = 3 * 1024 * 1024;
var MAX_APPROVERS = 30;
var anyDepth = (p) => p.startsWith("/") ? p.slice(1) : p.includes("/") ? p : `**/${p}`;
function pathMatcher(patterns) {
  if (patterns.length === 0) return () => false;
  return (0, import_picomatch.default)(patterns.map(anyDepth), { nocase: true, dot: true });
}
var LOCKFILES = /* @__PURE__ */ new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "poetry.lock", "uv.lock", "cargo.lock", "go.sum", "composer.lock", "gemfile.lock"]);
var BINARY_EXT = /* @__PURE__ */ new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "ico",
  "bmp",
  "tif",
  "tiff",
  "avif",
  "heic",
  "woff",
  "woff2",
  "ttf",
  "otf",
  "eot",
  "zip",
  "gz",
  "tgz",
  "bz2",
  "xz",
  "zst",
  "7z",
  "rar",
  "tar",
  "jar",
  "war",
  "pdf",
  "mp3",
  "mp4",
  "mov",
  "webm",
  "wav",
  "ogg",
  "flac",
  "avi",
  "wasm",
  "so",
  "dll",
  "exe",
  "dylib",
  "bin",
  "class",
  "pyc",
  "o",
  "a",
  "sqlite",
  "sqlite3",
  "psd"
]);
var baseName = (path) => path.slice(path.lastIndexOf("/") + 1);
var isLockfile = (path) => LOCKFILES.has(baseName(path).toLowerCase());
var isBinary = (path) => {
  const n = baseName(path).toLowerCase();
  const i = n.lastIndexOf(".");
  return i > 0 && BINARY_EXT.has(n.slice(i + 1));
};
var SCANNED_EXTENSIONS = /* @__PURE__ */ new Set([
  "js",
  "mjs",
  "cjs",
  "jsx",
  "ts",
  "mts",
  "cts",
  "tsx",
  "vue",
  "svelte",
  "astro",
  "py",
  "pyi",
  "pyw",
  "go",
  "java",
  "kt",
  "kts",
  "scala",
  "rb",
  "php",
  "cs",
  "swift",
  "rs",
  "c",
  "h",
  "cc",
  "cpp",
  "cxx",
  "hpp",
  "m",
  "sh",
  "bash",
  "ex",
  "exs",
  "lua",
  "dart",
  "tf",
  "hcl",
  "yaml",
  "yml",
  "json",
  "html",
  "erb",
  "sol"
]);
function caseVariantExtension(path) {
  const n = baseName(path);
  const i = n.lastIndexOf(".");
  if (i <= 0) return void 0;
  const ext = n.slice(i + 1);
  return ext !== ext.toLowerCase() && SCANNED_EXTENSIONS.has(ext.toLowerCase()) ? ext : void 0;
}
var IGNORE_FILE_RE = /^\.[^/]*ignore[^/]*$/i;
var MARKERS = [
  { name: "nosemgrep", re: /nosem/i },
  { name: "gitleaks:allow", re: /gitleaks:allow/i },
  { name: "trivy:ignore", re: /trivy:ignore/i },
  { name: "noqa", re: /\bnoqa\b/i },
  // bare, or with codes; `# noqa: E501` alone is not a security suppression (see MARKER_EXEMPT)
  { name: "eslint-disable", re: /eslint-disable/i },
  { name: "eslint config comment", re: /\/\*\s*eslint\s/i },
  { name: "hadolint ignore", re: /#\s*hadolint\s+(?:global\s+)?ignore/i },
  { name: "kube-linter ignore", re: /ignore-check\.kube-linter\.io/i },
  { name: "mypy ignore-errors", re: /#\s*mypy:\s*ignore-errors/i },
  { name: "nosec", re: /\bnosec\b/i },
  { name: "checkov:skip", re: /checkov:skip/i },
  { name: "tfsec:ignore", re: /tfsec:ignore/i },
  { name: "betterleaks:allow", re: /betterleaks:allow/i },
  { name: "biome-ignore", re: /biome-ignore/i },
  { name: "oxlint-disable", re: /oxlint-disable/i },
  { name: "ruff suppression", re: /#\s*ruff:\s*(?:noqa|disable)/i },
  { name: "coverage ignore", re: /(?:istanbul|c8|v8)\s+ignore|pragma:\s*no\s*cover/i },
  { name: "type ignore", re: /#\s*type:\s*ignore|@ts-(?:ignore|expect-error|nocheck)/i },
  { name: "zizmor ignore", re: /zizmor:\s*ignore/i }
];
var NEXT_LINE_RE = /nosem|eslint-disable-next-line|oxlint-disable-next-line|hadolint\s+ignore|trivy:ignore|@ts-ignore|@ts-expect-error|biome-ignore|(?:istanbul|c8|v8)\s+ignore\s+next|checkov:skip|tfsec:ignore/i;
function noqaIsSecurity(line) {
  for (const m of line.matchAll(/\bnoqa\b(?:\s*:\s*([A-Za-z0-9, \t]*))?/gi)) {
    if (m[1] === void 0 || m[1].trim() === "") return true;
    if (/(^|[\s,])S\d/i.test(m[1])) return true;
  }
  return false;
}
function markersOf(line) {
  const out = [];
  for (const m of MARKERS) {
    if (!m.re.test(line)) continue;
    if (m.name === "noqa" && !noqaIsSecurity(line)) continue;
    out.push(m.name);
  }
  return out;
}
var HUNK_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;
function parsePatch(patch) {
  if (patch.length > MAX_PATCH_CHARS) return null;
  const lines = patch.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  const added = [];
  const context = /* @__PURE__ */ new Map();
  let i = 0;
  while (i < lines.length) {
    const m = HUNK_RE.exec(lines[i]);
    if (m === null) return null;
    let oldLeft = m[2] === void 0 ? 1 : Number(m[2]);
    let newLeft = m[4] === void 0 ? 1 : Number(m[4]);
    let newNo = Number(m[3]);
    i++;
    while (oldLeft > 0 || newLeft > 0) {
      if (i >= lines.length) return null;
      const l = lines[i++];
      const c = l[0];
      if (c === "+") {
        if (newLeft <= 0) return null;
        added.push({ no: newNo, text: l.slice(1) });
        newNo++;
        newLeft--;
      } else if (c === "-") {
        if (oldLeft <= 0) return null;
        oldLeft--;
      } else if (c === " ") {
        if (oldLeft <= 0 || newLeft <= 0) return null;
        context.set(newNo, l.slice(1));
        oldLeft--;
        newLeft--;
        newNo++;
      } else if (c === "\\") continue;
      else return null;
    }
    while (i < lines.length && lines[i][0] === "\\") i++;
  }
  return { added, context };
}
function plusLines(patch) {
  const out = [];
  for (const l of patch.split("\n")) if (l[0] === "+") out.push(l.slice(1));
  return out;
}
var needsPatch = (f) => f.changes > 0 && f.status !== "removed" && !isBinary(f.filename);
var needsPatchForDiff = (f) => f.changes > 0 && f.status !== "removed";
function addedLinesOf(files) {
  const added = /* @__PURE__ */ new Map();
  const problems = [];
  let complete = true;
  for (const f of files) {
    if (typeof f.patch !== "string" || f.patch === "") {
      if (needsPatchForDiff(f)) {
        complete = false;
        problems.push("a changed file has no patch");
      }
      continue;
    }
    const parsed = parsePatch(f.patch);
    if (parsed === null) {
      complete = false;
      problems.push("a patch could not be read");
      continue;
    }
    if (parsed.added.length === 0) continue;
    let set = added.get(f.filename);
    if (set === void 0) {
      set = /* @__PURE__ */ new Set();
      added.set(f.filename, set);
    }
    for (const a of parsed.added) set.add(a.no);
  }
  return { added, complete, problems: [...new Set(problems)] };
}
function readFile(entry) {
  if (!isPlain4(entry)) return void 0;
  const filename = own3(entry, "filename");
  const status = own3(entry, "status");
  const changes = own3(entry, "changes");
  const prev = own3(entry, "previous_filename");
  const patch = own3(entry, "patch");
  if (typeof filename !== "string" || filename === "" || typeof status !== "string" || !natInt2(changes)) return void 0;
  if (prev !== void 0 && (typeof prev !== "string" || prev === "")) return void 0;
  return { filename, status, changes, ...prev === void 0 ? {} : { previous_filename: prev }, ...typeof patch === "string" ? { patch } : {} };
}
var REVIEW_STATES_IGNORED = /* @__PURE__ */ new Set(["COMMENTED", "PENDING"]);
async function readPrContext(gh, repo2, prNumber, opts) {
  const pr = { number: prNumber, headSha: "", baseSha: "", isFork: true, files: [], filesComplete: false, approvals: [], approvalsComplete: false, problems: [] };
  let pull;
  try {
    pull = await gh.getPull(repo2.owner, repo2.name, prNumber);
  } catch {
    pr.problems.push("the pull request could not be read");
    return pr;
  }
  if (!isPlain4(pull)) {
    pr.problems.push("the pull request answer is not an object");
    return pr;
  }
  const head = own3(pull, "head");
  const base = own3(pull, "base");
  const headSha = isPlain4(head) ? own3(head, "sha") : void 0;
  const baseSha = isPlain4(base) ? own3(base, "sha") : void 0;
  const changed = own3(pull, "changed_files");
  if (own3(pull, "number") !== prNumber || typeof headSha !== "string" || !SHA_RE4.test(headSha) || typeof baseSha !== "string" || !SHA_RE4.test(baseSha) || !natInt2(changed)) {
    pr.problems.push("the pull request answer is malformed");
    return pr;
  }
  pr.headSha = headSha;
  pr.baseSha = baseSha;
  const headRepo = isPlain4(head) ? own3(head, "repo") : void 0;
  pr.isFork = !(isPlain4(headRepo) && own3(headRepo, "id") === repo2.id);
  const author = isPlain4(own3(pull, "user")) ? own3(own3(pull, "user"), "login") : void 0;
  let filesOk = true;
  for (let page2 = 1; page2 <= API_FILE_CAP / PER_PAGE; page2++) {
    let answer;
    try {
      answer = await gh.listPullFiles(repo2.owner, repo2.name, prNumber, page2, PER_PAGE);
    } catch {
      filesOk = false;
      pr.problems.push("the list of changed files could not be read");
      break;
    }
    if (!Array.isArray(answer)) {
      filesOk = false;
      pr.problems.push("the list of changed files is not a list");
      break;
    }
    for (const e of answer) {
      const f = readFile(e);
      if (f === void 0) {
        filesOk = false;
        pr.problems.push("a changed file entry is malformed");
      } else pr.files.push(f);
    }
    if (answer.length < PER_PAGE) break;
  }
  if (filesOk && pr.files.length >= API_FILE_CAP) {
    filesOk = false;
    pr.problems.push(`the pull request has ${API_FILE_CAP} files or more, the most the API lists`);
  }
  if (filesOk && pr.files.length !== changed) {
    filesOk = false;
    pr.problems.push(`the list has ${pr.files.length} files, the pull request says ${changed}`);
  }
  if (opts.expectHeadSha !== void 0 && opts.expectHeadSha !== headSha) {
    filesOk = false;
    pr.problems.push("the pull request head moved since the event; re-run the gate");
  }
  pr.filesComplete = filesOk;
  pr.problems = [...new Set(pr.problems)];
  const reviews = [];
  let reviewsOk = true;
  for (let page2 = 1; page2 <= API_FILE_CAP / PER_PAGE + 1; page2++) {
    let answer;
    try {
      answer = await gh.listPullReviews(repo2.owner, repo2.name, prNumber, page2, PER_PAGE);
    } catch {
      reviewsOk = false;
      pr.problems.push("the reviews could not be read");
      break;
    }
    if (!Array.isArray(answer)) {
      reviewsOk = false;
      pr.problems.push("the reviews are not a list");
      break;
    }
    for (const r of answer) {
      if (!isPlain4(r) || !posInt3(own3(r, "id"))) continue;
      const user = own3(r, "user");
      const login = isPlain4(user) ? own3(user, "login") : void 0;
      const state = own3(r, "state");
      if (typeof login !== "string" || login === "" || typeof state !== "string") continue;
      reviews.push({ id: own3(r, "id"), login: login.toLowerCase(), state, commit: own3(r, "commit_id") });
    }
    if (answer.length < PER_PAGE) break;
    if (page2 === API_FILE_CAP / PER_PAGE + 1) {
      reviewsOk = false;
      pr.problems.push("the reviews were cut at the page cap");
    }
  }
  pr.approvalsComplete = reviewsOk;
  if (!reviewsOk) return pr;
  if (opts.expectHeadSha !== void 0 && opts.expectHeadSha !== headSha) return pr;
  const latest = /* @__PURE__ */ new Map();
  for (const r of reviews) {
    if (REVIEW_STATES_IGNORED.has(r.state)) continue;
    const cur = latest.get(r.login);
    if (cur === void 0 || r.id > cur.id) latest.set(r.login, r);
  }
  const ownerLogins = new Set((Array.isArray(opts.codeowners) ? opts.codeowners : []).flatMap((r) => r.owners));
  const authorLogin = typeof author === "string" ? author.toLowerCase() : "";
  const candidates = [...latest].filter(([login, r]) => r.state === "APPROVED" && r.commit === headSha && login !== authorLogin && ownerLogins.has(login)).map(([login]) => login).sort();
  if (candidates.length > MAX_APPROVERS) pr.problems.push(`more than ${MAX_APPROVERS} code-owner approvers; only the first ${MAX_APPROVERS} were checked`);
  for (const login of candidates.slice(0, MAX_APPROVERS)) {
    try {
      const a = await gh.collaboratorPermission(repo2.owner, repo2.name, login);
      const perm = isPlain4(a) ? own3(a, "permission") : void 0;
      const role = isPlain4(a) ? own3(a, "role_name") : void 0;
      if (perm === "admin" || perm === "write" || role === "maintain" || role === "admin" || role === "write") pr.approvals.push(login);
    } catch {
      pr.problems.push(`approval by ${login.replace(/[^a-z0-9-]/g, "?").slice(0, 39)} not counted: could not read their permission`);
    }
  }
  return pr;
}
async function readTextAt(gh, repo2, path, ref2, opts = {}) {
  const max = opts.max ?? MAX_FILE_BYTES;
  if (!SHA_RE4.test(ref2)) return { kind: "problem", why: "the commit is not a commit sha" };
  let a;
  try {
    a = await gh.fileAt(repo2.owner, repo2.name, path, ref2);
  } catch {
    return { kind: "problem", why: "the file could not be read" };
  }
  if (a === null) return { kind: "missing" };
  if (!isPlain4(a) || own3(a, "type") !== "file") return { kind: "problem", why: "the answer is not a file" };
  const size = own3(a, "size");
  const content = own3(a, "content");
  if (!natInt2(size) || size > max) return { kind: "problem", why: "the file is over the size cap" };
  if (own3(a, "encoding") === "none" && opts.raw === true && size > MAX_FILE_BYTES) {
    let raw;
    try {
      raw = await gh.rawFileAt(repo2.owner, repo2.name, path, ref2);
    } catch {
      return { kind: "problem", why: "the file could not be read" };
    }
    const bytes2 = typeof raw === "string" ? Buffer.from(raw, "utf8") : raw instanceof Uint8Array ? raw : void 0;
    if (bytes2 === void 0) return { kind: "problem", why: "the file content is not readable" };
    if (bytes2.length > max) return { kind: "problem", why: "the file is over the size cap" };
    return { kind: "text", text: Buffer.from(bytes2).toString("utf8") };
  }
  if (own3(a, "encoding") !== "base64" || typeof content !== "string" || size > MAX_FILE_BYTES) return { kind: "problem", why: size > MAX_FILE_BYTES ? "the file is over the size cap" : "the file content is not readable" };
  const bytes = Buffer.from(content.replace(/\s+/g, ""), "base64");
  if (bytes.length > MAX_FILE_BYTES) return { kind: "problem", why: "the file is over the size cap" };
  return { kind: "text", text: bytes.toString("utf8") };
}
async function baseHasInstall(gh, repo2, baseSha) {
  if (typeof baseSha !== "string" || !SHA_RE4.test(baseSha)) return true;
  try {
    return await gh.fileAt(repo2.owner, repo2.name, WORKFLOW_PATH, baseSha) !== null;
  } catch {
    return true;
  }
}
var MAX_RULES = 1e5;
var MAX_LINE = 4096;
var TEAM_RE = /^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]+$/;
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
var LOGIN_RE = /^@([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)$/;
function tokens(line) {
  const out = [];
  let cur = "";
  let started = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "\\" && line[i + 1] === " ") {
      cur += " ";
      started = true;
      i++;
      continue;
    }
    if (c === " " || c === "	") {
      if (started) {
        out.push(cur);
        cur = "";
        started = false;
      }
      continue;
    }
    if (!started && c === "#") break;
    cur += c;
    started = true;
  }
  if (started) out.push(cur);
  return out;
}
function codeOwners(text) {
  if (typeof text !== "string") return [];
  const rules = [];
  for (const raw of text.split(/\r?\n/)) {
    if (rules.length >= MAX_RULES) break;
    if (raw.length > MAX_LINE) continue;
    const t = tokens(raw.trim());
    const pattern = t[0];
    if (pattern === void 0) continue;
    if (pattern.startsWith("!") || pattern.startsWith("\\#") || /[[\]]/.test(pattern)) continue;
    if (pattern.replace(/\//g, "") === "" || pattern.includes("//")) continue;
    const owners = [];
    let valid = true;
    for (const o of t.slice(1)) {
      const m = LOGIN_RE.exec(o);
      if (m !== null) owners.push(m[1].toLowerCase());
      else if (!TEAM_RE.test(o) && !EMAIL_RE.test(o)) {
        valid = false;
        break;
      }
    }
    if (valid) rules.push({ pattern, owners });
  }
  return rules;
}
var compiled = /* @__PURE__ */ new WeakMap();
function compile(rule) {
  const got = compiled.get(rule);
  if (got !== void 0) return got;
  let p = rule.pattern;
  const dirOnly = p.endsWith("/");
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith("/") || p.includes("/");
  if (p.startsWith("/")) p = p.slice(1);
  let parts = p.split("/");
  if (!anchored) parts = ["**", ...parts];
  const segs = parts.map((part, idx) => {
    if (part === "**") return idx === parts.length - 1 ? { kind: "globstar+" } : { kind: "globstar" };
    const toks = [];
    for (let i = 0; i < part.length; i++) {
      const c2 = part[i];
      if (c2 === "\\" && i + 1 < part.length) {
        toks.push(part[++i]);
        continue;
      }
      if (c2 === "*") {
        if (toks[toks.length - 1] !== "*") toks.push("*");
        continue;
      }
      toks.push(c2 === "?" ? "?" : c2);
    }
    return { kind: "glob", toks };
  });
  const last = parts[parts.length - 1];
  const ancestors = dirOnly || !/[*?]/.test(last);
  const c = { segs, dirOnly, ancestors };
  compiled.set(rule, c);
  return c;
}
function segMatch(toks, s) {
  let t = 0;
  let i = 0;
  let star = -1;
  let mark = 0;
  while (i < s.length) {
    const k = toks[t];
    if (k === "*") {
      star = t++;
      mark = i;
    } else if (k !== void 0 && (k === "?" || k === s[i])) {
      t++;
      i++;
    } else if (star >= 0) {
      t = star + 1;
      i = ++mark;
    } else return false;
  }
  while (toks[t] === "*") t++;
  return t === toks.length;
}
function matchesPrefix(c, parts, end) {
  const memo = /* @__PURE__ */ new Map();
  const go = (pi, si) => {
    const key = pi * (end + 1) + si;
    const hit = memo.get(key);
    if (hit !== void 0) return hit;
    let r;
    const seg = c.segs[pi];
    if (seg === void 0) r = si === end;
    else if (seg.kind === "globstar+") r = si < end;
    else if (seg.kind === "globstar") {
      r = false;
      for (let j = si; j <= end && !r; j++) r = go(pi + 1, j);
    } else r = si < end && segMatch(seg.toks, parts[si]) && go(pi + 1, si + 1);
    memo.set(key, r);
    return r;
  };
  return go(0, 0);
}
function ruleMatches(rule, parts) {
  const c = compile(rule);
  for (let k = 1; k <= parts.length; k++) {
    if (k === parts.length) {
      if (!c.dirOnly && matchesPrefix(c, parts, k)) return true;
    } else if (c.ancestors && matchesPrefix(c, parts, k)) return true;
  }
  return false;
}
function ownersOf(rules, path) {
  const parts = path.split("/");
  if (parts.length > 256 || parts.includes("")) return void 0;
  let owners;
  for (const r of rules) if (ruleMatches(r, parts)) owners = r.owners;
  return owners;
}
var PIPEGEN_BLOCK_BEGIN = "# pipegen:begin";
var PIPEGEN_BLOCK_END = "# pipegen:end";
function pipegenBlockOwners(text) {
  if (typeof text !== "string") return [];
  const lines = text.split(/\r?\n/);
  const begins = lines.flatMap((l, i) => l === PIPEGEN_BLOCK_BEGIN ? [i] : []);
  const ends = lines.flatMap((l, i) => l === PIPEGEN_BLOCK_END ? [i] : []);
  if (begins.length !== 1 || ends.length !== 1 || ends[0] < begins[0]) return [];
  const inside = codeOwners(lines.slice(begins[0] + 1, ends[0]).join("\n"));
  return [...new Set(inside.flatMap((r) => r.owners))].sort();
}
async function loadCodeowners(gh, repo2, baseSha) {
  for (const path of [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]) {
    const r = await readTextAt(gh, repo2, path, baseSha, { max: MAX_CODEOWNERS_BYTES, raw: true });
    if (r.kind === "missing") continue;
    if (r.kind === "problem") return { rules: [], found: null, blockOwners: [], problem: `CODEOWNERS of the base commit could not be read (${r.why}); nobody can approve` };
    return { rules: codeOwners(r.text), found: path, blockOwners: pipegenBlockOwners(r.text) };
  }
  return { rules: [], found: null, blockOwners: [] };
}
var NonFinite = class {
  constructor(kind) {
    this.kind = kind;
  }
  kind;
};
var BigInteger = class {
  constructor(digits) {
    this.digits = digits;
  }
  digits;
};
var isTable = (v) => typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof NonFinite) && !(v instanceof BigInteger) && !(v instanceof Date);
function norm(v) {
  if (typeof v === "number") return Number.isFinite(v) ? v : new NonFinite(Number.isNaN(v) ? "nan" : v > 0 ? "inf" : "-inf");
  if (typeof v === "bigint") return new BigInteger(String(v));
  if (Array.isArray(v)) return v.map(norm);
  if (isTable(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])]));
  return v;
}
function canon(v) {
  if (v instanceof NonFinite) return `F:${v.kind}`;
  if (v instanceof BigInteger) return `I:${v.digits}`;
  if (v instanceof Date) return `D:${v.toISOString()}`;
  if (typeof v === "number") return `n:${Object.is(v, -0) ? "-0" : String(v)}`;
  if (typeof v === "string") return `s:${JSON.stringify(v)}`;
  if (typeof v === "boolean") return `b:${v}`;
  if (v === null || v === void 0) return "z";
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (isTable(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}=${canon(v[k])}`).join(",")}}`;
  return `?:${String(v)}`;
}
var INI_UNSAFE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufeff]|\r(?!\n)/;
function parseIni(text) {
  if (INI_UNSAFE.test(text)) return void 0;
  const sections = /* @__PURE__ */ new Map();
  const defaults = /* @__PURE__ */ new Map();
  let cur;
  let curName = "";
  let opt;
  let indentLevel = 0;
  const seen = /* @__PURE__ */ new Set();
  for (const line of text.split(/\r?\n/)) {
    const stripped = line.trim();
    const comment = stripped.startsWith("#") || stripped.startsWith(";");
    const value = comment ? "" : stripped;
    if (value === "") {
      if (!comment && cur !== void 0 && opt !== void 0) cur.get(opt)?.push("");
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (cur !== void 0 && opt !== void 0 && indent > indentLevel) {
      cur.get(opt)?.push(value);
      continue;
    }
    indentLevel = indent;
    const h = /^\[(.+)\]/.exec(value);
    if (h !== null) {
      const name = h[1];
      if (name === "DEFAULT") {
        cur = defaults;
        curName = name;
      } else {
        if (sections.has(name)) return void 0;
        cur = /* @__PURE__ */ new Map();
        sections.set(name, cur);
        curName = name;
      }
      opt = void 0;
      continue;
    }
    if (cur === void 0) return void 0;
    const o = /^(.*?)\s*[=:]\s*(.*)$/.exec(value);
    if (o === null) return void 0;
    const key = o[1].trimEnd().toLowerCase();
    if (key === "") return void 0;
    const id = `${curName}\0${key}`;
    if (seen.has(id)) return void 0;
    seen.add(id);
    const first = o[2].trim();
    cur.set(key, [first]);
    opt = key;
  }
  const done = (lines) => lines.join("\n").trimEnd();
  const out = {};
  for (const [name, entries] of sections) {
    const merged = {};
    for (const [k, v] of defaults) merged[k] = done(v);
    for (const [k, v] of entries) merged[k] = done(v);
    out[name] = merged;
  }
  return out;
}
function parseConfigDoc(path, text) {
  const lower = path.toLowerCase();
  try {
    if (lower.endsWith(".json")) {
      const v = JSON.parse(text);
      return isTable(v) ? norm(v) : void 0;
    }
    if (lower.endsWith(".toml")) return norm(parse(text, { integersAsBigInt: true }));
    if (lower.endsWith(".cfg") || lower.endsWith(".ini")) return parseIni(text);
  } catch {
    return void 0;
  }
  return void 0;
}
function sectionTree(path, doc) {
  const t = /* @__PURE__ */ new Map();
  if (!path.toLowerCase().endsWith(".toml")) {
    for (const k of Object.keys(doc)) t.set(JSON.stringify([k]), { segs: [k], value: doc[k] });
    return t;
  }
  const walk3 = (v, prefix, depth) => {
    if (!isTable(v) || depth > 16) return;
    for (const k of Object.keys(v)) {
      const segs = [...prefix, k];
      t.set(JSON.stringify(segs), { segs, value: v[k] });
      walk3(v[k], segs, depth + 1);
    }
  };
  walk3(doc, [], 0);
  return t;
}
var sectionRe = (section) => new RegExp(`^${section.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
var safeName = (s) => s.replace(/[^A-Za-z0-9._:*/() -]/g, "?").slice(0, 80);
var MAX_SECTION_FILES = 20;
async function readConfigSections(gh, repo2, pr, sections, protectedPaths) {
  const specs = sections.flatMap((s) => {
    const i = s.indexOf(":");
    return i > 0 ? [{ glob: pathMatcher([s.slice(0, i)]), section: s.slice(i + 1) }] : [];
  });
  if (specs.length === 0) return [];
  const whole = pathMatcher(protectedPaths);
  const out = [];
  let checked = 0;
  const compare = async (path, skipBase, skipHead) => {
    const relevant = specs.filter((s) => s.glob(path));
    if (relevant.length === 0 || whole(path)) return;
    if (++checked > MAX_SECTION_FILES) {
      out.push({ file: path, section: "*", problem: "too many shared config files changed to compare" });
      return;
    }
    const fail3 = () => {
      out.push({ file: path, section: safeName(relevant.map((r) => r.section).join(",")), problem: "the file could not be read, parsed or told apart at the base or the head" });
    };
    const side = async (ref2, skip) => {
      if (skip) return /* @__PURE__ */ new Map();
      const r = await readTextAt(gh, repo2, path, ref2);
      if (r.kind === "missing") return /* @__PURE__ */ new Map();
      if (r.kind === "problem") return "fail";
      const doc = parseConfigDoc(path, r.text);
      return doc === void 0 ? "fail" : sectionTree(path, doc);
    };
    const base = await side(pr.baseSha, skipBase);
    const head = await side(pr.headSha, skipHead);
    if (base === "fail" || head === "fail") {
      fail3();
      return;
    }
    const toml = path.toLowerCase().endsWith(".toml");
    const changed = /* @__PURE__ */ new Map();
    for (const r of relevant) {
      const want = (toml ? r.section.split(".") : [r.section]).map(sectionRe);
      const fits = (segs) => segs.length === want.length && segs.every((x, i) => want[i].test(x));
      for (const key of /* @__PURE__ */ new Set([...base.keys(), ...head.keys()])) {
        const segs = (base.get(key) ?? head.get(key)).segs;
        if (!fits(segs)) continue;
        const a = base.has(key) ? canon(base.get(key).value) : void 0;
        const b = head.has(key) ? canon(head.get(key).value) : void 0;
        if (a !== b) changed.set(key, segs);
      }
    }
    for (const [key, segs] of changed) {
      const nested = [...changed].some(([k, o]) => k !== key && o.length < segs.length && o.every((x, i) => x === segs[i]));
      if (!nested) out.push({ file: path, section: safeName(segs.join(".")) });
    }
  };
  for (const f of pr.files) {
    const prev = f.previous_filename;
    if (prev !== void 0 && prev !== f.filename && f.status !== "copied") {
      if (specs.some((s) => s.glob(prev)) && !whole(prev)) out.push({ file: prev, section: "(file moved)" });
      await compare(f.filename, true, f.status === "removed");
    } else {
      await compare(f.filename, f.status === "added" || f.status === "copied", f.status === "removed");
    }
  }
  return out;
}
async function buildPrDiff(gh, repo2, baseSha, headSha) {
  const bad = () => ({ added: /* @__PURE__ */ new Map(), complete: false, commit: headSha });
  if (typeof baseSha !== "string" || !SHA_RE4.test(baseSha) || typeof headSha !== "string" || !SHA_RE4.test(headSha)) return bad();
  let a;
  try {
    a = await gh.compareFiles(repo2.owner, repo2.name, baseSha, headSha);
  } catch {
    return bad();
  }
  const status = isPlain4(a) ? own3(a, "status") : void 0;
  const list = isPlain4(a) ? own3(a, "files") : void 0;
  if (status !== "ahead" && status !== "identical" || !Array.isArray(list)) return bad();
  let ok = list.length < COMPARE_FILE_CAP;
  const files = [];
  for (const e of list) {
    const f = readFile(e);
    if (f === void 0) ok = false;
    else files.push(f);
  }
  const r = addedLinesOf(files);
  return { added: r.added, complete: ok && r.complete, commit: headSha };
}
var fp = (...parts) => createHash6("sha256").update(parts.join("\0")).digest("hex");
function integrityFindings(pr, protectedPaths, rules, extra = {}) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const approvals = new Set(pr.approvals.map((a) => a.toLowerCase()));
  const isProtected = pathMatcher(protectedPaths);
  const blockOwners = extra.codeowners?.problem === void 0 && Array.isArray(extra.codeowners?.blockOwners) ? extra.codeowners.blockOwners.map((o) => String(o).toLowerCase()) : [];
  const waived = (path) => (ownersOf(rules, path) ?? []).some((o) => approvals.has(o));
  const waivedFile = (path) => {
    const o = ownersOf(rules, path);
    return (o === void 0 ? blockOwners : o).some((x) => approvals.has(x));
  };
  const push = (ruleId, severity, file, message, key, line) => {
    const k = `${ruleId}\0${file ?? ""}\0${key}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ tool: "pipegen", ruleId, severity, ...file === void 0 ? {} : { file }, ...line === void 0 ? {} : { line }, message, fingerprint: fp(ruleId, file ?? "", key) });
  };
  const how = (path, file = false) => {
    if (extra.codeowners?.problem !== void 0) return " CODEOWNERS of the base commit could not be read, so nobody can approve: re-run the gate, or merge with an administrator bypass.";
    if (rules.length === 0) {
      return extra.codeowners?.found != null ? " CODEOWNERS of the base commit has no rule that names a user, so nobody can approve: add one, or merge with an administrator bypass." : " The base commit has no CODEOWNERS, so nobody can approve: add one (user owners, not only teams), or merge with an administrator bypass.";
    }
    const o = ownersOf(rules, path);
    if (o === void 0 && file && blockOwners.length > 0) {
      return " No CODEOWNERS rule covers this file, so an owner listed in pipegen's CODEOWNERS block (a user with write access, not the author) must approve the pull request on its current head commit.";
    }
    if (o === void 0 || o.length === 0) {
      return " No user is a code owner of this path (a team-only entry cannot approve: the gate cannot read team membership, so name a user as an owner in CODEOWNERS), or merge with an administrator bypass.";
    }
    return " A code owner of this path (a user, not only a team) with write access must approve the pull request on its current head commit.";
  };
  if (!pr.filesComplete) push("integrity:incomplete-list", "critical", void 0, "The list of changed files is incomplete (or is not the list of the commit being checked), so the gate cannot see every change and blocks. Split the pull request into smaller ones, or re-run if the branch moved.", "list");
  for (const f of pr.files) {
    for (const path of f.previous_filename === void 0 || f.status === "copied" ? [f.filename] : [f.filename, f.previous_filename]) {
      if (isProtected(path) && !waived(path)) push("integrity:protected-path", "critical", path, `This file is part of the pipeline (a workflow, a tool config or an ignore file).${how(path)}`, "path");
    }
    if ((f.status === "added" || f.status === "renamed" || f.status === "copied") && caseVariantExtension(f.filename) !== void 0 && !waivedFile(f.filename)) {
      push("integrity:case-extension", "high", f.filename, `This new file name has a scanned language's extension written in another letter case, so the scanners skip the file while a runtime may still load it. Rename it to the lower-case extension.${how(f.filename, true)}`, "case-extension");
    }
    const hasPatch = typeof f.patch === "string" && f.patch !== "";
    const parsed = hasPatch ? parsePatch(f.patch) : void 0;
    if (!hasPatch ? needsPatch(f) && !isLockfile(f.filename) : parsed === null) {
      if (!waivedFile(f.filename)) push("integrity:no-patch", "critical", f.filename, `The gate cannot read this file's changes (no patch, or a patch it cannot parse), so it cannot check them for suppressions.${how(f.filename, true)}`, "patch");
    }
    if (!hasPatch) continue;
    const ignoreFile = isProtected(f.filename) && IGNORE_FILE_RE.test(baseName(f.filename));
    const texts = parsed === void 0 || parsed === null ? plusLines(f.patch).map((text) => ({ no: void 0, text })) : parsed.added.map((a) => ({ no: a.no, text: a.text, ...parsed.context.has(a.no - 1) ? { above: parsed.context.get(a.no - 1) } : {} }));
    const kinds = /* @__PURE__ */ new Set();
    let first;
    let hits = 0;
    for (const a of texts) {
      let m = ignoreFile ? ["ignore file entry"] : markersOf(a.text);
      if (m.length === 0 && a.above !== void 0 && NEXT_LINE_RE.test(a.above)) m = ["existing marker above a changed line"];
      if (m.length === 0) continue;
      hits++;
      for (const k of m) kinds.add(k);
      if (first === void 0 && a.no !== void 0) first = a.no;
    }
    if (hits > 0 && !waivedFile(f.filename)) {
      push("integrity:suppression", "high", f.filename, `${hits} added line${hits === 1 ? "" : "s"} suppress${hits === 1 ? "es" : ""} a check (${[...kinds].sort().join(", ")}).${how(f.filename, true)}`, "suppression", first);
    }
  }
  for (const c of extra.sectionChanges ?? []) {
    if (waived(c.file)) continue;
    push(
      "integrity:protected-path",
      "critical",
      c.file,
      c.problem === void 0 ? c.section === "(file moved)" ? `This shared config file was renamed or moved away from where its tool reads it.${how(c.file)}` : `The section ${safeName(c.section)} of this shared config file changed.${how(c.file)}` : `This shared config file (section ${safeName(c.section)}) could not be compared: ${c.problem}.${how(c.file)}`,
      `section:${c.section}`
    );
  }
  return out;
}

// gate/src/mode.ts
function decideMode(blockFrom, recorded, today, cleanRunSeen2) {
  if (cleanRunSeen2 === "unknown") return { mode: "block", why: "block mode: the clean-run marker could not be checked, so the gate takes the strict side" };
  if (cleanRunSeen2 === true) return { mode: "block", why: "block mode: a trusted clean run has been seen" };
  if (!(today instanceof Date) || Number.isNaN(today.getTime())) return { mode: "block", why: "block mode: the clock is not a date, so the gate fails closed" };
  const day = today.toISOString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || day < "0001-01-01") return { mode: "block", why: "block mode: the clock is outside the years 1 to 9999, so the gate fails closed" };
  const v = validDate(blockFrom);
  const r = validDate(recorded);
  const dates = [v, r].filter((x) => x !== void 0).sort();
  const effective = dates[0];
  if (effective === void 0) return { mode: "warn", why: "warn mode: no block-from date is set and no clean run has been seen yet" };
  const which = effective === r && effective !== v ? "the date recorded at setup" : effective === v && effective !== r ? "PIPEGEN_BLOCK_FROM" : "PIPEGEN_BLOCK_FROM and the date recorded at setup";
  return day >= effective ? { mode: "block", why: `block mode: ${which} (${effective}) has been reached` } : { mode: "warn", why: `warn mode until ${effective} (${which})` };
}

// src/engine/gate-job-list.ts
var GateJobListError = class extends Error {
};
var FLOOR2 = new Set(FLOOR_NEEDS);
function jobIdFor(needId, service) {
  try {
    return `${needId}${service === void 0 ? "" : `--${slug(service)}`}`;
  } catch (e) {
    if (e instanceof ArtifactNameError) throw new GateJobListError(e.message);
    throw e;
  }
}

// src/engine/protected-paths.ts
function effectiveProtectedPaths(inUse, serviceRoots) {
  const roots = [...new Set(serviceRoots.map((r) => r.replace(/^(?:\.\/)+|\/+$/g, "")).filter((r) => r !== "" && r !== "."))];
  const rooted = inUse.flatMap((t) => (t.rootConfigFiles ?? []).flatMap((n) => n.includes("/") ? [n] : [`/${n}`, ...roots.map((r) => `/${r}/${n}`)]));
  return [.../* @__PURE__ */ new Set([...PROTECTED_PATHS_BASE, ...inUse.flatMap((t) => t.configFiles), ...rooted])];
}

// gate/src/settings.ts
var SECRETS_CATEGORIES = /* @__PURE__ */ new Set(["secrets"]);
var SAME_RUN_CATEGORIES = /* @__PURE__ */ new Set(["deps", "image-scan", "dependency-review", "licences"]);
var GATE_INPUTS = [
  "mode",
  "jobs",
  "job-list",
  "not-proven",
  "skipped",
  "policy",
  "protected-paths",
  "service-roots",
  "licence-lockfiles",
  "block-from",
  "block-from-recorded",
  "github-token",
  "fp-key"
];
var MAX_JOBS_TEXT = 4 * 1024 * 1024;
var SKIP_REASON = "skipped at setup (--skip)";
var MAX_POLICY_TEXT = 2e5;
var FLOOR3 = new Set(FLOOR_NEEDS);
var categoryOf = (needId) => Object.hasOwn(NEED_ID_CATEGORY, needId) ? NEED_ID_CATEGORY[needId] : void 0;
var isFloorNeed2 = (needId) => FLOOR3.has(needId) || FLOOR3.has(categoryOf(needId) ?? "");
var isFindingsFormat = (f) => f === "sarif" || f === "zap-json";
var parse2 = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return void 0;
  }
};
var shownName = (k) => JSON.stringify(safeText(k.replace(/[^A-Za-z0-9._-]/g, "?"), 40));
function entryProblem(e, i) {
  const at3 = `entry ${i + 1}`;
  let job;
  try {
    job = jobIdFor(e.needId, e.service);
  } catch {
    return `${at3} has a service that names no job`;
  }
  if (e.job !== job) return `${at3} has the job ${shownName(e.job)}, but its need and service give ${shownName(job)}`;
  if (e.range === true) return e.needId === "secrets" && e.service === void 0 && e.artifact === SECRETS_RANGE_ARTIFACT && e.baseArtifact === void 0 && e.tool === RANGE_TOOL && e.format === "sarif" ? null : `${at3} is a commit-range entry that is not the one of the secrets job`;
  if (isFindingsFormat(e.format)) {
    if (e.artifact === void 0 || e.baseArtifact === void 0 || e.tool === void 0) return `${at3} is a findings check without its tool, artifact or base artifact`;
    let head;
    let base;
    try {
      head = resultArtifactName(e.needId, e.service);
      base = resultArtifactName(e.needId, e.service, { base: true });
    } catch {
      return `${at3} has a need id that names no artifact`;
    }
    if (e.artifact !== head || e.baseArtifact !== base) return `${at3} has artifact names that are not the ones of its need and service`;
  } else if (e.artifact !== void 0 || e.baseArtifact !== void 0) return `${at3} is judged by job status but names an artifact`;
  return null;
}
function readJobList(text, errors) {
  if (text === void 0 || text === "") {
    errors.push("the job-list input is missing: the gate has no trusted list of checks");
    return [];
  }
  const p = jobListLiteralProblem(text);
  if (p !== null) {
    errors.push(`the job-list input is refused (${p})`);
    return [];
  }
  const raw = JSON.parse(text);
  const list = raw.map((r) => {
    const e = {};
    for (const k of JOB_LIST_KEYS) if (Object.hasOwn(r, k)) e[k] = k === "warnFirst" ? { since: r[k].since } : r[k];
    return e;
  });
  for (const [i, e] of list.entries()) {
    const problem = entryProblem(e, i);
    if (problem !== null) {
      errors.push(`the job-list input is refused (${problem})`);
      return [];
    }
  }
  return list;
}
function resolveSettings(raw, ctx) {
  const errors = [];
  const notes = [];
  const get = (k) => {
    const v = Object.hasOwn(raw, k) ? raw[k] : void 0;
    return typeof v === "string" && v !== "" ? v : void 0;
  };
  for (const [k, v] of Object.entries(raw)) {
    if (v === void 0 || v === "" || GATE_INPUTS.includes(k)) continue;
    errors.push(`the gate in mode gate does not take the input ${/^[A-Za-z][A-Za-z0-9-]{0,39}$/.test(k) && !/[0-9].*[0-9].*[0-9]/.test(k) ? JSON.stringify(k) : "(a name that is not shown)"}`);
  }
  if (get("mode") !== "gate") errors.push("the mode input is not gate");
  const jobList = readJobList(get("job-list"), errors);
  const floorNeeds = [.../* @__PURE__ */ new Set(["secrets", ...jobList.filter((e) => isFloorNeed2(e.needId) || FLOOR3.has(e.category)).map((e) => e.needId)])];
  const idList = (name) => {
    const v = get(name);
    if (v === void 0) return [];
    const p = idListProblem(v);
    if (p !== null) {
      errors.push(`the ${name} input is refused (it must be ${p})`);
      return [];
    }
    return [...new Set(JSON.parse(v))];
  };
  const notProven = idList("not-proven").filter((n) => {
    if (!isFloorNeed2(n)) return true;
    errors.push(`not-proven can't include floor need ${n}`);
    return false;
  });
  const skipped = idList("skipped").map((needId) => ({ needId, reason: SKIP_REASON }));
  let policy = DEFAULT_POLICY;
  const pv = get("policy");
  if (!ctx.private) {
    if (pv !== void 0) notes.push("the policy input is ignored on a public repository: the built-in default policy is used");
  } else if (pv !== void 0 && pv.length > MAX_POLICY_TEXT) {
    errors.push("the policy input is refused (it is over the size cap), so the default policy is used");
  } else if (pv !== void 0) {
    const doc = parse2(pv);
    const p = policyProblem(doc);
    if (p === null) policy = doc;
    else errors.push(`the policy input is refused (it must be ${p}), so the default policy is used`);
  }
  let serviceRoots = [];
  const sr = get("service-roots");
  if (sr !== void 0) {
    const p = serviceRootsProblem(sr);
    if (p === null) serviceRoots = JSON.parse(sr);
    else errors.push(`the service-roots input is refused (it must be ${p})`);
  } else if (jobList.some((e) => e.service !== void 0)) {
    errors.push("the service-roots input is missing while the job list has per-service checks: the config files each service folder holds could not be protected");
  }
  let licenceLockfiles;
  const ll = get("licence-lockfiles");
  if (ll !== void 0) {
    const p = licenceLockfilesProblem(ll);
    if (p === null) licenceLockfiles = JSON.parse(ll).map((e) => ({ service: e.service, lockfiles: e.lockfiles.map((l) => ({ kind: l.kind, read: l.read })) }));
    else errors.push(`the licence-lockfiles input is refused (it must be ${p})`);
  }
  let extra = [];
  const pp = get("protected-paths");
  if (pp !== void 0) {
    const p = pathListProblem(pp);
    if (p === null) extra = JSON.parse(pp);
    else errors.push(`the protected-paths input is refused (it must be ${p})`);
  }
  const protectedPaths = [.../* @__PURE__ */ new Set([...effectiveProtectedPaths(ctx.reviewed.map((t) => ({ configFiles: [...t.configFiles], ...t.rootConfigFiles === void 0 ? {} : { rootConfigFiles: [...t.rootConfigFiles] } })), serviceRoots), ...extra])];
  const protectedSections = [.../* @__PURE__ */ new Set([...PROTECTED_SECTIONS_BASE, ...ctx.reviewed.flatMap((t) => t.configSections ?? [])])];
  const secretsTools = ctx.reviewed.filter((t) => t.categories.some((c) => SECRETS_CATEGORIES.has(c))).map((t) => t.id);
  const sameRunTools = ctx.reviewed.filter((t) => t.categories.some((c) => SAME_RUN_CATEGORIES.has(c))).map((t) => t.id);
  const bf = get("block-from");
  const blockFrom = validDate(bf);
  if (bf !== void 0 && blockFrom === void 0) notes.push("PIPEGEN_BLOCK_FROM is not a date YYYY-MM-DD, so it is ignored");
  const rec = get("block-from-recorded");
  const blockFromRecorded = validDate(rec);
  if (rec !== void 0 && blockFromRecorded === void 0) errors.push("the block-from-recorded input is refused (it must be a real calendar date YYYY-MM-DD)");
  let needs = {};
  const jobs = get("jobs");
  if (jobs === void 0) errors.push("the jobs input (toJSON(needs)) is missing");
  else if (jobs.length > MAX_JOBS_TEXT) errors.push("the jobs input (toJSON(needs)) is over the size cap");
  else {
    const doc = parse2(jobs);
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) errors.push("the jobs input (toJSON(needs)) is not a JSON object");
    else needs = doc;
  }
  const token = get("github-token") ?? "";
  if (token === "") errors.push("the github-token input is missing");
  const fpKey = get("fp-key");
  return {
    jobList,
    floorNeeds,
    policy,
    notProven,
    skipped,
    protectedPaths,
    protectedSections,
    serviceRoots,
    ...licenceLockfiles === void 0 ? {} : { licenceLockfiles },
    secretsTools,
    sameRunTools,
    ...blockFrom === void 0 ? {} : { blockFrom },
    ...blockFromRecorded === void 0 ? {} : { blockFromRecorded },
    needs,
    token,
    ...fpKey === void 0 ? {} : { fpKey },
    errors,
    notes
  };
}
var BASE_SCAN_JOB = "base-scan";
var BASE_SHA_OUTPUT = "base-sha";
var RESULTS = /* @__PURE__ */ new Set(["success", "failure", "cancelled", "skipped"]);
var SHA_RE5 = /^[0-9a-f]{40}$/;
var MAX_OUTPUT_CHARS = 2e3;
var isPlain5 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var own4 = (o, k) => Object.hasOwn(o, k) ? o[k] : void 0;
function jobOf(needs, job) {
  if (!isPlain5(needs)) return void 0;
  const j = own4(needs, job);
  if (j === void 0) return void 0;
  if (!isPlain5(j)) return { result: "missing", outputs: {} };
  const r = own4(j, "result");
  const o = own4(j, "outputs");
  return { result: typeof r === "string" && RESULTS.has(r) ? r : "missing", outputs: isPlain5(o) ? o : {} };
}
function outputsOf(outputs, artifact) {
  const o = {};
  for (const n of ["sha256", "status", "error"]) {
    const v = own4(outputs, `${artifact}-${n}`);
    if (typeof v === "string") o[n] = v.length > MAX_OUTPUT_CHARS ? v.slice(0, MAX_OUTPUT_CHARS) : v;
  }
  return o;
}
function mapJobs(needs, list) {
  const notes = [];
  const base = jobOf(needs, BASE_SCAN_JOB);
  let baseScan = null;
  if (base !== void 0) {
    const c = own4(base.outputs, BASE_SHA_OUTPUT);
    baseScan = { result: base.result, ...typeof c === "string" && SHA_RE5.test(c) ? { commit: c } : {} };
  }
  const checks = list.map((entry) => {
    const j = jobOf(needs, entry.job);
    if (j === void 0) return { entry, result: "missing", outputs: {} };
    if (j.result === "missing") notes.push(`the job ${shownName(entry.job)} has no result GitHub gives (success, failure, cancelled or skipped): it counts as missing`);
    const findings = isFindingsFormat(entry.format) && entry.artifact !== void 0;
    const outputs = findings ? outputsOf(j.outputs, entry.artifact) : {};
    const baseOutputs = findings && base !== void 0 && entry.baseArtifact !== void 0 ? outputsOf(base.outputs, entry.baseArtifact) : void 0;
    return { entry, result: j.result, outputs, ...baseOutputs === void 0 ? {} : { baseOutputs } };
  });
  if (isPlain5(needs)) {
    const listed = /* @__PURE__ */ new Set([...list.map((e) => e.job), BASE_SCAN_JOB]);
    const extra = Object.keys(needs).filter((k) => !listed.has(k));
    if (extra.length > 0) notes.push(`${extra.length} job${extra.length === 1 ? "" : "s"} the gate waits for ${extra.length === 1 ? "is" : "are"} not in the job list and ${extra.length === 1 ? "was" : "were"} not read: ${extra.slice(0, 10).map(shownName).join(", ")}`);
  }
  return { checks, baseScan, notes };
}

// gate/src/facts.ts
var SHA_RE6 = /^[0-9a-f]{40}$/;
var PR_EVENTS = /* @__PURE__ */ new Set(["pull_request", "pull_request_review"]);
var notAMergeRun = (defaultBranch, event) => `the gate runs on pull requests, merge queues and pushes to ${defaultBranch}; this ${/^[a-z_]{1,40}$/.test(event) ? event : "other"} run can't decide a merge`;
function compareOnce(gh) {
  const seen = /* @__PURE__ */ new Map();
  const once = (owner, name, base, head) => {
    const k = `${owner}/${name}\0${base}\0${head}`;
    let p = seen.get(k);
    if (p === void 0) {
      p = gh.compare(owner, name, base, head);
      seen.set(k, p);
    }
    return p;
  };
  return new Proxy(gh, {
    get(target, prop, receiver) {
      if (prop === "compare" || prop === "compareFiles") return once;
      const v = Reflect.get(target, prop, receiver);
      return typeof v === "function" ? v.bind(target) : v;
    }
  });
}
var isPlain6 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function at2(o, ...path) {
  let v = o;
  for (const k of path) {
    if (!isPlain6(v) || !Object.hasOwn(v, k)) return void 0;
    v = v[k];
  }
  return v;
}
var sha402 = (v) => typeof v === "string" && SHA_RE6.test(v) ? v : void 0;
function licenceCoverage(list) {
  if (list === void 0) return ["coverage per lockfile not known (the gate step has no licence-lockfiles input)"];
  if (list.length === 0) return ["not covered (no lockfile)"];
  return [...new Set(list.flatMap((e) => e.lockfiles.length === 0 ? [`${e.service}: not covered (no lockfile)`] : e.lockfiles.filter((l) => !l.read).map((l) => `${e.service}: ${l.kind}: not covered (lockfile type)`)))];
}
var ZERO_SHA2 = "0".repeat(40);
async function rangeScanOf(tool2, result, outputs, fileOf) {
  if (result !== "success") {
    return { tool: tool2, toolError: outputs.status === "tool-error" ? outputs.error ?? "no detail" : `the secrets job did not succeed (${result}), so its commit-range scan has no result` };
  }
  const st = fileState(outputs, outputs.status === "ok" ? await fileOf() : void 0);
  switch (st.kind) {
    case "ok":
      return st.read.rangeSkipped !== void 0 ? { tool: tool2, skipped: st.read.rangeSkipped } : { tool: tool2, findings: st.read.findings };
    case "absent":
      return { tool: tool2 };
    case "tool-error":
      return { tool: tool2, toolError: st.why };
    case "tampered":
      return { tool: tool2, toolError: `the commit-range result is not the one the job made: ${st.why}` };
    case "missing-file":
      return { tool: tool2, toolError: "the commit-range result artifact is missing" };
  }
}
function repoOf(payload, repository) {
  const r = at2(payload, "repository");
  const id = at2(r, "id");
  const name = at2(r, "name");
  const owner = at2(r, "owner", "login");
  const full = at2(r, "full_name");
  const def = at2(r, "default_branch");
  if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) return "the event payload has no repository id";
  if (typeof name !== "string" || typeof owner !== "string" || typeof full !== "string" || full !== `${owner}/${name}`) return "the event payload has no repository name";
  if (typeof repository !== "string" || full.toLowerCase() !== repository.toLowerCase()) return "the event payload is not of the repository this run belongs to";
  if (typeof def !== "string" || def === "") return "the event payload has no default branch";
  const priv = at2(r, "private");
  return { owner, name, id, defaultBranch: def, private: typeof priv === "boolean" ? priv : void 0 };
}
async function gatherGateInput(ctx, client, io) {
  const gh = compareOnce(client);
  let payload;
  try {
    payload = JSON.parse(io.readEvent());
  } catch {
    return { kind: "settings-error", errors: ["the event payload could not be read"] };
  }
  if (!isPlain6(payload)) return { kind: "settings-error", errors: ["the event payload is not an object"] };
  const repo2 = repoOf(payload, ctx.env.repository);
  if (typeof repo2 === "string") return { kind: "settings-error", errors: [repo2] };
  const sha3 = ctx.env.sha;
  if (typeof sha3 !== "string" || !SHA_RE6.test(sha3)) return { kind: "settings-error", errors: ["GITHUB_SHA is not a commit sha"] };
  const runId = /^[1-9][0-9]{0,15}$/.test(ctx.env.runId) ? Number(ctx.env.runId) : Number.NaN;
  if (!Number.isSafeInteger(runId)) return { kind: "settings-error", errors: ["GITHUB_RUN_ID is not a run id"] };
  const event = { name: ctx.env.eventName, sha: sha3, payload };
  const notes = [];
  if (repo2.private === void 0) notes.push("the event payload does not say whether the repository is private, so the public rules apply");
  const settings = resolveSettings(ctx.inputs, { private: repo2.private === true, reviewed: ctx.reviewed });
  notes.push(...settings.notes);
  const pushToDefault = event.name === "push" && at2(payload, "ref") === `refs/heads/${repo2.defaultBranch}`;
  if (!(PR_EVENTS.has(event.name) || event.name === "merge_group" || pushToDefault)) settings.errors.push(notAMergeRun(repo2.defaultBranch, event.name));
  const eventHead = PR_EVENTS.has(event.name) ? at2(payload, "pull_request", "head", "sha") : event.name === "merge_group" ? at2(payload, "merge_group", "head_sha") : void 0;
  if (PR_EVENTS.has(event.name) || event.name === "merge_group") {
    const head = sha402(eventHead);
    const stale = "the scanned commit does not contain the pull request's head: re-run the gate after GitHub has updated the merge commit";
    if (head === void 0) settings.errors.push("the event payload has no head commit, so the scanned commit can not be tied to it");
    else if (head !== sha3) {
      try {
        const a = await gh.compare(repo2.owner, repo2.name, head, sha3);
        const status = isPlain6(a) && Object.hasOwn(a, "status") ? a.status : void 0;
        if (status !== "ahead" && status !== "identical") settings.errors.push(stale);
      } catch {
        settings.errors.push("whether the scanned commit contains the pull request's head could not be checked, so the gate fails closed");
      }
    }
    if (head !== void 0 && PR_EVENTS.has(event.name)) {
      const notMerge = "the scanned commit is not GitHub's merge of the pull request's head (its second parent must be the head): re-run the gate after GitHub has updated the merge commit";
      try {
        const c = await gh.getCommit(repo2.owner, repo2.name, sha3);
        const parents = isPlain6(c) && Object.hasOwn(c, "parents") ? c.parents : void 0;
        const ok = isPlain6(c) && at2(c, "sha") === sha3 && Array.isArray(parents) && parents.length === 2 && sha402(at2(parents[1], "sha")) === head;
        if (!ok) settings.errors.push(notMerge);
      } catch {
        settings.errors.push("whether the scanned commit is the merge of the pull request's head could not be checked, so the gate fails closed");
      }
    }
  }
  const mapped = mapJobs(settings.needs, settings.jobList);
  notes.push(...mapped.notes);
  const outputFile = new Map(ctx.reviewed.flatMap((t) => t.outputFile === void 0 ? [] : [[t.id, t.outputFile]]));
  const checks = [];
  for (const m of mapped.checks.filter((x) => x.entry.range !== true)) {
    const e = m.entry;
    const c = { entry: e, result: m.result, outputs: m.outputs };
    if ((e.format === "sarif" || e.format === "zap-json") && e.artifact !== void 0) {
      const fileOf = async (name) => {
        const expectedFile = e.tool === void 0 ? void 0 : outputFile.get(e.tool);
        const d = await downloadResult(io, { owner: repo2.owner, repo: repo2.name, runId, name, format: e.format, ...expectedFile === void 0 ? {} : { expectedFile } });
        return d.kind === "file" ? d.file : void 0;
      };
      if (m.result === "success" && m.outputs.status === "ok") {
        const f = await fileOf(e.artifact);
        if (f !== void 0) c.file = f;
      }
      if (m.baseOutputs !== void 0 && e.baseArtifact !== void 0) {
        const base = { outputs: m.baseOutputs };
        if (m.baseOutputs.status === "ok") {
          const f = await fileOf(e.baseArtifact);
          if (f !== void 0) base.file = f;
        }
        c.base = base;
      }
    }
    checks.push(c);
  }
  const rangeScans = [];
  const prLike = PR_EVENTS.has(event.name) || event.name === "merge_group";
  const before = pushToDefault ? sha402(at2(payload, "before")) : void 0;
  if (pushToDefault && (before === void 0 || before === ZERO_SHA2)) {
    if (settings.jobList.some((e) => e.range === true)) notes.push("the push made the default branch (it has no previous commit), so there is no commit range to scan for secrets");
  } else if (prLike || pushToDefault) {
    const ranges = mapped.checks.filter((m) => m.entry.range === true);
    if (ranges.length === 0 && settings.jobList.some((e) => e.category === "secrets" && e.range !== true)) {
      const why2 = "the job list has no commit-range scan for the secrets check, so the commits of the pull request are not scanned (render the pipeline again with pipegen update)";
      if (prLike) rangeScans.push({ tool: RANGE_TOOL, toolError: why2 });
      else notes.push(why2);
    }
    for (const m of ranges) {
      const art = m.entry.artifact;
      const fileOf = async () => {
        const d = await downloadResult(io, { owner: repo2.owner, repo: repo2.name, runId, name: art, format: "sarif", ...outputFile.has(RANGE_TOOL) ? { expectedFile: outputFile.get(RANGE_TOOL) } : {} });
        return d.kind === "file" ? d.file : void 0;
      };
      const rs = await rangeScanOf(m.entry.tool ?? RANGE_TOOL, m.result, m.outputs, fileOf);
      if (rs.skipped !== void 0) {
        if (prLike) rangeScans.push({ tool: rs.tool, toolError: "the range scan found no commit range on this pull request event (an all-zero base or head, or a base it could not place), so the commits of the pull request are not scanned" });
        else if (rs.skipped === "no-merge-base") rangeScans.push({ tool: rs.tool, toolError: "this push rewrote the history of the default branch and its old head is not in the checkout, so its commit range was not scanned" });
        else notes.push("the range scan found no commit range on this event, so no commit range was scanned");
      } else rangeScans.push(rs);
    }
  }
  const exp = expectedBaseOf(event);
  let ancestry = null;
  if (exp.base !== void 0 && mapped.baseScan?.commit === exp.base) {
    try {
      const a = await gh.compare(repo2.owner, repo2.name, exp.base, sha3);
      const status = isPlain6(a) && Object.hasOwn(a, "status") ? a.status : void 0;
      ancestry = { base: exp.base, head: sha3, isAncestor: status === "ahead" };
    } catch {
      notes.push("the ancestry of the base commit could not be checked");
    }
  }
  let diff = null;
  if (PR_EVENTS.has(event.name)) {
    const base = sha402(at2(payload, "pull_request", "base", "sha"));
    diff = base === void 0 ? { added: /* @__PURE__ */ new Map(), complete: false, commit: sha3 } : await buildPrDiff(gh, repo2, base, sha3);
  } else if (event.name === "merge_group") {
    const base = sha402(at2(payload, "merge_group", "base_sha"));
    const head = sha402(at2(payload, "merge_group", "head_sha"));
    diff = base === void 0 || head === void 0 ? { added: /* @__PURE__ */ new Map(), complete: false, commit: sha3 } : await buildPrDiff(gh, repo2, base, head);
  }
  let installing = false;
  let integrity = [];
  if (PR_EVENTS.has(event.name)) {
    const number = at2(payload, "pull_request", "number");
    const baseSha = sha402(at2(payload, "pull_request", "base", "sha"));
    const headSha = sha402(at2(payload, "pull_request", "head", "sha"));
    if (typeof number !== "number" || !Number.isSafeInteger(number) || number <= 0 || baseSha === void 0 || headSha === void 0) {
      settings.errors.push("the pull request in the event payload has no number, base or head commit, so its changes can not be checked");
    } else {
      installing = !await baseHasInstall(gh, repo2, baseSha);
      const co = await loadCodeowners(gh, repo2, baseSha);
      if (co.problem !== void 0) notes.push(co.problem);
      const pr = await readPrContext(gh, repo2, number, { expectHeadSha: headSha, codeowners: co.rules });
      notes.push(...pr.problems);
      const sections = await readConfigSections(gh, repo2, pr, settings.protectedSections, settings.protectedPaths);
      integrity = integrityFindings(pr, settings.protectedPaths, co.rules, { sectionChanges: sections, codeowners: { found: co.found, blockOwners: co.blockOwners, ...co.problem === void 0 ? {} : { problem: co.problem } } });
    }
  }
  const verify = { key: settings.fpKey, now: ctx.now };
  const loaded = await loadBaseline(gh, repo2, verify);
  if (loaded.note !== void 0) notes.push(loaded.note);
  const marker = await cleanRunSeen(gh, repo2, verify);
  if (marker.note !== void 0) notes.push(marker.note);
  const mode = decideMode(settings.blockFrom, settings.blockFromRecorded, ctx.now, marker.state === "seen" ? true : marker.state === "none" ? false : "unknown");
  notes.push(mode.why);
  const coverage = settings.jobList.filter((e) => e.category === "licences").flatMap((e) => licenceCoverage(settings.licenceLockfiles).map((text) => ({ job: e.job, text })));
  notes.push(...ctx.clientNotes ?? []);
  return {
    event,
    checks,
    baseScan: mapped.baseScan,
    ancestry,
    baseline: loaded.baseline,
    sameRunTools: settings.sameRunTools,
    installing,
    diff,
    rangeScans,
    mode: mode.mode,
    policy: settings.policy,
    notProvenNeeds: settings.notProven,
    skipped: settings.skipped,
    settingsErrors: settings.errors,
    integrity,
    floorNeeds: settings.floorNeeds,
    notes: [...new Set(notes)],
    coverage,
    cleanRun: marker.state
  };
}

// gate/src/github-adapter.ts
var API_ROOT = "https://api.github.com";
var API_HOST = "api.github.com";
var API_VERSION = "2022-11-28";
var TIMEOUT_MS = 3e4;
var MAX_JSON_BYTES = 32 * 1024 * 1024;
var MAX_RAW_BYTES2 = 3 * 1024 * 1024;
var PAGE_CAP = { files: 30, reviews: 31, runs: 5, jobs: 5, pulls: 3, releases: 3, issues: 5 };
var MAX_PER_PAGE = 100;
var STORE_HOST_RE = /^(?:[a-z0-9-]{1,63}\.blob\.core\.windows\.net|[a-z0-9-]{1,63}\.actions\.githubusercontent\.com)$/;
var GitHubApiError = class extends Error {
  status;
  rateLimited;
  constructor(message, opts = {}) {
    super(message);
    this.name = "GitHubApiError";
    this.status = opts.status;
    this.rateLimited = opts.rateLimited ?? false;
  }
};
var MAX_ISSUE_TITLE = 256;
var MAX_ISSUE_BODY = 65e3;
var LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,49}$/;
var ISSUE_WRITE_RE = /^\/repos\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/issues(?:\/[1-9][0-9]{0,14}(?:\/labels)?)?$/;
var fail2 = (what) => {
  throw new GitHubApiError(`pipegen will not call GitHub with ${what}`);
};
var OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
var REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
var SHA_RE7 = /^[0-9a-f]{40}$/;
var LOGIN_RE2 = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
var REF_PART_RE = /^[A-Za-z0-9._+@-]{1,255}$/;
var ARTIFACT_NAME_RE = /^[A-Za-z0-9._-]{1,200}$/;
var WORKFLOW_RE = /^[A-Za-z0-9._-]{1,100}\.ya?ml$/;
var BRANCH_QUERY_RE = /^[A-Za-z0-9._/+@-]{1,255}$/;
var repo = (owner, name) => {
  if (typeof owner !== "string" || !OWNER_RE.test(owner)) fail2("an owner that is not a GitHub name");
  if (typeof name !== "string" || !REPO_RE.test(name) || name === "." || name === "..") fail2("a repository name that is not one");
  return `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
};
var sha2 = (s) => typeof s === "string" && SHA_RE7.test(s) ? s : fail2("a commit that is not a 40-hex sha");
var num = (n) => typeof n === "number" && Number.isSafeInteger(n) && n > 0 ? String(n) : fail2("a number that is not a positive whole number");
var page = (p, cap) => typeof p === "number" && Number.isSafeInteger(p) && p >= 1 && p <= cap ? String(p) : fail2(`a page past the cap of ${cap} pages`);
var perPage = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 1 && n <= MAX_PER_PAGE ? String(n) : fail2("a page size over 100");
var refPath = (r) => {
  if (typeof r !== "string") fail2("a ref name that is not text");
  const parts = r.split("/");
  if (parts.some((x) => !REF_PART_RE.test(x) || x === "." || x === ".." || x.endsWith(".lock"))) fail2("a ref name that is not one");
  return parts.map(encodeURIComponent).join("/");
};
var filePath = (p) => {
  if (typeof p !== "string" || p === "" || p.length > 4096 || /[\x00-\x1f\x7f]/.test(p)) fail2("a file path that is not a repository path");
  const parts = p.split("/");
  if (parts.some((x) => x === "" || x === "." || x === "..")) fail2("a file path that is not a repository path");
  return parts.map(encodeURIComponent).join("/");
};
async function readCapped(res, max, what) {
  const declared = res.headers.get("content-length");
  if (declared !== null && Number(declared) > max) {
    await res.body?.cancel().catch(() => void 0);
    throw new GitHubApiError(`${what}: the answer is over the size cap`);
  }
  if (res.body === null) return new Uint8Array();
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel().catch(() => void 0);
      throw new GitHubApiError(`${what}: the answer is over the size cap`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at3 = 0;
  for (const c of chunks) {
    out.set(c, at3);
    at3 += c.length;
  }
  return out;
}
function githubAdapter(opts) {
  const token = opts.token;
  if (typeof token !== "string" || token === "" || /[\s\x00-\x1f]/.test(token)) throw new GitHubApiError("the github-token input is empty or not a token");
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? TIMEOUT_MS;
  let masked = false;
  const mask = () => {
    if (!masked) {
      masked = true;
      opts.mask?.(token);
    }
  };
  async function call(path, o = {}) {
    mask();
    const url = `${API_ROOT}${path}`;
    const method = o.write?.method ?? "GET";
    const what = `${method} ${path.replace(/\?.*$/, "")}`;
    let res;
    try {
      res = await fetchFn(url, {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
        headers: { authorization: `Bearer ${token}`, accept: o.accept ?? "application/vnd.github+json", "x-github-api-version": API_VERSION, "user-agent": "pipegen-gate", ...o.write === void 0 ? {} : { "content-type": "application/json" } },
        ...o.write === void 0 ? {} : { body: o.write.body }
      });
    } catch {
      throw new GitHubApiError(`${what}: the request failed (network or timeout)`);
    }
    if (res.status >= 300 && res.status < 400) {
      await res.body?.cancel().catch(() => void 0);
      throw new GitHubApiError(`${what}: GitHub answered with a redirect, which the gate does not follow`, { status: res.status });
    }
    if (res.status === 404 && o.notFound === "null") {
      await res.body?.cancel().catch(() => void 0);
      return { status: 404 };
    }
    if (res.status < 200 || res.status >= 300) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      const limited = res.status === 429 || res.status === 403 && (remaining === "0" || res.headers.get("retry-after") !== null);
      await res.body?.cancel().catch(() => void 0);
      if (limited) {
        const reset = Number(res.headers.get("x-ratelimit-reset"));
        const when = Number.isSafeInteger(reset) && reset > 0 ? ` (it resets at ${new Date(reset * 1e3).toISOString()})` : "";
        const note = `GitHub rate limit reached on ${what}${when}: the gate could not read everything it needs, so it fails closed`;
        if (opts.notes !== void 0 && !opts.notes.includes(note)) opts.notes.push(note);
        throw new GitHubApiError(`${what}: GitHub rate limit`, { status: res.status, rateLimited: true });
      }
      throw new GitHubApiError(`${what}: GitHub answered ${res.status}`, { status: res.status });
    }
    return { status: 200, body: await readCapped(res, o.max ?? MAX_JSON_BYTES, what), res };
  }
  async function getJson(path, notFound = "throw") {
    const r = await call(path, { notFound });
    if (r.status === 404) return null;
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(r.body));
    } catch {
      throw new GitHubApiError(`GET ${path.replace(/\?.*$/, "")}: the answer is not JSON`);
    }
  }
  async function send(method, path, body) {
    const labels = /\/labels$/.test(path);
    if (!ISSUE_WRITE_RE.test(path) || method === "POST" !== /\/issues(?:\/[0-9]+\/labels)?$/.test(path)) fail2("a write that is not an issue");
    const r = await call(path, { write: { method, body: JSON.stringify(body) } });
    if (r.status === 404) throw new GitHubApiError(`${method} ${path}: not found`, { status: 404 });
    let answer;
    try {
      answer = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(r.body));
    } catch {
      throw new GitHubApiError(`${method} ${path}: the answer is not JSON`);
    }
    if (labels) {
      if (!Array.isArray(answer)) throw new GitHubApiError(`${method} ${path}: the answer is not a list of labels`);
      const names = answer.map((l) => typeof l === "object" && l !== null && !Array.isArray(l) && Object.hasOwn(l, "name") && typeof l.name === "string" ? l.name : void 0);
      if (names.some((n2) => n2 === void 0)) throw new GitHubApiError(`${method} ${path}: the answer has a label with no name`);
      return names;
    }
    const n = typeof answer === "object" && answer !== null && Object.hasOwn(answer, "number") ? answer.number : void 0;
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n <= 0) throw new GitHubApiError(`${method} ${path}: the answer has no issue number`);
    return { number: n };
  }
  async function downloadArtifactZip(owner, name, artifactId, maxBytes) {
    const path = `${repo(owner, name)}/actions/artifacts/${num(artifactId)}/zip`;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) fail2("a size cap that is not one");
    mask();
    const what = `GET ${path}`;
    let res;
    try {
      res = await fetchFn(`${API_ROOT}${path}`, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
        headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": API_VERSION, "user-agent": "pipegen-gate" }
      });
    } catch {
      throw new GitHubApiError(`${what}: the request failed (network or timeout)`);
    }
    if (res.status === 200) return readCapped(res, maxBytes, what);
    if (res.status !== 302 && res.status !== 301 && res.status !== 307) {
      await res.body?.cancel().catch(() => void 0);
      throw new GitHubApiError(`${what}: GitHub answered ${res.status}`, { status: res.status });
    }
    await res.body?.cancel().catch(() => void 0);
    const loc = res.headers.get("location") ?? "";
    let u;
    try {
      u = new URL(loc);
    } catch {
      throw new GitHubApiError(`${what}: the download redirect is not a URL`);
    }
    if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.port !== "" || !STORE_HOST_RE.test(u.hostname) || u.hostname === API_HOST) {
      throw new GitHubApiError(`${what}: the download redirect goes to a host the gate does not fetch from`);
    }
    let blob;
    try {
      blob = await fetchFn(u.toString(), { method: "GET", redirect: "manual", signal: AbortSignal.timeout(timeoutMs), headers: { "user-agent": "pipegen-gate" } });
    } catch {
      throw new GitHubApiError(`${what}: the download failed (network or timeout)`);
    }
    if (blob.status !== 200) {
      await blob.body?.cancel().catch(() => void 0);
      throw new GitHubApiError(`${what}: the artifact store answered ${blob.status}`, { status: blob.status });
    }
    return readCapped(blob, maxBytes, what);
  }
  return {
    compare: async (owner, name, base, head) => getJson(`${repo(owner, name)}/compare/${sha2(base)}...${sha2(head)}`),
    compareFiles: async (owner, name, base, head) => getJson(`${repo(owner, name)}/compare/${sha2(base)}...${sha2(head)}`),
    listRuns: async (owner, name, q) => {
      if (typeof q.workflow !== "string" || !WORKFLOW_RE.test(q.workflow)) fail2("a workflow file name that is not one");
      if (typeof q.branch !== "string" || !BRANCH_QUERY_RE.test(q.branch)) fail2("a branch name that is not one");
      if (q.event !== "push" || q.status !== void 0 && q.status !== "success") fail2("a run filter the gate does not use");
      if (q.headSha !== void 0) sha2(q.headSha);
      const query = new URLSearchParams({
        event: q.event,
        branch: q.branch,
        ...q.status === void 0 ? {} : { status: q.status },
        ...q.headSha === void 0 ? {} : { head_sha: q.headSha },
        per_page: perPage(q.perPage),
        page: page(q.page, PAGE_CAP.runs)
      });
      return getJson(`${repo(owner, name)}/actions/workflows/${encodeURIComponent(q.workflow)}/runs?${query.toString()}`);
    },
    listAttemptJobs: async (owner, name, runId, attempt, p, per) => getJson(`${repo(owner, name)}/actions/runs/${num(runId)}/attempts/${num(attempt)}/jobs?per_page=${perPage(per)}&page=${page(p, PAGE_CAP.jobs)}`),
    listRunArtifacts: async (owner, name, runId, artifactName) => {
      if (typeof artifactName !== "string" || !ARTIFACT_NAME_RE.test(artifactName)) fail2("an artifact name that is not one");
      const path = `${repo(owner, name)}/actions/runs/${num(runId)}/artifacts?${new URLSearchParams({ name: artifactName, per_page: String(MAX_PER_PAGE) }).toString()}`;
      const a = await getJson(path);
      const total = typeof a === "object" && a !== null && Object.hasOwn(a, "total_count") ? a.total_count : void 0;
      const list = typeof a === "object" && a !== null && Object.hasOwn(a, "artifacts") ? a.artifacts : void 0;
      if (typeof total !== "number" || !Array.isArray(list) || total > list.length) throw new GitHubApiError(`GET ${path.replace(/\?.*$/, "")}: the artifact list is cut (fewer entries than its total_count) or malformed`);
      return a;
    },
    downloadArtifact: async (owner, name, artifactId) => {
      const zip = await downloadArtifactZip(owner, name, artifactId, MAX_ARTIFACT_BYTES);
      const r = readZipEntry(zip, { maxBytes: MAX_ARTIFACT_BYTES });
      if (!r.ok) throw new GitHubApiError(`the artifact ${artifactId} is refused: ${r.problem}`);
      return r.bytes;
    },
    downloadArtifactZip,
    branchHead: async (owner, name, branch) => getJson(`${repo(owner, name)}/git/ref/heads/${refPath(branch)}`),
    tagExists: async (owner, name, tag) => {
      const r = await call(`${repo(owner, name)}/git/ref/tags/${refPath(tag)}`, { notFound: "null" });
      return r.status === 200;
    },
    getPull: async (owner, name, n) => getJson(`${repo(owner, name)}/pulls/${num(n)}`),
    listPullFiles: async (owner, name, n, p, per) => getJson(`${repo(owner, name)}/pulls/${num(n)}/files?per_page=${perPage(per)}&page=${page(p, PAGE_CAP.files)}`),
    listPullReviews: async (owner, name, n, p, per) => getJson(`${repo(owner, name)}/pulls/${num(n)}/reviews?per_page=${perPage(per)}&page=${page(p, PAGE_CAP.reviews)}`),
    fileAt: async (owner, name, path, ref2) => getJson(`${repo(owner, name)}/contents/${filePath(path)}?ref=${sha2(ref2)}`, "null"),
    rawFileAt: async (owner, name, path, ref2) => {
      const r = await call(`${repo(owner, name)}/contents/${filePath(path)}?ref=${sha2(ref2)}`, { accept: "application/vnd.github.raw+json", notFound: "null", max: MAX_RAW_BYTES2 });
      if (r.status === 404) return null;
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(r.body);
      } catch {
        throw new GitHubApiError("the raw file is not UTF-8 text");
      }
    },
    getCommit: async (owner, name, commit) => getJson(`${repo(owner, name)}/commits/${sha2(commit)}`),
    // ---- C7 (nightly): reads, then the issue writes ----
    getRepo: async (owner, name) => getJson(repo(owner, name)),
    listSetupPulls: async (owner, name, p, per) => getJson(`${repo(owner, name)}/pulls?${new URLSearchParams({ state: "closed", head: `${owner}:pipegen/setup`, sort: "updated", direction: "desc", per_page: perPage(per), page: page(p, PAGE_CAP.pulls) }).toString()}`),
    listReleases: async (owner, name, p, per) => getJson(`${repo(owner, name)}/releases?${new URLSearchParams({ per_page: perPage(per), page: page(p, PAGE_CAP.releases) }).toString()}`),
    tagRef: async (owner, name, tag) => getJson(`${repo(owner, name)}/git/ref/tags/${refPath(tag)}`),
    gitTag: async (owner, name, tagSha) => getJson(`${repo(owner, name)}/git/tags/${sha2(tagSha)}`),
    // labelled (default): the search by the label pipegen; labelled false: the best-effort fallback page, which does not depend on a label that may have been dropped
    listIssues: async (owner, name, p, per, labelled = true) => getJson(`${repo(owner, name)}/issues?${new URLSearchParams({ state: "all", ...labelled ? { labels: "pipegen" } : {}, creator: "github-actions[bot]", sort: "created", direction: "desc", per_page: perPage(per), page: page(p, PAGE_CAP.issues) }).toString()}`),
    getIssue: async (owner, name, n) => getJson(`${repo(owner, name)}/issues/${num(n)}`),
    createIssue: async (owner, name, issue) => {
      const labels = issue.labels ?? [];
      if (typeof issue.title !== "string" || issue.title === "" || issue.title.length > MAX_ISSUE_TITLE) fail2("an issue title that is empty or over 256 characters");
      if (typeof issue.body !== "string" || issue.body.length > MAX_ISSUE_BODY) fail2("an issue body over the size cap");
      if (!Array.isArray(labels) || labels.length > 5 || labels.some((l) => typeof l !== "string" || !LABEL_RE.test(l))) fail2("a label that is not a plain label name");
      return send("POST", `${repo(owner, name)}/issues`, { title: issue.title, body: issue.body, ...labels.length === 0 ? {} : { labels } });
    },
    addLabels: async (owner, name, n, labels) => {
      if (!Array.isArray(labels) || labels.length === 0 || labels.length > 5 || labels.some((l) => typeof l !== "string" || !LABEL_RE.test(l))) fail2("a label that is not a plain label name");
      return send("POST", `${repo(owner, name)}/issues/${num(n)}/labels`, { labels });
    },
    updateIssue: async (owner, name, n, issue) => {
      if (typeof issue.title !== "string" || issue.title === "" || issue.title.length > MAX_ISSUE_TITLE) fail2("an issue title that is empty or over 256 characters");
      if (typeof issue.body !== "string" || issue.body.length > MAX_ISSUE_BODY) fail2("an issue body over the size cap");
      return send("PATCH", `${repo(owner, name)}/issues/${num(n)}`, { title: issue.title, body: issue.body });
    },
    collaboratorPermission: async (owner, name, login) => {
      if (typeof login !== "string" || !LOGIN_RE2.test(login)) fail2("a login that is not a GitHub login");
      return getJson(`${repo(owner, name)}/collaborators/${encodeURIComponent(login)}/permission`);
    }
  };
}

// gate/src/gated-run.ts
var DEFAULT_WAIT_MS = 30 * 6e4;
var DEFAULT_POLL_MS = 2e4;
var MAX_POLLS = 300;
var DEFAULT_MAX_CALLS = 400;
var MAX_CANDIDATES = 20;
var LISTING_GRACE_MS = 5 * 6e4;
var JOBS_PER_PAGE = 100;
var JOB_PAGE_CAP = 5;
var SHA_RE8 = /^[0-9a-f]{40}$/;
var ACTIVE = /* @__PURE__ */ new Set(["queued", "in_progress", "waiting", "pending", "requested"]);
var isPlain7 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var own5 = (o, k) => Object.hasOwn(o, k) ? o[k] : void 0;
var posInt4 = (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
var realSleep = (ms) => new Promise((r) => setTimeout(r, ms));
var BudgetError = class extends Error {
};
var why = (what, e) => e instanceof BudgetError ? `${what}: the call budget is used up` : e instanceof GitHubApiError ? `${what}: ${e.message}` : `${what}: the request failed`;
async function attemptVerdict(gh, repo2, runId, attempt, gateJobName) {
  const what = `the jobs of run ${runId} attempt ${attempt}`;
  const jobs = [];
  let total = -1;
  try {
    for (let page2 = 1; page2 <= JOB_PAGE_CAP; page2++) {
      const answer = await gh.listAttemptJobs(repo2.owner, repo2.name, runId, attempt, page2, JOBS_PER_PAGE);
      const t = isPlain7(answer) ? own5(answer, "total_count") : void 0;
      const list = isPlain7(answer) ? own5(answer, "jobs") : void 0;
      if (typeof t !== "number" || !Number.isSafeInteger(t) || t < 0 || !Array.isArray(list)) return { kind: "error", detail: `${what} could not be read (the answer is not a job list)` };
      if (total !== -1 && t !== total) return { kind: "error", detail: `${what} changed while they were read` };
      total = t;
      jobs.push(...list);
      if (jobs.length >= total) break;
      if (list.length === 0) return { kind: "error", detail: `${what} could not be read (the list is cut short)` };
    }
  } catch (e) {
    return { kind: "error", detail: why(`${what} could not be read`, e) };
  }
  if (jobs.length < total) return { kind: "error", detail: `${what} are more than the ${JOB_PAGE_CAP * JOBS_PER_PAGE} that are read, so a second gate job could hide` };
  if (jobs.length > total) return { kind: "error", detail: `${what} could not be read (more jobs than the total)` };
  const gate = [];
  for (const j of jobs) {
    if (!isPlain7(j)) return { kind: "error", detail: `${what} could not be read (a job is not an object)` };
    if (own5(j, "run_id") !== runId) return { kind: "error", detail: `${what} could not be read (a job belongs to another run)` };
    const a = own5(j, "run_attempt");
    if (a !== void 0 && a !== attempt) return { kind: "error", detail: `${what} could not be read (a job belongs to another attempt)` };
    if (own5(j, "name") === gateJobName) gate.push(j);
  }
  if (gate.length === 0) return { kind: "failed", detail: `run ${runId} has no job named ${gateJobName} in its latest attempt` };
  if (gate.length > 1) return { kind: "failed", detail: `in the latest attempt of run ${runId} more than one job reports as the gate` };
  const g = gate[0];
  const conclusion = own5(g, "conclusion");
  const shown2 = typeof conclusion === "string" && /^[a-z_]{1,30}$/.test(conclusion) ? conclusion : "not readable";
  if (own5(g, "status") !== "completed" || conclusion !== "success") return { kind: "failed", detail: `the gate job of run ${runId} did not succeed in its latest attempt (${shown2})` };
  return { kind: "ok" };
}
function centralProblem(run, central) {
  const refs = own5(run, "referenced_workflows");
  if (!Array.isArray(refs)) return `run ${String(own5(run, "id"))} lists no referenced workflows`;
  const mine = refs.filter((e) => isPlain7(e) && typeof own5(e, "path") === "string" && own5(e, "path").startsWith(`${central.pathPrefix}@`));
  if (mine.length === 0) return `run ${String(own5(run, "id"))} did not call the central workflow`;
  if (mine.some((e) => own5(e, "sha") !== central.sha)) return `run ${String(own5(run, "id"))} called the central workflow at a different commit than the expected one`;
  return void 0;
}
async function findGatedRun(gh0, repo2, sha3, o) {
  const error = (detail) => ({ ok: false, reason: "error", detail });
  if (typeof sha3 !== "string" || !SHA_RE8.test(sha3)) return error("the commit is not a 40-character lower-case sha");
  if (!isPlain7(repo2) || !posInt4(repo2.id) || typeof repo2.owner !== "string" || typeof repo2.name !== "string" || typeof repo2.defaultBranch !== "string" || repo2.defaultBranch === "") return error("the repository is not known");
  if (o.workflowPath !== WORKFLOW_PATH) return error("run trust is defined for .github/workflows/pipegen.yml only");
  const central = o.central;
  if (central !== void 0 && (!SHA_RE8.test(central.sha) || typeof central.pathPrefix !== "string" || central.pathPrefix === "" || central.pathPrefix.includes("@"))) return error("the central workflow or its commit is not usable");
  const waitMs = o.waitMs ?? DEFAULT_WAIT_MS;
  if (typeof waitMs !== "number" || !Number.isFinite(waitMs) || waitMs < 0) return error("the wait time is not usable");
  const pollMs = Math.max(1, o.pollMs ?? DEFAULT_POLL_MS, Math.ceil(waitMs / MAX_POLLS));
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? realSleep;
  const budget = { left: o.maxCalls ?? DEFAULT_MAX_CALLS, spent: false };
  const spend = () => {
    if (budget.left <= 0) {
      budget.spent = true;
      throw new BudgetError();
    }
    budget.left--;
  };
  const gh = {
    compare: (...a) => {
      spend();
      return gh0.compare(...a);
    },
    branchHead: (...a) => {
      spend();
      return gh0.branchHead(...a);
    },
    tagExists: (...a) => {
      spend();
      return gh0.tagExists(...a);
    },
    listRuns: (...a) => {
      spend();
      return gh0.listRuns(...a);
    },
    listAttemptJobs: (...a) => {
      spend();
      return gh0.listAttemptJobs(...a);
    }
  };
  const url = (id) => `https://github.com/${repo2.owner}/${repo2.name}/actions/runs/${id}`;
  const start = now();
  const waitingFor = /* @__PURE__ */ new Set();
  const failedVerdicts = /* @__PURE__ */ new Map();
  for (; ; ) {
    let listed;
    try {
      listed = await gh.listRuns(repo2.owner, repo2.name, { workflow: "pipegen.yml", branch: repo2.defaultBranch, event: "push", headSha: sha3, page: 1, perPage: 100 });
    } catch (e) {
      return error(why("the runs of this commit could not be listed", e));
    }
    const runs = isPlain7(listed) ? own5(listed, "workflow_runs") : void 0;
    if (!Array.isArray(runs)) return error("the runs of this commit could not be read (the answer is not a run list)");
    const lk = {};
    const errors = [];
    const failed = [];
    const wrongCentral = [];
    let active = 0;
    let considered = 0;
    for (const r of runs) {
      if (!runFieldsTrusted(r, repo2) || own5(r, "head_sha") !== sha3) continue;
      if (++considered > MAX_CANDIDATES) {
        errors.push(`more than ${MAX_CANDIDATES} runs for this commit`);
        break;
      }
      const id = own5(r, "id");
      if (central !== void 0) {
        const c = centralProblem(r, central);
        if (c !== void 0) {
          wrongCentral.push(c);
          continue;
        }
      }
      const attempt = own5(r, "run_attempt");
      if (!posInt4(attempt)) {
        errors.push(`run ${id} has no usable run_attempt`);
        continue;
      }
      const status = own5(r, "status");
      const isActive = typeof status === "string" && ACTIVE.has(status);
      if (!isActive && status !== "completed") {
        errors.push(`run ${id} has a status this search does not know`);
        continue;
      }
      if (isActive && waitingFor.has(id)) {
        active++;
        continue;
      }
      const kept = isActive ? void 0 : failedVerdicts.get(`${id}:${attempt}`);
      if (kept !== void 0) {
        failed.push(kept);
        continue;
      }
      const j = await judgeRun(gh, r, repo2, void 0, lk);
      if (!j.ok) {
        if (j.why === "untrusted" || j.why === "history") continue;
        errors.push(j.why === "tag" ? "a tag named like the default branch exists, so no run is trusted until it is deleted" : `run ${id} could not be checked against the default branch`);
        continue;
      }
      if (isActive) {
        waitingFor.add(id);
        active++;
        continue;
      }
      const v = await attemptVerdict(gh, repo2, id, attempt, o.gateJobName);
      if (v.kind === "ok") return { ok: true, runId: id, url: url(id) };
      if (v.kind === "failed") {
        failedVerdicts.set(`${id}:${attempt}`, v.detail);
        failed.push(v.detail);
      } else errors.push(v.detail);
    }
    if (budget.spent) return error(`the call budget of ${o.maxCalls ?? DEFAULT_MAX_CALLS} calls is used up, so the gated run could not be found`);
    if (errors.length > 0) return error(errors[0]);
    if (active > 0) {
      const left = waitMs - (now() - start);
      if (left <= 0) return { ok: false, reason: "timeout", detail: `a run for this commit was still running after ${Math.round(waitMs / 6e4)} minutes` };
      await sleep(Math.min(pollMs, left));
      continue;
    }
    if (considered === 0) {
      const left = Math.min(waitMs, LISTING_GRACE_MS) - (now() - start);
      if (left > 0) {
        await sleep(Math.min(pollMs, left));
        continue;
      }
    }
    if (failed.length > 0) return { ok: false, reason: "gate-failed", detail: failed[0] };
    if (wrongCentral.length > 0) return { ok: false, reason: "wrong-central", detail: wrongCentral[0] };
    return { ok: false, reason: "none", detail: `no trusted push run of pipegen.yml on ${repo2.defaultBranch} was found for this commit; re-run the pipeline on this commit (runs older than the retention period no longer exist)` };
  }
}

// gate/src/nightly.ts
import { createHash as createHash7 } from "node:crypto";

// gate/src/generated/gate-view.ts
var GATE_VERSION = "0.2.0";
var GATE_VIEW = [
  {
    "id": "actions-checkout",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "actions-setup-node",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "actions-setup-python",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "actions-upload-artifact",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "actions-download-artifact",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "docker-login-action",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "docker-setup-buildx-action",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "docker-build-push-action",
    "categories": [
      "platform",
      "image-build"
    ],
    "configFiles": []
  },
  {
    "id": "codeql-upload-sarif",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "actions-attest",
    "categories": [
      "platform",
      "attestation"
    ],
    "configFiles": []
  },
  {
    "id": "bullfrog",
    "categories": [
      "egress"
    ],
    "configFiles": []
  },
  {
    "id": "registry",
    "categories": [
      "platform"
    ],
    "configFiles": []
  },
  {
    "id": "zap-baseline",
    "categories": [
      "dast"
    ],
    "configFiles": [
      ".zap/**"
    ],
    "outputFile": "zap.json"
  },
  {
    "id": "trivy-config",
    "categories": [
      "iac"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      "trivy.yaml",
      ".trivyignore",
      ".trivyignore.yaml",
      "trivy-secret.yaml"
    ],
    "outputFile": "trivy-config.sarif"
  },
  {
    "id": "trivy-image",
    "categories": [
      "image-scan"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      "trivy.yaml",
      ".trivyignore",
      ".trivyignore.yaml",
      "trivy-secret.yaml"
    ],
    "outputFile": "trivy-image.sarif"
  },
  {
    "id": "betterleaks",
    "categories": [
      "secrets"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      ".betterleaks.toml",
      ".gitleaks.toml",
      ".gitleaksignore",
      ".betterleaksignore"
    ],
    "outputFile": "betterleaks.sarif"
  },
  {
    "id": "gitleaks",
    "categories": [
      "secrets"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      ".gitleaks.toml",
      ".gitleaksignore"
    ],
    "outputFile": "gitleaks.sarif"
  },
  {
    "id": "semgrep",
    "categories": [
      "sast"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      ".semgrepignore"
    ],
    "outputFile": "semgrep.sarif"
  },
  {
    "id": "osv-scanner",
    "categories": [
      "deps",
      "dependency-review"
    ],
    "configFiles": [
      "**/osv-scanner.toml"
    ],
    "outputFile": "osv.sarif"
  },
  {
    "id": "lefthook",
    "categories": [
      "hooks",
      "hooks-ci"
    ],
    "configFiles": [
      ".lefthook/**",
      ".lefthook-local/**"
    ],
    "rootConfigFiles": [
      "lefthook.yml",
      "lefthook.yaml",
      ".lefthook.yml",
      ".lefthook.yaml",
      "lefthook-local.yml",
      "lefthook-local.yaml",
      ".lefthook-local.yml",
      ".lefthook-local.yaml"
    ]
  },
  {
    "id": "syft",
    "categories": [
      "sbom"
    ],
    "configFiles": [
      ".syft/**"
    ],
    "rootConfigFiles": [
      ".syft.yaml",
      ".syft.yml",
      "syft.yaml"
    ]
  },
  {
    "id": "cosign",
    "categories": [
      "signing"
    ],
    "configFiles": []
  },
  {
    "id": "actionlint",
    "categories": [
      "workflow-lint"
    ],
    "configFiles": [
      ".github/actionlint.yaml",
      ".github/actionlint.yml"
    ]
  },
  {
    "id": "zizmor",
    "categories": [
      "workflow-lint"
    ],
    "configFiles": [
      ".github/zizmor.yml",
      ".github/zizmor.yaml"
    ],
    "rootConfigFiles": [
      "zizmor.yml",
      "zizmor.yaml"
    ]
  },
  {
    "id": "biome",
    "categories": [
      "lint",
      "format",
      "format-lint"
    ],
    "configFiles": [
      "biome.json",
      "biome.jsonc",
      ".biome.json",
      ".biome.jsonc",
      "**/biome.json",
      "**/biome.jsonc",
      ".editorconfig"
    ]
  },
  {
    "id": "eslint",
    "categories": [
      "lint"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      "eslint.config.js",
      "eslint.config.mjs",
      "eslint.config.cjs",
      "eslint.config.ts",
      "eslint.config.mts",
      "eslint.config.cts"
    ]
  },
  {
    "id": "eslint-typescript",
    "categories": [
      "lint"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      "eslint.config.js",
      "eslint.config.mjs",
      "eslint.config.cjs",
      "eslint.config.ts",
      "eslint.config.mts",
      "eslint.config.cts"
    ]
  },
  {
    "id": "oxlint-typeaware",
    "categories": [
      "lint"
    ],
    "configFiles": [
      ".oxlintrc.json",
      "oxlint.config.ts",
      "**/.oxlintrc.json"
    ]
  },
  {
    "id": "prettier",
    "categories": [
      "format"
    ],
    "configFiles": [
      ".prettierrc",
      ".prettierrc.*",
      "prettier.config.*",
      "**/.prettierrc",
      "**/.prettierrc.*",
      ".editorconfig"
    ],
    "rootConfigFiles": [
      ".prettierignore"
    ],
    "configSections": [
      "package.json:prettier"
    ]
  },
  {
    "id": "vitest-coverage",
    "categories": [
      "coverage"
    ],
    "configFiles": [
      "vitest.config.*",
      "vite.config.*",
      "vitest.workspace.*",
      "**/vitest.config.*"
    ]
  },
  {
    "id": "c8",
    "categories": [
      "coverage"
    ],
    "configFiles": [
      ".c8rc",
      ".c8rc.*",
      ".nycrc",
      ".nycrc.*"
    ],
    "configSections": [
      "package.json:c8"
    ]
  },
  {
    "id": "knip",
    "categories": [
      "dead-code"
    ],
    "configFiles": [
      "knip.json",
      "knip.jsonc",
      ".knip.json",
      ".knip.jsonc",
      "knip.config.*",
      "knip.ts",
      "knip.js"
    ],
    "configSections": [
      "package.json:knip"
    ]
  },
  {
    "id": "jscpd",
    "categories": [
      "duplication"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      ".jscpd.json"
    ],
    "configSections": [
      "package.json:jscpd"
    ]
  },
  {
    "id": "trivy-licence",
    "categories": [
      "licences"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      "trivy.yaml",
      ".trivyignore",
      ".trivyignore.yaml",
      "trivy-secret.yaml"
    ],
    "outputFile": "trivy-licence.sarif"
  },
  {
    "id": "dependency-review-action",
    "categories": [
      "dependency-review"
    ],
    "configFiles": [
      ".github/dependency-review-config.yml"
    ]
  },
  {
    "id": "hadolint",
    "categories": [
      "dockerfile-lint"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      ".hadolint.yaml",
      ".hadolint.yml"
    ],
    "outputFile": "hadolint.sarif"
  },
  {
    "id": "kube-linter",
    "categories": [
      "iac"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      ".kube-linter.yaml",
      ".kube-linter.yml"
    ],
    "outputFile": "kube-linter.sarif"
  },
  {
    "id": "schemathesis",
    "categories": [
      "api-dast"
    ],
    "configFiles": [
      "schemathesis.toml"
    ],
    "outputFile": "schemathesis.xml"
  },
  {
    "id": "nuclei",
    "categories": [
      "dast"
    ],
    "configFiles": [],
    "outputFile": "nuclei.sarif"
  },
  {
    "id": "scorecard-action",
    "categories": [
      "scorecard"
    ],
    "configFiles": [],
    "outputFile": "scorecard.sarif"
  },
  {
    "id": "pinact",
    "categories": [
      "workflow-pin-check"
    ],
    "configFiles": [
      ".pinact.yaml",
      ".pinact.yml",
      ".github/pinact.yaml",
      ".github/pinact.yml"
    ]
  },
  {
    "id": "poutine",
    "categories": [
      "workflow-lint"
    ],
    "configFiles": [
      ".github/poutine.yml",
      ".github/poutine.yaml"
    ],
    "rootConfigFiles": [
      ".poutine.yml",
      ".poutine.yaml"
    ]
  },
  {
    "id": "gosec",
    "categories": [
      "sast"
    ],
    "configFiles": [],
    "outputFile": "gosec.sarif"
  },
  {
    "id": "ruff",
    "categories": [
      "lint",
      "format-lint"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      "ruff.toml",
      ".ruff.toml"
    ],
    "configSections": [
      "pyproject.toml:tool.ruff"
    ],
    "outputFile": "ruff.sarif"
  },
  {
    "id": "ruff-format",
    "categories": [
      "format"
    ],
    "configFiles": [],
    "rootConfigFiles": [
      "ruff.toml",
      ".ruff.toml"
    ],
    "configSections": [
      "pyproject.toml:tool.ruff"
    ]
  },
  {
    "id": "mypy",
    "categories": [
      "type-check"
    ],
    "configFiles": [
      "mypy.ini",
      ".mypy.ini"
    ],
    "configSections": [
      "pyproject.toml:tool.mypy",
      "setup.cfg:mypy",
      "setup.cfg:mypy-*"
    ]
  },
  {
    "id": "coverage-py",
    "categories": [
      "coverage"
    ],
    "configFiles": [
      ".coveragerc"
    ],
    "configSections": [
      "pyproject.toml:tool.coverage",
      "setup.cfg:coverage:*",
      "tox.ini:coverage:*"
    ]
  },
  {
    "id": "creosote",
    "categories": [
      "dead-code"
    ],
    "configFiles": [],
    "configSections": [
      "pyproject.toml:tool.creosote"
    ]
  },
  {
    "id": "vulture",
    "categories": [
      "dead-code"
    ],
    "configFiles": [],
    "configSections": [
      "pyproject.toml:tool.vulture"
    ]
  },
  {
    "id": "bandit",
    "categories": [
      "sast"
    ],
    "configFiles": [
      ".bandit"
    ],
    "configSections": [
      "pyproject.toml:tool.bandit"
    ],
    "outputFile": "bandit.sarif"
  },
  {
    "id": "pypi-publish",
    "categories": [
      "attestation",
      "publishing"
    ],
    "configFiles": []
  },
  {
    "id": "pipegen-gate",
    "categories": [
      "gate"
    ],
    "configFiles": []
  }
];

// gate/src/pin-patch.ts
var isPlain8 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var SHA_RE9 = /^[0-9a-f]{40}$/;
var SEMVER_RE = /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/;
var PatchRefused = class extends Error {
};
var CONTEXT = 3;
var MAX_SHOWN_LINE = 400;
var PATCH_PATH_RE = /^[A-Za-z0-9._/-]{1,200}$/;
var UNSAFE_CHAR_RE = new RegExp("[\\u0000-\\u0008\\u000a-\\u001f\\u007f-\\u009f\\p{Cf}\\p{Zl}\\p{Zp}\\p{Co}\\p{Cs}\\p{Default_Ignorable_Code_Point}\\u202a-\\u202e\\u2066-\\u2069\\u061c\\ufeff\\ufff9-\\ufffb]", "u");
function blockScalarLines(lines) {
  const inside = /* @__PURE__ */ new Set();
  let col;
  lines.forEach((raw, i) => {
    const line = raw.replace(/\r$/, "");
    if (col !== void 0) {
      if (line.trim() === "") {
        inside.add(i);
        return;
      }
      if (/^ */.exec(line)[0].length > col) {
        inside.add(i);
        return;
      }
      col = void 0;
    }
    if (/^\s*#/.test(line)) return;
    const m = /^( *)((?:- +)?)[^\s#:][^#]*?:[ \t]+[|>][+-]?[1-9]?[+-]?[ \t]*(?:#.*)?$/.exec(line);
    if (m !== null) col = m[1].length + m[2].length;
  });
  return inside;
}
var RARE_WINDOW = 50;
var RARE_FORMS = [
  /:[ \t]+(?:[&!]\S*[ \t]+)+[|>]/,
  /^\s*-\s+(?:[&!]\S*\s+)*[|>][+-]?[0-9]?[+-]?\s*(?:#.*)?$/,
  /^\s*\?(?:\s|$)/,
  /(?:^\s*-\s+|:[ \t]+)"(?:[^"\\]|\\.)*$/,
  /(?:^\s*-\s+|:[ \t]+)'(?:[^']|'')*$/
];
function refuseRareForms(lines, pinRe, path) {
  lines.forEach((line, i) => {
    if (!pinRe.test(line)) return;
    for (let k = Math.max(0, i - RARE_WINDOW); k < i; k++) {
      const above = lines[k].replace(/\r$/, "");
      if (/^\s*#/.test(above)) continue;
      if (RARE_FORMS.some((f) => f.test(above))) throw new PatchRefused(`Refused: ${path} uses a YAML form (an anchor or tag on a block scalar, a block scalar as a list item, an explicit key, or a quoted scalar over several lines) near line ${i + 1}, which this patch maker does not parse.`);
    }
  });
}
var pinLineRe = (sha3, version) => new RegExp(`^(\\s*(?:-\\s+)?uses:\\s+)crisworking/pipegen/gate@${sha3} # gate-v${version.replace(/\./g, "\\.")}(\\s*)$`);
function pinnedShas(text, version) {
  const lines = text.split("\n");
  const block = blockScalarLines(lines);
  const re = pinLineRe("([0-9a-f]{40})", version);
  return [...new Set(lines.map((l, i) => block.has(i) ? void 0 : re.exec(l)?.[2]).filter((x) => x !== void 0))];
}
function filePatch(file, from, to) {
  if (!PATCH_PATH_RE.test(file.path) || file.path.split("/").some((p) => p === "" || p === "." || p === "..")) throw new PatchRefused("Refused: the file path is not a plain repository path.");
  const parts = file.text.split("\n");
  const endsWithNewline = parts[parts.length - 1] === "";
  const lines = endsWithNewline ? parts.slice(0, -1) : parts;
  const re = pinLineRe(from.sha, from.version);
  const block = blockScalarLines(lines);
  refuseRareForms(lines, re, file.path);
  const at3 = [];
  const replaced = /* @__PURE__ */ new Map();
  lines.forEach((line, i) => {
    const m = block.has(i) ? null : re.exec(line);
    if (m === null) return;
    at3.push(i);
    replaced.set(i, `${m[1]}crisworking/pipegen/gate@${to.sha} # gate-v${to.version}${m[2]}`);
  });
  if (at3.length === 0) return "";
  const ranges = [];
  for (const i of at3) {
    const start = Math.max(0, i - CONTEXT);
    const end = Math.min(lines.length - 1, i + CONTEXT);
    const last = ranges[ranges.length - 1];
    if (last !== void 0 && start <= last.end + 1) last.end = end;
    else ranges.push({ start, end });
  }
  const out = [`--- a/${file.path}`, `+++ b/${file.path}`];
  const noNewlineAtEnd = (i) => !endsWithNewline && i === lines.length - 1;
  for (const r of ranges) {
    const count = r.end - r.start + 1;
    out.push(`@@ -${r.start + 1},${count} +${r.start + 1},${count} @@`);
    for (let i = r.start; i <= r.end; i++) {
      const line = lines[i];
      const shown2 = (text) => {
        const bare = text.endsWith("\r") ? text.slice(0, -1) : text;
        if (UNSAFE_CHAR_RE.test(bare) || bare.length > MAX_SHOWN_LINE || bare.includes("<!--") || bare.includes("-->") || bare.includes("\r")) {
          throw new PatchRefused(`Refused: line ${i + 1} of ${file.path} holds text the issue format can not carry safely (a control or invisible character, a very long line, or an HTML comment marker).`);
        }
      };
      shown2(line);
      const mark = noNewlineAtEnd(i) ? ["\\ No newline at end of file"] : [];
      const swap = replaced.get(i);
      if (swap === void 0) {
        out.push(` ${line}`, ...mark);
        continue;
      }
      shown2(swap);
      out.push(`-${line}`, ...mark, `+${swap}`, ...mark);
    }
  }
  return `${out.join("\n")}
`;
}
function checkPin(p, which) {
  if (!isPlain8(p) || typeof p.sha !== "string" || !SHA_RE9.test(p.sha) || typeof p.version !== "string" || !SEMVER_RE.test(p.version)) {
    throw new PatchRefused(`Refused: the ${which} pin is not a 40-character lower-case commit and a plain x.y.z version.`);
  }
}
function updatePatch(files, from, to) {
  checkPin(from, "old");
  checkPin(to, "new");
  return files.map((f) => filePatch(f, from, to)).join("");
}

// gate/src/nightly.ts
var isPlain9 = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var own6 = (o, k) => Object.hasOwn(o, k) ? o[k] : void 0;
var SHA_RE10 = /^[0-9a-f]{40}$/;
var SEMVER_RE2 = /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/;
var GATE_TAG_RE = /^gate-v((?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5}))$/;
var ISO_RE = /^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
var DAY_MS = 864e5;
function isoTime(v) {
  if (typeof v !== "string") return void 0;
  const m = ISO_RE.exec(v);
  if (m === null || validDate(m[1]) === void 0) return void 0;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : void 0;
}
var clockOf = (d) => d instanceof Date && Number.isFinite(d.getTime()) ? d.getTime() : void 0;
function semver(v) {
  const m = SEMVER_RE2.exec(v);
  return m === null ? void 0 : [Number(m[1]), Number(m[2]), Number(m[3])];
}
var newer = (a, b) => a[0] !== b[0] ? a[0] > b[0] : a[1] !== b[1] ? a[1] > b[1] : a[2] > b[2];
function effectiveBlockFrom(blockFrom, recorded) {
  const dates = [validDate(blockFrom), validDate(recorded)].filter((x) => x !== void 0).sort();
  return dates[0];
}
function warnEnding(blockFrom, today, oldFindings) {
  const date = validDate(blockFrom);
  const now = clockOf(today);
  if (date === void 0 || now === void 0) return null;
  const startOfToday = Math.floor(now / DAY_MS) * DAY_MS;
  const daysLeft = Math.round((Date.parse(`${date}T00:00:00Z`) - startOfToday) / DAY_MS);
  if (daysLeft <= 0) return null;
  const unknown = typeof oldFindings !== "number" || !Number.isSafeInteger(oldFindings) || oldFindings < 0;
  if (!unknown && oldFindings === 0) return null;
  return { open: daysLeft <= 2, daysLeft, unknown };
}
function finishMissing(blockFrom, setupMergedAt2, now) {
  if (validDate(blockFrom) !== void 0) return false;
  const merged = isoTime(setupMergedAt2);
  const clock = clockOf(now);
  if (merged === void 0 || clock === void 0) return false;
  return clock - merged > DAY_MS;
}
var WARN_FIRST_DAYS = 14;
var NEED_ID_RE2 = /^(?!base-)(?!.*--)[a-z0-9][a-z0-9-]{0,63}$/;
function warnFirstEnd(since, setupMergedAt2) {
  const start = validDate(since);
  const merged = isoTime(setupMergedAt2);
  if (start === void 0 || merged === void 0) return void 0;
  const from = Math.max(Date.parse(`${start}T00:00:00Z`), Math.floor(merged / DAY_MS) * DAY_MS);
  return new Date(from + WARN_FIRST_DAYS * DAY_MS).toISOString().slice(0, 10);
}
var UPDATE_COOLDOWN_DAYS = 7;
function updateAvailable(current, latest, now) {
  if (latest === null) return false;
  const cur = semver(current);
  const next = semver(latest.version);
  const published = isoTime(latest.publishedAt);
  const clock = clockOf(now);
  if (cur === void 0 || next === void 0 || published === void 0 || clock === void 0) return false;
  return newer(next, cur) && clock - published >= UPDATE_COOLDOWN_DAYS * DAY_MS;
}
var FULL_RE = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/;
async function resolveRepo(gh, full, idText) {
  const m = typeof full === "string" ? FULL_RE.exec(full) : null;
  if (m === null || m[2] === "." || m[2] === "..") return "GITHUB_REPOSITORY is not an owner/name";
  if (typeof idText !== "string" || !/^[1-9][0-9]{0,15}$/.test(idText) || !Number.isSafeInteger(Number(idText))) return "GITHUB_REPOSITORY_ID is not a repository id";
  const [owner, name] = [m[1], m[2]];
  let a;
  try {
    a = await gh.getRepo(owner, name);
  } catch {
    return "the repository could not be read (GET /repos/{owner}/{name})";
  }
  if (!isPlain9(a)) return "the repository answer is not an object";
  const id = own6(a, "id");
  const fullName = own6(a, "full_name");
  const branch = own6(a, "default_branch");
  if (id !== Number(idText)) return "the repository id does not equal GITHUB_REPOSITORY_ID";
  if (typeof fullName !== "string" || fullName.toLowerCase() !== full.toLowerCase()) return "the repository name does not equal GITHUB_REPOSITORY";
  if (typeof branch !== "string" || branch === "" || branch.length > 255) return "the repository answer has no default branch";
  return { owner, name, id: Number(idText), defaultBranch: branch };
}
var BOT_LOGIN = "github-actions[bot]";
var ISSUE_PAGE_CAP = 5;
var ISSUE_PER_PAGE = 100;
var KEY_RE = /^[a-z0-9][a-z0-9.-]{0,99}$/;
var MAX_TITLE = 256;
var MAX_BODY = 6e4;
var markerOf = (key) => `<!-- pipegen:key=${key} -->`;
var ISSUE_LABEL = "pipegen";
async function upsertIssueDetailed(gh, repo2, key, title, body, opts = {}) {
  if (typeof key !== "string" || !KEY_RE.test(key)) throw new Error("nightly: the issue key is not a plain key");
  if (typeof title !== "string" || title === "" || title.length > MAX_TITLE) throw new Error("nightly: the issue title is empty or too long");
  if (typeof body !== "string" || markerOf(key).length + 1 + body.length > MAX_BODY) throw new Error("nightly: the issue body is too long");
  const marker = markerOf(key);
  const wanted = opts.labels ?? [];
  const hitOf = (raw, strict) => {
    if (!isPlain9(raw)) {
      if (strict) throw new Error("nightly: the issue list holds an entry that is not an issue, so no issue is written");
      return void 0;
    }
    const number = own6(raw, "number");
    if (typeof number !== "number" || !Number.isSafeInteger(number) || number <= 0) {
      if (strict) throw new Error("nightly: the issue list holds an entry with no issue number, so no issue is written");
      return void 0;
    }
    if (own6(raw, "pull_request") !== void 0) return void 0;
    const user = own6(raw, "user");
    if (!isPlain9(user) || own6(user, "login") !== BOT_LOGIN || own6(user, "type") !== "Bot") return void 0;
    const b = own6(raw, "body");
    if (typeof b !== "string" || b.split("\n")[0].replace(/\r$/, "") !== marker) return void 0;
    const ls = own6(raw, "labels");
    const names = Array.isArray(ls) ? ls.map((l) => isPlain9(l) ? own6(l, "name") : void 0).filter((n2) => typeof n2 === "string") : [];
    return { number, state: String(own6(raw, "state")), title: String(own6(raw, "title") ?? ""), body: b, labels: names };
  };
  let open;
  const closed = [];
  let complete = false;
  for (let page2 = 1; page2 <= ISSUE_PAGE_CAP; page2++) {
    const list = await gh.listIssues(repo2.owner, repo2.name, page2, ISSUE_PER_PAGE);
    if (!Array.isArray(list)) throw new Error("nightly: the issue list is not a list, so no issue is written");
    for (const raw of list) {
      const h = hitOf(raw, true);
      if (h === void 0) continue;
      if (h.state === "open") {
        open = h;
        break;
      }
      if (closed.length < MAX_CLOSED_CHECKS) closed.push(h.number);
    }
    if (open !== void 0) break;
    if (list.length < ISSUE_PER_PAGE) {
      complete = true;
      break;
    }
  }
  let adopted = false;
  if (open === void 0 && closed.length === 0) {
    if (!complete) throw new Error(`nightly: the issue list reaches its cap of ${ISSUE_PAGE_CAP} pages without ending, so no issue is created (it might be a duplicate)`);
    const list = await gh.listIssues(repo2.owner, repo2.name, 1, ISSUE_PER_PAGE, false);
    if (!Array.isArray(list)) throw new Error("nightly: the unlabelled issue list is not a list, so no issue is written");
    for (const raw of list) {
      const h = hitOf(raw, false);
      if (h === void 0) continue;
      adopted = true;
      if (h.state === "open") {
        open = h;
        break;
      }
      if (closed.length < MAX_CLOSED_CHECKS) closed.push(h.number);
    }
  }
  const want = adopted ? [ISSUE_LABEL, ...wanted] : wanted;
  if (open !== void 0) {
    const second = open.body.replace(/\r\n/g, "\n").split("\n")[1] ?? "";
    const kept = !adopted && /^> Reopened after a bot closed #[0-9]+\.$/.test(second) ? `${second}

` : "";
    const text = `${marker}
${kept}${body}`;
    const missing = want.filter((l) => !open.labels.includes(l));
    const same = open.title === title && open.body.replace(/\r\n/g, "\n") === text;
    if (!same) await gh.updateIssue(repo2.owner, repo2.name, open.number, { title, body: text });
    if (missing.length > 0) await ensureLabels(gh, repo2, open.number, missing);
    return { key, number: open.number, action: same ? "unchanged" : "updated" };
  }
  let botClosed;
  for (const n2 of closed) {
    const full = await gh.getIssue(repo2.owner, repo2.name, n2);
    if (!isPlain9(full)) throw new Error(`nightly: issue #${n2} could not be read, so no issue is written`);
    if (isPerson(own6(full, "closed_by"))) {
      if (adopted) await ensureLabels(gh, repo2, n2, [ISSUE_LABEL]);
      return { key, number: n2, action: "left-closed" };
    }
    botClosed ??= n2;
  }
  if (!complete) throw new Error(`nightly: the issue list reaches its cap of ${ISSUE_PAGE_CAP} pages without ending, so no issue is created (it might be a duplicate)`);
  const reopened = botClosed === void 0 ? "" : `> Reopened after a bot closed #${botClosed}.

`;
  const made = await gh.createIssue(repo2.owner, repo2.name, { title, body: `${marker}
${reopened}${body}` });
  const n = isPlain9(made) ? own6(made, "number") : void 0;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n <= 0) throw new Error("nightly: GitHub did not answer with the number of the new issue");
  await ensureLabels(gh, repo2, n, [ISSUE_LABEL, ...wanted]);
  return { key, number: n, action: "created" };
}
var MAX_CLOSED_CHECKS = 3;
function isPerson(closedBy) {
  if (!isPlain9(closedBy)) return false;
  const login = own6(closedBy, "login");
  return own6(closedBy, "type") === "User" && typeof login === "string" && login !== "" && login !== BOT_LOGIN && !login.endsWith("[bot]");
}
async function ensureLabels(gh, repo2, number, labels) {
  const answer = await gh.addLabels(repo2.owner, repo2.name, number, labels);
  const names = Array.isArray(answer) ? answer.map((l) => typeof l === "string" ? l : isPlain9(l) ? own6(l, "name") : void 0) : [];
  const missing = labels.filter((l) => !names.includes(l));
  if (missing.length > 0) throw new Error(`nightly: the label ${missing.join(", ")} could not be set on issue #${number} (a token without push access drops labels), so nightly stops instead of risking a duplicate issue every night`);
}
var SETUP_BRANCH = "pipegen/setup";
var PULL_PAGES = 3;
async function setupMergedAt(gh, repo2, now) {
  const clock = clockOf(now);
  if (clock === void 0) return { note: "the clock is not a date, so the setup merge is not proven" };
  let best;
  try {
    for (let page2 = 1; page2 <= PULL_PAGES; page2++) {
      const list = await gh.listSetupPulls(repo2.owner, repo2.name, page2, 100);
      if (!Array.isArray(list)) return { note: "the list of closed setup pull requests could not be read (not a list), so the setup merge is not proven" };
      for (const pr of list) {
        if (!isPlain9(pr)) continue;
        const head = own6(pr, "head");
        const base = own6(pr, "base");
        if (!isPlain9(head) || !isPlain9(base) || own6(head, "ref") !== SETUP_BRANCH || own6(base, "ref") !== repo2.defaultBranch) continue;
        const hr = own6(head, "repo");
        const br = own6(base, "repo");
        const hid = isPlain9(hr) ? own6(hr, "id") : void 0;
        const bid = isPlain9(br) ? own6(br, "id") : void 0;
        if (typeof hid !== "number" || hid !== bid || hid !== repo2.id) continue;
        const merged = own6(pr, "merged_at");
        const t = isoTime(merged);
        const mergeSha = own6(pr, "merge_commit_sha");
        if (t === void 0 || t > clock || typeof mergeSha !== "string" || !SHA_RE10.test(mergeSha)) continue;
        if (best === void 0 || t > best.t) best = { t, at: merged, sha: mergeSha };
      }
      if (list.length < 100) break;
    }
  } catch {
    return { note: "the list of closed setup pull requests could not be read, so the setup merge is not proven" };
  }
  return best === void 0 ? {} : { at: best.at, sha: best.sha };
}
var PIPEGEN_OWNER = "crisworking";
var PIPEGEN_NAME = "pipegen";
var RELEASE_PAGES = 3;
var MAX_TAG_CHAIN = 4;
async function resolveGateTag(gh, tag) {
  const ref2 = await gh.tagRef(PIPEGEN_OWNER, PIPEGEN_NAME, tag);
  if (!isPlain9(ref2) || own6(ref2, "ref") !== `refs/tags/${tag}`) throw new Error("the tag ref is not the tag asked for");
  let obj = own6(ref2, "object");
  const seen = /* @__PURE__ */ new Set();
  for (let depth = 0; depth <= MAX_TAG_CHAIN; depth++) {
    if (!isPlain9(obj)) throw new Error("the tag has no object");
    const type = own6(obj, "type");
    const sha3 = own6(obj, "sha");
    if (typeof sha3 !== "string" || !SHA_RE10.test(sha3)) throw new Error("the tag points at something that is not a 40-hex sha");
    if (type === "commit") return sha3;
    if (type !== "tag") throw new Error(`the tag points at a ${typeof type === "string" && /^[a-z]{1,10}$/.test(type) ? type : "thing"}, not a commit`);
    if (seen.has(sha3) || depth === MAX_TAG_CHAIN) throw new Error("the annotated tag chain loops or is too long");
    seen.add(sha3);
    const tagObject = await gh.gitTag(PIPEGEN_OWNER, PIPEGEN_NAME, sha3);
    if (!isPlain9(tagObject) || own6(tagObject, "sha") !== sha3) throw new Error("the annotated tag object is not the one asked for");
    obj = own6(tagObject, "object");
  }
  throw new Error("the annotated tag chain is too long");
}
async function latestGateRelease(gh, current, now) {
  const found = [];
  try {
    for (let page2 = 1; page2 <= RELEASE_PAGES; page2++) {
      const list = await gh.listReleases(PIPEGEN_OWNER, PIPEGEN_NAME, page2, 100);
      if (!Array.isArray(list)) return { note: "no update check: the release list of pipegen could not be read (not a list)" };
      for (const r of list) {
        if (!isPlain9(r)) continue;
        const tag = own6(r, "tag_name");
        const m = typeof tag === "string" ? GATE_TAG_RE.exec(tag) : null;
        const published = own6(r, "published_at");
        if (m === null || own6(r, "draft") !== false || own6(r, "prerelease") !== false || isoTime(published) === void 0) continue;
        const ver = semver(m[1]);
        if (ver !== void 0) found.push({ version: m[1], ver, publishedAt: published, tag, immutable: own6(r, "immutable") === true });
      }
      if (list.length < 100) break;
    }
  } catch {
    return { note: "no update check: the release list of pipegen could not be read (the repository is private until v0.4, so this is expected)" };
  }
  const eligible = found.filter((f) => updateAvailable(current, { version: f.version, publishedAt: f.publishedAt }, now)).sort((a, b) => newer(a.ver, b.ver) ? -1 : newer(b.ver, a.ver) ? 1 : 0);
  const top = eligible.find((f) => f.immutable);
  if (top === void 0) return eligible.length === 0 ? {} : { note: `no update: ${eligible[0]?.tag ?? "the newest release"} is not an immutable release, so its tag could be moved after the cooldown` };
  try {
    const sha3 = await resolveGateTag(gh, top.tag);
    return { release: { version: top.version, publishedAt: top.publishedAt, tag: top.tag, sha: sha3 } };
  } catch (e) {
    return { note: `no update: the tag ${top.tag} could not be resolved to a commit (${e instanceof Error ? e.message : "unknown"})` };
  }
}
function blobSha(bytes) {
  return createHash7("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}
var MAX_WORKFLOW_BYTES = 1024 * 1024;
async function readWorkflow(gh, repo2) {
  const tip = await resolveTip(gh, repo2);
  if (tip === void 0) return { why: "the default branch could not be resolved" };
  let a;
  try {
    a = await gh.fileAt(repo2.owner, repo2.name, WORKFLOW_PATH, tip);
  } catch {
    return { why: "the workflow file could not be read" };
  }
  if (a === null) return { why: "there is no pipegen.yml in this repository (a private repository keeps the pin in the central repository)" };
  if (!isPlain9(a) || own6(a, "type") !== "file" || own6(a, "encoding") !== "base64" || typeof own6(a, "content") !== "string") return { why: "the workflow file answer is not a readable file" };
  const size = own6(a, "size");
  if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0 || size > MAX_WORKFLOW_BYTES) return { why: "the workflow file is over the size cap" };
  const bytes = Buffer.from(own6(a, "content").replace(/\s+/g, ""), "base64");
  if (bytes.length > MAX_WORKFLOW_BYTES) return { why: "the workflow file is over the size cap" };
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { why: "the workflow file is not UTF-8 text" };
  }
  return { text, baseSha: blobSha(bytes) };
}
var repoName = (repo2) => safeMarkdown(`${repo2.owner}/${repo2.name}`, 200);
var branchName = (repo2) => safeMarkdown(repo2.defaultBranch, 100);
var plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
function warnEndingIssue(repo2, date, w, old, note) {
  const days = plural(w.daysLeft, "day", "days");
  const count = typeof old === "number" ? `There are ${plural(old, "existing finding", "existing findings")} on ${branchName(repo2)} in the trusted baseline (signed by this repository's own pipegen run). In block mode they follow the policy and can block merges.` : `Old findings unknown: pipegen found no trusted baseline for ${branchName(repo2)}${note === void 0 ? "" : ` (${safeMarkdown(note, 300)})`}, so it can not count the findings that block mode would start to judge. Do not read this as "none".`;
  return {
    title: `pipegen: warn mode ends in ${days}${w.unknown ? "; old findings unknown" : ""}`,
    body: [
      `## Warn mode ends in ${days}`,
      "",
      `In ${repoName(repo2)}, old findings only warn until \`${date}\` (00:00 UTC). From that day the pipegen gate runs in block mode.`,
      "",
      count,
      "",
      "What to do: fix the old findings, or accept them knowingly before that day. The date is the earlier of the repository variable `PIPEGEN_BLOCK_FROM` and the date recorded at setup; moving the variable later does not postpone a recorded date.",
      "",
      "This issue is opened by pipegen's nightly job and updated in place every night. pipegen does not close it."
    ].join("\n")
  };
}
function finishMissingIssue(repo2, mergedAt) {
  return {
    title: "pipegen: setup was merged but finish has not run",
    body: [
      "## `pipegen finish` has not run",
      "",
      `The pipegen setup pull request for ${repoName(repo2)} was merged at \`${mergedAt}\`, more than 24 hours ago, but the repository variable \`PIPEGEN_BLOCK_FROM\` is still not set. That variable is set by \`finish\`, which also applies the repository settings.`,
      "",
      "Run it from a machine where you are signed in to GitHub:",
      "",
      "`npx pipegen finish`",
      "",
      "This issue is opened by pipegen's nightly job and updated in place every night. pipegen does not close it."
    ].join("\n")
  };
}
function warnFirstIssue(repo2, needId, since, end) {
  return {
    title: `pipegen: make the ${needId} check blocking (its warn-first period ended ${end})`,
    body: [
      `## The \`${needId}\` check can block now`,
      "",
      `In ${repoName(repo2)}, the pipegen gate has run the \`${needId}\` check as warn-first since \`${since}\`: its failures and its old or medium findings only warn. A new critical, high or secret finding already blocks. The warn period (${WARN_FIRST_DAYS} days after setup) ended on \`${end}\`.`,
      "",
      "To make the check blocking, run:",
      "",
      "`npx pipegen update`",
      "",
      "It removes warn-first from this check in a pull request you review: `pipegen.yml` is a protected file, and CI never edits a workflow. To keep the check warn-first, close this issue: pipegen does not open it again for this check and date.",
      "",
      "> **This issue is advisory.** Anyone with issue rights in a public repository, and any job with `issues: write`, can open an issue that looks like this one. `pipegen update` reads the checks from your pipeline, not from this issue.",
      "",
      "This issue is opened by pipegen's nightly job and updated in place every night. pipegen does not close it."
    ].join("\n")
  };
}
function fenceFor(text) {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((r) => r.length));
  return "`".repeat(Math.max(3, longest + 1));
}
var ADVISORY = [
  "> **This issue is advisory.** Anyone with issue rights in a public repository, and any job with `issues: write`, can open an issue that looks exactly like this one, even as `github-actions[bot]`.",
  "> So `pipegen update` does not apply a patch from an issue: it re-derives the patch itself, from the reviewed list bundled with the pipegen version you run, and uses this issue only as a prompt.",
  "> If you apply anything by hand, compare the commit with the pin in the reviewed list of `pipegen@{VERSION}` (the list `pipegen update` uses), not with the tag: a tag is not authority."
].join("\n");
function updateIssue(repo2, rel, patch, notes) {
  const v = safeMarkdown(`v${rel.version}`, 40);
  const cur = safeMarkdown(`v${GATE_VERSION}`, 40);
  const lines = [
    `## pipegen gate ${v} is available`,
    "",
    `${repoName(repo2)} runs pipegen gate ${cur}. Version ${v} was released at \`${rel.publishedAt}\`, at least ${UPDATE_COOLDOWN_DAYS} days ago.`,
    "",
    `- release tag: \`${rel.tag}\``,
    `- the commit that tag resolves to (the new pin): \`${rel.sha}\``,
    "",
    "The commit comes from resolving the tag through the git refs API, never from the release text.",
    "",
    "To update, run:",
    "",
    `\`npx pipegen@${rel.version} update\``,
    ""
  ];
  if (patch !== void 0) {
    const fence = fenceFor(patch.diff);
    lines.push(
      "The patch below swaps only the pinned gate line or lines in `.github/workflows/pipegen.yml`; every other byte stays the same.",
      "",
      `${fence}diff`,
      patch.diff.replace(/\n$/, ""),
      fence,
      `<!-- pipegen:patch ${JSON.stringify({ repo: "app", path: WORKFLOW_PATH, baseSha: patch.baseSha })} -->`,
      ""
    );
  } else {
    lines.push("There is no patch in this issue: pipegen could not read a pin line to swap here (a private repository keeps the pin in the central repository, which `pipegen update` changes with your token).", "");
  }
  for (const n of notes) lines.push(`Note: ${safeMarkdown(n, 300)}`, "");
  lines.push(ADVISORY.replace("{VERSION}", rel.version), "", "This issue is opened by pipegen's nightly job. pipegen does not close it.");
  return { title: `pipegen: gate v${rel.version} is available`, body: lines.join("\n"), labels: patch === void 0 ? [] : ["pipegen:patch"] };
}
var MAX_PATCH_CHARS2 = 3e4;
var UPDATE_KEY_RE = /^update-((?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5}))$/;
var SUPERSEDED_RE = /^> Superseded by #/;
async function supersedeOlder(gh, repo2, version, newNumber) {
  const cur = semver(version);
  for (let page2 = 1; page2 <= ISSUE_PAGE_CAP; page2++) {
    const list = await gh.listIssues(repo2.owner, repo2.name, page2, ISSUE_PER_PAGE);
    if (!Array.isArray(list)) throw new Error("the issue list is not a list");
    for (const raw of list) {
      if (!isPlain9(raw) || own6(raw, "pull_request") !== void 0 || own6(raw, "state") !== "open") continue;
      const number = own6(raw, "number");
      const user = own6(raw, "user");
      const body = own6(raw, "body");
      const title = own6(raw, "title");
      if (typeof number !== "number" || !Number.isSafeInteger(number) || number <= 0 || number === newNumber || typeof body !== "string" || typeof title !== "string" || title === "") continue;
      if (!isPlain9(user) || own6(user, "login") !== BOT_LOGIN || own6(user, "type") !== "Bot") continue;
      const lines = body.replace(/\r\n/g, "\n").split("\n");
      const k = UPDATE_KEY_RE.exec((/^<!-- pipegen:key=([^ ]+) -->$/.exec(lines[0]) ?? [])[1] ?? "");
      const old = k === null ? void 0 : semver(k[1]);
      if (old === void 0 || !newer(cur, old)) continue;
      const rest = lines.slice(1);
      if (SUPERSEDED_RE.test(rest[0] ?? "")) rest.shift();
      const next = [lines[0], `> Superseded by #${newNumber}: pipegen gate v${version} is out.`, ...rest].join("\n");
      if (next !== lines.join("\n")) await gh.updateIssue(repo2.owner, repo2.name, number, { title, body: next });
    }
    if (list.length < ISSUE_PER_PAGE) return;
  }
}
async function runNightly(gh, ctx, deps = {}) {
  const result = { issues: [], notes: [], errors: [] };
  const { repo: repo2, now } = ctx;
  const upsert = async (key, issue) => {
    try {
      const out = await upsertIssueDetailed(gh, repo2, key, issue.title, issue.body, { labels: issue.labels ?? [] });
      result.issues.push(out);
      return out;
    } catch (e) {
      result.errors.push(`the issue ${key} was not written: ${e instanceof Error ? e.message : "unknown error"}`);
      return void 0;
    }
  };
  const effective = effectiveBlockFrom(ctx.blockFrom, ctx.recorded);
  if (effective !== void 0 && warnEnding(effective, now, "unknown")?.open === true) {
    let old = "unknown";
    let note;
    try {
      const loaded = await (deps.loadBaseline ?? loadBaseline)(gh, repo2, { key: ctx.key, now });
      if (loaded.baseline !== null) {
        old = 0;
        for (const n of loaded.baseline.counts.values()) old += n;
      } else note = loaded.note;
    } catch {
      note = "the baseline lookup failed";
    }
    const w = warnEnding(effective, now, old);
    if (w?.open === true) await upsert(`warn-ending-${effective}`, warnEndingIssue(repo2, effective, w, old, note));
  }
  let mergedOnce;
  const merge = () => {
    mergedOnce ??= setupMergedAt(gh, repo2, now).then((m) => {
      if (m.note !== void 0) result.notes.push(m.note);
      return m;
    });
    return mergedOnce;
  };
  if (validDate(ctx.blockFrom) === void 0) {
    const merged = await merge();
    if (merged.at !== void 0 && merged.sha !== void 0 && finishMissing(ctx.blockFrom, merged.at, now)) await upsert(`finish-missing-${merged.sha}`, finishMissingIssue(repo2, merged.at));
  }
  const switches = [];
  const clock = clockOf(now);
  for (const w of ctx.warnFirst ?? []) {
    if (typeof w?.needId !== "string" || !NEED_ID_RE2.test(w.needId) || validDate(w.since) !== w.since) {
      result.notes.push("a warn-first entry is not in the form pipegen writes, so it was skipped");
      continue;
    }
    const merged = await merge();
    const end = warnFirstEnd(w.since, merged.at);
    if (end === void 0) {
      result.notes.push(`warn-first ${w.needId}: the setup merge is not proven, so its warn period can not be counted and no switch issue is opened`);
      continue;
    }
    if (clock !== void 0 && clock >= Date.parse(`${end}T00:00:00Z`)) switches.push({ needId: w.needId, since: w.since, end });
  }
  const latest = await latestGateRelease(gh, GATE_VERSION, now);
  if (latest.note !== void 0) result.notes.push(latest.note);
  if (latest.release !== void 0) {
    const rel = latest.release;
    const notes = [];
    let patch;
    try {
      const file = await readWorkflow(gh, repo2);
      if ("why" in file) notes.push(`no patch: ${file.why}`);
      else {
        const pinned = new Set(pinnedShas(file.text, GATE_VERSION));
        if (pinned.size === 0) notes.push(`no patch: pipegen.yml has no gate pin line for v${GATE_VERSION}`);
        else if (pinned.size > 1) notes.push("no patch: pipegen.yml pins the gate at more than one commit for this version, so the swap is ambiguous");
        else {
          const diff = updatePatch([{ path: WORKFLOW_PATH, text: file.text }], { sha: [...pinned][0], version: GATE_VERSION }, { sha: rel.sha, version: rel.version });
          if (diff === "") notes.push("no patch: nothing to swap");
          else if (diff.length > MAX_PATCH_CHARS2) notes.push("no patch: the patch is too large for an issue");
          else patch = { diff, baseSha: file.baseSha };
        }
      }
    } catch (e) {
      notes.push(e instanceof PatchRefused ? `the patch was left out: ${e.message}` : "no patch: the workflow file could not be read");
    }
    result.notes.push(...notes);
    const made = await upsert(`update-${rel.version}`, updateIssue(repo2, rel, patch, notes));
    if (made !== void 0 && made.action !== "left-closed") {
      try {
        await supersedeOlder(gh, repo2, rel.version, made.number);
      } catch (e) {
        result.notes.push(`older update issues were not marked as superseded: ${e instanceof Error ? e.message : "unknown error"}`);
      }
    }
  }
  for (const s of switches) await upsert(`warn-first-${s.needId}-${s.end}`, warnFirstIssue(repo2, s.needId, s.since, s.end));
  return result;
}

// gate/src/main.ts
var MODE_INPUTS = {
  scrub: ["mode", "artifact", "tool", "stage", "format", "raw", "out", "fp-key"],
  stage: ["mode", "artifact", "tool", "stage"],
  gate: [...GATE_INPUTS],
  "baseline-check": ["mode", "github-token", "fp-key"],
  "find-run": ["mode", "layout", "sha", "central-workflow", "central-sha", "timeout-minutes", "github-token"],
  nightly: ["mode", "block-from", "block-from-recorded", "warn-first", "github-token", "fp-key"]
};
var isMode = (m) => Object.hasOwn(MODE_INPUTS, m);
var REAL_FS = {
  unlink: unlinkSync2,
  rename: renameSync,
  chmod: chmodSync2,
  overwrite: (path, data) => {
    writeFileSync(path, data, { flag: constants5.O_WRONLY | constants5.O_TRUNC | constants5.O_NOFOLLOW });
  },
  access: (path) => {
    accessSync(path, constants5.R_OK);
  }
};
var MAX_EVENT_BYTES = 16 * 1024 * 1024;
var TOOL_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
var FILE_RE2 = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;
var RESULT_FILE2 = GATE_UPLOAD_FILES["pipegen-gate-result"];
var StepError = class extends Error {
};
var StaleResultError = class extends StepError {
};
var STALE_EXIT = 2;
function removeIfThere(fs, dir, name) {
  try {
    fs.unlink(join4(dir, name));
    return true;
  } catch (e) {
    return e.code === "ENOENT";
  }
}
function entryStillThere(dir, name) {
  try {
    lstatSync5(join4(dir, name));
    return true;
  } catch {
    return false;
  }
}
function quarantine(step, dir, blockDoc) {
  const fs = step.fs;
  try {
    fs.rename(dir, join4(dirname3(dir), `${basename2(dir)}.stale-${randomUUID()}`));
    step.error("the gate folder holds a file that could not be removed, so the folder was moved aside: the result file may be stale, the upload finds nothing and fails");
    return;
  } catch {
  }
  try {
    fs.overwrite(join4(dir, RESULT_FILE2), blockDoc);
  } catch {
  }
  try {
    fs.chmod(dir, 0);
    let readable = true;
    try {
      fs.access(dir);
    } catch {
      readable = false;
    }
    if (!readable) {
      step.error("the gate folder holds a file that could not be removed, so the folder was locked: the result file may be stale, the upload can not read it and fails");
      return;
    }
  } catch {
  }
  step.error("the gate folder holds a file that could not be removed, and the folder could not be moved aside or locked: the result file may be stale and the uploads may ship stale files");
}
var MIN_REDACTED = 8;
var BAD_KEY = "the fp-key input is not a usable PIPEGEN_FP_KEY (one line of at least 32 printable characters, no quote or backslash), so the step fails closed";
var badKey = (key) => key !== void 0 && keyProblem(key, false, true) !== void 0;
var escapeData = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
var Step = class {
  constructor(deps) {
    this.deps = deps;
    this.fs = { ...REAL_FS, ...deps.fs };
  }
  deps;
  secrets = [];
  fs;
  env(name) {
    const v = this.deps.env[name];
    return typeof v === "string" ? v : void 0;
  }
  /** `::add-mask::` for each line of a secret, before anything else is written with it. */
  mask(value) {
    if (value === void 0) return;
    for (const line of value.split(/\r?\n/)) {
      if (line.trim() === "") continue;
      if (line.length >= MIN_REDACTED) this.secrets.push(line);
      this.deps.write(`::add-mask::${escapeData(line)}
`);
    }
    this.secrets.sort((a, b) => b.length - a.length);
  }
  /** Every masked value replaced, wherever it is (a last belt: nothing is meant to carry one). */
  redact(text) {
    let t = text;
    for (const s of this.secrets) t = t.split(s).join("***");
    return t;
  }
  line(text) {
    this.deps.write(`${this.redact(text)}
`);
  }
  /** The one log helper: one line of safe text, prefixed so it never starts a workflow command. */
  log(text) {
    this.line(`pipegen: ${safeText(text, 600)}`);
  }
  warn(text) {
    this.line(`::warning::${escapeData(safeText(text, 600))}`);
  }
  error(text) {
    this.line(`::error::${escapeData(safeText(text, 600))}`);
  }
  /** One step output, in GITHUB_OUTPUT's `name<<delimiter` form. No output file → a StepError (the step fails closed). */
  setOutput(name, value) {
    const file = this.env("GITHUB_OUTPUT");
    if (file === void 0 || !isAbsolute3(file)) throw new StepError("GITHUB_OUTPUT is not set, so the step can not hand on its result");
    const v = this.redact(value);
    const delim = `ghadelimiter_${randomUUID()}`;
    if (v.includes(delim) || name.includes(delim)) throw new StepError("an output holds its own delimiter");
    appendFile(file, `${name}<<${delim}
${v}
${delim}
`);
  }
  /** Appends Markdown to the job summary (an exclusive append to GITHUB_STEP_SUMMARY, never through a shell). */
  summary(markdown) {
    const file = this.env("GITHUB_STEP_SUMMARY");
    if (file === void 0 || !isAbsolute3(file)) {
      this.log("GITHUB_STEP_SUMMARY is not set, so there is no job summary");
      return;
    }
    appendFile(file, this.redact(markdown));
  }
  /** A file in the gate folder, created new (never over a file, never through a link). */
  writeGateFile(dir, name, bytes) {
    const data = typeof bytes === "string" ? Buffer.from(this.redact(bytes)) : Buffer.from(bytes);
    let fd;
    try {
      fd = openSync5(join4(dir, name), constants5.O_WRONLY | constants5.O_CREAT | constants5.O_EXCL | constants5.O_NOFOLLOW, 420);
      let at3 = 0;
      while (at3 < data.length) at3 += writeSync3(fd, data, at3, data.length - at3);
    } catch {
      throw new StepError(`the gate file ${name} could not be written`);
    } finally {
      if (fd !== void 0) try {
        closeSync5(fd);
      } catch {
      }
    }
  }
};
function appendFile(path, text) {
  let fd;
  try {
    fd = openSync5(path, constants5.O_WRONLY | constants5.O_APPEND | constants5.O_NOFOLLOW);
    const data = Buffer.from(text);
    let at3 = 0;
    while (at3 < data.length) at3 += writeSync3(fd, data, at3, data.length - at3);
  } catch {
    throw new StepError("a runner file (the outputs or the summary) could not be written");
  } finally {
    if (fd !== void 0) try {
      closeSync5(fd);
    } catch {
    }
  }
}
function readRunnerFile(path, what) {
  if (path === void 0 || !isAbsolute3(path)) throw new StepError(`${what} is not set`);
  let fd;
  try {
    fd = openSync5(path, constants5.O_RDONLY | constants5.O_NOFOLLOW | constants5.O_NONBLOCK);
    const st = fstatSync5(fd);
    if (!st.isFile() || st.size > MAX_EVENT_BYTES) throw new StepError(`${what} is not a regular file within the size cap`);
    const buf = Buffer.alloc(st.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync5(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    return buf.subarray(0, got).toString("utf8");
  } catch (e) {
    throw e instanceof StepError ? e : new StepError(`${what} could not be read`);
  } finally {
    if (fd !== void 0) try {
      closeSync5(fd);
    } catch {
    }
  }
}
function readInputs(env) {
  const out = /* @__PURE__ */ new Map();
  const seen = /* @__PURE__ */ new Set();
  let twice;
  for (const key of Object.keys(env)) {
    if (!key.startsWith("INPUT_")) continue;
    const name = key.slice("INPUT_".length).toLowerCase();
    if (seen.has(name)) twice ??= name;
    seen.add(name);
    const v = env[key];
    if (typeof v !== "string" || v.trim() === "") continue;
    out.set(name, v.trim());
  }
  return twice === void 0 ? { inputs: out } : { inputs: out, twice };
}
function runnerTemp(step) {
  const t = step.env("RUNNER_TEMP");
  if (t === void 0 || !isAbsolute3(t)) throw new StepError("RUNNER_TEMP is not set");
  return t;
}
async function main(deps) {
  const step = new Step(deps);
  try {
    const { inputs, twice } = readInputs(deps.env);
    step.mask(inputs.get("github-token"));
    step.mask(inputs.get("fp-key"));
    if (twice !== void 0) {
      step.error(`the input ${safeText(twice, 40)} is given more than once, so the step fails closed`);
      return 1;
    }
    const mode = inputs.get("mode");
    if (mode === void 0) {
      step.error("the mode input is missing, so the gate action does nothing (it fails closed)");
      return 1;
    }
    if (!isMode(mode)) {
      step.error("the mode input is not one the gate action knows, so it does nothing (it fails closed)");
      return 1;
    }
    const allowed = MODE_INPUTS[mode];
    const extra = [...inputs.keys()].filter((k) => !allowed.includes(k));
    if (extra.length > 0) {
      step.error(`the input ${safeText(extra[0], 40)} is not used in mode ${mode}, so the step fails closed`);
      return 1;
    }
    const get = (name) => inputs.get(name);
    switch (mode) {
      case "scrub":
        return runScrub(step, get);
      case "stage":
        return runStage(step, get);
      case "gate":
        return await runGate(step, deps, inputs);
      case "baseline-check":
        return await runBaselineCheck(step, deps, get);
      case "find-run":
        return await runFindRun(step, deps, get);
      case "nightly":
        return await runNightlyMode(step, deps, get);
    }
  } catch (e) {
    step.error(e instanceof StepError ? `the gate action failed closed: ${e.message}` : "the gate action failed unexpectedly, so it fails closed");
    return e instanceof StaleResultError ? STALE_EXIT : 1;
  }
}
function runScrub(step, get) {
  const r = scrubResult(step, get);
  step.setOutput("sha256", r.sha256 ?? "");
  step.setOutput("status", r.status);
  step.setOutput("error", r.error ?? "");
  if (r.status !== "ok") {
    step.error(`the scrub reports a tool error: ${r.error ?? "unknown"}`);
    return 1;
  }
  step.log(`scrubbed ${r.findings ?? 0} findings`);
  for (const n of (r.notes ?? []).slice(0, 20)) step.log(n);
  return 0;
}
function scrubResult(step, get) {
  const bad = (error) => ({ status: "tool-error", error });
  let temp;
  try {
    temp = runnerTemp(step);
  } catch {
    return bad("RUNNER_TEMP is not set");
  }
  const artifact = get("artifact");
  const tool2 = get("tool");
  const format = get("format");
  const raw = get("raw");
  const out = get("out");
  const stage = get("stage");
  if (artifact === void 0 || !RESULT_ARTIFACT_NAME_RE.test(artifact)) return bad("the artifact input is not a result artifact name");
  if (tool2 === void 0 || !TOOL_RE.test(tool2)) return bad("the tool input is not a reviewed tool id");
  if (format !== "sarif" && format !== "zap-json") return bad("the format input is not sarif or zap-json");
  const file = raw === void 0 ? "" : basename2(raw);
  if (raw === void 0 || !FILE_RE2.test(file) || raw !== `${temp}/pipegen-raw/${artifact}/${file}`) return bad("the raw input is not RUNNER_TEMP/pipegen-raw/<artifact>/<file>");
  if (out !== `${temp}/pipegen-out/${artifact}/${file}`) return bad("the out input is not RUNNER_TEMP/pipegen-out/<artifact>/<file> for the same file as raw");
  if (stage !== void 0 && stage !== `${temp}/pipegen-stage/${artifact}`) return bad("the stage input is not RUNNER_TEMP/pipegen-stage/<artifact>");
  const workspace = step.env("GITHUB_WORKSPACE");
  if (workspace === void 0 || !isAbsolute3(workspace)) return bad("GITHUB_WORKSPACE is not set");
  const key = get("fp-key");
  if (badKey(key)) return bad(BAD_KEY);
  const eventPath = step.env("GITHUB_EVENT_PATH");
  return scrubFile({
    artifact,
    tool: tool2,
    format,
    raw,
    out,
    workspace,
    mask: () => void 0,
    ...key === void 0 ? {} : { fpKey: key },
    ...eventPath === void 0 ? {} : { eventPath },
    ...stage === void 0 ? {} : { stage }
  });
}
function runStage(step, get) {
  const done = (status, error) => {
    step.setOutput("status", status);
    step.setOutput("error", error);
    if (status === "error") {
      step.error(`the stage step failed: ${error}`);
      return 1;
    }
    return 0;
  };
  let temp;
  try {
    temp = runnerTemp(step);
  } catch {
    return done("error", "RUNNER_TEMP is not set");
  }
  const artifact = get("artifact");
  const tool2 = get("tool");
  const stage = get("stage");
  if (artifact === void 0 || !RESULT_ARTIFACT_NAME_RE.test(artifact)) return done("error", "the artifact input is not a result artifact name");
  if (tool2 === void 0 || !isStagedTool(tool2)) return done("error", "the tool input is not a tool that scans a stage folder");
  if (stage !== `${temp}/pipegen-stage/${artifact}`) return done("error", "the stage input is not RUNNER_TEMP/pipegen-stage/<artifact>");
  const workspace = step.env("GITHUB_WORKSPACE");
  if (workspace === void 0 || !isAbsolute3(workspace)) return done("error", "GITHUB_WORKSPACE is not set");
  const r = stageWorkspace({ workspace, stage });
  if (r.status === "ok") step.log(`staged ${r.files} files as ${r.staged} names`);
  return done(r.status, r.status === "ok" ? "" : r.error);
}
function gateFolder(step) {
  const dir = join4(runnerTemp(step), GATE_FILES_FOLDER);
  let st;
  try {
    st = lstatSync5(dir);
  } catch {
    st = void 0;
  }
  if (st === void 0) {
    try {
      mkdirSync3(dir, { mode: 493 });
    } catch {
      throw new StepError("the gate folder could not be made");
    }
    st = lstatSync5(dir);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new StepError("the gate folder is a link or not a folder, so nothing is written there");
  return dir;
}
async function decide(step, deps, inputs) {
  try {
    const notes = [];
    const gh = (deps.github ?? githubAdapter)({ token: inputs.get("github-token") ?? "", mask: () => void 0, notes });
    const io = {
      readEvent: () => readRunnerFile(step.env("GITHUB_EVENT_PATH"), "the event payload (GITHUB_EVENT_PATH)"),
      listRunArtifacts: (o, n, runId, name) => gh.listRunArtifacts(o, n, runId, name),
      artifactZip: (o, n, id, max) => gh.downloadArtifactZip(o, n, id, max)
    };
    const reviewed = (deps.reviewed ?? defaultReviewed)();
    const g = await gatherGateInput({
      inputs: Object.fromEntries(inputs),
      env: { eventName: step.env("GITHUB_EVENT_NAME") ?? "", sha: step.env("GITHUB_SHA") ?? "", runId: step.env("GITHUB_RUN_ID") ?? "", repository: step.env("GITHUB_REPOSITORY") ?? "" },
      now: (deps.now ?? (() => /* @__PURE__ */ new Date()))(),
      reviewed,
      clientNotes: notes
    }, gh, io);
    if ("kind" in g) return { errors: g.errors };
    return { input: g, result: decideGate(g) };
  } catch {
    return { errors: ["the gate could not finish reading what it needs, so it fails closed"] };
  }
}
var verdictOf = (d) => {
  const r = d.result;
  if (r === void 0 || !r.pass) return "block";
  return r.warnings.length > 0 || r.warnReasons.length > 0 ? "warn" : "pass";
};
function greenPushToDefault(g, r) {
  if (g.event.name !== "push" || !r.pass) return false;
  const p = g.event.payload;
  const repo2 = typeof p.repository === "object" && p.repository !== null ? p.repository : {};
  const def = Object.hasOwn(repo2, "default_branch") ? repo2.default_branch : void 0;
  if (typeof def !== "string" || !Object.hasOwn(p, "ref") || p.ref !== `refs/heads/${def}`) return false;
  const skipped = new Set(g.skipped.map((s) => s.needId));
  const allRan = g.checks.every((c) => c.result === "success" || c.result === "skipped" && skipped.has(c.entry.needId));
  return allRan && (g.baseScan === null || g.baseScan.result === "success") && r.toolErrors.length === 0 && g.settingsErrors.length === 0;
}
function isCleanRun(r) {
  return r.blocking.length === 0 && r.warnings.length === 0 && r.warnReasons.length === 0 && r.toolErrors.length === 0;
}
function baselineChecks(g, r) {
  const noCoverage = new Set(r.noCoverage.map((n) => n.job));
  return g.checks.flatMap((c) => {
    const e = c.entry;
    if (e.tool === void 0 || e.artifact === void 0 || e.format !== "sarif" && e.format !== "zap-json") return [];
    const f = c.file;
    const ok = c.outputs.status === "ok" && f !== void 0 && f.problem === void 0 && f.read.toolError === void 0 && f.sha256 === c.outputs.sha256;
    return [{ job: e.job, tool: e.tool, status: ok ? "ok" : "tool-error", noCoverage: noCoverage.has(e.job), ...ok && f.read.keyId !== void 0 ? { keyId: f.read.keyId } : {}, findings: ok ? f.read.findings : [] }];
  });
}
async function saveTrusted(step, dir, g, r, key, runId) {
  const lines = [];
  if (!greenPushToDefault(g, r)) return { baseline: "not eligible", marker: "not eligible", lines };
  if (key === void 0) {
    step.warn("the baseline and the clean-run marker were not written: PIPEGEN_FP_KEY is missing on this push to the default branch");
    return { baseline: "not written", marker: "not written", lines: ["- the baseline and the clean-run marker were not written: PIPEGEN_FP_KEY is missing"] };
  }
  const uploader = { upload: async (name, bytes) => step.writeGateFile(dir, GATE_UPLOAD_FILES[name], bytes) };
  let baseline = "written";
  try {
    await saveBaseline({ runId, key, checks: baselineChecks(g, r), sameRunTools: g.sameRunTools }, uploader);
    lines.push("- the signed baseline of this run was written (uploaded as pipegen-baseline)");
  } catch {
    baseline = "failed";
    step.warn("the baseline of this run could not be written; the next green push writes one (this is not a gate failure)");
    lines.push("- the baseline of this run could not be written (not a gate failure)");
  }
  const clean2 = isCleanRun(r);
  let marker = "not written";
  if (clean2 || g.cleanRun === "seen") {
    try {
      await uploader.upload("pipegen-clean-run", buildCleanRunMarker(runId, key), { retentionDays: 90 });
      marker = "written";
      lines.push(clean2 ? "- this run is clean: the clean-run marker was written (uploaded as pipegen-clean-run)" : "- block mode was reached through a clean run: the clean-run marker was written again");
    } catch {
      marker = "failed";
      step.warn("the clean-run marker could not be written (this is not a gate failure)");
      lines.push("- the clean-run marker could not be written (not a gate failure)");
    }
  }
  return { baseline, marker, lines };
}
var ref = (f) => ({
  needId: f.needId,
  job: f.job,
  tool: safeText(f.tool, 64),
  ruleId: safeText(f.ruleId, 200),
  severity: f.severity,
  ...f.file === void 0 ? {} : { file: safeText(f.file, 300) },
  ...f.line === void 0 ? {} : { line: f.line },
  isNew: f.isNew ?? null,
  secret: f.secret
});
function resultDoc(d, verdict, ev, saved) {
  const r = d.result;
  const text = (xs, max = 400) => xs.map((x) => safeText(x, max));
  return `${JSON.stringify({
    pipegenGateResult: 1,
    result: verdict,
    pass: r?.pass ?? false,
    mode: r?.mode ?? null,
    event: safeText(ev.name, 40),
    sha: safeText(ev.sha, 40),
    runId: ev.runId,
    blockReasons: text(r?.blockReasons ?? d.errors ?? []),
    warnReasons: text(r?.warnReasons ?? []),
    counted: r?.counted ?? null,
    blocking: (r?.blocking ?? []).slice(0, 500).map(ref),
    warnings: (r?.warnings ?? []).slice(0, 500).map(ref),
    toolErrors: (r?.toolErrors ?? []).map((t) => ({ needId: t.needId, job: t.job, ...t.tool === void 0 ? {} : { tool: t.tool }, base: t.base, blocks: t.blocks, reason: safeText(t.reason, 300) })),
    failedJobs: (r?.failedJobs ?? []).map((f) => ({ needId: f.needId, job: f.job })),
    notRun: (r?.notRun ?? []).map((f) => ({ needId: f.needId, job: f.job })),
    checks: (r?.checks ?? []).map((c) => ({ needId: c.needId, job: c.job, ...c.tool === void 0 ? {} : { tool: c.tool }, judgedBy: c.judgedBy, state: safeText(c.state, 200) })),
    notes: text((r?.notes ?? []).slice(0, 100)),
    baseline: saved.baseline,
    marker: saved.marker
  })}
`;
}
function blockedSummary(errors) {
  const md2 = (s) => {
    const v = safeMarkdown(s);
    return v === "" ? "(empty)" : v;
  };
  return [`## pipegen gate: blocked`, "", "### Blocking", ...errors.map((e) => `- ${md2(e)}`), ""].join("\n");
}
async function runGate(step, deps, inputs) {
  const runIdText = step.env("GITHUB_RUN_ID") ?? "";
  const runId = /^[1-9][0-9]{0,15}$/.test(runIdText) ? Number(runIdText) : 0;
  const ev = { name: step.env("GITHUB_EVENT_NAME") ?? "", sha: step.env("GITHUB_SHA") ?? "", runId };
  let dir;
  let d;
  try {
    dir = gateFolder(step);
    d = badKey(inputs.get("fp-key")) ? { errors: [BAD_KEY] } : await decide(step, deps, inputs);
  } catch (e) {
    d = { errors: [e instanceof StepError ? e.message : "the gate could not start, so it fails closed"] };
  }
  let verdict = verdictOf(d);
  let saved = { baseline: "not eligible", marker: "not eligible", lines: [] };
  if (dir !== void 0 && d.input !== void 0 && d.result !== void 0) {
    try {
      saved = await saveTrusted(step, dir, d.input, d.result, inputs.get("fp-key"), runId);
    } catch {
      step.warn("the baseline and the marker were not written (this is not a gate failure)");
    }
  }
  let written = false;
  let stale = false;
  if (dir !== void 0) {
    if (!removeIfThere(step.fs, dir, RESULT_FILE2) && entryStillThere(dir, RESULT_FILE2)) stale = true;
    try {
      step.writeGateFile(dir, RESULT_FILE2, resultDoc(d, verdict, ev, saved));
      written = true;
    } catch {
    }
  }
  if (!written) {
    verdict = "block";
    d = { ...d, errors: [...d.errors ?? [], "the gate result file could not be written, so the gate fails closed"] };
    if (dir !== void 0 && entryStillThere(dir, RESULT_FILE2)) stale = true;
    if (dir !== void 0) {
      for (const f of [GATE_UPLOAD_FILES["pipegen-baseline"], GATE_UPLOAD_FILES["pipegen-clean-run"]]) if (!removeIfThere(step.fs, dir, f)) stale = true;
    }
  }
  if (stale && dir !== void 0) {
    step.error("a gate file could not be removed beside a missing or planted result: the result file may be stale, so the step fails with status 2");
    quarantine(step, dir, resultDoc({ errors: [...d.errors ?? [], "the gate folder may hold a stale result"] }, "block", ev, { baseline: "removed", marker: "removed" }));
  }
  try {
    step.setOutput("result", verdict);
    const summary = d.result !== void 0 && written ? d.result.summary : blockedSummary([...d.result?.blockReasons ?? [], ...d.errors ?? []]);
    step.summary(`${summary}${saved.lines.length > 0 ? `
### Baseline
${saved.lines.join("\n")}
` : ""}`);
  } catch (e) {
    if (stale) throw new StaleResultError("the gate folder may hold a stale result");
    if (dir !== void 0 && written) {
      let left = false;
      for (const f of [GATE_UPLOAD_FILES["pipegen-baseline"], GATE_UPLOAD_FILES["pipegen-clean-run"]]) if (!removeIfThere(step.fs, dir, f)) left = true;
      const failed = { errors: [...d.result?.blockReasons ?? [], ...d.errors ?? [], "the gate could not hand on its result (the outputs or the summary), so it fails closed"] };
      const tmp = `.${RESULT_FILE2}.${randomUUID()}.tmp`;
      let replaced = false;
      try {
        step.writeGateFile(dir, tmp, resultDoc(failed, "block", ev, { baseline: "removed", marker: "removed" }));
        renameSync(join4(dir, tmp), join4(dir, RESULT_FILE2));
        replaced = true;
      } catch {
        removeIfThere(step.fs, dir, tmp);
        replaced = removeIfThere(step.fs, dir, RESULT_FILE2);
      }
      if (left || !replaced) {
        step.error("the gate failed after writing its files, and they could not be replaced or removed: the result file may be stale, so the step fails with status 2");
        quarantine(step, dir, resultDoc(failed, "block", ev, { baseline: "removed", marker: "removed" }));
        throw new StaleResultError("the gate folder may hold a stale result");
      }
    }
    throw e;
  }
  step.log(`gate result: ${verdict}`);
  if (stale) return STALE_EXIT;
  if (verdict === "block") {
    step.error("pipegen gate: blocked; the job summary says why");
    return 1;
  }
  return 0;
}
async function runBaselineCheck(step, deps, get) {
  let found = false;
  if (badKey(get("fp-key"))) {
    step.setOutput("found", "missing");
    step.error(BAD_KEY);
    return 1;
  }
  try {
    const payload = JSON.parse(readRunnerFile(step.env("GITHUB_EVENT_PATH"), "the event payload (GITHUB_EVENT_PATH)"));
    const repo2 = repoOf(payload, step.env("GITHUB_REPOSITORY") ?? "");
    if (typeof repo2 === "string") throw new StepError(repo2);
    const gh = (deps.github ?? githubAdapter)({ token: get("github-token") ?? "", mask: () => void 0, notes: [] });
    const loaded = await loadBaseline(gh, repo2, { key: get("fp-key"), now: (deps.now ?? (() => /* @__PURE__ */ new Date()))() });
    found = loaded.baseline !== null;
    if (!found) step.warn(`no verified trusted baseline, so the base scan checks every tool on the base commit${loaded.note === void 0 ? "" : `: ${loaded.note}`}`);
  } catch (e) {
    found = false;
    step.warn(`the stored baseline could not be looked up${e instanceof StepError ? ` (${e.message})` : ""}, so the base scan checks every tool on the base commit`);
  }
  step.setOutput("found", found ? "found" : "missing");
  step.log(`stored baseline: ${found ? "found" : "missing"}`);
  return 0;
}
var SHA_RE11 = /^[0-9a-f]{40}$/;
var FIND_RUN_DEFAULT_MINUTES = 30;
async function runFindRun(step, deps, get) {
  const fail3 = (text) => {
    step.error(`find-run: ${text}`);
    step.setOutput("run-id", "");
    step.setOutput("run-url", "");
    return 1;
  };
  const sha3 = get("sha");
  if (sha3 === void 0 || !SHA_RE11.test(sha3)) return fail3("the sha input is not a 40-character lower-case commit sha, so the step fails closed");
  const layout = get("layout");
  if (layout !== "inline" && layout !== "central") return fail3("the layout input is not inline or central, so the step fails closed");
  const workflow = get("central-workflow");
  const centralSha = get("central-sha");
  if (layout === "inline" && (workflow !== void 0 || centralSha !== void 0)) return fail3("layout inline takes no central-workflow or central-sha, so the step fails closed");
  if (layout === "central" && (workflow === void 0 || centralSha === void 0)) return fail3("layout central needs both central-workflow and central-sha, so the step fails closed");
  if (workflow !== void 0 && (!PLAIN_REL_RE.test(workflow) || workflow.includes("@"))) return fail3("the central-workflow input is not a plain path of the central workflow, so the step fails closed");
  if (centralSha !== void 0 && !SHA_RE11.test(centralSha)) return fail3("the central-sha input is not a 40-character lower-case commit sha, so the step fails closed");
  const minutes = get("timeout-minutes");
  if (minutes !== void 0 && !TIMEOUT_MINUTES_RE.test(minutes)) return fail3("the timeout-minutes input is not a whole number of minutes from 1 to 360, so the step fails closed");
  const token = get("github-token");
  if (token === void 0) return fail3("the github-token input is missing, so the step fails closed");
  let repo2;
  try {
    repo2 = repoOf(JSON.parse(readRunnerFile(step.env("GITHUB_EVENT_PATH"), "the event payload (GITHUB_EVENT_PATH)")), step.env("GITHUB_REPOSITORY") ?? "");
  } catch (e) {
    return fail3(e instanceof StepError ? `${e.message}, so the step fails closed` : "the event payload could not be read, so the step fails closed");
  }
  if (typeof repo2 === "string") return fail3(`${repo2}, so the step fails closed`);
  const notes = [];
  const clock = deps.now ?? (() => /* @__PURE__ */ new Date());
  const opts = {
    workflowPath: WORKFLOW_PATH,
    gateJobName: GATE_CHECK_NAME,
    waitMs: Number(minutes ?? FIND_RUN_DEFAULT_MINUTES) * 6e4,
    now: () => clock().getTime(),
    ...workflow === void 0 || centralSha === void 0 ? {} : { central: { pathPrefix: workflow, sha: centralSha } },
    ...deps.sleep === void 0 ? {} : { sleep: deps.sleep }
  };
  let found;
  try {
    const gh = (deps.github ?? githubAdapter)({ token, mask: () => void 0, notes });
    found = await findGatedRun(gh, repo2, sha3, opts);
  } catch {
    return fail3("GitHub could not be reached or set up, so the step fails closed");
  }
  for (const n of notes) step.warn(n);
  if (!found.ok) return fail3(`no gated run for this commit (${found.reason}): ${found.detail}`);
  step.setOutput("run-id", String(found.runId));
  step.setOutput("run-url", found.url);
  step.log(`the gate passed for this commit in run ${found.runId}`);
  return 0;
}
async function runNightlyMode(step, deps, get) {
  const fail3 = (text) => {
    step.error(`nightly: ${text}`);
    return 1;
  };
  const token = get("github-token");
  if (token === void 0) return fail3("the github-token input is missing, so the step fails closed");
  if (badKey(get("fp-key"))) return fail3(BAD_KEY);
  const wf = get("warn-first");
  const wfProblem = wf === void 0 ? null : warnFirstListProblem(wf);
  if (wfProblem !== null) return fail3(`the warn-first input is refused (it must be ${wfProblem}), so the step fails closed`);
  const warnFirst = wf === void 0 ? [] : JSON.parse(wf).map((e) => ({ needId: e.needId, since: e.since }));
  const notes = [];
  let done;
  try {
    const gh = (deps.nightly ?? githubAdapter)({ token, mask: () => void 0, notes });
    const repo2 = await resolveRepo(gh, step.env("GITHUB_REPOSITORY"), step.env("GITHUB_REPOSITORY_ID"));
    if (typeof repo2 === "string") return fail3(`${repo2}, so the step fails closed`);
    done = await runNightly(gh, { repo: repo2, now: (deps.now ?? (() => /* @__PURE__ */ new Date()))(), blockFrom: get("block-from"), recorded: get("block-from-recorded"), key: get("fp-key"), warnFirst });
  } catch {
    return fail3("GitHub could not be reached or set up, so the step fails closed");
  }
  const summary = ["### pipegen nightly", ""];
  for (const i of done.issues) {
    step.log(`issue ${i.key}: #${i.number} ${i.action}`);
    summary.push(`- \`${i.key}\`: issue #${i.number} ${i.action}`);
  }
  if (done.issues.length === 0) summary.push("- no issue to open or update tonight");
  for (const n of [...notes, ...done.notes]) {
    step.log(n);
    summary.push(`- note: ${safeMarkdown(n, 300)}`);
  }
  for (const e of done.errors) {
    step.error(e);
    summary.push(`- error: ${safeMarkdown(e, 300)}`);
  }
  step.summary(`${summary.join("\n")}
`);
  return done.errors.length === 0 ? 0 : 1;
}
function defaultReviewed() {
  return GATE_VIEW;
}

// gate/src/index.ts
void main({ env: process.env, write: (t) => {
  process.stdout.write(t);
} }).then(
  (code3) => {
    process.exitCode = code3;
  },
  () => {
    process.stdout.write("::error::the gate action failed unexpectedly, so it fails closed\n");
    process.exitCode = 1;
  }
);
/*! Bundled license information:

smol-toml/dist/error.js:
smol-toml/dist/primitive.js:
smol-toml/dist/date.js:
smol-toml/dist/extract.js:
smol-toml/dist/util.js:
smol-toml/dist/struct.js:
smol-toml/dist/parse.js:
smol-toml/dist/stringify.js:
smol-toml/dist/index.js:
  (*!
   * Copyright (c) Squirrel Chat et al., All rights reserved.
   * SPDX-License-Identifier: BSD-3-Clause
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions are met:
   *
   * 1. Redistributions of source code must retain the above copyright notice, this
   *    list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright notice,
   *    this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. Neither the name of the copyright holder nor the names of its contributors
   *    may be used to endorse or promote products derived from this software without
   *    specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   *)
*/
