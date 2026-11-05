#!/usr/bin/env node
// Static check: every value interpolated into HTML in the webview goes
// through the shared escaper (dist/js/html.js), and no markup carries inline
// style= / on*= attributes (the CSP forbids both).
//
//   node apps/kdx-client/scripts/check-escaping.mjs [files or dirs...]
//
// Defaults to apps/kdx-client/dist/js. Exits 1 and lists findings if any.
//
// Rules, for code under dist/js:
//  1. In a template literal whose text contains markup (`<tag`), each
//     `${...}` must be `esc(...)`, `num(...)`, a call to a function whose
//     name ends in `Html` (by convention: returns trusted markup built under
//     these same rules), a plain string literal, a nested template that
//     itself follows these rules, or a ternary whose branches do.
//  2. A string/template containing markup may only be `+`-concatenated with
//     the same kinds of operands.
//  3. `x.innerHTML = <rhs>`: every top-level operand of the right-hand side
//     must be one of the above (or `list.map(...).join(...)`, whose mapped
//     templates are checked by rule 1). `innerHTML +=`, `outerHTML`,
//     `insertAdjacentHTML`, `document.write`, `eval` and `new Function` are
//     always flagged.
//  4. No `style=` or `on<event>=` attributes inside markup, and no
//     `setAttribute("style"|"on…")` (CSP: style-src 'self', no inline
//     handlers). Use classes, or set `el.style.prop` (CSSOM) instead.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MARKUP = /<\/?[a-zA-Z!]/;
const REGEX_KEYWORDS = new Set([
  "return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
  "void", "throw", "instanceof", "yield", "await",
]);

// ---------------------------------------------------------------- tokenizer

/**
 * Tokenize JS source. Returns { tokens, templates }: `tokens` is the flat
 * top-level token list (a template is one token); `templates` lists every
 * template literal at any depth as { start, end, quasis[], exprs[] } where
 * each expr is { text, start }.
 */
export function tokenize(src) {
  const templates = [];
  const tokens = scanCode(src, 0, false, templates).tokens;
  return { tokens, templates };
}

function isIdentStart(c) {
  return /[A-Za-z_$]/.test(c);
}
function isIdentPart(c) {
  return /[\w$]/.test(c);
}

function regexAllowed(prev) {
  if (!prev) return true;
  if (prev.type === "punct") return ![")", "]"].includes(prev.value);
  if (prev.type === "ident") return REGEX_KEYWORDS.has(prev.value);
  return false;
}

/** Scan code from i. If `inExpr`, stop at the `}` closing a `${`. */
function scanCode(src, i, inExpr, templates) {
  const tokens = [];
  let depth = 0;
  const prevSig = () => tokens[tokens.length - 1];
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (/\s/.test(c)) {
      i++;
    } else if (c === "/" && n === "/") {
      const e = src.indexOf("\n", i);
      i = e === -1 ? src.length : e;
    } else if (c === "/" && n === "*") {
      const e = src.indexOf("*/", i + 2);
      if (e === -1) throw new SyntaxError("unterminated comment");
      i = e + 2;
    } else if (c === "'" || c === '"') {
      const end = scanString(src, i);
      tokens.push({ type: "str", value: src.slice(i, end), start: i, end });
      i = end;
    } else if (c === "`") {
      const t = scanTemplate(src, i, templates);
      tokens.push({ type: "tpl", value: src.slice(i, t.end), start: i, end: t.end, tpl: t });
      i = t.end;
    } else if (c === "/" && regexAllowed(prevSig())) {
      const end = scanRegex(src, i);
      tokens.push({ type: "regex", value: src.slice(i, end), start: i, end });
      i = end;
    } else if (isIdentStart(c)) {
      let e = i + 1;
      while (e < src.length && isIdentPart(src[e])) e++;
      tokens.push({ type: "ident", value: src.slice(i, e), start: i, end: e });
      i = e;
    } else if (/[0-9]/.test(c)) {
      let e = i + 1;
      while (e < src.length && /[\w.]/.test(src[e])) e++;
      tokens.push({ type: "num", value: src.slice(i, e), start: i, end: e });
      i = e;
    } else {
      if (inExpr && c === "}" && depth === 0) return { tokens, end: i };
      if ("({[".includes(c)) depth++;
      if (")}]".includes(c)) depth--;
      // Multi-char operators we care about.
      const three = src.slice(i, i + 3);
      const two = src.slice(i, i + 2);
      let op = c;
      if (["===", "!==", "...", "**=", "&&=", "||=", "??="].includes(three)) op = three;
      else if (["+=", "-=", "==", "!=", "<=", ">=", "&&", "||", "??", "=>", "?.", "++", "--"].includes(two)) op = two;
      tokens.push({ type: "punct", value: op, start: i, end: i + op.length });
      i += op.length;
    }
  }
  if (inExpr) throw new SyntaxError("unterminated ${");
  return { tokens, end: i };
}

function scanString(src, i) {
  const q = src[i];
  let j = i + 1;
  while (j < src.length) {
    if (src[j] === "\\") j += 2;
    else if (src[j] === q) return j + 1;
    else if (src[j] === "\n") throw new SyntaxError("unterminated string");
    else j++;
  }
  throw new SyntaxError("unterminated string");
}

function scanRegex(src, i) {
  let j = i + 1;
  let inClass = false;
  while (j < src.length) {
    const c = src[j];
    if (c === "\\") j += 2;
    else if (c === "[") (inClass = true), j++;
    else if (c === "]") (inClass = false), j++;
    else if (c === "/" && !inClass) {
      j++;
      while (j < src.length && /[a-z]/i.test(src[j])) j++;
      return j;
    } else if (c === "\n") throw new SyntaxError("unterminated regex");
    else j++;
  }
  throw new SyntaxError("unterminated regex");
}

function scanTemplate(src, i, templates) {
  const t = { start: i, end: -1, quasis: [], exprs: [] };
  templates.push(t);
  let j = i + 1;
  let chunk = "";
  while (j < src.length) {
    const c = src[j];
    if (c === "\\") {
      chunk += src.slice(j, j + 2);
      j += 2;
    } else if (c === "`") {
      t.quasis.push(chunk);
      t.end = j + 1;
      return t;
    } else if (c === "$" && src[j + 1] === "{") {
      t.quasis.push(chunk);
      chunk = "";
      const inner = scanCode(src, j + 2, true, templates);
      t.exprs.push({ text: src.slice(j + 2, inner.end), start: j + 2, tokens: inner.tokens });
      j = inner.end + 1;
    } else {
      chunk += c;
      j++;
    }
  }
  throw new SyntaxError("unterminated template");
}

// ---------------------------------------------------------------- rules

/** Index of the token closing the bracket opened at tokens[i], or -1. */
function matchClose(tokens, i) {
  let depth = 0;
  for (let k = i; k < tokens.length; k++) {
    const v = tokens[k].type === "punct" ? tokens[k].value : "";
    if ("({[".includes(v) && v) depth++;
    else if (")}]".includes(v) && v) {
      depth--;
      if (depth === 0) return k;
    }
  }
  return -1;
}

/** Split a token list at top-level occurrences of punctuator `sep`. */
function splitTop(tokens, sep) {
  const parts = [[]];
  let depth = 0;
  for (const t of tokens) {
    const v = t.type === "punct" ? t.value : "";
    if (v && "({[".includes(v)) depth++;
    if (v && ")}]".includes(v)) depth--;
    if (depth === 0 && v === sep) parts.push([]);
    else parts[parts.length - 1].push(t);
  }
  return parts;
}

/** Top-level ternary split: [cond, a, b] or null. */
function splitTernary(tokens) {
  let depth = 0;
  let q = -1;
  let nested = 0;
  for (let k = 0; k < tokens.length; k++) {
    const v = tokens[k].type === "punct" ? tokens[k].value : "";
    if (v && "({[".includes(v)) depth++;
    if (v && ")}]".includes(v)) depth--;
    if (depth !== 0) continue;
    if (v === "?") {
      if (q === -1) q = k;
      else nested++;
    } else if (v === ":" && q !== -1) {
      if (nested) nested--;
      else return [tokens.slice(0, q), tokens.slice(q + 1, k), tokens.slice(k + 1)];
    }
  }
  return null;
}

function isSafeCall(tokens) {
  if (tokens.length < 3 || tokens[0].type !== "ident") return false;
  const name = tokens[0].value;
  if (!(name === "esc" || name === "num" || /Html$/.test(name))) return false;
  if (tokens[1].type !== "punct" || tokens[1].value !== "(") return false;
  return matchClose(tokens, 1) === tokens.length - 1;
}

function isSafeTemplate(tpl) {
  return tpl.exprs.every((e) => isSafeOperand(e.tokens));
}

/** Is this token list (one operand / interpolation) safe to put in HTML? */
function isSafeOperand(tokens) {
  if (tokens.length === 0) return false;
  // Strip redundant parens: (expr)
  if (tokens[0].value === "(" && tokens[0].type === "punct" && matchClose(tokens, 0) === tokens.length - 1) {
    return isSafeOperand(tokens.slice(1, -1));
  }
  const tern = splitTernary(tokens);
  if (tern) return isSafeOperand(tern[1]) && isSafeOperand(tern[2]);
  const plus = splitTop(tokens, "+");
  if (plus.length > 1) return plus.every(isSafeOperand);
  if (tokens.length === 1) {
    if (tokens[0].type === "str") return true;
    if (tokens[0].type === "tpl") return isSafeTemplate(tokens[0].tpl);
    return false;
  }
  return isSafeCall(tokens);
}

/** list.map(...).join(...) — the mapped templates are checked separately. */
function isMapJoin(tokens, src) {
  const text = src.slice(tokens[0].start, tokens[tokens.length - 1].end);
  return /^[\w$.]+\.map\([\s\S]*\)\s*\.join\([^()]*\)$/.test(text);
}

function lineOf(src, offset) {
  let line = 1;
  for (let k = 0; k < offset && k < src.length; k++) if (src[k] === "\n") line++;
  return line;
}

/** Check one file's source; returns [{ line, rule, message }]. */
export function checkSource(src) {
  const findings = [];
  const flag = (offset, rule, message) => findings.push({ line: lineOf(src, offset), rule, message });
  let parsed;
  try {
    parsed = tokenize(src);
  } catch (e) {
    flag(0, "parse", `could not tokenize: ${e.message}`);
    return findings;
  }
  const { tokens, templates } = parsed;

  // Rule 1 + 4 (templates).
  for (const t of templates) {
    const text = t.quasis.join("");
    if (!MARKUP.test(text)) continue;
    for (const e of t.exprs) {
      if (!isSafeOperand(e.tokens)) {
        flag(e.start, "unescaped", `\${${e.text.trim()}} in markup is not esc()/num()/…Html()`);
      }
    }
    checkInlineAttrs(text, t.start, flag);
  }

  // Rules 2, 3, 4 on the flat token stream (plus nested expression tokens).
  const streams = [tokens, ...templates.flatMap((t) => t.exprs.map((e) => e.tokens))];
  for (const toks of streams) checkStream(toks, src, flag);

  findings.sort((a, b) => a.line - b.line);
  return findings;
}

function checkInlineAttrs(text, offset, flag) {
  if (/\sstyle\s*=/i.test(text)) flag(offset, "inline-style", "inline style= attribute (blocked by CSP style-src)");
  if (/\son[a-z]+\s*=/i.test(text)) flag(offset, "inline-handler", "inline on*= handler (blocked by CSP)");
}

function checkStream(toks, src, flag) {
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    const prev = toks[k - 1];
    const next = toks[k + 1];

    // Rule 4: inline attributes in plain strings with markup.
    if (t.type === "str" && MARKUP.test(t.value)) checkInlineAttrs(t.value, t.start, flag);

    // Rule 4: setAttribute("style" | "on…").
    if (t.type === "ident" && t.value === "setAttribute" && next && next.value === "(") {
      const arg = toks[k + 2];
      if (arg && arg.type === "str" && /^["'](style|on[a-z]+)["']$/i.test(arg.value)) {
        flag(t.start, "inline-style", `setAttribute(${arg.value}, …) is blocked by CSP`);
      }
    }

    // Rule 3: dangerous sinks.
    if (t.type === "ident" && ["outerHTML", "insertAdjacentHTML"].includes(t.value)) {
      flag(t.start, "sink", `${t.value} is not allowed; build nodes or use innerHTML with esc()`);
    }
    if (t.type === "ident" && t.value === "write" && prev && prev.value === "." && toks[k - 2] && toks[k - 2].value === "document") {
      flag(t.start, "sink", "document.write is not allowed");
    }
    if (t.type === "ident" && t.value === "eval" && next && next.value === "(") flag(t.start, "sink", "eval is not allowed");
    if (t.type === "ident" && t.value === "Function" && prev && prev.value === "new") flag(t.start, "sink", "new Function is not allowed");

    if (t.type === "ident" && t.value === "innerHTML" && prev && prev.value === "." && next) {
      if (next.value === "+=") {
        flag(t.start, "sink", "innerHTML += re-parses existing markup; append nodes instead");
      } else if (next.value === "=") {
        let end = k + 2;
        let depth = 0;
        for (; end < toks.length; end++) {
          const v = toks[end].type === "punct" ? toks[end].value : "";
          if (v && "({[".includes(v)) depth++;
          if (v && ")}]".includes(v)) {
            if (depth === 0) break;
            depth--;
          }
          if (depth === 0 && (v === ";" || v === ",")) break;
        }
        const rhs = toks.slice(k + 2, end);
        if (!isSafeRhs(rhs, src)) {
          const text = rhs.length ? src.slice(rhs[0].start, rhs[rhs.length - 1].end) : "";
          flag(t.start, "innerHTML", `innerHTML = ${text.slice(0, 60)}${text.length > 60 ? "…" : ""} is not built from escaped parts`);
        }
      }
    }

    // Rule 2: markup strings concatenated with unsafe operands.
    if ((t.type === "str" || t.type === "tpl") && MARKUP.test(t.value)) {
      if (next && next.value === "+") {
        const operand = operandAfter(toks, k + 2);
        if (operand && !isSafeOperand(operand) && !isMapJoin(operand, src)) {
          flag(t.start, "concat", "markup concatenated with an unescaped value");
        }
      }
      if (prev && prev.value === "+") {
        const operand = operandBefore(toks, k - 2);
        if (operand && !isSafeOperand(operand) && !isMapJoin(operand, src)) {
          flag(t.start, "concat", "markup concatenated with an unescaped value");
        }
      }
    }
  }
}

function isSafeRhs(rhs, src) {
  if (rhs.length === 0) return false;
  const tern = splitTernary(rhs);
  if (tern) return isSafeRhs(tern[1], src) && isSafeRhs(tern[2], src);
  return splitTop(rhs, "+").every((op) => op.length > 0 && (isSafeOperand(op) || isMapJoin(op, src)));
}

/** The operand starting at token index i: a primary plus member/call tails. */
function operandAfter(toks, i) {
  if (i >= toks.length) return null;
  let k = i;
  if (toks[k].type === "punct" && "([{".includes(toks[k].value)) {
    k = matchClose(toks, k);
    if (k === -1) return null;
  }
  while (k + 1 < toks.length) {
    const v = toks[k + 1].value;
    if (v === "." || v === "?.") k += 2;
    else if (v === "(" || v === "[") {
      k = matchClose(toks, k + 1);
      if (k === -1) return null;
    } else break;
  }
  return toks.slice(i, k + 1);
}

/** The operand ending at token index i (walking back over calls/members). */
function operandBefore(toks, i) {
  if (i < 0) return null;
  let k = i;
  for (;;) {
    const t = toks[k];
    if (t.type === "punct" && (t.value === ")" || t.value === "]")) {
      // find the matching opener
      let depth = 0;
      let j = k;
      for (; j >= 0; j--) {
        const v = toks[j].type === "punct" ? toks[j].value : "";
        if (v === ")" || v === "]") depth++;
        else if (v === "(" || v === "[") {
          depth--;
          if (depth === 0) break;
        }
      }
      if (j < 0) return null;
      k = j - 1;
      if (k < 0 || toks[k].type === "punct") return toks.slice(k + 1, i + 1);
      continue;
    }
    if (k - 1 >= 0 && (toks[k - 1].value === "." || toks[k - 1].value === "?.")) {
      k -= 2;
      continue;
    }
    return toks.slice(k, i + 1);
  }
}

// ---------------------------------------------------------------- CLI

function walk(p, out) {
  if (statSync(p).isDirectory()) {
    for (const name of readdirSync(p)) walk(join(p, name), out);
  } else if (/\.m?js$/.test(p)) {
    out.push(p);
  }
  return out;
}

function main(argv) {
  const here = dirname(fileURLToPath(import.meta.url));
  const roots = argv.length ? argv.map((a) => resolve(a)) : [join(here, "..", "dist", "js")];
  const files = roots.flatMap((r) => walk(r, []));
  let total = 0;
  for (const f of files) {
    const findings = checkSource(readFileSync(f, "utf8"));
    for (const x of findings) {
      console.log(`${relative(process.cwd(), f)}:${x.line}: [${x.rule}] ${x.message}`);
    }
    total += findings.length;
  }
  console.log(`check-escaping: ${files.length} files, ${total} finding${total === 1 ? "" : "s"}`);
  return total ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
