/**
 * Normalizers exist so the detector can look at the text differently from the
 * way the redactor looked at it.
 *
 * The redactor matches the text as written, because its output has to stay a
 * working document. The detector is allowed to rewrite the text into a form
 * where evasion collapses, then match that. `northwind_robotics`, `Northwind
 * Robotics` and `NorthwindRobotics` are three strings to a redactor and one
 * string to `flatten`.
 *
 * Every normalizer returns an index map alongside the rewritten text, because a
 * finding that cannot point at a line in the original is not actionable.
 * `map[i]` is the offset in the source that produced normalized character `i`.
 */

const ALNUM = /[a-z0-9]/;

/** Identity. The detector runs the precise patterns over this one too. */
function raw(src) {
  const map = new Array(src.length);
  for (let i = 0; i < src.length; i++) map[i] = i;
  return { text: src, map };
}

/** Lowercase, then drop everything that is not a letter or a digit. */
function flatten(src) {
  let text = "";
  const map = [];
  for (let i = 0; i < src.length; i++) {
    const c = src[i].toLowerCase();
    if (ALNUM.test(c)) {
      text += c;
      map.push(i);
    }
  }
  return { text, map };
}

// Sticky so each rule can be tested at one exact offset. Surrounding whitespace
// is consumed by the token itself, which is what turns "jane [at] northwind"
// back into "jane@northwind" rather than "jane @ northwind".
//
// The bracketed forms only. A bare " at " is NOT rewritten to "@", because
// "hosted at northwind.example" is ordinary English and rewriting it turns
// every sentence containing the word "at" beside a hostname into an address.
// The all-words evasion is caught instead by a scan pattern that requires both
// halves to be spelled out, which prose almost never does.
const OBFUSCATION_RULES = [
  { re: /\s*[[({<]\s*(?:at|@)\s*[\])}>]\s*/iy, to: "@" },
  { re: /\s*[[({<]\s*(?:dot|\.)\s*[\])}>]\s*/iy, to: "." },
];

/** Reverse the usual ways an address is written to dodge a matcher. */
function deobfuscate(src) {
  let text = "";
  const map = [];
  let i = 0;
  outer: while (i < src.length) {
    for (const rule of OBFUSCATION_RULES) {
      rule.re.lastIndex = i;
      const m = rule.re.exec(src);
      if (m && m.index === i) {
        text += rule.to;
        map.push(i);
        i += m[0].length;
        continue outer;
      }
    }
    text += src[i];
    map.push(i);
    i += 1;
  }
  return { text, map };
}

// Brackets, every flavour of dash including the Unicode minus a PDF paste
// leaves behind, and dots. Commas and spaces are deliberately absent, because
// stripping them glues a timestamp or a currency amount into a false ten-digit
// run.
const PHONE_SEPARATOR = /[()\-‐-―−. ]/;

/** Remove phone separators so an oddly punctuated number is still a digit run. */
function digits(src) {
  let text = "";
  const map = [];
  for (let i = 0; i < src.length; i++) {
    if (PHONE_SEPARATOR.test(src[i])) continue;
    text += src[i];
    map.push(i);
  }
  return { text, map };
}

/** Remove all whitespace, so a token broken by a line wrap rejoins. */
function despace(src) {
  let text = "";
  const map = [];
  for (let i = 0; i < src.length; i++) {
    if (/\s/.test(src[i])) continue;
    text += src[i];
    map.push(i);
  }
  return { text, map };
}

export const NORMALIZERS = { raw, flatten, deobfuscate, digits, despace };

export function normalize(text, name) {
  const fn = NORMALIZERS[name];
  if (!fn) throw new Error(`redaction-gate: unknown normalizer "${name}"`);
  return fn(text);
}
