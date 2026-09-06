import { resolveConfig, requireStringSource } from "./config.js";
import { normalize } from "./normalize.js";
import { isAllowed } from "./redact.js";

/**
 * Thrown when redaction missed. The whole library exists to produce this.
 *
 * `findings` is the machine-readable half. The message is the half a developer
 * reads at 2am, so it names the class and the position — the two things they act
 * on — and by default not the value.
 *
 * THE VALUE IS WITHHELD BY DEFAULT BECAUSE AN EXCEPTION CROSSES A BOUNDARY. It
 * lands in Sentry, Datadog, CloudWatch, a log aggregator, a CI transcript. Stopping
 * an identifier reaching the model and then writing it to the error tracker is not
 * a smaller leak, it is the same leak through a door nobody was watching. Set
 * `revealTerms: true` where the error stream is trusted, and let that decision be
 * visible in the code that made it.
 */
export class RedactionRefusal extends Error {
  constructor(findings, { revealTerms = false } = {}) {
    const lines = findings.map((f) =>
      revealTerms
        ? `  line ${f.line}, col ${f.column}  ${f.class}  ${JSON.stringify(f.term)}`
        : `  line ${f.line}, col ${f.column}  ${f.class}  (${f.length} chars)`
    );
    super(
      `redaction-gate: REFUSING TO PROCEED. ${findings.length} identifier(s) survived redaction.\n` +
        lines.join("\n") +
        `\nAdd them to your roster, fix the source, or run with warnOnly if you are triaging an existing corpus.`
    );
    this.name = "RedactionRefusal";
    this.code = "REDACTION_REFUSED";
    // THE TYPE ENFORCES THIS, NOT ITS CALLER.
    //
    // scan() already drops `term` when revealTerms is off, so every path inside this
    // library arrived here clean and the invariant looked held. It was held by the
    // caller. RedactionRefusal is a public export — a custom gate, a test double, a
    // rethrow can all build one from findings that still carry values, and .findings
    // is exactly the property an error reporter serialises. Stripping here makes the
    // guarantee a property of the error rather than of the route taken to it.
    //
    // A copy, never a mutation. The caller's array is theirs.
    this.findings = findings.map(({ term, ...rest }) => (revealTerms ? { ...rest, term } : rest));
  }
}

function positionOf(src, index) {
  let line = 1;
  let lastBreak = -1;
  for (let i = 0; i < index; i++) {
    if (src[i] === "\n") {
      line += 1;
      lastBreak = i;
    }
  }
  return { line, column: index - lastBreak };
}

/**
 * The paranoid half. Runs every precise pattern AND every loose pattern over
 * the normalized copies of the text, so it can catch forms the redactor could
 * not touch. Never throws, so a caller can report before it enforces.
 */
export function scan(text, config = {}) {
  const cfg = resolveConfig(config);
  requireStringSource(text, { origin: "the source passed to scan", hint: `pass the string field: scan(value.body, config)` });
  const src = String(text);
  const views = new Map();
  const view = (via) => {
    if (!views.has(via)) views.set(via, normalize(src, via));
    return views.get(via);
  };

  const kept = [];
  const seen = new Set();
  for (const detector of cfg.detectors) {
    const specs = [
      ...detector.redact.map((re) => ({ re, via: "raw" })),
      ...detector.scan,
    ];
    for (const spec of specs) {
      const norm = view(spec.via);
      const rx = new RegExp(spec.re.source, spec.re.flags);
      let m;
      while ((m = rx.exec(norm.text)) !== null) {
        if (m[0].length === 0) {
          rx.lastIndex += 1;
          continue;
        }
        const start = norm.map[m.index];
        const end = (norm.map[m.index + m[0].length - 1] ?? start) + 1;
        const term = src.slice(start, end);
        if (isAllowed(term, detector, cfg) || isAllowed(m[0], detector, cfg)) continue;
        const key = `${detector.class}:${start}:${end}`;
        if (seen.has(key)) continue;
        // Detectors run most specific first, so an address already reported as
        // an email is not reported again as the domain inside it.
        if (kept.some((f) => start >= f.index && end <= f.index + f.length)) continue;
        seen.add(key);
        kept.push({
          class: detector.class,
          detector: detector.name,
          ...(cfg.revealTerms ? { term } : {}),
          index: start,
          length: end - start,
          ...positionOf(src, start),
        });
      }
    }
  }
  return kept.sort((a, b) => a.index - b.index);
}

/**
 * The gate. Returns the text when it is clean and throws when it is not.
 *
 * Run it on the FINAL string, after every other transform, because a check that
 * runs before the last edit checks something other than what ships.
 */
export function assertClean(text, config = {}) {
  const cfg = resolveConfig(config);
  // Its own check, with its own origin, before it delegates to scan — a safety
  // assertion that answers "is this clean" must never return a non-string it did
  // not scan. This is the scariest fail-open of the set: a false pass.
  requireStringSource(text, { origin: "the source passed to assertClean", hint: `pass the string field: assertClean(value.body, config)` });
  const findings = scan(text, cfg);
  if (findings.length === 0) return text;
  if (cfg.warnOnly) {
    reportWarning(findings, cfg);
    return text;
  }
  throw new RedactionRefusal(findings, cfg);
}

/**
 * warnOnly does not silence anything. It changes what happens next and nothing
 * else, so a corpus being onboarded can be surveyed without the survey itself
 * becoming a quiet pass.
 */
export function reportWarning(findings, cfg) {
  const err = new RedactionRefusal(findings, cfg);
  if (cfg.onWarn) cfg.onWarn(findings, err);
  else process.stderr.write(`${err.message}\n`);
  return err;
}
