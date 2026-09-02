import { resolveConfig } from "./config.js";

const flat = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * True when a match is on a list the caller told us to leave alone. Kept here
 * rather than folded into the patterns because an allowlist is a policy
 * decision and a pattern is a shape.
 */
export function isAllowed(match, detector, cfg) {
  if (cfg.allow.has(flat(match))) return true;
  if (detector.class === "domain" && cfg.allowDomains.has(match.toLowerCase())) return true;
  return false;
}

/**
 * The precise half. Substitutes typed placeholders so the surviving text stays
 * readable and keeps its structure, and so a reader can tell an address from a
 * client name in the output.
 *
 * This function is allowed to miss. That is not a defect to be patched by
 * making it greedier, because a greedier redactor damages clean documents. It
 * is the reason `assertClean` exists and uses a different matcher.
 */
export function redact(text, config = {}) {
  const cfg = resolveConfig(config);
  let out = String(text);
  for (const detector of cfg.detectors) {
    for (const re of detector.redact) {
      out = out.replace(re, (match) => (isAllowed(match, detector, cfg) ? match : detector.as));
    }
  }
  return out;
}

/** Same pass, plus a per-class count for the compliance log. */
export function redactWithCounts(text, config = {}) {
  const cfg = resolveConfig(config);
  const counts = {};
  let out = String(text);
  for (const detector of cfg.detectors) {
    for (const re of detector.redact) {
      out = out.replace(re, (match) => {
        if (isAllowed(match, detector, cfg)) return match;
        counts[detector.class] = (counts[detector.class] ?? 0) + 1;
        return detector.as;
      });
    }
  }
  return { text: out, counts };
}
