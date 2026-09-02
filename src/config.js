import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { BUILT_IN_DETECTORS, placeholderFor } from "./detectors.js";

const RESOLVED = Symbol.for("redaction-gate.resolved");

export const DEFAULT_CONFIG_FILES = [
  "redaction-gate.config.json",
  ".redactiongaterc.json",
];

const DEFAULTS = {
  roster: [],
  extraPatterns: [],
  patterns: {},
  allow: [],
  allowDomains: [],
  minScanLength: 4,
  revealTerms: true,
  warnOnly: false,
  audit: { enabled: false, path: null, label: null, algorithm: "sha256" },
};

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const flatten = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

/** Later files win on scalars. Lists append, because a roster is additive. */
export function mergeConfigs(...sources) {
  const out = { ...DEFAULTS, audit: { ...DEFAULTS.audit }, roster: [], extraPatterns: [], allow: [], allowDomains: [], patterns: {} };
  for (const src of sources) {
    if (!src) continue;
    for (const [k, v] of Object.entries(src)) {
      if (k === "roster" || k === "extraPatterns" || k === "allow" || k === "allowDomains") {
        out[k] = [...out[k], ...(v ?? [])];
      } else if (k === "patterns" || k === "audit") {
        out[k] = { ...out[k], ...(v ?? {}) };
      } else if (v !== undefined) {
        out[k] = v;
      }
    }
  }
  return out;
}

function compile(specs, label) {
  return (specs ?? []).map((spec) => {
    const { pattern, flags = "g" } = typeof spec === "string" ? { pattern: spec } : spec;
    try {
      return new RegExp(pattern, flags.includes("g") ? flags : flags + "g");
    } catch (err) {
      throw new Error(`redaction-gate: detector "${label}" has an invalid pattern /${pattern}/${flags}. ${err.message}`);
    }
  });
}

function compileScan(specs, label) {
  return (specs ?? []).map((spec) => {
    const via = spec.via ?? "raw";
    return { re: compile([spec], label)[0], via };
  });
}

function rosterDetector(entry, index, minScanLength) {
  const cls = entry.class ?? "custom";
  const terms = (entry.match ?? entry.terms ?? []).filter((t) => typeof t === "string" && t.length);
  const as = entry.as ?? placeholderFor(cls);
  // Precise. Word boundaries cannot damage a document.
  const redact = terms.map((t) => new RegExp(`\\b${escapeRe(t)}\\b`, "gi"));
  // Paranoid, and only for terms long enough that a substring hit means
  // something. A three letter roster entry would refuse every document.
  const scan = terms
    .map((t) => flatten(t))
    .filter((t) => t.length >= minScanLength)
    .map((t) => ({ re: new RegExp(escapeRe(t), "g"), via: "flatten" }));
  return { name: entry.name ?? `roster:${cls}:${index}`, class: cls, as, terms, redact, scan };
}

function canonical(detectors, cfg) {
  return JSON.stringify({
    detectors: detectors.map((d) => ({
      name: d.name,
      class: d.class,
      as: d.as,
      terms: d.terms ?? [],
      redact: d.redact.map((r) => `${r.source}/${r.flags}`),
      scan: d.scan.map((s) => `${s.via}:${s.re.source}/${s.re.flags}`),
    })),
    allow: [...cfg.allow].sort(),
    allowDomains: [...cfg.allowDomains].sort(),
    minScanLength: cfg.minScanLength,
    revealTerms: cfg.revealTerms,
    warnOnly: cfg.warnOnly,
  });
}

/**
 * Turn user input into the frozen, compiled ruleset the engine runs. Safe to
 * call on an already resolved config, so every entry point can call it.
 */
export function resolveConfig(input = {}) {
  if (input && input[RESOLVED]) return input;
  const cfg = mergeConfigs(input);

  const detectors = [];
  cfg.roster.forEach((entry, i) => {
    const d = rosterDetector(entry, i, cfg.minScanLength);
    if (d.redact.length) detectors.push(d);
  });
  for (const spec of cfg.extraPatterns) {
    detectors.push({
      name: spec.name ?? `custom:${detectors.length}`,
      class: spec.class ?? spec.name ?? "custom",
      as: spec.as ?? placeholderFor(spec.class ?? spec.name ?? "custom"),
      terms: [],
      redact: compile(spec.redact, spec.name ?? "custom"),
      scan: compileScan(spec.scan, spec.name ?? "custom"),
    });
  }
  for (const spec of BUILT_IN_DETECTORS) {
    if (cfg.patterns[spec.name] === false) continue;
    detectors.push({
      name: spec.name,
      class: spec.class,
      as: spec.as,
      terms: [],
      redact: compile(spec.redact, spec.name),
      scan: compileScan(spec.scan, spec.name),
    });
  }

  const resolved = {
    detectors,
    allow: new Set(cfg.allow.map((s) => flatten(s))),
    allowDomains: new Set(cfg.allowDomains.map((s) => s.toLowerCase())),
    minScanLength: cfg.minScanLength,
    revealTerms: cfg.revealTerms !== false,
    warnOnly: cfg.warnOnly === true,
    audit: { ...cfg.audit },
    [RESOLVED]: true,
  };
  resolved.policyHash = createHash("sha256").update(canonical(detectors, resolved)).digest("hex");
  return resolved;
}

/** Read and merge JSON config files. Missing paths are skipped, not an error. */
export function loadConfig(paths = DEFAULT_CONFIG_FILES, overrides = {}) {
  const found = [];
  for (const p of paths) {
    if (!existsSync(p)) continue;
    try {
      found.push(JSON.parse(readFileSync(p, "utf8")));
    } catch (err) {
      throw new Error(`redaction-gate: could not parse config "${p}". ${err.message}`);
    }
  }
  return resolveConfig(mergeConfigs(...found, overrides));
}
