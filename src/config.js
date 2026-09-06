import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { BUILT_IN_DETECTORS, placeholderFor, expandTlds } from "./detectors.js";

const RESOLVED = Symbol.for("redaction-gate.resolved");

export const DEFAULT_CONFIG_FILES = [
  "redaction-gate.config.json",
  ".redactiongaterc.json",
];

const DEFAULTS = {
  roster: [],
  extraPatterns: [],
  extraTlds: [],
  patterns: {},
  allow: [],
  allowDomains: [],
  minScanLength: 4,
  revealTerms: false,
  warnOnly: false,
  onWarn: null,
  audit: { enabled: false, path: null, label: null, algorithm: "sha256", hmacKey: null },
};

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const flatten = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

const KNOWN_KEYS = Object.keys(DEFAULTS);

/**
 * Thrown when the config itself is wrong.
 *
 * A library whose whole thesis is "refuse loudly rather than fail confusingly"
 * cannot have a front door that throws an internal TypeError naming neither the
 * offending key nor the expected shape. Worse, a caller who wraps setup in a
 * try/catch to be careful would then see a misconfigured gate as an unrelated
 * runtime error rather than as a policy problem.
 */
export class RedactionConfigError extends Error {
  constructor(problems, origin) {
    const width = Math.max(...problems.map((p) => p.key.length));
    const lines = problems.flatMap((p) => {
      const head = `  ${p.key.padEnd(width)}  ${p.detail}`;
      return p.hint ? [head, `  ${" ".repeat(width)}  try  ${p.hint}`] : [head];
    });
    super(
      `redaction-gate: REFUSING TO CONFIGURE. ${problems.length} problem${problems.length === 1 ? "" : "s"} in ${origin}.\n` +
        lines.join("\n") +
        `\nNothing was redacted and nothing was checked.`
    );
    this.name = "RedactionConfigError";
    this.code = "REDACTION_CONFIG_INVALID";
    this.problems = problems;
  }
}

function describe(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  if (typeof value === "object") {
    const keys = Object.keys(value);
    const shown = keys.slice(0, 3).map((k) => `"${k}"`).join(", ");
    if (!keys.length) return "an empty object";
    return `an object with key${keys.length === 1 ? "" : "s"} ${shown}`;
  }
  return `a ${typeof value}`;
}

/** Cheap edit distance, only ever run against ten known keys. */
function nearest(key, candidates) {
  const distance = (a, b) => {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 0; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
    }
    return d[a.length][b.length];
  };
  let best = null;
  let bestScore = 3;
  for (const c of candidates) {
    const score = distance(key.toLowerCase(), c.toLowerCase());
    if (score < bestScore) {
      best = c;
      bestScore = score;
    }
  }
  return best;
}

/** Builds the suggested roster from what the caller actually wrote. */
function rosterHint(value) {
  const [key, terms] = Object.entries(value)[0] ?? ["client", ["Northwind"]];
  const list = Array.isArray(terms) ? terms : [String(terms)];
  return `"roster": [{ "class": ${JSON.stringify(key)}, "match": ${JSON.stringify(list)} }]`;
}

const isArrayOfStrings = (v) => Array.isArray(v) && v.every((s) => typeof s === "string");

/**
 * Checks one config source and refuses with every problem at once, the same way
 * a refusal reports every finding at once. Runs before anything is merged, so a
 * bad config can never be half applied.
 */
export function validateSource(src, origin = "the config") {
  const problems = [];
  const add = (key, detail, hint) => problems.push({ key, detail, hint });

  if (src === null || typeof src !== "object" || Array.isArray(src)) {
    throw new RedactionConfigError(
      [{ key: "config", detail: `expected an object, received ${describe(src)}`, hint: `{ "roster": [] }` }],
      origin
    );
  }

  for (const key of Object.keys(src)) {
    if (KNOWN_KEYS.includes(key)) continue;
    const guess = nearest(key, KNOWN_KEYS);
    add(key, `is not a setting this library reads${guess ? `, did you mean "${guess}"` : ""}`, `one of ${KNOWN_KEYS.join(", ")}`);
  }

  if ("roster" in src) {
    if (!Array.isArray(src.roster)) {
      add(
        "roster",
        `expected an array of roster entries, received ${describe(src.roster)}`,
        src.roster && typeof src.roster === "object" ? rosterHint(src.roster) : `"roster": [{ "class": "client", "match": ["Northwind"] }]`
      );
    } else {
      src.roster.forEach((entry, i) => {
        if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
          add(`roster[${i}]`, `expected an entry object, received ${describe(entry)}`, `{ "class": "client", "match": ["Northwind"] }`);
          return;
        }
        if (typeof entry.class !== "string" || !entry.class.length) {
          add(
            `roster[${i}].class`,
            entry.class === undefined ? "is missing, and every entry names the class its placeholder comes from" : `expected a string, received ${describe(entry.class)}`,
            `{ "class": "client", "match": ["Northwind"] }`
          );
        }
        const match = entry.match ?? entry.terms;
        if (match === undefined) {
          add(`roster[${i}].match`, "is missing, and an entry with no terms redacts nothing", `{ "class": "client", "match": ["Northwind"] }`);
        } else if (!isArrayOfStrings(match)) {
          add(
            `roster[${i}].match`,
            `expected an array of strings, received ${describe(match)}`,
            typeof match === "string" ? `"match": ${JSON.stringify([match])}` : `"match": ["Northwind"]`
          );
        }
      });
    }
  }

  for (const key of ["allow", "allowDomains"]) {
    if (key in src && !isArrayOfStrings(src[key])) {
      add(key, `expected an array of strings, received ${describe(src[key])}`, typeof src[key] === "string" ? `"${key}": ${JSON.stringify([src[key]])}` : `"${key}": []`);
    }
  }

  if ("extraTlds" in src) {
    if (!Array.isArray(src.extraTlds) || src.extraTlds.some((v) => typeof v !== "string" || !v.length)) {
      add("extraTlds", `expected an array of TLD strings, received ${describe(src.extraTlds)}`, `"extraTlds": ["agency", "solutions"]`);
    }
  }
  if ("extraPatterns" in src) {
    if (!Array.isArray(src.extraPatterns)) {
      add("extraPatterns", `expected an array of detector records, received ${describe(src.extraPatterns)}`, `"extraPatterns": [{ "name": "employee_id", "class": "employee", "redact": ["EMP-\\\\d{6}"] }]`);
    } else {
      src.extraPatterns.forEach((spec, i) => {
        if (spec === null || typeof spec !== "object" || Array.isArray(spec)) {
          add(`extraPatterns[${i}]`, `expected a detector record, received ${describe(spec)}`);
        } else if (!Array.isArray(spec.redact) || !spec.redact.length) {
          add(`extraPatterns[${i}].redact`, spec.redact === undefined ? "is missing, and a detector with no redact half substitutes nothing" : `expected a non-empty array of patterns, received ${describe(spec.redact)}`, `"redact": ["EMP-\\\\d{6}"]`);
        }
      });
    }
  }

  if ("patterns" in src) {
    if (src.patterns === null || typeof src.patterns !== "object" || Array.isArray(src.patterns)) {
      add("patterns", `expected an object of detector switches, received ${describe(src.patterns)}`, `"patterns": { "phone": false }`);
    } else {
      for (const [name, value] of Object.entries(src.patterns)) {
        if (typeof value !== "boolean") add(`patterns.${name}`, `expected a boolean, received ${describe(value)}`, `"${name}": false`);
      }
    }
  }

  for (const key of ["warnOnly", "revealTerms"]) {
    // A truthy string used to be ignored quietly, which meant a caller who
    // wrote warnOnly: "true" believed the gate was disarmed when it was not.
    // Either direction of that misunderstanding is worth refusing over.
    if (key in src && typeof src[key] !== "boolean") {
      add(key, `expected a boolean, received ${describe(src[key])}`, `"${key}": true`);
    }
  }

  if ("minScanLength" in src && (typeof src.minScanLength !== "number" || !Number.isInteger(src.minScanLength) || src.minScanLength < 1)) {
    add("minScanLength", `expected a positive whole number, received ${describe(src.minScanLength)}`, `"minScanLength": 4`);
  }

  if ("onWarn" in src && src.onWarn !== null && typeof src.onWarn !== "function") {
    add("onWarn", `expected a function, received ${describe(src.onWarn)}`);
  }

  if ("audit" in src) {
    if (src.audit === null || typeof src.audit !== "object" || Array.isArray(src.audit)) {
      add("audit", `expected an object, received ${describe(src.audit)}`, `"audit": { "enabled": true, "path": "logs/compliance.jsonl" }`);
    } else if ("hmacKey" in src.audit && src.audit.hmacKey !== null && (typeof src.audit.hmacKey !== "string" || !src.audit.hmacKey.length)) {
      // An empty string is falsy and would take the unkeyed path while the config
      // says a key was configured. A control that looks applied and is not is the
      // failure this library exists to refuse.
      add("audit.hmacKey", `expected a non-empty string or null, received ${describe(src.audit.hmacKey)}`, `"hmacKey": "\${REDACTION_AUDIT_KEY}"`);
    } else if (src.audit.enabled === true && typeof src.audit.path !== "string") {
      add("audit.path", `is required when audit.enabled is true, received ${describe(src.audit.path)}`, `"path": "logs/compliance.jsonl"`);
    }
  }

  if (problems.length) throw new RedactionConfigError(problems, origin);
  return src;
}

/** Later files win on scalars. Lists append, because a roster is additive. */
export function mergeConfigs(...sources) {
  const out = { ...DEFAULTS, audit: { ...DEFAULTS.audit }, roster: [], extraPatterns: [], allow: [], allowDomains: [], patterns: {} };
  for (const src of sources) {
    if (!src) continue;
    if (!src[RESOLVED]) validateSource(src);
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

function compile(specs, label, extraTlds = []) {
  return (specs ?? []).map((spec) => {
    const raw = typeof spec === "string" ? { pattern: spec } : spec;
    const { flags = "g" } = raw;
    const pattern = expandTlds(raw.pattern, extraTlds);
    try {
      return new RegExp(pattern, flags.includes("g") ? flags : flags + "g");
    } catch (err) {
      throw new Error(`redaction-gate: detector "${label}" has an invalid pattern /${pattern}/${flags}. ${err.message}`);
    }
  });
}

function compileScan(specs, label, extraTlds = []) {
  return (specs ?? []).map((spec) => {
    const via = spec.via ?? "raw";
    return { re: compile([spec], label, extraTlds)[0], via };
  });
}

function rosterDetector(entry, index, minScanLength) {
  const cls = entry.class ?? "custom";
  const terms = (entry.match ?? entry.terms ?? []).filter((t) => typeof t === "string" && t.length);
  const as = entry.as ?? placeholderFor(cls);
  // Precise. Word boundaries cannot damage a document. Longest first, so
  // "Northwind Robotics" is consumed before a bare "Northwind" can eat its head
  // and leave "[client] Robotics" behind.
  const redact = [...terms]
    .sort((a, b) => b.length - a.length)
    .map((t) => new RegExp(`\\b${escapeRe(t)}\\b`, "gi"));
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

  // Order is load bearing. Structured patterns run FIRST, so an address or a
  // hostname is claimed whole. A roster term running first would substitute
  // inside the token, break it open, and leave a fragment such as
  // "ada@[client].example" that no pattern can see any more.
  const detectors = [];
  for (const spec of cfg.extraPatterns) {
    detectors.push({
      name: spec.name ?? `custom:${detectors.length}`,
      class: spec.class ?? spec.name ?? "custom",
      as: spec.as ?? placeholderFor(spec.class ?? spec.name ?? "custom"),
      terms: [],
      redact: compile(spec.redact, spec.name ?? "custom", cfg.extraTlds),
      scan: compileScan(spec.scan, spec.name ?? "custom", cfg.extraTlds),
    });
  }
  for (const spec of BUILT_IN_DETECTORS) {
    if (cfg.patterns[spec.name] === false) continue;
    detectors.push({
      name: spec.name,
      class: spec.class,
      as: spec.as,
      terms: [],
      redact: compile(spec.redact, spec.name, cfg.extraTlds),
      scan: compileScan(spec.scan, spec.name, cfg.extraTlds),
    });
  }
  cfg.roster.forEach((entry, i) => {
    const d = rosterDetector(entry, i, cfg.minScanLength);
    if (d.redact.length) detectors.push(d);
  });

  const resolved = {
    detectors,
    allow: new Set(cfg.allow.map((s) => flatten(s))),
    allowDomains: new Set(cfg.allowDomains.map((s) => s.toLowerCase())),
    minScanLength: cfg.minScanLength,
    // Carried through so the policy hash moves when the TLD set moves. Two gates
    // with different reach must not hash alike, or the compliance log claims a
    // control that was not the one that ran.
    extraTlds: [...cfg.extraTlds],
    // Strict equality as a second line, not the guard. Validation already refuses a
    // non-boolean `revealTerms`, so by the time this runs the value is a real boolean
    // and `=== true` is equivalent to `!== false` — mutating it fails nothing, which
    // is how we know this is not the line under test. It stays because falling closed
    // costs nothing if a future path ever reaches here unvalidated.
    revealTerms: cfg.revealTerms === true,
    // Strict equality on purpose. A truthy string from an env var or a JSON
    // typo must not be enough to disarm the gate.
    warnOnly: cfg.warnOnly === true,
    onWarn: typeof cfg.onWarn === "function" ? cfg.onWarn : null,
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
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(p, "utf8"));
    } catch (err) {
      throw new Error(`redaction-gate: could not parse config "${p}". ${err.message}`);
    }
    // Validated per file, with the path as the origin, so a problem points at
    // the file that has it rather than at the merged result.
    validateSource(parsed, p);
    found.push(parsed);
  }
  return resolveConfig(mergeConfigs(...found, overrides));
}
