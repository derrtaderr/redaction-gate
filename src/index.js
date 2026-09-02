/**
 * redaction-gate
 *
 * Redaction that refuses the write when it misses.
 *
 * The redactor and the detector are deliberately different matchers. See
 * SPEC.md section 3 for why that asymmetry is the whole design and not an
 * implementation detail.
 */

export { redact, redactWithCounts } from "./redact.js";
export { scan, assertClean, RedactionRefusal } from "./gate.js";
export { guard } from "./middleware.js";
export { resolveConfig, loadConfig, mergeConfigs, validateSource, RedactionConfigError, DEFAULT_CONFIG_FILES } from "./config.js";
export { buildRecord, writeRecord, hashText, VERSION } from "./audit.js";
export { BUILT_IN_DETECTORS, TLDS } from "./detectors.js";
export { normalize, NORMALIZERS } from "./normalize.js";

import { resolveConfig } from "./config.js";
import { redact, redactWithCounts } from "./redact.js";
import { scan, assertClean } from "./gate.js";
import { guard } from "./middleware.js";

/** One config, resolved once, bound to every helper. */
export function createGate(config = {}) {
  const cfg = resolveConfig(config);
  return {
    config: cfg,
    redact: (text) => redact(text, cfg),
    redactWithCounts: (text) => redactWithCounts(text, cfg),
    scan: (text) => scan(text, cfg),
    assertClean: (text) => assertClean(text, cfg),
    guard: (fn, options = {}) => guard(fn, { ...options, config: cfg }),
  };
}
