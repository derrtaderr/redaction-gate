import { resolveConfig, requireStringSource } from "./config.js";
import { redactWithCounts } from "./redact.js";
import { scan, RedactionRefusal, reportWarning } from "./gate.js";
import { buildRecord, writeRecord } from "./audit.js";

const identityGet = (v) => v;
const identitySet = (_v, text) => text;

/**
 * The middleware shape.
 *
 * Put it in front of anything that would otherwise carry text out of the
 * process. An LLM call, a log write, an outbound webhook, an analytics event.
 * It redacts, then it checks, and on a miss it throws before the wrapped
 * function is ever called. Nothing leaves.
 *
 *   const ask = guard(callTheModel, { config, label: "outbound-llm" });
 *   await ask(prompt);   // the model sees redacted text, or sees nothing
 *
 * Non-string payloads are handled with `get` and `set`, so the guard sits in
 * front of a function whose argument is an object.
 */
export function guard(fn, options = {}) {
  const {
    config = {},
    argIndex = 0,
    get = identityGet,
    set = identitySet,
    label = null,
    onWarn = null,
  } = options;
  const cfg = resolveConfig(config);

  return async function guarded(...args) {
    const payload = args[argIndex];
    const source = get(payload);
    // A non-string source means the scan is meaningless. String(object) is
    // "[object Object]", which matches no detector, so the gate would pass
    // everything — a control that looks applied and is not, the exact shape
    // config refusal already forbids. Fire at call time on the actual source
    // (get could return a string for one payload and not the next), before the
    // scan and before set, so a bad wiring never corrupts or leaks. Same shared
    // helper the primitives route through, so "a source must be a string" has one
    // definition and the callers cannot drift. See SPEC 12.
    requireStringSource(source, {
      origin: "the guard's source",
      key: "get",
      verb: "returned",
      expected: "the string to scan",
      hint: `guard(fn, { get: (p) => p.body, set: (p, text) => ({ ...p, body: text }) })`,
    });
    const { text, counts } = redactWithCounts(source, cfg);
    const findings = scan(text, cfg);
    const record = buildRecord({ event: "guard", label, input: source, output: text, counts, findings, cfg });
    writeRecord(record, cfg);

    if (findings.length && !cfg.warnOnly) throw new RedactionRefusal(findings, cfg);
    if (findings.length) reportWarning(findings, onWarn ? { ...cfg, onWarn } : cfg);

    const next = [...args];
    next[argIndex] = set(payload, text);
    return fn(...next);
  };
}
