import { createHash, createHmac } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export const VERSION = "0.1.0";

/**
 * The compliance log.
 *
 * A SOC 2 or GDPR reviewer asks the same three questions about a control. Did
 * it run, what did it find, and what did the system do next. This produces a
 * durable answer to all three without the record ever becoming a second copy of
 * the data it was protecting.
 *
 * The rule that governs every field below: hashes and counts and positions go
 * in, values never do. A log that contains the leaked value has moved the leak
 * rather than recorded it.
 */

export function hashText(text, algorithm = "sha256", hmacKey = null) {
  return hmacKey
    ? createHmac("sha256", hmacKey).update(String(text)).digest("hex")
    : createHash(algorithm).update(String(text)).digest("hex");
}

function outcomeOf({ findings, counts, warnOnly }) {
  if (findings.length) return warnOnly ? "warned" : "refused";
  return Object.keys(counts).length ? "redacted" : "clean";
}

export function buildRecord({ event, label = null, input, output, counts = {}, findings = [], cfg, at = new Date() }) {
  const policyAlgorithm = cfg?.audit?.algorithm ?? "sha256";
  // KEYING IS OPT-IN, AND IT BUYS CORRELATION RESISTANCE, NOT CONFIDENTIALITY.
  //
  // An unkeyed digest of a low-entropy input can be guessed: hash a candidate and
  // compare. More importantly, an identical input always produces an identical
  // digest, so a party holding this log can confirm whether a specific known record
  // passed through, and can link records across separate logs and across time.
  //
  // The cost is stated in the README rather than hidden here: a keyed digest can
  // only ever be re-derived by someone holding that key, so rotating it makes every
  // earlier record uncheckable. The algorithm name in the record changes with it, so
  // a reader can tell which scheme wrote which record without guessing.
  const hmacKey = cfg?.audit?.hmacKey ?? null;
  const algorithm = hmacKey ? "hmac-sha256" : policyAlgorithm;
  return {
    v: 1,
    ts: at.toISOString(),
    lib: `redaction-gate@${VERSION}`,
    event,
    label: label ?? cfg?.audit?.label ?? null,
    outcome: outcomeOf({ findings, counts, warnOnly: cfg?.warnOnly === true }),
    input: { [algorithm]: hashText(input, policyAlgorithm, hmacKey), bytes: Buffer.byteLength(String(input)) },
    output: { [algorithm]: hashText(output, policyAlgorithm, hmacKey), bytes: Buffer.byteLength(String(output)) },
    redacted: { ...counts },
    // Class and position only. A position is enough to find the line in the
    // source system, and the source system is where the value is allowed to be.
    survivors: findings.map((f) => ({ class: f.class, line: f.line, column: f.column, length: f.length })),
    // The policy fingerprint stays unkeyed on purpose. It identifies a configuration,
    // not a person, and its one useful property is that anyone holding the config can
    // recompute it and confirm which control ran. There is nothing in it to correlate.
    policy: { [policyAlgorithm]: cfg?.policyHash ?? null, warnOnly: cfg?.warnOnly === true },
  };
}

/** Append-only, one JSON object per line, created on first write. */
export function writeRecord(record, cfg) {
  const audit = cfg?.audit ?? {};
  if (!audit.enabled || !audit.path) return null;
  mkdirSync(dirname(audit.path), { recursive: true });
  appendFileSync(audit.path, JSON.stringify(record) + "\n", { encoding: "utf8", flag: "a" });
  return audit.path;
}
