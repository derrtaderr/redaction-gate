import { createHash } from "node:crypto";
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

export function hashText(text, algorithm = "sha256") {
  return createHash(algorithm).update(String(text)).digest("hex");
}

function outcomeOf({ findings, counts, warnOnly }) {
  if (findings.length) return warnOnly ? "warned" : "refused";
  return Object.keys(counts).length ? "redacted" : "clean";
}

export function buildRecord({ event, label = null, input, output, counts = {}, findings = [], cfg, at = new Date() }) {
  const algorithm = cfg?.audit?.algorithm ?? "sha256";
  return {
    v: 1,
    ts: at.toISOString(),
    lib: `redaction-gate@${VERSION}`,
    event,
    label: label ?? cfg?.audit?.label ?? null,
    outcome: outcomeOf({ findings, counts, warnOnly: cfg?.warnOnly === true }),
    input: { [algorithm]: hashText(input, algorithm), bytes: Buffer.byteLength(String(input)) },
    output: { [algorithm]: hashText(output, algorithm), bytes: Buffer.byteLength(String(output)) },
    redacted: { ...counts },
    // Class and position only. A position is enough to find the line in the
    // source system, and the source system is where the value is allowed to be.
    survivors: findings.map((f) => ({ class: f.class, line: f.line, column: f.column, length: f.length })),
    policy: { [algorithm]: cfg?.policyHash ?? null, warnOnly: cfg?.warnOnly === true },
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
