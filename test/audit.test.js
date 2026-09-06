import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildRecord, writeRecord, VERSION } from "../src/audit.js";
import { resolveConfig } from "../src/config.js";
import { scan } from "../src/gate.js";
import { redactWithCounts } from "../src/redact.js";

const CFG = { roster: [{ class: "client", match: ["Northwind Robotics"] }] };
const SOURCE = "the Northwind Robotics renewal, ada@northwind.example, filed under northwind_robotics";

function eventFor(source, config) {
  const cfg = resolveConfig(config);
  const { text, counts } = redactWithCounts(source, cfg);
  const findings = scan(text, cfg);
  return buildRecord({
    event: "guard",
    label: "outbound-llm",
    input: source,
    output: text,
    counts,
    findings,
    cfg,
  });
}

test("a record carries the fields an audit asks for", () => {
  const rec = eventFor(SOURCE, CFG);
  assert.equal(rec.v, 1);
  assert.equal(rec.lib, `redaction-gate@${VERSION}`);
  assert.equal(rec.event, "guard");
  assert.equal(rec.label, "outbound-llm");
  assert.equal(rec.outcome, "refused");
  assert.ok(!Number.isNaN(Date.parse(rec.ts)));
  assert.equal(typeof rec.policy.sha256, "string");
  assert.equal(rec.policy.warnOnly, false);
});

test("the record hashes the text and never carries it", () => {
  const rec = eventFor(SOURCE, CFG);
  const expected = createHash("sha256").update(SOURCE).digest("hex");
  assert.equal(rec.input.sha256, expected);
  assert.equal(rec.input.bytes, Buffer.byteLength(SOURCE));
  const serialized = JSON.stringify(rec);
  assert.ok(!serialized.includes("Northwind Robotics"));
  assert.ok(!serialized.includes("northwind_robotics"));
  assert.ok(!serialized.includes("ada@northwind.example"));
});

test("survivors carry a class and a position, never a value", () => {
  const rec = eventFor(SOURCE, CFG);
  assert.ok(rec.survivors.length >= 1);
  for (const s of rec.survivors) {
    assert.deepEqual(Object.keys(s).sort(), ["class", "column", "length", "line"]);
  }
});

test("counts are per class, which is what a reviewer asks for", () => {
  const rec = eventFor(SOURCE, CFG);
  assert.equal(rec.redacted.client, 1);
  assert.equal(rec.redacted.email, 1);
});

test("a clean pass records outcome clean with no survivors", () => {
  const rec = eventFor("a sentence with nothing in it", CFG);
  assert.equal(rec.outcome, "clean");
  assert.deepEqual(rec.survivors, []);
});

test("a pass that redacted something records outcome redacted", () => {
  const rec = eventFor("the Northwind Robotics renewal", CFG);
  assert.equal(rec.outcome, "redacted");
});

test("writeRecord appends JSONL rather than truncating", () => {
  const dir = mkdtempSync(join(tmpdir(), "rg-audit-"));
  const path = join(dir, "compliance.jsonl");
  const cfg = resolveConfig({ ...CFG, audit: { enabled: true, path } });
  writeRecord(eventFor("first Northwind Robotics", cfg), cfg);
  writeRecord(eventFor("second Northwind Robotics", cfg), cfg);
  const lines = readFileSync(path, "utf8").trim().split("\n");
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[1]).v, 1);
});

test("logging is off until a caller turns it on", () => {
  const dir = mkdtempSync(join(tmpdir(), "rg-audit-off-"));
  const path = join(dir, "compliance.jsonl");
  const cfg = resolveConfig({ ...CFG, audit: { path } });
  writeRecord(eventFor("Northwind Robotics", cfg), cfg);
  assert.equal(existsSync(path), false);
});

test("the reported version matches the package", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(VERSION, pkg.version);
});

test("an unkeyed digest is guessable for a low-entropy input, which is the reason hmacKey exists", () => {
  // Not a confidentiality break — a digest of high-entropy text is not reversible.
  // The exposure is CORRELATION. An identical input always produces an identical
  // digest, so a party holding the log can confirm whether a specific known record
  // passed through, and can link records across logs and across time.
  const cfg = resolveConfig(CFG);
  const record = buildRecord({ event: "check", input: "ada@northwind.example", output: "[email]", cfg });
  const guess = createHash("sha256").update("ada@northwind.example").digest("hex");
  assert.equal(record.input.sha256, guess, "a candidate can simply be hashed and compared");
});

test("hmacKey keys the digests, so the same input no longer hashes to a knowable value", () => {
  const cfg = resolveConfig({ ...CFG, audit: { hmacKey: "k1" } });
  const record = buildRecord({ event: "check", input: "ada@northwind.example", output: "[email]", cfg });

  const guess = createHash("sha256").update("ada@northwind.example").digest("hex");
  assert.notEqual(record.input["hmac-sha256"], guess);
  assert.equal(record.input.sha256, undefined, "the unkeyed digest must not sit beside it");
  assert.equal(record.output.sha256, undefined);
  assert.ok(record.output["hmac-sha256"]);
});

test("a different key gives a different digest for the same input, which is the correlation break", () => {
  const one = buildRecord({
    event: "check", input: "ada@northwind.example", output: "x",
    cfg: resolveConfig({ ...CFG, audit: { hmacKey: "k1" } }),
  });
  const two = buildRecord({
    event: "check", input: "ada@northwind.example", output: "x",
    cfg: resolveConfig({ ...CFG, audit: { hmacKey: "k2" } }),
  });
  assert.notEqual(one.input["hmac-sha256"], two.input["hmac-sha256"]);
});

test("the policy fingerprint stays unkeyed, because it identifies a config and not a person", () => {
  // Keying it would cost the one property it has: anyone holding the config can
  // recompute it and confirm which policy ran. There is nothing in it to correlate.
  const cfg = resolveConfig({ ...CFG, audit: { hmacKey: "k1" } });
  const record = buildRecord({ event: "check", input: "a", output: "a", cfg });
  assert.equal(record.policy.sha256, cfg.policyHash);
  assert.equal(record.policy["hmac-sha256"], undefined);
});

test("an empty hmacKey is refused rather than silently falling back to unkeyed", () => {
  // The failure class this repo already guards elsewhere: a setting that looks
  // applied and is not. An empty string is falsy, so it would take the unkeyed path
  // while the config file plainly says a key was configured.
  assert.throws(
    () => resolveConfig({ ...CFG, audit: { hmacKey: "" } }),
    (err) => {
      assert.match(err.message, /audit\.hmacKey/);
      return true;
    }
  );
});
