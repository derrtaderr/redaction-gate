import test from "node:test";
import assert from "node:assert/strict";
import { scan, assertClean, RedactionRefusal } from "../src/gate.js";
import { resolveConfig } from "../src/config.js";

const CFG = {
  roster: [{ class: "client", match: ["Northwind Robotics"] }],
  allowDomains: ["example.com"],
};

test("assertClean returns the text it was given when nothing survives", () => {
  const clean = "the [client] account renewed on 2026-01-04";
  assert.equal(assertClean(clean, CFG), clean);
});

test("assertClean refuses rather than warning, and names the class and the term", () => {
  assert.throws(
    () => assertClean("the Northwind Robotics account renewed", CFG),
    (err) => {
      assert.ok(err instanceof RedactionRefusal);
      assert.equal(err.code, "REDACTION_REFUSED");
      assert.equal(err.findings[0].class, "client");
      assert.match(err.message, /Northwind Robotics/);
      return true;
    }
  );
});

test("a finding carries a line and a column, so it can be found in the source", () => {
  const src = "line one\nline two\nfiled under Northwind Robotics\n";
  const [f] = scan(src, CFG);
  assert.equal(f.line, 3);
  assert.equal(f.column, 13);
  assert.equal(f.term, "Northwind Robotics");
});

test("revealTerms false keeps the class and the position and drops the value", () => {
  const cfg = { ...CFG, revealTerms: false };
  try {
    assertClean("filed under Northwind Robotics", cfg);
    assert.fail("expected a refusal");
  } catch (err) {
    assert.ok(!err.message.includes("Northwind"));
    assert.match(err.message, /client/);
    assert.match(err.message, /line 1/);
    assert.equal(err.findings[0].term, undefined);
  }
});

test("scan never throws, so a caller can report before it enforces", () => {
  const findings = scan("Northwind Robotics and ada@northwind.example", CFG);
  assert.ok(findings.length >= 2);
  assert.deepEqual([...new Set(findings.map((f) => f.class))].sort(), ["client", "email"]);
});

test("findings come back in source order", () => {
  const findings = scan("ada@northwind.example then Northwind Robotics", CFG);
  assert.ok(findings[0].index < findings[1].index);
});

test("a finding inside a more specific finding is not reported twice", () => {
  const classes = scan("ada@northwind.example", {}).map((f) => f.class);
  assert.deepEqual(classes, ["email"]);
});

test("an allowlisted host does not become a finding", () => {
  assert.deepEqual(scan("docs at example.com", CFG), []);
});

test("no detector uses the same expression for both halves", () => {
  const cfg = resolveConfig(CFG);
  for (const d of cfg.detectors) {
    for (const s of d.scan) {
      const identical = d.redact.some((r) => r.source === s.re.source && s.via === "raw");
      assert.ok(
        !identical,
        `detector ${d.name} reuses its redact expression as a scan expression, which means the gate cannot fire`
      );
    }
  }
});
