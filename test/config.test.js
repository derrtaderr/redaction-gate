import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveConfig, loadConfig } from "../src/config.js";

const names = (cfg) => cfg.detectors.map((d) => d.name);

test("an empty config still arms every built-in detector", () => {
  const cfg = resolveConfig({});
  for (const n of ["email", "domain", "phone", "secret", "honorific"]) {
    assert.ok(names(cfg).includes(n), `expected the ${n} detector`);
  }
});

test("a built-in detector can be switched off by name", () => {
  const cfg = resolveConfig({ patterns: { phone: false } });
  assert.ok(!names(cfg).includes("phone"));
  assert.ok(names(cfg).includes("email"));
});

test("a roster entry becomes a detector carrying its class placeholder", () => {
  const cfg = resolveConfig({ roster: [{ class: "client", match: ["Northwind Robotics"] }] });
  const d = cfg.detectors.find((x) => x.class === "client");
  assert.equal(d.as, "[client]");
  assert.equal(d.terms[0], "Northwind Robotics");
});

test("an explicit placeholder on a roster entry wins over the class default", () => {
  const cfg = resolveConfig({ roster: [{ class: "custom", as: "[project]", match: ["Bluebird"] }] });
  assert.equal(cfg.detectors.find((x) => x.class === "custom").as, "[project]");
});

test("a class nobody defined still gets a usable placeholder", () => {
  const cfg = resolveConfig({ roster: [{ class: "vendor", match: ["Halcyon Freight"] }] });
  assert.equal(cfg.detectors.find((x) => x.class === "vendor").as, "[vendor]");
});

test("a caller adds a detector as data, without touching the source", () => {
  const cfg = resolveConfig({
    extraPatterns: [
      { name: "employee_id", class: "employee", as: "[employee-id]", redact: ["EMP-\\d{6}"] },
    ],
  });
  const d = cfg.detectors.find((x) => x.name === "employee_id");
  assert.equal(d.as, "[employee-id]");
  assert.equal(d.redact[0].source, "EMP-\\d{6}");
});

test("allowed domains are folded to lowercase for comparison", () => {
  const cfg = resolveConfig({ allowDomains: ["Example.COM"] });
  assert.ok(cfg.allowDomains.has("example.com"));
});

test("refusal is the default and warnOnly has to be asked for", () => {
  assert.equal(resolveConfig({}).warnOnly, false);
  assert.equal(resolveConfig({ warnOnly: true }).warnOnly, true);
});

test("the policy hash ignores key order and moves when the ruleset moves", () => {
  const a = resolveConfig({ minScanLength: 4, roster: [{ class: "client", match: ["Northwind"] }] });
  const b = resolveConfig({ roster: [{ class: "client", match: ["Northwind"] }], minScanLength: 4 });
  const c = resolveConfig({ minScanLength: 4, roster: [{ class: "client", match: ["Halcyon"] }] });
  assert.equal(a.policyHash, b.policyHash);
  assert.notEqual(a.policyHash, c.policyHash);
});

test("loadConfig merges files in order and appends rosters rather than replacing them", () => {
  const dir = mkdtempSync(join(tmpdir(), "rg-config-"));
  const base = join(dir, "base.json");
  const extra = join(dir, "extra.json");
  writeFileSync(base, JSON.stringify({ roster: [{ class: "client", match: ["Northwind"] }] }));
  writeFileSync(extra, JSON.stringify({ roster: [{ class: "person", match: ["Ada Vasquez"] }], minScanLength: 5 }));
  const cfg = loadConfig([base, extra, join(dir, "absent.json")]);
  assert.equal(cfg.minScanLength, 5);
  assert.equal(cfg.detectors.filter((d) => d.terms?.length).length, 2);
});
