import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The README tells a stranger to run this. A README that tells you to run
// something broken is worse than no README, so the suite runs it too.
const SCRIPT = fileURLToPath(new URL("../example/guard-an-llm-call.js", import.meta.url));

test("the worked example runs, refuses, and leaks nothing into its own output", () => {
  const cwd = mkdtempSync(join(tmpdir(), "rg-example-"));
  const r = spawnSync(process.execPath, [SCRIPT], { cwd, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /RedactionRefusal/);
  assert.match(r.stdout, /the model was called 1 time\(s\), not 2/);
  assert.ok(!r.stdout.includes("ada@northwind.example"), "the redacted call must not carry the address");

  const log = r.stdout.slice(r.stdout.indexOf('{"v":1'));
  for (const secret of ["Northwind", "northwind", "Vasquez", "Bluebird", "555"]) {
    assert.ok(!log.includes(secret), `the compliance log must not contain ${secret}`);
  }
});

test("the worked example prints a usable finding, not the word undefined", () => {
  // The suite asserted the example leaks nothing and it passed, because withholding
  // the term does not leak. It printed "person undefined" for four findings and no
  // test noticed, because absence-of-leak and presence-of-useful-output are two
  // different claims and only the first was being made.
  const cwd = mkdtempSync(join(tmpdir(), "rg-example-undef-"));
  const r = spawnSync(process.execPath, [SCRIPT], { cwd, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /undefined/);
  assert.match(r.stdout, /line 1, col \d+  person  \(\d+ chars\)/);
});
