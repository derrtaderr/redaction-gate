import test from "node:test";
import assert from "node:assert/strict";
import { redact } from "../src/redact.js";
import { scan } from "../src/gate.js";

/**
 * A gate that can be made to hang is a gate that gets removed.
 *
 * The host and address patterns originally used unbounded runs followed by a
 * required separator, which backtracks over every start position when the
 * separator never arrives. A 50k run of one character took 7.7 seconds to scan.
 * Nobody keeps a pre-commit hook that does that, and a redaction step that gets
 * disabled protects nothing.
 *
 * The fix is the real length limits. A DNS label is at most 63 characters and
 * an email local part at most 64, so the patterns say so and the backtracking
 * is bounded per position rather than per document.
 */

const BUDGET_MS = 2000;

function timed(label, fn) {
  const started = Date.now();
  fn();
  const took = Date.now() - started;
  assert.ok(took < BUDGET_MS, `${label} took ${took}ms, over the ${BUDGET_MS}ms budget`);
}

test("a long run of one character does not blow up the host and address patterns", () => {
  const evil = "x".repeat(100000);
  timed("redact", () => redact(evil, {}));
  timed("scan", () => scan(evil, {}));
});

test("a long run of dotted digits does not blow up the address patterns", () => {
  timed("scan dotted digits", () => scan("1.".repeat(20000), {}));
});

test("a long hyphenated run does not blow up the label pattern", () => {
  timed("scan hyphens", () => scan("ab-".repeat(20000), {}));
});

test("a realistic document of ordinary prose stays fast", () => {
  timed("scan prose", () => scan("lorem ipsum dolor sit amet ".repeat(10000), {}));
});

test("the length caps do not cost real matches", () => {
  assert.equal(redact("mail ada.vasquez@northwind.example now", {}), "mail [email] now");
  assert.equal(redact("host api.northwind.example there", {}), "host [domain] there");
});
