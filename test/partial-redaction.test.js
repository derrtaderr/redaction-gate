import test from "node:test";
import assert from "node:assert/strict";
import { redact } from "../src/redact.js";
import { assertClean, scan } from "../src/gate.js";

/**
 * Regression, found by running the worked example rather than by reasoning.
 *
 * A roster term that sits INSIDE a structured token used to be substituted
 * first, which broke the token so the pattern detector could no longer see it.
 * "ada@northwind.example" became "ada@[client].example", the local part of a
 * real person's address survived, and nothing in the library noticed, because
 * the surviving text no longer matched any pattern.
 *
 * Two fixes. Structured patterns now run before roster terms so the token is
 * claimed whole, and a residue detector treats a placeholder welded into an
 * address as evidence that something was half redacted.
 */

const CFG = {
  roster: [{ class: "client", match: ["Northwind Robotics", "Northwind"] }],
};

test("a roster term inside an address does not break the address open", () => {
  const out = redact("reply to ada@northwind.example today", CFG);
  assert.equal(out, "reply to [email] today");
  assert.ok(!out.includes("ada@"), "the local part must not survive");
});

test("a roster term inside a hostname still redacts the whole host", () => {
  assert.equal(redact("traffic from northwind.example", CFG), "traffic from [domain]");
});

test("a plain roster term is still claimed by the roster, not by a pattern", () => {
  assert.equal(redact("the Northwind Robotics renewal", CFG), "the [client] renewal");
});

test("a placeholder welded into an address is treated as a survivor", () => {
  const damaged = "reply to ada@[client].example today";
  assert.throws(() => assertClean(damaged, CFG), /REFUSING TO PROCEED/);
  assert.equal(scan(damaged, CFG)[0].class, "residue");
});

test("a placeholder welded to the front of an address is a survivor too", () => {
  assert.throws(() => assertClean("reply to [client]@northwind.test", CFG), /residue/);
});

test("an ordinary placeholder in clean prose is not residue", () => {
  const clean = "reply to [email] or [phone]. the [client] account renewed.";
  assert.equal(assertClean(clean, CFG), clean);
});

test("an obfuscated address half claimed by a roster term is still residue", () => {
  // "ada [at] northwind [dot] example" is not matchable by the strict email
  // pattern, and the roster claims the middle of it, leaving the local part
  // behind in a form nothing else recognizes.
  const out = redact("write to ada [at] northwind [dot] example", CFG);
  assert.ok(out.includes("ada [at]"), "redact was expected to leave the local part");
  assert.throws(() => assertClean(out, CFG), /residue/);
});

test("a markdown link is not residue", () => {
  const clean = "see [the docs](https://docs.test/guide) for more";
  assert.equal(scan(clean, { ...CFG, allowDomains: ["docs.test"] }).length, 0);
});
