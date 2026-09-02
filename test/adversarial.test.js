import test from "node:test";
import assert from "node:assert/strict";
import { redact } from "../src/redact.js";
import { assertClean, scan } from "../src/gate.js";

/**
 * The thesis, tested.
 *
 * Every case here follows the same shape. The redactor is given text it cannot
 * match, we assert that it really did miss, and then the gate catches the
 * survivor anyway. If a detector has no test in this file it is decorative,
 * because nothing proves its check is capable of failing.
 */

const CFG = {
  roster: [{ class: "client", match: ["Northwind Robotics"] }],
  allowDomains: ["example.com"],
};

function missedThenCaught(t, input, { survives, cls }, cfg = CFG) {
  const out = redact(input, cfg);
  assert.ok(out.includes(survives), `redact was expected to miss ${JSON.stringify(survives)}`);
  assert.throws(() => assertClean(out, cfg), /REFUSING TO PROCEED/);
  assert.equal(scan(out, cfg)[0].class, cls);
}

test("roster, an underscored form slips word-boundary substitution and is refused", (t) => {
  missedThenCaught(t, "filed under northwind_robotics/notes", {
    survives: "northwind_robotics",
    cls: "client",
  });
});

test("roster, a glued form slips substitution and is refused", (t) => {
  missedThenCaught(t, "see NorthwindRobotics on the board", {
    survives: "NorthwindRobotics",
    cls: "client",
  });
});

test("roster, a hyphenated form slips substitution and is refused", (t) => {
  missedThenCaught(t, "the Northwind-Robotics renewal", {
    survives: "Northwind-Robotics",
    cls: "client",
  });
});

test("email, a bracketed address slips the strict pattern and is refused", (t) => {
  missedThenCaught(t, "reach ada [at] northwind [dot] example today", {
    survives: "[at]",
    cls: "email",
  });
});

test("email, an all-words address slips the strict pattern and is refused", (t) => {
  missedThenCaught(t, "reach ada at northwind dot example today", {
    survives: "ada at northwind dot example",
    cls: "email",
  });
});

test("domain, a defanged host slips the strict pattern and is refused", (t) => {
  missedThenCaught(t, "traffic came from northwind[.]example", {
    survives: "northwind[.]example",
    cls: "domain",
  });
});

test("phone, a Unicode minus slips the strict pattern and is refused", (t) => {
  // U+2212. Word processors and PDF copy-paste produce this constantly.
  missedThenCaught(t, "call 555−018−3921 today", {
    survives: "555−018−3921",
    cls: "phone",
  });
});

test("secret, a key wrapped across a line slips every pattern and is refused", (t) => {
  missedThenCaught(t, "OPENAI_API_KEY=sk-abcdefghij\n  klmnop1234\n", {
    survives: "sk-abcdefghij",
    cls: "secret",
  });
});

test("person, an honorific without its period slips substitution and is refused", (t) => {
  missedThenCaught(t, "Dr Vasquez signed off", { survives: "Dr Vasquez", cls: "person" });
});

test("the gate is what stands between a miss and a write", () => {
  // The failure mode this library exists to remove. Without the gate the
  // redactor's miss is indistinguishable from a clean pass.
  const leaky = redact("filed under northwind_robotics/notes", CFG);
  let wrote = false;
  try {
    assertClean(leaky, CFG);
    wrote = true;
  } catch {
    /* refused, which is the point */
  }
  assert.equal(wrote, false);
});
