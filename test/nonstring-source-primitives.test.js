import test from "node:test";
import assert from "node:assert/strict";
import { redact, redactWithCounts } from "../src/redact.js";
import { scan, assertClean } from "../src/gate.js";
import { RedactionConfigError } from "../src/config.js";

/**
 * The class, not one instance. `guard` fails closed on a non-string source, but
 * the public primitives it is built on are called directly, and each one used
 * to fail OPEN on a non-string: String(object) is "[object Object]", which
 * matches no detector. A function named "assert this is clean" that passes an
 * object it never scanned is the exact "control looks applied and is not" shape
 * this library exists to refuse. Every entry point that consumes a
 * source-to-scan now throws RedactionConfigError, in the same register as guard,
 * naming the type and never the value. See SPEC.md section 12.
 */

const CFG = { roster: [{ class: "client", match: ["Northwind Robotics", "Northwind"] }] };
const OBJ = { body: "email Northwind about the renewal" };

test("assertClean throws on a non-string source instead of returning it as a false pass", () => {
  assert.throws(
    () => assertClean(OBJ, CFG),
    (err) => {
      assert.ok(err instanceof RedactionConfigError);
      assert.match(err.message, /REFUSING TO CONFIGURE/);
      assert.match(err.message, /assertClean/);
      assert.match(err.message, /received an object with key "body", expected a string to scan/);
      assert.match(err.message, /Nothing was redacted and nothing was checked/);
      return true;
    }
  );
});

test("scan throws on a non-string source instead of returning [] on [object Object]", () => {
  assert.throws(
    () => scan(OBJ, CFG),
    (err) => {
      assert.ok(err instanceof RedactionConfigError);
      assert.match(err.message, /in the source passed to scan/);
      assert.match(err.message, /received an object with key "body", expected a string to scan/);
      return true;
    }
  );
});

test("redact throws on a non-string source instead of silently returning [object Object]", () => {
  assert.throws(
    () => redact(OBJ, CFG),
    (err) => {
      assert.ok(err instanceof RedactionConfigError);
      assert.match(err.message, /in the source passed to redact/);
      assert.match(err.message, /received an object with key "body", expected a string to scan/);
      return true;
    }
  );
});

test("redactWithCounts throws on a non-string source", () => {
  assert.throws(
    () => redactWithCounts(OBJ, CFG),
    (err) => {
      assert.ok(err instanceof RedactionConfigError);
      assert.match(err.message, /in the source passed to redactWithCounts/);
      assert.match(err.message, /received an object with key "body", expected a string to scan/);
      return true;
    }
  );
});

test("no refusal from any primitive prints the payload value, only its type and keys", () => {
  const secret = { body: "email Northwind about the renewal" };
  for (const call of [
    () => assertClean(secret, CFG),
    () => scan(secret, CFG),
    () => redact(secret, CFG),
    () => redactWithCounts(secret, CFG),
  ]) {
    try {
      call();
      assert.fail("expected a refusal");
    } catch (err) {
      assert.ok(err instanceof RedactionConfigError);
      assert.doesNotMatch(err.message, /Northwind/, "the surviving value must never reach the error stream");
      assert.doesNotMatch(err.message, /renewal/);
    }
  }
});

test("no regression: string sources still redact, scan, and assert exactly as before", () => {
  // redact still substitutes on a string
  assert.equal(redact("the Northwind Robotics renewal", CFG), "the [client] renewal");
  // redactWithCounts still counts
  const { text, counts } = redactWithCounts("the Northwind Robotics renewal", CFG);
  assert.equal(text, "the [client] renewal");
  assert.equal(counts.client, 1);
  // scan on a clean string returns [], on a survivor returns a finding
  assert.deepEqual(scan("nothing sensitive here", CFG), []);
  assert.equal(scan("filed under northwind_robotics/notes", CFG).length, 1);
  // assertClean returns the text on a clean string, throws RedactionRefusal on a survivor
  assert.equal(assertClean("nothing sensitive here", CFG), "nothing sensitive here");
  assert.throws(() => assertClean("filed under northwind_robotics/notes", CFG), (err) => err.name === "RedactionRefusal");
});
