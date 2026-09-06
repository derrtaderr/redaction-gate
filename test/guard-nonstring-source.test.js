import test from "node:test";
import assert from "node:assert/strict";
import { guard } from "../src/middleware.js";
import { RedactionConfigError } from "../src/config.js";

/**
 * The guard's `get` accessor defaults to identity. Wrap an object-taking
 * function and forget `get`, and the source handed to the scan is the object,
 * which stringifies to "[object Object]", matches no detector, and lets
 * everything through. The scan is meaningless on a non-string source, so the
 * guard fails closed — the same posture the library already takes for a
 * misconfigured hmacKey or warnOnly. See SPEC.md section 12.
 */

const CFG = { roster: [{ class: "client", match: ["Northwind Robotics", "Northwind"] }] };

test("the leak path: an object source with a preserving set never reaches the wrapped function", async () => {
  let called = false;
  let seen = null;
  // The realistic mistake. `get` is forgotten, so the source is the whole
  // object; `set` preserves the PII-bearing field and writes the (blind)
  // scan result to a separate field. Today `body` keeps "Northwind" and it
  // reaches fn untouched, because the scan only ever saw "[object Object]".
  const send = guard(
    async (payload) => {
      called = true;
      seen = payload;
      return "ok";
    },
    { config: CFG, set: (p, text) => ({ ...p, scannedPreview: text }) }
  );

  await assert.rejects(
    () => send({ body: "email Northwind about the renewal" }),
    (err) => {
      assert.ok(err instanceof RedactionConfigError, "throws the config-refusal class");
      return true;
    }
  );
  assert.equal(called, false, "the wrapped function is never called");
  assert.equal(seen, null, "no PII-bearing object reached the wrapped function");
});
