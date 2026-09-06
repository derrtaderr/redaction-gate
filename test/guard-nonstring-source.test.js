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

test("the corruption path: the default set never delivers a stringified '[object Object]'", async () => {
  let called = false;
  let seen = null;
  // `get` and `set` both forgotten. Today the wrapped function receives the
  // literal "[object Object]" — the original payload silently destroyed. The
  // guard refuses before that substitution can happen, naming the received type.
  const send = guard(
    async (payload) => {
      called = true;
      seen = payload;
      return "ok";
    },
    { config: CFG }
  );

  await assert.rejects(
    () => send({ body: "email Northwind about the renewal" }),
    (err) => {
      assert.ok(err instanceof RedactionConfigError);
      assert.match(err.message, /REFUSING TO CONFIGURE/);
      assert.match(err.message, /the guard's source/);
      assert.match(err.message, /returned an object with key "body", expected the string to scan/);
      assert.match(err.message, /get: \(p\) => p\.body/);
      assert.match(err.message, /Nothing was redacted and nothing was checked/);
      assert.equal(err.problems[0].key, "get");
      return true;
    }
  );
  assert.equal(called, false);
  assert.equal(seen, null);
});

test("no regression: a string source still redacts, refuses on a survivor, and passes clean", async () => {
  // Happy path: string source, default identity get, redacted text delivered.
  let delivered = null;
  const send = guard(
    async (text) => {
      delivered = text;
      return "sent";
    },
    { config: CFG }
  );
  assert.equal(await send("the Northwind Robotics renewal"), "sent");
  assert.equal(delivered, "the [client] renewal", "the wrapped function still sees redacted text");

  // Refusal path: a survivor the redactor misses still throws the refusal.
  let refusedCall = false;
  const guarded = guard(async () => { refusedCall = true; }, { config: CFG });
  await assert.rejects(() => guarded("filed under northwind_robotics/notes"), (err) => err.name === "RedactionRefusal");
  assert.equal(refusedCall, false);

  // Clean path: no identifiers, the call goes straight through.
  const clean = guard(async (text) => `ok:${text}`, { config: CFG });
  assert.equal(await clean("nothing sensitive here"), "ok:nothing sensitive here");
});
