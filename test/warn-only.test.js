import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertClean } from "../src/gate.js";
import { guard } from "../src/middleware.js";
import { resolveConfig } from "../src/config.js";

const DIRTY = "filed under northwind_robotics/notes";
const BASE = { roster: [{ class: "client", match: ["Northwind Robotics"] }] };

test("warnOnly is off at every level unless it is asked for", () => {
  assert.equal(resolveConfig({}).warnOnly, false);
  assert.equal(resolveConfig({ roster: [] }).warnOnly, false);
  // A truthy string used to resolve quietly to false, which left a caller who
  // wrote warnOnly: "true" believing the gate was disarmed when it was not.
  // Refusing is louder than ignoring, and only a literal true disarms it.
  assert.throws(() => resolveConfig({ warnOnly: "yes" }), /REFUSING TO CONFIGURE/);
  assert.equal(resolveConfig({ warnOnly: true }).warnOnly, true);
});

test("warnOnly returns the text instead of throwing", () => {
  const warned = [];
  const cfg = { ...BASE, warnOnly: true, onWarn: (f) => warned.push(...f) };
  assert.equal(assertClean(DIRTY, cfg), DIRTY);
  assert.equal(warned.length, 1);
  assert.equal(warned[0].class, "client");
});

test("warnOnly silences nothing, so every finding is still reported", () => {
  const warned = [];
  const cfg = { ...BASE, warnOnly: true, onWarn: (f) => warned.push(...f) };
  assertClean("northwind_robotics and ada@northwind.example", cfg);
  assert.deepEqual([...new Set(warned.map((f) => f.class))].sort(), ["client", "email"]);
});

test("under warnOnly the guard proceeds and the call still gets redacted text", async () => {
  let seen = null;
  const cfg = { ...BASE, warnOnly: true, onWarn: () => {} };
  const send = guard(async (t) => { seen = t; return "ok"; }, { config: cfg });
  assert.equal(await send("the Northwind Robotics renewal, filed as northwind_robotics"), "ok");
  assert.equal(seen.includes("[client]"), true);
});

test("the compliance log marks a disarmed gate as warned, so a review can find it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "rg-warn-"));
  const path = join(dir, "compliance.jsonl");
  const cfg = { ...BASE, warnOnly: true, onWarn: () => {}, audit: { enabled: true, path } };
  const send = guard(async (t) => t, { config: cfg });
  await send(DIRTY);
  const row = JSON.parse(readFileSync(path, "utf8").trim());
  assert.equal(row.outcome, "warned");
  assert.equal(row.policy.warnOnly, true);
  assert.equal(row.survivors.length, 1);
});
