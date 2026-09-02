import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { guard } from "../src/middleware.js";
import { RedactionRefusal } from "../src/gate.js";

const CFG = { roster: [{ class: "client", match: ["Northwind Robotics"] }] };

test("the wrapped function receives redacted text, never the original", async () => {
  let seen = null;
  const send = guard(async (text) => { seen = text; return "ok"; }, { config: CFG });
  const result = await send("the Northwind Robotics renewal");
  assert.equal(seen, "the [client] renewal");
  assert.equal(result, "ok");
});

test("on a refusal the wrapped function is never called", async () => {
  let called = false;
  const send = guard(async () => { called = true; }, { config: CFG });
  await assert.rejects(
    () => send("filed under northwind_robotics/notes"),
    (err) => err instanceof RedactionRefusal
  );
  assert.equal(called, false);
});

test("extra arguments pass straight through", async () => {
  const send = guard(async (text, opts) => `${text}|${opts.model}`, { config: CFG });
  assert.equal(await send("clean text", { model: "haiku" }), "clean text|haiku");
});

test("an object payload is guarded through get and set", async () => {
  let seen = null;
  const send = guard(async (payload) => { seen = payload; return "ok"; }, {
    config: CFG,
    get: (p) => p.prompt,
    set: (p, text) => ({ ...p, prompt: text }),
  });
  await send({ model: "haiku", prompt: "about Northwind Robotics" });
  assert.equal(seen.prompt, "about [client]");
  assert.equal(seen.model, "haiku");
});

test("a different argument position can be guarded", async () => {
  let seen = null;
  const write = guard(async (path, body) => { seen = body; }, { config: CFG, argIndex: 1 });
  await write("/tmp/out.txt", "the Northwind Robotics file");
  assert.equal(seen, "the [client] file");
});

test("a synchronous wrapped function still works", async () => {
  const send = guard((text) => text.toUpperCase(), { config: CFG });
  assert.equal(await send("Northwind Robotics"), "[CLIENT]");
});

test("both a pass and a refusal land in the compliance log", async () => {
  const dir = mkdtempSync(join(tmpdir(), "rg-guard-"));
  const path = join(dir, "compliance.jsonl");
  const config = { ...CFG, audit: { enabled: true, path, label: "outbound-llm" } };
  const send = guard(async (t) => t, { config });
  await send("the Northwind Robotics renewal");
  await assert.rejects(() => send("filed under northwind_robotics/notes"));
  const rows = readFileSync(path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(rows.map((r) => r.outcome), ["redacted", "refused"]);
  assert.equal(rows[0].label, "outbound-llm");
  assert.equal(rows[1].event, "guard");
});

test("a rejection from the wrapped function is not swallowed", async () => {
  const send = guard(async () => { throw new Error("upstream 500"); }, { config: CFG });
  await assert.rejects(() => send("clean text"), /upstream 500/);
});
