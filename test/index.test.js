import test from "node:test";
import assert from "node:assert/strict";
import * as api from "../src/index.js";

const CFG = { roster: [{ class: "client", match: ["Northwind Robotics"] }] };

test("the public surface is what the spec says it is", () => {
  for (const name of ["redact", "scan", "assertClean", "guard", "createGate", "loadConfig", "resolveConfig", "RedactionRefusal", "VERSION"]) {
    assert.ok(name in api, `missing export ${name}`);
  }
});

test("createGate binds one config to every helper", async () => {
  const gate = api.createGate(CFG);
  assert.equal(gate.redact("the Northwind Robotics renewal"), "the [client] renewal");
  assert.throws(() => gate.assertClean("filed under northwind_robotics"));
  assert.equal(gate.scan("clean text").length, 0);
  const send = gate.guard(async (t) => t);
  assert.equal(await send("the Northwind Robotics renewal"), "the [client] renewal");
});

test("a bound gate resolves its config once and reuses it", () => {
  const gate = api.createGate(CFG);
  assert.equal(gate.config.policyHash, api.resolveConfig(CFG).policyHash);
  assert.equal(api.resolveConfig(gate.config), gate.config);
});
