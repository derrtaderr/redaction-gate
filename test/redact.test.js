import test from "node:test";
import assert from "node:assert/strict";
import { redact } from "../src/redact.js";

const ROSTER = {
  roster: [
    { class: "client", match: ["Northwind Robotics", "Northwind"] },
    { class: "person", match: ["Ada Vasquez"] },
    { class: "custom", as: "[project]", match: ["Bluebird"] },
  ],
  allowDomains: ["example.com"],
};

test("a roster client name is replaced with its typed placeholder", () => {
  assert.equal(
    redact("the Northwind Robotics account renewed", ROSTER),
    "the [client] account renewed"
  );
});

test("substitution is case insensitive", () => {
  assert.equal(redact("NORTHWIND ROBOTICS renewed", ROSTER), "[client] renewed");
});

test("a roster entry keeps its own placeholder when it declares one", () => {
  assert.equal(redact("Bluebird ships Friday", ROSTER), "[project] ships Friday");
});

test("word boundaries hold, so a longer word containing a roster term survives", () => {
  assert.equal(redact("the northwindmill is old", ROSTER), "the northwindmill is old");
});

test("the document stays structurally intact around a substitution", () => {
  const out = redact("| Northwind Robotics | renewed | 2026-01-04 |", ROSTER);
  assert.equal(out, "| [client] | renewed | 2026-01-04 |");
});

test("redact is a fixed point, so running it twice changes nothing", () => {
  const once = redact("Ada Vasquez emailed about Northwind", ROSTER);
  assert.equal(redact(once, ROSTER), once);
});

test("an empty config leaves roster-shaped text alone but still runs the built-ins", () => {
  assert.equal(redact("Northwind Robotics renewed", {}), "Northwind Robotics renewed");
});

test("redact accepts an already resolved config without re-resolving it", () => {
  const out = redact("Northwind renewed", ROSTER);
  assert.equal(out, "[client] renewed");
});
