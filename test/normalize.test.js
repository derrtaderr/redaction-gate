import test from "node:test";
import assert from "node:assert/strict";
import { normalize, NORMALIZERS } from "../src/normalize.js";

// Every normalizer returns a rewritten string plus an index map back to the
// original, because a finding is worthless if it cannot say where it was.

test("raw is the identity and maps one to one", () => {
  const { text, map } = normalize("hello world", "raw");
  assert.equal(text, "hello world");
  assert.equal(map[6], 6);
});

test("flatten lowercases and drops every non-alphanumeric character", () => {
  const { text } = normalize("Northwind_Robotics, Inc.", "flatten");
  assert.equal(text, "northwindroboticsinc");
});

test("flatten maps a normalized index back to the original offset", () => {
  const src = "filed under northwind_robotics/notes";
  const { text, map } = normalize(src, "flatten");
  const at = text.indexOf("northwindrobotics");
  assert.equal(map[at], src.indexOf("northwind_robotics"));
});

test("deobfuscate rebuilds an address written to dodge a matcher", () => {
  const { text } = normalize("jane.doe [at] northwind [dot] example", "deobfuscate");
  assert.equal(text, "jane.doe@northwind.example");
});

test("deobfuscate handles the defanged bracket-dot form", () => {
  const { text } = normalize("northwind[.]example", "deobfuscate");
  assert.equal(text, "northwind.example");
});

test("deobfuscate maps back to the start of the consumed source", () => {
  const src = "reach jane [at] northwind [dot] example today";
  const { text, map } = normalize(src, "deobfuscate");
  const at = text.indexOf("jane@northwind.example");
  assert.equal(map[at], src.indexOf("jane"));
});

test("digits removes phone separators but never commas or spaces", () => {
  const { text } = normalize("555−018−3921 and 1,234,567", "digits");
  assert.equal(text, "5550183921 and 1,234,567");
});

test("despace removes a line wrap so a split token rejoins", () => {
  const { text } = normalize("sk-abc\n  def", "despace");
  assert.equal(text, "sk-abcdef");
});

test("every named normalizer is registered and callable", () => {
  for (const name of Object.keys(NORMALIZERS)) {
    const { text, map } = normalize("Test 1.2 value", name);
    assert.equal(typeof text, "string");
    assert.equal(map.length, text.length);
  }
});
