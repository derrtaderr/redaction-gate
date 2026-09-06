import test from "node:test";
import assert from "node:assert/strict";
import { redact } from "../src/redact.js";
import { scan } from "../src/gate.js";

// Fictional throughout. northwind-robotics.example uses the IANA reserved
// `.example` TLD, which can never belong to anyone.
const CFG = { allowDomains: ["example.com"] };

test("email, a plain address is replaced", () => {
  assert.equal(redact("write to ada.vasquez@northwind.example soon", CFG), "write to [email] soon");
});

test("email, the address is claimed before the domain detector sees its host", () => {
  assert.ok(!redact("ada@northwind.example", CFG).includes("[domain]"));
});

test("email, a bare mention and a filename do not trip it", () => {
  const src = "@here please review src/index.js";
  assert.equal(redact(src, CFG), src);
});

test("domain, a company host is replaced", () => {
  assert.equal(redact("hosted at northwind.example today", CFG), "hosted at [domain] today");
});

test("domain, filenames are never mistaken for companies", () => {
  const src = "see README.md, package.json, index.js and build-report.mjs";
  assert.equal(redact(src, CFG), src);
});

test("domain, an allowlisted host is left alone", () => {
  assert.equal(redact("docs live at example.com", CFG), "docs live at example.com");
});

test("phone, a separated number is replaced", () => {
  assert.equal(redact("call (555) 018-3921 today", CFG), "call [phone] today");
  assert.equal(redact("call +1 555.018.3921 today", CFG), "call [phone] today");
});

test("phone, currency, dates and version strings do not trip it", () => {
  const src = "invoice 1,234,567.89 dated 2026-01-04 on v1.22.3";
  assert.equal(redact(src, CFG), src);
});

test("secret, known token prefixes are replaced", () => {
  assert.equal(redact("OPENAI_API_KEY=sk-abcdefghijklmnop1234", CFG), "OPENAI_API_KEY=[secret]");
  assert.equal(redact("token ghp_abcdefghijklmnopqrstuvwxyz0123", CFG), "token [secret]");
  assert.equal(redact("AKIAIOSFODNN7EXAMPLE is the id", CFG), "[secret] is the id");
});

test("secret, an assignment gates the generic high entropy rule", () => {
  assert.equal(
    redact("Authorization: Bearer aGVsbG93b3JsZDEyMzQ1Njc4OTA", CFG),
    "Authorization: Bearer [secret]"
  );
});

test("secret, a bare git sha in prose is not a credential", () => {
  const src = "reverted in commit a192bca5f3d94c2b81e0ff77aa1c3d5e9b620a41 yesterday";
  assert.equal(redact(src, CFG), src);
});

test("person, an honorific with a full name is replaced", () => {
  assert.equal(redact("Dr. Ada Vasquez signed off", CFG), "[person] signed off");
});

test("person, MS Word and a bare honorific do not trip it", () => {
  const src = "open MS Word, ask Mr and Dr. later";
  assert.equal(redact(src, CFG), src);
});

test("a caller-supplied pattern behaves like a built-in", () => {
  const cfg = {
    extraPatterns: [{ name: "employee_id", class: "employee", as: "[employee-id]", redact: ["EMP-\\d{6}"] }],
  };
  assert.equal(redact("assigned to EMP-004182", cfg), "assigned to [employee-id]");
});

test("ip, a v4 address is replaced", () => {
  assert.equal(redact("request came from 203.0.113.42 twice", CFG), "request came from [ip] twice");
});

test("ip, version strings and dotted dates do not trip it", () => {
  const src = "upgraded to v1.22.3 on 2026.01.04 with build 10.15";
  assert.equal(redact(src, CFG), src);
});

test("a TLD outside the built-in list is left alone, which is the documented tradeoff", () => {
  // Not a bug. The list is short so `index.js` and `notes.md` can never be mangled
  // into a company. This test pins the cost of that choice so the next test can show
  // the escape hatch closing it.
  const cfg = {};
  assert.equal(redact("hosted at northwind.agency today", cfg), "hosted at northwind.agency today");
  assert.deepEqual(scan("hosted at northwind.agency today", cfg), []);
});

test("extraTlds widens both halves of the gate, not just the redactor", () => {
  // The failure this prevents: a user adds a wider domain pattern through
  // extraPatterns, forgets `via: "deobfuscate"` on the scan half, and ends up with a
  // redactor that handles the plain form and a paranoid scan that no longer covers
  // it. Half a gate reads exactly like a whole one until it misses.
  const cfg = { extraTlds: ["agency"] };

  assert.equal(redact("hosted at northwind.agency today", cfg), "hosted at [domain] today");
  assert.equal(scan("hosted at northwind[dot]agency today", cfg).length, 1, "the paranoid half too");
  assert.equal(scan("hosted at northwind[dot]agency today", cfg)[0].class, "domain");

  // And the email pattern is built from the same group, so it widens in step.
  assert.equal(redact("write to ada@northwind.agency", cfg), "write to [email]");
});

test("extraTlds does not disturb the filenames the short list exists to protect", () => {
  const cfg = { extraTlds: ["agency"] };
  assert.equal(redact("see index.js and notes.md", cfg), "see index.js and notes.md");
});
