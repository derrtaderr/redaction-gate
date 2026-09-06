import test from "node:test";
import assert from "node:assert/strict";
import { scan, assertClean, RedactionRefusal } from "../src/gate.js";
import { resolveConfig } from "../src/config.js";

const CFG = {
  roster: [{ class: "client", match: ["Northwind Robotics"] }],
  allowDomains: ["example.com"],
};

test("assertClean returns the text it was given when nothing survives", () => {
  const clean = "the [client] account renewed on 2026-01-04";
  assert.equal(assertClean(clean, CFG), clean);
});

test("assertClean refuses rather than warning, and names the class and the position", () => {
  assert.throws(
    () => assertClean("the Northwind Robotics account renewed", CFG),
    (err) => {
      assert.ok(err instanceof RedactionRefusal);
      assert.equal(err.code, "REDACTION_REFUSED");
      assert.equal(err.findings[0].class, "client");
      assert.match(err.message, /client/);
      // The term used to be here. It is withheld by default now; the case that it
      // is still available on request is its own test below.
      assert.doesNotMatch(err.message, /Northwind Robotics/);
      return true;
    }
  );
});

test("a finding carries a line and a column, so it can be found in the source", () => {
  const src = "line one\nline two\nfiled under Northwind Robotics\n";
  const [f] = scan(src, CFG);
  assert.equal(f.line, 3);
  assert.equal(f.column, 13);
  assert.equal(f.length, "Northwind Robotics".length, "length stands in for the withheld value");
  assert.equal(f.term, undefined);

  const [revealed] = scan(src, { ...CFG, revealTerms: true });
  assert.equal(revealed.term, "Northwind Robotics");
});

test("revealTerms false keeps the class and the position and drops the value", () => {
  const cfg = { ...CFG, revealTerms: false };
  try {
    assertClean("filed under Northwind Robotics", cfg);
    assert.fail("expected a refusal");
  } catch (err) {
    assert.ok(!err.message.includes("Northwind"));
    assert.match(err.message, /client/);
    assert.match(err.message, /line 1/);
    assert.equal(err.findings[0].term, undefined);
  }
});

test("scan never throws, so a caller can report before it enforces", () => {
  const findings = scan("Northwind Robotics and ada@northwind.example", CFG);
  assert.ok(findings.length >= 2);
  assert.deepEqual([...new Set(findings.map((f) => f.class))].sort(), ["client", "email"]);
});

test("findings come back in source order", () => {
  const findings = scan("ada@northwind.example then Northwind Robotics", CFG);
  assert.ok(findings[0].index < findings[1].index);
});

test("a finding inside a more specific finding is not reported twice", () => {
  const classes = scan("ada@northwind.example", {}).map((f) => f.class);
  assert.deepEqual(classes, ["email"]);
});

test("an allowlisted host does not become a finding", () => {
  assert.deepEqual(scan("docs at example.com", CFG), []);
});

test("no detector uses the same expression for both halves", () => {
  const cfg = resolveConfig(CFG);
  for (const d of cfg.detectors) {
    for (const s of d.scan) {
      const identical = d.redact.some((r) => r.source === s.re.source && s.via === "raw");
      assert.ok(
        !identical,
        `detector ${d.name} reuses its redact expression as a scan expression, which means the gate cannot fire`
      );
    }
  }
});

test("a refusal does not put the surviving value in the message it throws", () => {
  // The whole library exists to stop this string crossing a process boundary. An
  // exception message crosses one: it lands in Sentry, Datadog, CloudWatch, a log
  // aggregator. Refusing to send the value to the model and then sending it to the
  // error tracker is not a smaller version of the leak, it is the same leak.
  assert.throws(
    () => assertClean("the Northwind Robotics account renewed", CFG),
    (err) => {
      assert.ok(err instanceof RedactionRefusal);
      assert.doesNotMatch(err.message, /Northwind Robotics/);
      assert.match(err.message, /client/, "the class still has to be there to act on");
      assert.match(err.message, /line 1, col 5/, "and so does the position");
      return true;
    }
  );
});

test("a refusal does not carry the surviving value on the error object either", () => {
  // Error reporters serialise custom properties. A value reachable at err.findings[0].term
  // travels whether or not anything reads err.message.
  assert.throws(
    () => assertClean("the Northwind Robotics account renewed", CFG),
    (err) => {
      assert.equal(err.findings[0].term, undefined);
      assert.equal(err.findings[0].class, "client");
      assert.ok(err.findings[0].length > 0, "length stands in for the value");
      return true;
    }
  );
});

test("revealTerms true is still available, and is now something the caller wrote down", () => {
  assert.throws(
    () => assertClean("the Northwind Robotics account renewed", { ...CFG, revealTerms: true }),
    (err) => {
      assert.match(err.message, /Northwind Robotics/);
      assert.equal(err.findings[0].term, "Northwind Robotics");
      return true;
    }
  );
});

test("RedactionRefusal built by hand withholds the value too", () => {
  // It is a public export, so someone can construct one directly — a custom gate, a
  // test double, a rethrow. Every call site inside this library passes revealTerms
  // explicitly, which means the constructor default is reachable only from outside
  // and only a direct test covers it. Mutating that default broke nothing until this
  // existed.
  const findings = [{ class: "client", line: 1, column: 5, length: 18, term: "Northwind Robotics" }];
  assert.doesNotMatch(new RedactionRefusal(findings).message, /Northwind Robotics/);
  assert.match(new RedactionRefusal(findings).message, /\(18 chars\)/);
  assert.match(new RedactionRefusal(findings, { revealTerms: true }).message, /Northwind Robotics/);
});

test("the refusal strips the value from findings too, not only from the message", () => {
  // The test above asserts the message and stopped there, three tests after the one
  // that names error.findings as the surface a reporter serialises. Inside the
  // library scan() has already dropped term, so every internal path upheld the
  // invariant and the hand-built path did not. Enforcing it in the constructor
  // stops the guarantee depending on who called it.
  const findings = [{ class: "person", line: 1, column: 5, length: 12, term: "Ada Vasquez" }];

  const withheld = new RedactionRefusal(findings);
  assert.equal(withheld.findings[0].term, undefined);
  assert.equal(withheld.findings[0].class, "person");
  assert.equal(withheld.findings[0].length, 12);

  assert.equal(new RedactionRefusal(findings, { revealTerms: true }).findings[0].term, "Ada Vasquez");

  // The caller's array is not mutated on the way through. It is theirs.
  assert.equal(findings[0].term, "Ada Vasquez");
});

test("JSON.stringify of a withheld refusal carries no value anywhere in it", () => {
  // How an error actually reaches a log aggregator. Asserting on the serialised
  // form is the claim that matters, rather than on the fields we remembered to check.
  const err = new RedactionRefusal([
    { class: "person", line: 1, column: 5, length: 12, term: "Ada Vasquez" },
    { class: "client", line: 2, column: 9, length: 18, term: "Northwind Robotics" },
  ]);
  const wire = JSON.stringify({ message: err.message, findings: err.findings, code: err.code });
  assert.doesNotMatch(wire, /Ada Vasquez/);
  assert.doesNotMatch(wire, /Northwind Robotics/);
  assert.match(wire, /person/);
  assert.match(wire, /client/);
});
