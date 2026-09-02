import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveConfig, loadConfig, RedactionConfigError } from "../src/config.js";
import { createGate } from "../src/index.js";

/**
 * A library whose thesis is "refuse loudly rather than fail confusingly" cannot
 * have a front door that throws an internal TypeError naming neither the key
 * nor the expected shape. Every case below is a config a stranger would
 * plausibly write before reading the example.
 */

test("a roster keyed by class, the shape a stranger tries first, refuses with a usable message", () => {
  assert.throws(
    () => createGate({ roster: { client: ["Northwind"] } }),
    (err) => {
      assert.ok(err instanceof RedactionConfigError);
      assert.equal(err.code, "REDACTION_CONFIG_INVALID");
      assert.match(err.message, /REFUSING TO CONFIGURE/);
      assert.match(err.message, /roster/);
      assert.match(err.message, /received an object with key "client"/);
      assert.match(err.message, /expected an array/);
      assert.match(err.message, /try/);
      assert.equal(err.problems[0].key, "roster");
      return true;
    }
  );
});

test("the suggested fix is built from the keys the caller actually wrote", () => {
  try {
    resolveConfig({ roster: { client: ["Northwind"] } });
    assert.fail("expected a refusal");
  } catch (err) {
    assert.match(err.message, /"class": "client"/);
    assert.match(err.message, /"match": \["Northwind"\]/);
  }
});

test("a roster entry with no class is refused, not silently filed as custom", () => {
  assert.throws(
    () => resolveConfig({ roster: [{ match: ["Northwind"] }] }),
    (err) => {
      assert.equal(err.problems[0].key, "roster[0].class");
      assert.match(err.message, /missing/);
      return true;
    }
  );
});

test("a roster entry with no match is refused", () => {
  assert.throws(
    () => resolveConfig({ roster: [{ class: "client" }] }),
    (err) => {
      assert.equal(err.problems[0].key, "roster[0].match");
      return true;
    }
  );
});

test("match as a bare string is refused, because one name would become a list of letters", () => {
  assert.throws(
    () => resolveConfig({ roster: [{ class: "client", match: "Northwind" }] }),
    (err) => {
      assert.equal(err.problems[0].key, "roster[0].match");
      assert.match(err.message, /received a string/);
      return true;
    }
  );
});

test("allow, allowDomains and extraPatterns each refuse a non-array", () => {
  for (const key of ["allow", "allowDomains", "extraPatterns"]) {
    assert.throws(
      () => resolveConfig({ [key]: "Northwind" }),
      (err) => {
        assert.equal(err.problems[0].key, key);
        assert.match(err.message, /expected an array/);
        return true;
      },
      `${key} accepted a string`
    );
  }
});

test("an extraPatterns entry with no redact is refused", () => {
  assert.throws(
    () => resolveConfig({ extraPatterns: [{ name: "employee_id" }] }),
    (err) => {
      assert.equal(err.problems[0].key, "extraPatterns[0].redact");
      return true;
    }
  );
});

test("an unknown top-level key is refused, because doing nothing quietly is the whole failure", () => {
  assert.throws(
    () => resolveConfig({ rosters: [{ class: "client", match: ["Northwind"] }] }),
    (err) => {
      assert.equal(err.problems[0].key, "rosters");
      assert.match(err.message, /did you mean "roster"/);
      return true;
    }
  );
});

test("warnOnly refuses a truthy string rather than quietly ignoring it", () => {
  assert.throws(
    () => resolveConfig({ warnOnly: "yes" }),
    (err) => {
      assert.equal(err.problems[0].key, "warnOnly");
      assert.match(err.message, /expected a boolean/);
      return true;
    }
  );
});

test("a config that is not an object at all is refused", () => {
  assert.throws(() => resolveConfig("roster.json"), /REFUSING TO CONFIGURE/);
});

test("every problem is reported at once, the way findings are", () => {
  try {
    resolveConfig({ allow: "Support", minScanLength: "four", nope: true });
    assert.fail("expected a refusal");
  } catch (err) {
    assert.equal(err.problems.length, 3);
    assert.deepEqual(err.problems.map((p) => p.key).sort(), ["allow", "minScanLength", "nope"]);
    assert.match(err.message, /3 problems/);
  }
});

test("the refusal says nothing was redacted and nothing was checked", () => {
  assert.throws(() => resolveConfig({ nope: true }), /Nothing was redacted and nothing was checked/);
});

test("loadConfig names the file the problem is in", () => {
  const dir = mkdtempSync(join(tmpdir(), "rg-badcfg-"));
  const bad = join(dir, "broken.json");
  writeFileSync(bad, JSON.stringify({ roster: { client: ["Northwind"] } }));
  assert.throws(() => loadConfig([bad]), /broken\.json/);
});

test("the shipped example config still resolves, so validation rejects nothing valid", () => {
  const path = fileURLToPath(new URL("../example/roster.json", import.meta.url));
  const cfg = loadConfig([path]);
  assert.ok(cfg.detectors.length > 0);
});
