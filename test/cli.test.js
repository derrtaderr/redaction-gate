import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/redaction-gate.js", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "rg-cli-"));
const CONFIG = join(dir, "rg.json");
writeFileSync(CONFIG, JSON.stringify({ roster: [{ class: "client", match: ["Northwind Robotics"] }] }));

const run = (args, input = "") =>
  spawnSync(process.execPath, [BIN, ...args], { input, encoding: "utf8" });

test("check exits 0 on clean input", () => {
  const r = run(["check", "--config", CONFIG], "a sentence with nothing in it\n");
  assert.equal(r.status, 0);
});

test("check exits 2 and names the class when redaction would have missed", () => {
  const r = run(["check", "--config", CONFIG], "filed under northwind_robotics/notes\n");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /client/);
  assert.match(r.stderr, /stdin:1:13/, "the position is editor-clickable");
});

test("redact writes the redacted text to stdout", () => {
  const r = run(["redact", "--config", CONFIG], "the Northwind Robotics renewal\n");
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "the [client] renewal\n");
});

test("redact emits nothing on stdout when the gate refuses", () => {
  const r = run(["redact", "--config", CONFIG], "filed under northwind_robotics/notes\n");
  assert.equal(r.status, 2);
  assert.equal(r.stdout, "");
});

test("a file path is read and named in the report", () => {
  const f = join(dir, "notes.txt");
  writeFileSync(f, "line one\nfiled under northwind_robotics\n");
  const r = run(["check", "--config", CONFIG, f]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /notes\.txt/);
  assert.match(r.stderr, /notes\.txt:2:13/);
});

test("json output is machine readable", () => {
  const r = run(["check", "--config", CONFIG, "--json"], "filed under northwind_robotics\n");
  assert.equal(r.status, 2);
  const out = JSON.parse(r.stdout);
  assert.equal(out.ok, false);
  assert.equal(out.findings[0].class, "client");
});

test("warn-only alone still exits non-zero, and needs a second flag to go quiet", () => {
  const warn = run(["check", "--config", CONFIG, "--warn-only"], "northwind_robotics\n");
  assert.equal(warn.status, 2);
  const silent = run(["check", "--config", CONFIG, "--warn-only", "--exit-zero"], "northwind_robotics\n");
  assert.equal(silent.status, 0);
  assert.match(silent.stderr, /client/, "the findings are still reported");
});

test("--no-reveal is gone, because withholding is what happens without a flag", () => {
  // Asserted rather than deleted. A flag that silently becomes a no-op is worse than
  // one that errors, because a pipeline still passing it believes it is being careful.
  const r = run(["check", "--config", CONFIG, "--no-reveal"], "northwind_robotics\n");
  assert.equal(r.status, 1, "an unknown flag is a usage error");
  assert.match(r.stderr, /unknown flag --no-reveal/);
});

test("the audit flag writes a compliance record", () => {
  const path = join(dir, "audit.jsonl");
  const r = run(["check", "--config", CONFIG, "--audit", path, "--label", "pre-commit"], "northwind_robotics\n");
  assert.equal(r.status, 2);
  assert.ok(existsSync(path));
  const row = JSON.parse(readFileSync(path, "utf8").trim());
  assert.equal(row.outcome, "refused");
  assert.equal(row.label, "pre-commit");
  assert.ok(!JSON.stringify(row).includes("northwind_robotics"));
});

test("help and version exit clean", () => {
  assert.equal(run(["--help"]).status, 0);
  const v = run(["--version"]);
  assert.equal(v.status, 0);
  assert.match(v.stdout, /\d+\.\d+\.\d+/);
});

test("an unknown flag is a usage error, not a silent pass", () => {
  const r = run(["check", "--nope"], "text\n");
  assert.equal(r.status, 1);
});

test("a config path that does not exist is an error, not a quiet under-protection", () => {
  // The worst outcome available to this CLI. A typo in --config would load an
  // empty roster, find nothing, and exit 0 looking exactly like a clean run.
  const r = run(["check", "--config", join(dir, "typo.json")], "filed under northwind_robotics\n");
  assert.equal(r.status, 1);
  assert.match(r.stderr, /typo\.json/);
});

test("check does not print the surviving value by default", () => {
  // CI logs are usually more widely readable and longer retained than application
  // logs, so the CLI is the worst of the three surfaces, not the least important.
  const r = run(["check", "--config", CONFIG], "filed under northwind_robotics/notes\n");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /client/, "the class and position still have to be actionable");
  assert.doesNotMatch(r.stderr, /northwind_robotics/);
  assert.doesNotMatch(r.stdout, /northwind_robotics/);
});

test("--reveal opts back in, and the JSON report follows the same rule", () => {
  const r = run(["check", "--config", CONFIG, "--reveal"], "filed under northwind_robotics/notes\n");
  assert.match(r.stderr, /northwind_robotics/);

  const quiet = run(["check", "--config", CONFIG, "--json"], "filed under northwind_robotics/notes\n");
  assert.equal(JSON.parse(quiet.stdout).findings[0].term, undefined);

  const loud = run(["check", "--config", CONFIG, "--json", "--reveal"], "filed under northwind_robotics/notes\n");
  assert.equal(JSON.parse(loud.stdout).findings[0].term, "northwind_robotics");
});
