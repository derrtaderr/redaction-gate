import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The README tells a stranger to run this, so the suite runs it too.
const SCRIPT = fileURLToPath(new URL("../example/guard-agent-tool-calls.js", import.meta.url));

function run() {
  const cwd = mkdtempSync(join(tmpdir(), "rg-agent-"));
  return spawnSync(process.execPath, [SCRIPT], { cwd, encoding: "utf8" });
}

test("the agent example runs and reports every tool call it attempted", () => {
  const r = run();
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /send_email/);
  assert.match(r.stdout, /post_slack/);
  assert.match(r.stdout, /send_to_crm/);
});

test("a refused tool call does not run, and rerouting to a second tool does not either", () => {
  // The point the existing LLM example cannot make. The guard wraps the tool
  // TABLE, so an agent that gets refused on one exit and tries another is refused
  // there too. If this ever passes with a second exit having run, the wrapper has
  // been applied per-call-site again and the property is gone.
  const r = run();
  const ran = [...r.stdout.matchAll(/^\d+\.\s+RAN\s+(\w+)/gm)].map((m) => m[1]);
  const refused = [...r.stdout.matchAll(/^\d+\.\s+REFUSED\s+(\w+)/gm)].map((m) => m[1]);

  assert.ok(refused.includes("send_email"), "the first exit is refused");
  assert.ok(refused.includes("post_slack"), "and so is the reroute");
  assert.ok(!ran.includes("send_email"));
  assert.ok(!ran.includes("post_slack"));
  assert.ok(ran.length > 0, "a clean call still gets through, or this reads as a wall");
  assert.deepEqual(ran, ["send_to_crm"], "exactly the clean call, and nothing else");
  assert.deepEqual(refused, ["send_email", "post_slack", "send_to_crm"], "all three exits");
});

test("nothing the roster names appears anywhere the example prints", () => {
  const r = run();
  // Empty output contains no secrets, so this passes on a broken script unless the
  // presence of real output is asserted first. That is the same shape as the
  // "leaks nothing" test that stayed green while the example printed undefined.
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.length > 400, "the example has to have actually said something");
  for (const secret of ["Ada Vasquez", "Northwind", "northwind", "Bluebird", "555"]) {
    assert.ok(!r.stdout.includes(secret), `stdout must not contain ${secret}`);
  }
});
