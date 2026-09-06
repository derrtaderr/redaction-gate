/**
 * Worked example. Run it with:
 *
 *   node example/guard-an-llm-call.js
 *
 * It stands in for the shape most teams have. A function that sends text
 * somewhere it cannot be recalled from, and a redaction step in front of it.
 * The first call goes through with placeholders. The second one does not go at
 * all, because the redactor missed and the gate caught what it missed.
 */
import { fileURLToPath } from "node:url";
import { createGate, loadConfig } from "../src/index.js";

// Pretend this posts to a model API. It records what it was actually handed,
// so the example can prove the original text never reached it.
const sent = [];
async function callTheModel(prompt) {
  sent.push(prompt);
  return `model saw ${prompt.length} chars`;
}

const config = loadConfig([fileURLToPath(new URL("./roster.json", import.meta.url))], {
  audit: { enabled: true, path: "tmp/compliance.jsonl", label: "example" },
});
const gate = createGate(config);
const ask = gate.guard(callTheModel, { label: "outbound-llm" });

const CLEAN = "Ada Vasquez at Northwind Robotics asked about Bluebird. Reply to ada@northwind.example or 555-018-3921.";
const EVASIVE = "Ticket filed under northwind_robotics/renewal by Dr Vasquez, reachable at ada [at] northwind [dot] example.";

console.log("1. text the redactor can match\n");
console.log(await ask(CLEAN));
console.log(`   the model was handed: ${sent[0]}\n`);

console.log("2. the same facts, written in forms the redactor cannot match\n");
try {
  await ask(EVASIVE);
  console.log("   the call went through, which would be the bug");
} catch (err) {
  console.log(`   ${err.name}, and the model was called ${sent.length} time(s), not ${sent.length + 1}`);
  for (const f of err.findings) {
    // Same shape the refusal message uses. `term` is absent unless revealTerms is
    // on, and printing `undefined` where a value used to be is not a smaller
    // disclosure, it is just a worse report.
    const shown = f.term === undefined ? `(${f.length} chars)` : JSON.stringify(f.term);
    console.log(`   line ${f.line}, col ${f.column}  ${f.class}  ${shown}`);
  }
}

console.log("\n3. what the compliance log recorded, with no source text in it\n");
console.log(await import("node:fs").then((fs) => fs.readFileSync("tmp/compliance.jsonl", "utf8").trim()));
