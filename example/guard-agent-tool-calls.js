/**
 * Worked example. Run it with:
 *
 *   node example/guard-agent-tool-calls.js
 *
 * The other example guards one call — the prompt on its way to a model. This one
 * guards the OTHER egress an agent has, and the one that is easier to forget: the
 * tools it decides to call.
 *
 * An agent with send_email, post_slack and send_to_crm has three ways out of the
 * process. Guarding the model call and leaving those unguarded protects the door
 * and not the windows. So the wrapper goes on the TOOL TABLE rather than on any
 * call site, which is the whole idea in one line:
 *
 *   Object.entries(tools).map(([name, fn]) => [name, gate.guard(fn, ...)])
 *
 * The plan below is fixed rather than model-generated, so the output is the same
 * on every run and CI can assert on it. What it demonstrates is the property that
 * per-call-site guarding does not give you: when the agent is refused on one exit
 * and reroutes the same content to another, it is refused there too.
 */
import { fileURLToPath } from "node:url";
import { createGate, loadConfig } from "../src/index.js";

// Stand-ins for the real thing. Each records what it was actually handed, so the
// example can prove the original text never reached any of them.
const delivered = { send_email: [], post_slack: [], send_to_crm: [] };
const tools = {
  send_email: async ({ body }) => void delivered.send_email.push(body),
  post_slack: async ({ body }) => void delivered.post_slack.push(body),
  send_to_crm: async ({ body }) => void delivered.send_to_crm.push(body),
};

const config = loadConfig([fileURLToPath(new URL("./roster.json", import.meta.url))], {
  audit: { enabled: true, path: "tmp/agent-compliance.jsonl", label: "agent-tools" },
});
const gate = createGate(config);

// ONE WRAPPER, EVERY EXIT. Adding a tool to the table adds it to the gate; there
// is no second place to remember.
//
// Tool arguments are objects, not strings, so `get` and `set` tell the guard which
// field carries the text. That pair is not optional decoration here: without it the
// guard stringifies the whole argument, scans "[object Object]", finds nothing, and
// passes everything. Name the field.
const guarded = Object.fromEntries(
  Object.entries(tools).map(([name, fn]) => [
    name,
    gate.guard(fn, {
      label: `tool:${name}`,
      get: (args) => args.body,
      set: (args, text) => ({ ...args, body: text }),
    }),
  ])
);

const CLEAN = "The renewal is confirmed and the invoice is queued for the finance team.";
const LEAKY = "Ticket filed under northwind_robotics/renewal by Dr Vasquez, reachable at ada [at] northwind [dot] example.";

// A fixed plan. The second and third steps are the same content through two
// different exits, which is the case the guard has to survive.
const plan = [
  { tool: "send_to_crm", body: CLEAN, why: "a clean call, so the gate reads as a control and not a wall" },
  { tool: "send_email", body: LEAKY, why: "the redactor misses the evasive forms, so the gate refuses" },
  { tool: "post_slack", body: LEAKY, why: "the agent reroutes the same content to another exit" },
  { tool: "send_to_crm", body: LEAKY, why: "and to a third, which it also does not get" },
];

console.log("an agent with three ways out of the process, and one gate on all of them\n");

for (const [i, step] of plan.entries()) {
  try {
    await guarded[step.tool]({ body: step.body });
    console.log(`${i + 1}. RAN     ${step.tool}  (${step.why})`);
    console.log(`   the tool was handed: ${delivered[step.tool].at(-1)}\n`);
  } catch (err) {
    console.log(`${i + 1}. REFUSED ${step.tool}  (${step.why})`);
    console.log(`   ${err.name}, ${err.findings.length} identifier(s) survived redaction`);
    for (const f of err.findings) {
      console.log(`     line ${f.line}, col ${f.column}  ${f.class}  (${f.length} chars)`);
    }
    console.log();
  }
}

const ran = Object.entries(delivered).filter(([, calls]) => calls.length);
console.log("what actually left the process:");
for (const [name, calls] of ran) console.log(`   ${name}, ${calls.length} time(s)`);
console.log(`   and nothing at all through ${Object.keys(delivered).length - ran.length} of the three tools\n`);
console.log("the refusal names a class and a position and never the value, so this");
console.log("transcript is safe to paste into an issue.");
