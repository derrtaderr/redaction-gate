# redaction-gate

Redaction that refuses the write when it misses.

Zero dependencies. Node 20 or newer. A library, a middleware wrapper, and a CLI.

## Why this is not another redaction library

Redactors miss. That is not a fixable defect, because a redactor aggressive enough to never miss
would destroy the clean text it was hired to preserve. It would turn `index.js` into
`index[domain]` and get switched off in a week.

The real problem is that a miss looks exactly like a clean pass. Both return a string, both let
the request through, and you find out at the incident review.

So this library ships two matchers instead of one, and they are deliberately different.

- **`redact` is precise.** Word boundaries and strict patterns. Its output has to stay a working
  document.
- **`assertClean` is paranoid.** It runs the strict patterns and then runs looser ones over
  normalized copies of the text, where case, punctuation, spacing and the usual obfuscations have
  collapsed. It can see what the redactor could not touch.

When the second one finds something, nothing gets written, sent, or logged. It throws.

That asymmetry is the entire point. The first version of this code used one matcher for both
jobs, which meant the check could only ever look for what the redactor had already replaced, so
it passed on everything. A verification that cannot return a failure is not a verification.

## Install

```bash
npm install redaction-gate
```

Or clone it and run the tests, which need no network and no install step.

```bash
git clone https://github.com/derrtaderr/redaction-gate.git
cd redaction-gate
npm test
node example/guard-an-llm-call.js
```

## Thirty seconds

```bash
echo "ticket filed under northwind_robotics by Dr Vasquez" \
  | npx redaction-gate check --config example/roster.json
# redaction-gate: REFUSING. 2 identifier(s) survived redaction in stdin.
#   stdin:1:20  client  "northwind_robotics"
#   stdin:1:42  person  "Dr Vasquez"
# exit 2
```

## Worked example

Copy this into a file and run it.

```js
import { createGate } from "redaction-gate";

const gate = createGate({
  roster: [
    { class: "client", match: ["Northwind Robotics", "Northwind"] },
    { class: "person", match: ["Ada Vasquez"] },
    { class: "custom", as: "[project]", match: ["Bluebird"] },
  ],
  allowDomains: ["example.com"],
});

// Anything that carries text out of your process. An LLM call, a log write,
// an outbound webhook, an analytics event.
async function callTheModel(prompt) {
  console.log("the model was handed:", prompt);
  return "ok";
}

const ask = gate.guard(callTheModel, { label: "outbound-llm" });

// 1. Text the redactor can match. The call goes through with placeholders.
await ask("Ada Vasquez at Northwind Robotics asked about Bluebird. Reply to ada@northwind.example or 555-018-3921.");
// the model was handed: [person] at [client] asked about [project]. Reply to [email] or [phone].

// 2. The same facts, written in forms the redactor cannot match.
try {
  await ask("Ticket filed under northwind_robotics by Dr Vasquez, at ada [at] northwind [dot] example.");
} catch (err) {
  console.log(err.name);      // RedactionRefusal
  console.log(err.findings);
  // class 'client'   line 1 col 20  "northwind_robotics"   underscored, so no word boundary
  // class 'person'   line 1 col 42  "Dr Vasquez"           no period, so the strict form missed
  // class 'residue'  line 1 col 57  "ada [at] [client]"    an address left half redacted
  // callTheModel was never invoked.
}
```

The second call is the one that matters. `redact` genuinely missed all three identifiers, because
none of them match on a word boundary or a strict pattern. The gate caught them anyway, and the
model never saw the request.

A runnable version lives in [`example/guard-an-llm-call.js`](example/guard-an-llm-call.js), and
the test suite runs it, so it cannot rot.

## API

```js
import { redact, scan, assertClean, guard, createGate, loadConfig } from "redaction-gate";

redact(text, config);        // -> redacted string. Precise. Allowed to miss.
scan(text, config);          // -> findings[]. Paranoid. Never throws.
assertClean(text, config);   // -> text, or throws RedactionRefusal.
guard(fn, { config });       // -> wrapped fn. Redacts, checks, refuses before calling fn.
createGate(config);          // -> the four above, bound to one resolved config.
loadConfig([paths], extra);  // -> config merged from JSON files.
```

A finding is `{ class, detector, term, index, length, line, column }`. `term` is the only place
the library surfaces sensitive text, because a developer fixing a refusal needs to see what
tripped it. Set `revealTerms: false` to reduce every finding to a class and a position.

### Middleware around a non-string payload

```js
const ask = guard(client.messages.create, {
  config,
  get: (payload) => payload.messages[0].content,
  set: (payload, text) => ({ ...payload, messages: [{ ...payload.messages[0], content: text }] }),
});
```

## Configuration

Detectors are data. A roster is a JSON file you own, and a new pattern is a new record rather
than a code change.

```json
{
  "roster": [
    { "class": "client", "match": ["Northwind Robotics", "Northwind"] },
    { "class": "person", "match": ["Ada Vasquez"] },
    { "class": "custom", "as": "[project]", "match": ["Bluebird"] }
  ],
  "allowDomains": ["example.com"],
  "allow": ["Support"],
  "patterns": { "phone": false },
  "minScanLength": 4,
  "extraPatterns": [
    { "name": "employee_id", "class": "employee", "as": "[employee-id]", "redact": ["EMP-\\d{6}"] }
  ],
  "audit": { "enabled": true, "path": "logs/compliance.jsonl", "label": "outbound-llm" }
}
```

| key | what it does |
|---|---|
| `roster` | Named entities you control. Each entry redacts on word boundaries and is scanned as a flattened substring. |
| `allowDomains` | Hosts that are yours and are fine to keep. |
| `allow` | Literal strings that never become a finding. |
| `patterns` | Switch a built-in off by name. |
| `extraPatterns` | Your own detectors, as records. `redact` is required, `scan` is optional and takes `{ pattern, flags, via }`. |
| `minScanLength` | How short a roster term can be before the paranoid half stops substring-matching it. Default 4. |
| `revealTerms` | `false` keeps matched values out of error messages. |
| `warnOnly` | See below. |
| `audit` | The compliance log. |

Built-in detectors are `secret`, `email`, `domain`, `residue`, `phone` and `honorific`. The
`residue` one is scan only. It looks for a placeholder welded into an address, which is the
signature of a half redaction.

## Refusal is the default

`warnOnly: true` exists for one situation, which is onboarding an existing corpus where the first
run produces hundreds of findings and you need the shape of the problem before you can fix any of
it.

It is deliberately hard to reach by accident.

- It takes a literal `true`. A truthy string from an env var will not disarm the gate.
- It silences nothing. Every finding still goes to `onWarn` or to stderr.
- The audit record says `outcome: "warned"`, so a log review can find every place it was used.
- On the CLI, `--warn-only` on its own still exits 2. Going quiet takes `--exit-zero` as well.

There is no configuration that produces a clean exit and an empty log while findings exist.

## CLI

```
redaction-gate check  [file...]   scan for identifiers, exit 2 if any survive
redaction-gate redact [file...]   print redacted text, exit 2 if any survive

  --config <path>   JSON config, repeatable
  --audit <path>    append a compliance record for this run
  --label <name>    tag the record with a context
  --json            machine-readable report on stdout
  --no-reveal       report class and position without the matched value
  --warn-only       report and continue, still exits 2
  --exit-zero       with --warn-only, exit 0 as well
```

Exit codes are 0 clean, 1 usage error, 2 refused. `redact` writes nothing to stdout when it
refuses, because a pipeline that prints unclean text and then sets an exit code has already
handed the text to whatever was reading.

As a pre-commit hook.

```bash
#!/bin/sh
git diff --cached --name-only --diff-filter=ACM \
  | xargs -r npx redaction-gate check --config .redaction.json --audit .git/redaction.jsonl
```

## Compliance log

Append-only JSONL, one record per gate event. The row it serves names SOC 2 and GDPR. This is not
a certification and does not claim to be one. It produces the artifact those reviews ask for,
which is a durable record that a control ran, what it found, and what happened next.

```json
{"v":1,"ts":"2026-09-02T17:26:13.093Z","lib":"redaction-gate@0.1.0","event":"guard",
 "label":"outbound-llm","outcome":"refused",
 "input":{"sha256":"f633d434…","bytes":107},
 "output":{"sha256":"cf8bc76c…","bytes":106},
 "redacted":{"client":1},
 "survivors":[{"class":"client","line":1,"column":20,"length":18}],
 "policy":{"sha256":"1753a127…","warnOnly":false}}
```

Hashes and counts and positions go in. Values never do. A log that contains the leaked value has
moved the leak rather than recorded it. `policy.sha256` hashes the resolved ruleset, so a
reviewer can prove which configuration was in force on a given day without the log carrying your
roster.

## What this does not do

Read this part. The failure mode of a security tool is a team that trusts it further than it goes.

- **It is not a classifier.** No model, no NER. Person and company names come from a roster you
  maintain. A name nobody wrote down will not be found, with one narrow exception for honorifics.
- **It over-flags, on purpose.** The paranoid half is allowed to be wrong in one direction only.
  A ten digit Unix timestamp reads as a phone number. `Dr. Martens` reads as a person. A roster
  entry of `Acme` will fire inside `acmegraph`. The remedy is `allow`, `allowDomains` and
  `minScanLength`, not a looser gate.
- **It is not reversible.** Placeholders are typed, not keyed. There is no un-redact and no way to
  recover the original from the output.
- **It is ASCII and English leaning.** Unicode homoglyph substitution, right-to-left scripts and
  non-Latin names are not normalized. A roster term written in Cyrillic lookalikes will pass.
- **It does not parse formats.** It takes text. A PDF, an image, a zip or a base64 blob is opaque
  to it, and text inside a nested encoding is not decoded before scanning.
- **It has no rate or size strategy.** Everything is synchronous and in memory. It is not built
  for streaming a multi-gigabyte file.
- **Credit card numbers, national IDs and IPs are not detected.** They were out of scope for the
  first version. Add them through `extraPatterns` if you need them.
- **It is not a certification.** See the compliance log section.

## Development

```bash
npm test           # node --test, no install, no network
```

The suite has one rule worth knowing about. Every detector needs a true positive, a near miss
that must not trip, and a case where the redactor misses and the gate catches it anyway. That
third class lives in [`test/adversarial.test.js`](test/adversarial.test.js) and it is the whole
thesis. A detector without one is decorative, because nothing proves its check can fail.

Design notes, including the extraction history and the compliance record shape, are in
[SPEC.md](SPEC.md).

## License

MIT
