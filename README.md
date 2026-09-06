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

A finding is `{ class, detector, index, length, line, column }`, and `term` is added only when
you ask for it.

**The value is withheld by default, because an exception crosses a boundary too.** A refusal
lands in Sentry, Datadog, CloudWatch or a CI transcript, and stopping an identifier reaching the
model and then writing it to the error tracker is the same leak through a door nobody watches.
Class, line, column and length are what you act on at 2am and they are always there. Set
`revealTerms: true` where the error stream is trusted, and let that choice be visible in the code
that made it.

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

The same shape works inline and in a file, and `roster` is an **array of entries** in both. Each
entry names its `class` and carries a `match` array. An object keyed by class is the shape most
people try first, and it is refused with a message that shows the array form.

```js
import { createGate } from "redaction-gate";

const gate = createGate({
  roster: [
    { class: "client", match: ["Northwind Robotics", "Northwind"] },
    { class: "person", match: ["Ada Vasquez"] },
    { class: "custom", as: "[project]", match: ["Bluebird"] },
  ],
  allowDomains: ["example.com"],
  audit: { enabled: true, path: "logs/compliance.jsonl" },
});
```

The identical config as a file, loaded with `loadConfig(["redaction-gate.config.json"])`.

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
| `revealTerms` | `true` puts the matched value in the error message, the error object and the CLI output. Off by default; takes a literal `true`. |
| `extraTlds` | Extra TLDs for the domain and email detectors, e.g. `["agency", "solutions"]`. Widens both halves of the gate together. |
| `warnOnly` | See below. |
| `audit` | The compliance log. |

Built-in detectors are `secret`, `email`, `domain`, `phone`, `ipv4`, `residue` and `honorific`.
The `residue` one is scan only. It looks for a placeholder welded into an address, which is the
signature of a half redaction.

### A wrong config refuses, it does not crash

Misconfiguration is the quietest way to end up unprotected, so the config is checked before
anything is merged and every problem is reported at once.

```
redaction-gate: REFUSING TO CONFIGURE. 1 problem in the config.
  roster  expected an array of roster entries, received an object with key "client"
          try  "roster": [{ "class": "client", "match": ["Northwind"] }]
Nothing was redacted and nothing was checked.
```

The error is a `RedactionConfigError` with `code: "REDACTION_CONFIG_INVALID"` and a `problems`
array. An unknown top-level key is refused rather than ignored, because a setting that quietly
does nothing is how you end up believing you configured something you did not. On the CLI, a
`--config` path that does not exist is an error for the same reason.

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
  --reveal          include the matched value. Off by default
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

### Keyed hashes, if you need correlation resistance

An unkeyed digest is not reversible for anything with real entropy, so the plain log does not
leak content. What it does allow is **correlation**: the same input always produces the same
digest, so someone holding the log can confirm whether a specific known record passed through,
and can link records across separate logs and across time. For a short, guessable input a
candidate can simply be hashed and compared.

```json
{ "audit": { "enabled": true, "path": "logs/compliance.jsonl", "hmacKey": "${REDACTION_AUDIT_KEY}" } }
```

The digest fields become `hmac-sha256`, so a reader can tell which scheme wrote which record.

**The cost, stated plainly.** A keyed digest can only be re-derived by someone holding that key.
Rotate it and every record written before the rotation stops being checkable — you keep the
audit trail, you lose the ability to prove what any earlier line hashed. Unkeyed remains the
default for exactly that reason: it is verifiable by anyone holding the input, and for most
compliance uses that is worth more than correlation resistance. `policy.sha256` stays unkeyed
either way, because it fingerprints a configuration rather than a person.

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
- **It is synchronous and in memory.** Pattern runs are length capped so a large or hostile input
  cannot make it hang, and the suite holds the full detector set to a two second budget on
  deliberately pathological inputs. It is still not built for streaming a multi-gigabyte file.
- **Credit card numbers and national IDs are not detected.** IPv4 is, because an IP address is
  personal data under GDPR. The other two are country-specific and checksum-shaped, and a
  half-right implementation of them is worse than an honest gap. Add them through
  `extraPatterns` if you need them.
- **IPv6 is not detected.** Only IPv4.
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
