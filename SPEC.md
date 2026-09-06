# redaction-gate spec

A redaction library that refuses the write when redaction misses.

Status: v0.1.0. Node >= 20. Zero runtime dependencies.

## 1. The problem this exists for

Every team that pipes internal text into an LLM, a log sink, an analytics event or an outbound
API eventually writes a redaction step. Almost all of those steps share one property. When the
redactor fails to match something, the text goes out anyway, unredacted, and nobody finds out
until the incident review.

The failure is not that redactors miss. Redactors will always miss, because a redactor that
matched aggressively enough to never miss would destroy the clean text it is supposed to
preserve. The failure is that a miss is indistinguishable from a clean pass. Both look like
success from the outside.

This library makes them different. A miss is loud, it is a thrown refusal, and the wrapped call
does not run.

## 2. Origin. What was extracted and what was generalized

The capability shipped 2026-09-01 inside a private internal script that harvested working
sessions into a searchable record. That script had to write files that could never contain a
client or prospect name, and a warning was not good enough, because the file would still be on
disk. So the write path ended in a hard gate.

Extracted from that implementation, essentially verbatim in behaviour:

- Word-boundary substitution for named entities loaded from a roster.
- A separate normalizing detector that lowercases and strips every non-alphanumeric character,
  then substring-matches, so a glued or punctuated form of a roster name is still caught.
- A minimum term length on the normalizing detector, so short roster entries do not turn every
  document into a refusal.
- Refusal by throwing, with the surviving terms named in the message.
- A domain matcher restricted to a known TLD list, so file extensions such as `.md` and `.mjs`
  are never mistaken for company domains.

Generalized for this library:

- The roster moves from one hardcoded file to a config object with named entity classes, so a
  stranger points it at their own data.
- Pattern detectors are added as data rather than code. Emails, domains, phone numbers, tokens
  and honorific person names ship built in, each one a record with a precise pattern and a set
  of loose scan patterns, and a caller can add their own record without touching the source.
- Typed placeholders replace the single substitution string, so redacted text stays readable and
  structurally intact.

Added, with no counterpart in the original:

- A middleware wrapper, `guard`, that puts the gate in front of any function.
- An append-only compliance log with a hashed source and no source text.
- A CLI with exit codes for CI and pre-commit hooks.
- A `warnOnly` escape hatch, described in section 6.
- A `residue` detector, which the original did not need because it had one entity class. Once
  roster terms and structured patterns coexist, a roster term can be substituted inside an
  address and break it open, and the fragment that survives matches nothing. See section 5.

## 3. The asymmetry, and why it is the whole design

The first version of the original implementation used one matcher for both jobs. Redact and check
shared a regex. That is the obvious design and it is worthless, because the check can only look
for the thing the redactor already replaced. Every run passed. A verification that cannot return
a failure is not a verification, it is a decoration.

So the two halves are deliberately different, and they are different in a specific direction.

**The redactor is precise.** It substitutes on word boundaries and on strict, well formed
patterns. Precision is what it owes the caller, because its output is text that has to keep
working downstream. A redactor that mangles `index.js` into `index[domain]` has broken the
document it was asked to protect.

**The detector is paranoid.** It runs the precise patterns and then runs looser ones over
normalized copies of the text. It lowercases and strips punctuation, so `northwind_robotics`
and `NorthwindRobotics` both reduce to the same string as `Northwind Robotics`. It reverses
common obfuscations, so `jane [at] northwind [dot] com` reduces to an address the strict email
pattern matches. It strips dashes and brackets between digits, so a phone number pasted out of a
PDF with a Unicode minus is still a run of ten digits.

The detector is allowed to be wrong in one direction only. It may flag something clean, and the
cost of that is a refusal the caller has to look at. It may not miss, and the cost of that is a
leak nobody looks at.

Every detector record therefore carries two fields, and they are never the same expression.

## 4. Public surface

```js
redact(text, config)          // -> redacted string
scan(text, config)            // -> findings[], never throws
assertClean(text, config)     // -> text, or throws RedactionRefusal
guard(fn, options)            // -> wrapped fn that redacts, asserts, then calls fn
createGate(config)            // -> { redact, scan, assertClean, guard } bound to one config
loadConfig(paths, overrides)  // -> merged config from JSON files
```

A finding is `{ class, term, index, line, column, length, detector }`. `term` is the matched
text. It is present because a developer fixing a refusal needs to know what tripped it, and it
is the one place in the library where sensitive text is surfaced. It never reaches the
compliance log, and it is **withheld by default** — see section 10.1. `revealTerms: true` adds
it back, on all three of the surfaces a refusal reaches.

## 5. Detectors that ship

| class | precise pattern catches | loose scan additionally catches |
|---|---|---|
| `client`, `person`, `custom` | roster terms on word boundaries | glued, joined and punctuated forms of the same terms |
| `email` | `local@domain.tld` | `name [at] domain [dot] tld` and its variants |
| `domain` | `host.tld` on a known TLD list | defanged forms such as `host[.]tld` |
| `phone` | separated 10 or 11 digit forms with an optional country code | any 10 or 11 digit run once dashes, brackets and dots are removed |
| `secret` | known prefixes such as `sk-`, `ghp_`, `AKIA`, `xox`, JWTs, and assignment-gated high entropy strings | the same shapes once whitespace, including a line wrap, is removed |
| `honorific` | `Dr. Ada Vasquez` with the period and space | `Dr Vasquez` and `Dr.Vasquez` |
| `ipv4` | dotted quads with range-checked octets | the defanged `203[.]0[.]113[.]42` form |
| `residue` | nothing, it has no redact half | a placeholder welded into an address, in raw or deobfuscated form |

Roster entries and extra patterns are supplied as config, so the detector set is data. A user
adds an employee id format by adding a record, not by opening a source file.

Ordering is load bearing. Structured patterns run before roster terms, so an address or a
hostname is claimed whole. A roster term running first substitutes inside the token, breaks it
open, and leaves a fragment such as `ada@[client].example` that no pattern can see any more.
`residue` is the backstop for the cases where that still happens, and it has no redact half
because there is nothing safe to substitute into damaged text.

The `secret` assignment rule deliberately does NOT run against the despaced copy. Removing
spaces glues ordinary prose into one long run, and "the token is a placeholder for something"
would then refuse every document that discusses tokens. The paranoid half is allowed to
over-flag, but not to the point where a team switches the gate off.

## 6. Refusal posture

Refusal is the default and it is the reason the library exists.

`assertClean` throws. `guard` throws before the wrapped function is called, so an LLM request
that would have carried a client name is never issued. The CLI exits 2.

`warnOnly: true` exists for one situation, which is onboarding an existing codebase where the
first run will produce hundreds of findings and the team needs to see the shape of the problem
before they can fix it. It is deliberately awkward to reach and it cannot be reached by accident.

- It is never the default, at any level.
- It must be set explicitly in config or passed as `--warn-only` on the CLI.
- It does not silence anything. Every finding is still written to stderr and to the compliance
  log, with `outcome: "warned"` so a log review can find every place the gate was disarmed.
- The CLI still exits non-zero under `--warn-only` unless `--exit-zero` is also given, which is
  two explicit flags to get a silent pass.

There is no config value that produces a clean exit and an empty log while findings exist.

## 7. Compliance log

Append-only JSONL, one record per gate event, each written in a single append so a record is
never split. The row this build serves names SOC 2 and GDPR. This library is not
a certification and does not claim one. It produces the artifact those reviews ask for, which is
a durable record showing that a control ran, what it found, and what the system did next, with
no copy of the sensitive data inside the record.

```json
{
  "v": 1,
  "ts": "2026-09-02T17:04:11.238Z",
  "lib": "redaction-gate@0.1.0",
  "event": "guard",
  "label": "outbound-llm",
  "outcome": "refused",
  "input": { "sha256": "9f2c...", "bytes": 1423 },
  "output": { "sha256": "41ba...", "bytes": 1390 },
  "redacted": { "client": 1, "email": 2 },
  "survivors": [ { "class": "client", "line": 12, "column": 4, "length": 18 } ],
  "policy": { "sha256": "77de...", "warnOnly": false }
}
```

Field rules, all binding.

- `input.sha256` and `output.sha256` are hashes of the text. The text itself is never written.
- `survivors` carries class and position only. No matched term, ever. A position is enough to
  find the line in the source system, and the source system is where the sensitive value is
  allowed to live.
- `redacted` is a count per class, which is what an auditor asks for and what a leak report
  cannot be reconstructed from.
- `policy.sha256` hashes the normalized config, so a reviewer can prove which ruleset was in
  force on a given day without the log carrying the roster.
- `outcome` is one of `clean`, `redacted`, `refused`, `warned`.

## 7b. Config refusal

Misconfiguration is the quietest way to end up unprotected, so the same posture applies to the
config itself. Every source is validated before anything is merged, which means a bad config can
never be half applied, and every problem is reported at once the way findings are.

```
redaction-gate: REFUSING TO CONFIGURE. 1 problem in the config.
  roster  expected an array of roster entries, received an object with key "client"
          try  "roster": [{ "class": "client", "match": ["Northwind"] }]
Nothing was redacted and nothing was checked.
```

Binding rules.

- An unknown top-level key is a refusal, not a shrug. A setting that quietly does nothing is how
  a caller ends up believing they configured something they did not.
- `warnOnly` and `revealTerms` refuse a non-boolean, and both require a literal `true`.
- `audit.hmacKey` refuses an empty string, which would be falsy and take the unkeyed path while
  the config plainly said a key was set.
- `extraTlds` refuses anything but an array of non-empty strings. Ignoring `warnOnly: "true"` left the caller
  believing the gate was disarmed when it was not, and the reverse misunderstanding is worse.
- The suggested fix is built from what the caller actually wrote, not from a static example.
- `loadConfig` validates per file, so the message names the file with the problem.

## 7c. Bounded matching

Every pattern run is length capped, and the caps are the real limits rather than arbitrary ones.
A DNS label is at most 63 characters, an email local part at most 64. Unbounded runs followed by
a required separator backtrack over every start position when the separator never arrives, and a
100k run of one character took 7.9 seconds to scan before this was fixed.

This is a refusal problem rather than a performance nicety. A gate that can be made to hang is a
gate that gets removed, and a removed gate protects nothing. The suite holds the full detector
set to a two second budget on inputs designed to be pathological.

## 8. Non-goals

- Not a classifier. There is no model, no entropy scoring beyond one narrow assignment-gated
  rule, and no attempt to recognize a person's name from its shape alone. Names come from a
  roster the caller controls.
- Not reversible. Placeholders are typed, not keyed. There is no un-redact.
- Not a database or file scanner. It takes text.
- Not certification. See section 7.
- Credit cards and national IDs are absent on purpose. They are country-specific and
  checksum-shaped, and a half-right implementation reads as coverage while providing none. IPv4
  is present because an IP address is personal data under GDPR. IPv6 is not.

## 9. Acceptance

- Clean clone, `npm test`, green, no install step and no network.
- Every detector has a true positive test, a near-miss test that must not trip, and a test where
  the redactor misses and the detector catches. The third class is the thesis. If it is missing
  for a detector, that detector is decorative.
- No vault content, no real client names, no real domains beyond IANA reserved examples.

---

## 10. Egress pass 01 (2026-09-06)

Three changes from external review of the shipped 0.1.0, confirmed against the source before
any code was written. One is a security defect in this library's own behaviour, one is an
ergonomics gap that lets a user build a weaker gate by accident, and one is a compliance
property the log does not currently have.

### 10.1 The refusal must not print what it refused to let out

`config.js:19` and the `RedactionRefusal` constructor at `gate.js:13` both default
`revealTerms` to `true`, and the message interpolates `JSON.stringify(f.term)`. A library whose
entire claim is that identifiers do not cross the process boundary currently writes them to
three places outside the process, by default:

1. **The exception message.** Straight into whatever catches it.
2. **`error.findings`.** `gate.js:26` attaches the findings array to the error, and each finding
   carries `term` when `revealTerms` is on. Error reporters serialise custom properties, so the
   value travels even when nothing logs `err.message`.
3. **CLI stdout and stderr.** `bin/redaction-gate.js:117` defaults the same way and `:161`
   formats terms into its output. In CI that lands in build logs, which are typically more
   widely readable and longer retained than application logs.

So the failure mode is precise and ironic: the gate successfully stops `Ada Vasquez` reaching
the model, and then sends `Ada Vasquez` to Sentry.

The compliance log already has the right rule and has always had it — `audit.js` writes class,
line, column and length into `survivors` and never the value, regardless of this setting. The
care went into the artifact that was consciously designed as a compliance surface and skipped
the one that was "just an exception."

**Decision: `revealTerms` defaults to `false` on all three surfaces.** A developer opts in
locally and the opt-in is visible in the code or the command they wrote. This is a breaking
change to error output and ships alone, in its own commit, for that reason.

### 10.2 `extraTlds`

`detectors.js:20` holds 34 TLDs, deliberately short so a filename such as `index.js` or
`notes.md` can never be mangled into a company. That reasoning stands and the list stays
conservative. But `.agency`, `.company`, `.solutions` and `.consulting` are all absent, and a
company operating on one of them has no obvious way to say so.

An escape hatch already exists: `extraPatterns` (`config.js:304`) compiles both `redact` and
`scan` with full `via` support, so a wider domain detector is already expressible. The problem
is that expressing it correctly means hand-writing the HOST regex and remembering
`via: "deobfuscate"` on the scan half. Forget that and the custom TLD is redacted but not
paranoid-scanned, which silently removes the asymmetry that is the entire product.

So `extraTlds` adds no capability. It is a way to stop a user building a weaker gate by
accident, and it feeds the existing HOST and EMAIL patterns so both halves stay in step.

**Rejected: an aggressive `domainMode` that matches any label after a dot.** That reopens the
filename mangling the short list exists to prevent, and destructive redaction is what gets a
tool switched off in a week.

### 10.3 Optional keyed audit hashing

`audit.js:20` hashes with unkeyed SHA-256. The reason to offer HMAC is not confidentiality —
anything with real entropy is not recoverable from a digest — it is **correlation**. An
identical input always produces an identical digest, so a party holding the log can confirm
whether a specific known record passed through, and can link records across separate logs and
across time. For a low-entropy input a candidate can simply be hashed and compared.

**Decision: opt-in, via `audit.hmacKey`.** Unkeyed stays the default, because it is verifiable
by anyone holding the input and that is a real property for a compliance log.

**The cost, which is documented rather than hidden.** A keyed digest can only be re-derived by
someone holding that key. Rotate it and every record written before the rotation stops being
checkable. The algorithm name in the record changes to `hmac-sha256` so a reader can tell which
records were written under which scheme without guessing.

### Out of scope

First-party OpenAI / Anthropic / AI SDK wrappers, a GitHub Action, and an MCP egress example.
All are separate packages and a separate decision about what goes public. The core stays tiny,
synchronous, deterministic and dependency-free.

### The mutation check for egress pass 01

Every guard this pass added was reverted in turn against the full suite.

| Mutation | Failures | Caught by |
|---|---|---|
| `RedactionRefusal` defaults to revealing again | 1 | the hand-built refusal test |
| The CLI reveals by default again | 2 | the default-output test and the `--reveal` opt-in test |
| `expandTlds` ignores `extraTlds` | 2 | the both-halves test and the policy-hash test |
| `hashText` ignores the key | 2 | both keyed-digest tests |
| An empty `audit.hmacKey` is accepted | 1 | the empty-key refusal test |
| `resolveConfig` uses `!== false` for `revealTerms` | **0** | nothing, deliberately — see below |

Two of these caught nothing on the first run and both were defects in the pass rather than in
the tests.

**The constructor default was genuinely uncovered.** Every call site inside the library passes
`revealTerms` explicitly, so the default is reachable only from outside — and `RedactionRefusal`
is a public export, so a custom gate or a rethrow can construct one. A direct test now covers it.

**The `=== true` in `resolveConfig` catches nothing on purpose.** Validation refuses a
non-boolean `revealTerms` before that line runs, so the value is always a real boolean there and
strict equality is equivalent to the loose form. The line stays as a second line of defense and
the comment says so, rather than claiming a protection that validation is already providing.
Same distinction the retry loop in `webhook-engine` records for its doubled attempt bound: a
redundancy worth keeping and a redundancy worth believing in are different things, and only the
comment can tell them apart.

**And one defect no mutation could have found.** The worked example printed `person undefined`
for every finding once the term was withheld. The example is run by the suite, and its test
asserts that nothing leaks — which stayed true, because withholding does not leak. Absence of a
leak and presence of a usable report are two different claims and only the first was being made.
It was found by running the example and reading the output.
