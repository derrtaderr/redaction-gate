#!/usr/bin/env node
/**
 * redaction-gate CLI.
 *
 * Exit codes are the product here, because the point of a CLI version is a CI
 * job or a pre-commit hook that fails.
 *
 *   0  clean, or redacted and clean
 *   1  usage or I/O error
 *   2  REFUSED. Something survived redaction.
 */
import { existsSync, readFileSync } from "node:fs";
import { loadConfig } from "../src/config.js";
import { redactWithCounts } from "../src/redact.js";
import { scan, reportWarning } from "../src/gate.js";
import { buildRecord, writeRecord, VERSION } from "../src/audit.js";

const USAGE = `redaction-gate ${VERSION}

  redaction-gate check  [file...]   scan for identifiers, exit 2 if any survive
  redaction-gate redact [file...]   print redacted text, exit 2 if any survive

Reads stdin when no file is given.

  --config <path>   JSON config, repeatable, later files win on scalars
  --audit <path>    append a compliance record for this run
  --label <name>    tag the compliance record with a context
  --json            report as JSON on stdout
  --reveal          include the matched value in the report. Off by default
  --warn-only       report and continue instead of refusing, still exits 2
  --exit-zero       with --warn-only, exit 0 as well. Two flags, on purpose
  --help, --version

Exit codes: 0 clean, 1 usage error, 2 refused.
`;

const FLAGS_WITH_VALUES = new Set(["--config", "--audit", "--label"]);
const BOOLEAN_FLAGS = new Set(["--json", "--reveal", "--warn-only", "--exit-zero", "--help", "--version"]);

function parseArgs(argv) {
  const opts = { command: null, files: [], configs: [], audit: null, label: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (FLAGS_WITH_VALUES.has(arg)) {
      const value = argv[++i];
      if (value === undefined) throw new Error(`${arg} needs a value`);
      if (arg === "--config") opts.configs.push(value);
      if (arg === "--audit") opts.audit = value;
      if (arg === "--label") opts.label = value;
    } else if (BOOLEAN_FLAGS.has(arg)) {
      opts[arg.replace(/^--/, "").replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`unknown flag ${arg}`);
    } else if (!opts.command) {
      opts.command = arg;
    } else {
      opts.files.push(arg);
    }
  }
  return opts;
}

function readStdin() {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function formatFindings(findings, source, reveal) {
  return findings
    .map((f) => {
      const where = `${source}:${f.line}:${f.column}`;
      return reveal
        ? `  ${where}  ${f.class}  ${JSON.stringify(f.term)}`
        : `  ${where}  ${f.class}  (${f.length} chars)`;
    })
    .join("\n");
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`redaction-gate: ${err.message}\n\n${USAGE}`);
    return 1;
  }
  if (opts.help || !opts.command) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (opts.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (opts.command !== "check" && opts.command !== "redact") {
    process.stderr.write(`redaction-gate: unknown command "${opts.command}"\n\n${USAGE}`);
    return 1;
  }

  // A typo in --config would otherwise load an empty roster, find nothing, and
  // exit 0 looking exactly like a clean run. That is the silent pass this
  // library exists to remove, so an explicitly named config has to be there.
  for (const path of opts.configs) {
    if (!existsSync(path)) {
      process.stderr.write(`redaction-gate: config not found at ${path}\n`);
      return 1;
    }
  }

  let cfg;
  try {
    cfg = loadConfig(opts.configs.length ? opts.configs : undefined, {
      warnOnly: opts.warnOnly === true,
      revealTerms: opts.reveal === true,
      audit: { enabled: Boolean(opts.audit), path: opts.audit ?? null, label: opts.label ?? null },
    });
  } catch (err) {
    process.stderr.write(`redaction-gate: ${err.message}\n`);
    return 1;
  }

  const inputs = [];
  try {
    if (opts.files.length) {
      for (const file of opts.files) inputs.push({ source: file, text: readFileSync(file, "utf8") });
    } else if (process.stdin.isTTY) {
      // Nothing to read and nothing piped in. Blocking on an interactive
      // terminal here would look like a hang, and a hang gets killed and
      // retried without the gate.
      process.stderr.write(`redaction-gate: no files given and nothing on stdin\n\n${USAGE}`);
      return 1;
    } else {
      inputs.push({ source: "stdin", text: readStdin() });
    }
  } catch (err) {
    process.stderr.write(`redaction-gate: ${err.message}\n`);
    return 1;
  }

  const report = { ok: true, files: [], findings: [] };
  let refused = false;
  const out = [];

  for (const { source, text } of inputs) {
    const { text: redacted, counts } = redactWithCounts(text, cfg);
    const findings = scan(redacted, cfg);
    writeRecord(
      buildRecord({ event: opts.command, label: opts.label, input: text, output: redacted, counts, findings, cfg }),
      cfg
    );
    report.files.push({ source, redacted: counts, findings: findings.length });
    report.findings.push(...findings.map((f) => ({ ...f, source })));
    if (findings.length) {
      refused = true;
      if (!opts.json) {
        process.stderr.write(
          `redaction-gate: ${cfg.warnOnly ? "WARNING" : "REFUSING"}. ${findings.length} identifier(s) survived redaction in ${source}.\n` +
            `${formatFindings(findings, source, cfg.revealTerms)}\n`
        );
      }
    } else if (opts.command === "redact") {
      out.push(redacted);
    }
  }

  if (opts.command === "redact" && !refused) process.stdout.write(out.join(""));
  if (opts.json) {
    report.ok = !refused;
    if (!cfg.revealTerms) report.findings = report.findings.map(({ term, ...rest }) => rest);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }

  if (!refused) return 0;
  if (cfg.warnOnly && opts.exitZero) return 0;
  return 2;
}

process.exitCode = main(process.argv.slice(2));
