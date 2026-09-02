/**
 * Detectors are data, not code.
 *
 * Each record is a plain object with two halves that are never the same
 * expression. `redact` is precise, because its matches get substituted and the
 * surviving document has to stay usable. `scan` is paranoid, because its only
 * job is to make the gate capable of firing. A `scan` entry names the
 * normalizer it runs against, so it can look at a rewritten copy of the text
 * where the usual evasions have collapsed.
 *
 * Patterns are stored as source strings so the identical record can arrive from
 * a JSON config file. A caller adds a detector by adding a record, never by
 * editing this file.
 */

// TLDs only, and a short list on purpose. `.md`, `.js`, `.json` and `.mjs` are
// absent so a filename in a document can never be redacted as a company.
// The IANA reserved names are present because they are what fixtures and
// documentation should use.
export const TLDS = [
  "com", "org", "net", "io", "ai", "co", "dev", "app", "cloud", "tech",
  "info", "biz", "me", "us", "uk", "de", "fr", "ca", "au", "eu", "in",
  "edu", "gov", "mil", "health", "finance", "xyz", "sh", "so", "gg",
  "example", "test", "invalid", "localhost",
];

const TLD_GROUP = TLDS.join("|");

const HOST = `\\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:${TLD_GROUP})\\b`;
const EMAIL = `[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\\.)+(?:${TLD_GROUP})\\b`;

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const OCTET_QUAD = `\\b(?:${OCTET}\\.){3}${OCTET}\\b`;

// The one entropy rule in the library, and it is gated on an assignment rather
// than on entropy alone. A bare 40 character hex string is a git sha far more
// often than it is a credential, so the shape is not enough. The key word
// beside it is.
const SECRET_ASSIGNMENT =
  `(?<=(?:api[_-]?key|apikey|access[_-]?token|secret|token|password|passwd|bearer)["']?\\s*[:=]?\\s*["']?)` +
  `[A-Za-z0-9_\\-./+]{16,}`;

/** The built-in set. Order matters, most specific first. */
export const BUILT_IN_DETECTORS = [
  {
    name: "secret",
    class: "secret",
    as: "[secret]",
    redact: [
      { pattern: "\\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}", flags: "g" },
      { pattern: "\\bgh[pousr]_[A-Za-z0-9]{20,}", flags: "g" },
      { pattern: "\\bAKIA[0-9A-Z]{16}\\b", flags: "g" },
      { pattern: "\\bxox[baprs]-[A-Za-z0-9-]{10,}", flags: "g" },
      { pattern: "\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}", flags: "g" },
      { pattern: SECRET_ASSIGNMENT, flags: "gi" },
    ],
    // A key wrapped across two lines by an editor or an email client survives
    // every pattern above. Removing whitespace first is what catches it.
    scan: [
      { pattern: "\\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}", flags: "g", via: "despace" },
      { pattern: "\\bgh[pousr]_[A-Za-z0-9]{20,}", flags: "g", via: "despace" },
      { pattern: "\\bAKIA[0-9A-Z]{16}", flags: "g", via: "despace" },
      { pattern: "\\bxox[baprs]-[A-Za-z0-9-]{10,}", flags: "g", via: "despace" },
    ],
    // Note what is deliberately absent. The assignment rule is not run against
    // the despaced copy, because removing spaces glues ordinary prose into one
    // long run and "the token is a placeholder for something" would refuse
    // every document that discusses tokens. The paranoid half is allowed to
    // over-flag, but not to the point where a team switches the gate off.
  },
  {
    name: "email",
    class: "email",
    as: "[email]",
    redact: [{ pattern: EMAIL, flags: "gi" }],
    scan: [
      { pattern: EMAIL, flags: "gi", via: "deobfuscate" },
      // Both halves spelled out. Requiring both is what keeps "hosted at
      // northwind.example" from reading as an address.
      {
        pattern: `[A-Za-z0-9._%+-]+\\s+at\\s+[A-Za-z0-9-]+\\s+dot\\s+(?:${TLD_GROUP})\\b`,
        flags: "gi",
        via: "raw",
      },
    ],
  },
  {
    name: "domain",
    class: "domain",
    as: "[domain]",
    redact: [{ pattern: HOST, flags: "gi" }],
    scan: [{ pattern: HOST, flags: "gi", via: "deobfuscate" }],
  },
  {
    name: "phone",
    class: "phone",
    as: "[phone]",
    redact: [
      { pattern: "(?:\\+?\\d{1,3}[ .\\-]?)?(?:\\(\\d{3}\\)|\\d{3})[ .\\-]\\d{3}[ .\\-]\\d{4}\\b", flags: "g" },
    ],
    // Strip the separators and a phone number is a run of ten or eleven digits,
    // whatever exotic dash it was pasted with.
    scan: [{ pattern: "(?<!\\d)\\d{10,11}(?!\\d)", flags: "g", via: "digits" }],
  },
  {
    // An IP address is personal data under GDPR, which is why it is here and
    // why credit cards and national IDs are not. Octets are range checked, so
    // "2026.01.04" and "v1.22.3" cannot pass for one.
    name: "ipv4",
    class: "ip",
    as: "[ip]",
    redact: [{ pattern: OCTET_QUAD, flags: "g" }],
    // Same shape over the deobfuscated copy, which is what catches the defanged
    // form every security write-up uses so a reader cannot click it.
    scan: [{ pattern: OCTET_QUAD, flags: "g", via: "deobfuscate" }],
  },
  {
    // Scan only, and it looks for damage rather than for data. A placeholder
    // welded into an address means something was half redacted, and half
    // redacted text is the one shape no pattern can recognize afterwards. It
    // carries no redact half on purpose. There is nothing safe to substitute,
    // the caller has to look.
    name: "residue",
    class: "residue",
    as: "[residue]",
    redact: [],
    scan: [
      { pattern: "[A-Za-z0-9._%+-]+@\\[[a-z][a-z-]*\\]", flags: "g", via: "raw" },
      { pattern: "\\[[a-z][a-z-]*\\]@[A-Za-z0-9.-]+", flags: "g", via: "raw" },
      { pattern: `\\[[a-z][a-z-]*\\]\\.(?:${TLD_GROUP})\\b`, flags: "g", via: "raw" },
      // The same three shapes over the deobfuscated copy, because an address
      // written as "ada [at] northwind [dot] example" can be half claimed by a
      // roster term the same way a plain one can, and the strict email pattern
      // will never see either half.
      { pattern: "[A-Za-z0-9._%+-]+@\\[[a-z][a-z-]*\\]", flags: "g", via: "deobfuscate" },
      { pattern: "\\[[a-z][a-z-]*\\]@[A-Za-z0-9.-]+", flags: "g", via: "deobfuscate" },
      { pattern: `\\[[a-z][a-z-]*\\]\\.(?:${TLD_GROUP})\\b`, flags: "g", via: "deobfuscate" },
    ],
  },
  {
    name: "honorific",
    class: "person",
    as: "[person]",
    // Case sensitive and the period is required, so "MS Word" is untouched.
    redact: [{ pattern: "\\b(?:Mrs|Ms|Mr|Dr|Prof)\\.\\s+[A-Z][a-z]+(?:\\s+[A-Z][a-z]+)?", flags: "g" }],
    // The period and the space both become optional, which is what catches
    // "Dr Vasquez" and "Dr.Vasquez".
    scan: [{ pattern: "\\b(?:Mrs|Ms|Mr|Dr|Prof)\\.?\\s*[A-Z][a-z]{2,}", flags: "g", via: "raw" }],
  },
];

/** Placeholder used when a roster entry names a class nobody defined. */
export const placeholderFor = (cls) => `[${String(cls).replace(/[^a-z0-9_-]/gi, "") || "redacted"}]`;
