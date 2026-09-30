#!/usr/bin/env node
// Scans git-tracked (and new, non-ignored) files for embedded secrets (Constitution I, SC-006).
//   node tools/scan-secrets.mjs              scan the repository
//   node tools/scan-secrets.mjs --self-test  prove the detector fires on a known-positive fixture
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const RULES = [
  ["private key block", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_\-]{35}\b/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ["Firebase service account", /"type"\s*:\s*"service_account"/],
  ["generic secret assignment", /\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*["'][A-Za-z0-9+/_\-]{24,}["']/i],
  ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ["Android keystore password", /storePassword\s*[=:]\s*["'][^"'$]{6,}["']/],
];

// Public, non-secret material that legitimately looks like keys: protocol test vectors use fixed
// throwaway scalars, and the Google attestation roots are public certificates.
const ALLOW_PATHS = [/^protocol\/vectors\//, /^crates\/pg-core\/roots\/.*\.pem$/, /^tools\/fixtures\/secret-positive\.b64$/];
const BINARY = /\.(png|jpe?g|webp|ico|ttf|otf|woff2?|jar|dll|exe|so|apk|keystore|jks|gif|pdf)$/i;

function scanText(name, text) {
  const hits = [];
  text.split(/\r?\n/).forEach((line, i) => {
    for (const [rule, re] of RULES) if (re.test(line)) hits.push(`${name}:${i + 1}: ${rule}`);
  });
  return hits;
}

if (process.argv.includes("--self-test")) {
  // Stored base64-encoded so the fake tokens are not flagged by hosting-side secret scanning.
  const fixture = Buffer.from(readFileSync(new URL("./fixtures/secret-positive.b64", import.meta.url), "utf8"), "base64").toString("utf8");
  const hits = scanText("fixture", fixture);
  const expected = RULES.length;
  const rulesHit = new Set(hits.map((h) => h.split(": ").pop()));
  if (rulesHit.size !== expected) {
    console.error(`SELF-TEST: FAIL (detected ${rulesHit.size}/${expected} rules)`);
    process.exit(1);
  }
  console.log(`SELF-TEST: OK (${rulesHit.size}/${expected} rules fire on the positive fixture)`);
  process.exit(0);
}

const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], { encoding: "utf8" })
  .split("\n")
  .filter(Boolean)
  .filter((f) => !BINARY.test(f) && !ALLOW_PATHS.some((re) => re.test(f)));
let hits = [];
for (const f of files) {
  let text;
  try {
    text = readFileSync(f, "utf8");
  } catch {
    continue;
  }
  hits = hits.concat(scanText(f, text));
}
console.log(`scanned ${files.length} files`);
if (hits.length) {
  for (const h of hits) console.error(`  ${h}`);
  console.error(`SECRET-SCAN: FOUND ${hits.length}`);
  process.exit(1);
}
console.log("SECRET-SCAN: CLEAN");
