#!/usr/bin/env node
// Aggregates JUnit XML results (Gradle test output) and requires >0 tests, 0 failures, 0 errors,
// and that the shared protocol-vector suite actually ran.
// Usage: node tools/check-junit.mjs <results-dir> [required-suite-substring]
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
const required = process.argv[3] ?? "ProtocolVectorsTest";
if (!dir) {
  console.error("usage: check-junit.mjs <dir> [suite]");
  process.exit(2);
}
let files;
try {
  files = readdirSync(dir).filter((f) => f.endsWith(".xml"));
} catch (e) {
  console.error(`JUNIT: FAIL (cannot read ${dir}: ${e.message})`);
  process.exit(1);
}
let tests = 0, failures = 0, errors = 0, skipped = 0;
let sawRequired = false;
for (const f of files) {
  const x = readFileSync(join(dir, f), "utf8");
  const m = x.match(/<testsuite\b[^>]*>/);
  if (!m) continue;
  const attr = (n) => Number((m[0].match(new RegExp(`\\b${n}="(\\d+)"`)) ?? [0, 0])[1]);
  tests += attr("tests");
  failures += attr("failures");
  errors += attr("errors");
  skipped += attr("skipped");
  if (m[0].includes(required) && attr("tests") > 0) sawRequired = true;
}
console.log(`suites=${files.length} tests=${tests} failures=${failures} errors=${errors} skipped=${skipped} ${required}=${sawRequired ? "ran" : "MISSING"}`);
if (tests === 0 || failures || errors || !sawRequired) {
  console.error("JUNIT: FAIL");
  process.exit(1);
}
console.log("JUNIT: OK");
