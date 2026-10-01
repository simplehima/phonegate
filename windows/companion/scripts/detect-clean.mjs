// Runs the impeccable detector on the UI source and fails on any finding.
import { execSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const bin = "C:/Users/azab/.claude/skills/impeccable/scripts/impeccable.cmd";
let out;
try {
  // .cmd shims need a shell on Windows; the command is a fixed string built from known paths.
  out = execSync(`"${bin}" detect --json "${join(root, "ui")}"`, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
} catch (e) {
  out = e.stdout ?? "";
}
const findings = JSON.parse(out.trim() || "null");
if (!Array.isArray(findings)) {
  console.error("detector produced no JSON");
  process.exit(1);
}
if (findings.length) {
  for (const f of findings) console.error(`${f.antipattern}: ${f.file}:${f.line} ${f.snippet}`);
  process.exit(1);
}
console.log("DETECT-CLEAN");
