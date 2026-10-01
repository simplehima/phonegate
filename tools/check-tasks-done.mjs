#!/usr/bin/env node
// Requires every task line in a Spec Kit tasks.md to be checked. Usage: node tools/check-tasks-done.mjs <tasks.md>
import { readFileSync } from "node:fs";

const text = readFileSync(process.argv[2], "utf8");
const tasks = text.split(/\r?\n/).filter((l) => /^- \[[ xX]\] T\d{3}/.test(l));
const open = tasks.filter((l) => l.startsWith("- [ ]"));
console.log(`tasks=${tasks.length} checked=${tasks.length - open.length} open=${open.length}`);
for (const l of open) console.log(`  OPEN ${l.slice(6, 90)}`);
if (tasks.length === 0 || open.length) {
  console.error("TASKS: INCOMPLETE");
  process.exit(1);
}
console.log("TASKS: ALL CHECKED");
