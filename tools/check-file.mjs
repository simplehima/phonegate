#!/usr/bin/env node
// Requires a non-trivial file (size > 1 KiB) to exist. Usage: node tools/check-file.mjs <path>
import { statSync } from "node:fs";

const p = process.argv[2];
try {
  const s = statSync(p);
  if (!s.isFile() || s.size <= 1024) throw new Error(`size ${s.size}`);
  console.log(`${p}: ${s.size} bytes`);
  console.log("FILE-PRESENT");
} catch (e) {
  console.error(`FILE-MISSING (${p}: ${e.message})`);
  process.exit(1);
}
