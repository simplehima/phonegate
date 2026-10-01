// Fails unless every place that carries the app version agrees with the expected one.
// Usage: node tools/check-versions.mjs 0.3.0   ->   "VERSIONS: 0.3.0" on success.

import { readFileSync } from "node:fs";

const expected = process.argv[2];
if (!expected || !/^\d+\.\d+\.\d+$/.test(expected)) {
  console.log("usage: node tools/check-versions.mjs <x.y.z>");
  process.exit(2);
}
const read = (p) => readFileSync(p, "utf8");
const found = {};

// Workspace version: the first `version = "..."` after [workspace.package].
const root = read("Cargo.toml");
found["Cargo.toml (workspace)"] = root.slice(root.indexOf("[workspace.package]")).match(/^version\s*=\s*"([^"]+)"/m)?.[1];
found["companion Cargo.toml"] = read("windows/companion/src-tauri/Cargo.toml").match(/^version\s*=\s*"([^"]+)"/m)?.[1];
found["tauri.conf.json"] = JSON.parse(read("windows/companion/src-tauri/tauri.conf.json")).version;
found["Android versionName"] = read("android/app/build.gradle.kts").match(/versionName\s*=\s*"([^"]+)"/)?.[1];

// versionCode must be a positive integer that grows; the release script owns the exact value.
const code = Number(read("android/app/build.gradle.kts").match(/versionCode\s*=\s*(\d+)/)?.[1]);

const bad = Object.entries(found).filter(([, v]) => v !== expected);
if (bad.length || !(code >= 1)) {
  console.log("VERSIONS: MISMATCH");
  for (const [k, v] of bad) console.log(`  ${k}: ${v ?? "not found"} (expected ${expected})`);
  if (!(code >= 1)) console.log("  Android versionCode not found");
  process.exit(1);
}
console.log(`VERSIONS: ${expected}`);
