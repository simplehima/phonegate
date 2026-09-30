#!/usr/bin/env node
// Checks the Inno Setup output manifest (OutputManifestFile) lists every file the setup must carry.
// Usage: node tools/check-installer-manifest.mjs dist/installer/PhoneGate-Setup-manifest.txt
import { readFileSync } from "node:fs";

const REQUIRED = [
  "phonegate-agent.exe",
  "phonegate_cp.dll",
  "PhoneGate.exe",
  "LICENSE.txt",
  "install.ps1",
  "uninstall.ps1",
  "PhoneGate.apk",
  "PhoneGate.apk.json",
  "How to install on your phone.txt",
];
let text;
try {
  text = readFileSync(process.argv[2], "utf8");
} catch (e) {
  console.error(`INSTALLER: FAIL (cannot read manifest: ${e.message})`);
  process.exit(1);
}
// Manifest lines are tab-separated; the source file path is one of the columns.
const lower = text.toLowerCase();
const missing = REQUIRED.filter((f) => !lower.includes(f.toLowerCase()));
if (missing.length) {
  console.error(`INSTALLER: FAIL (missing from setup: ${missing.join(", ")})`);
  process.exit(1);
}
console.log(`setup carries all ${REQUIRED.length} required files`);
console.log("INSTALLER: OK");
