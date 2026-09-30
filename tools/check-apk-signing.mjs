#!/usr/bin/env node
// Verifies an APK's signature with apksigner and requires a release certificate (never the
// Android debug key). Prints the APK and signer SHA-256 fingerprints.
// Usage: node tools/check-apk-signing.mjs <apk> [--json]
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const apk = process.argv[2];
const asJson = process.argv.includes("--json");
const fail = (m) => {
  console.error(`APK-SIGNING: FAIL (${m})`);
  process.exit(1);
};
if (!apk || !existsSync(apk)) fail(`no APK at ${apk}`);

function apksignerJar() {
  const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || join(process.env.LOCALAPPDATA ?? "", "Android", "Sdk");
  const bt = join(sdk, "build-tools");
  if (!existsSync(bt)) fail(`Android build-tools not found under ${sdk}`);
  const versions = readdirSync(bt).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
  for (const v of versions) {
    const p = join(bt, v, "lib", "apksigner.jar");
    if (existsSync(p)) return p;
  }
  fail("apksigner.jar not found in build-tools");
}

const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, "bin", process.platform === "win32" ? "java.exe" : "java") : "java";
let out;
try {
  out = execFileSync(java, ["-jar", apksignerJar(), "verify", "--verbose", "--print-certs", apk], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
} catch (e) {
  fail(`signature does not verify: ${String(e.stderr || e.stdout || e.message).trim().split(/\r?\n/)[0]}`);
}
const dn = (out.match(/(?:Signer #1|V[\d.]+ Signer):? certificate DN: (.+)/) ?? [])[1]?.trim() ?? "";
const signer = (out.match(/(?:Signer #1|V[\d.]+ Signer):? certificate SHA-256 digest: ([0-9a-f]+)/i) ?? [])[1]?.toLowerCase() ?? "";
const v2 = /Verified using v2 scheme \(APK Signature Scheme v2\): true/.test(out) || /Verified using v3 scheme.*: true/.test(out);
if (!dn || !signer) fail("could not read the signing certificate");
if (/Android Debug/i.test(dn)) fail(`signed with the Android DEBUG key (${dn})`);
if (!v2) fail("APK is not signed with APK Signature Scheme v2/v3");
const sha256 = createHash("sha256").update(readFileSync(apk)).digest("hex");
if (asJson) {
  console.log(JSON.stringify({ sha256, signer_sha256: signer, signer_dn: dn }));
} else {
  console.log(`signer: ${dn}`);
  console.log(`signer SHA-256: ${signer}`);
  console.log(`APK SHA-256:    ${sha256}`);
}
console.log("APK-SIGNING: RELEASE");
