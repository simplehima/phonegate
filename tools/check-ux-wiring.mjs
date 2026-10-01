// Static check that the 0.3.0 user-facing pieces are wired up, so they cannot quietly regress:
// loading indicators, the Settings pages, the overlay permission, and the tapjacking guard that
// goes with it. Visual correctness is checked separately (tools/check-android-demo.mjs).
//
//   node tools/check-ux-wiring.mjs --self-test   every rule must FAIL on empty input
//   node tools/check-ux-wiring.mjs               prints "UX-WIRING: OK" when every rule holds

import { existsSync, readFileSync } from "node:fs";

const A = "android/app/src/main/";
const J = A + "java/dev/phonegate/";
const C = "windows/companion/";

/** A rule: a file, and a predicate over its text. */
const rules = [
  [A + "AndroidManifest.xml", "declares SYSTEM_ALERT_WINDOW", (t) => t.includes("android.permission.SYSTEM_ALERT_WINDOW")],
  [J + "MainActivity.kt", "asks for the overlay permission", (t) => t.includes("canDrawOverlays") && t.includes("ACTION_MANAGE_OVERLAY_PERMISSION")],
  [J + "MainActivity.kt", "has a Settings tab", (t) => t.includes("SettingsScreen(") && t.includes('label = { Text("Settings") }')],
  [J + "MainActivity.kt", "tracks busy PCs (turn off, unpair)", (t) => t.includes("busyPcs[") && t.includes("Unpairing...")],
  [J + "ui/approve/ApproveActivity.kt", "ignores touches while obscured", (t) => /filterTouchesWhenObscured\s*=\s*true/.test(t)],
  [J + "ui/pcs/PcsScreen.kt", "shows loading indicators", (t) => t.includes("CircularProgressIndicator") && t.includes("LinearProgressIndicator")],
  [J + "ui/pcs/PcsScreen.kt", "keeps action buttons on one line", (t) => (t.match(/maxLines = 1/g) ?? []).length >= 4],
  [J + "ui/pcs/PcsScreen.kt", "collapses and expands cards", (t) => t.includes("PcListLogic.isExpanded") && t.includes("Collapse all")],
  [J + "ui/settings/SettingsScreen.kt", "has About, Updates, Permissions and licence", (t) => ["About PhoneGate", "Check now", "Permissions", "Apache License 2.0", "Help and licence"].every((x) => t.includes(x))],
  [J + "net/UpdateChecker.kt", "has fixed project links", (t) => ["REPO_URL", "RELEASES_URL", "LICENSE_URL", "SECURITY_URL"].every((x) => t.includes(x))],
  [C + "ui/src/agent.ts", "tracks in-flight requests", (t) => t.includes("export function onBusy") && t.includes("setInFlight")],
  [C + "ui/src/main.ts", "shows the app-wide loading bar", (t) => t.includes("busy-bar") && t.includes("onBusy(")],
  [C + "ui/src/views/settings.ts", "has About, Check now and links", (t) => ["About PhoneGate", "Check now", "appInfo", "openLink"].every((x) => t.includes(x))],
  [C + "src-tauri/src/lib.rs", "opens only named links and reports the version", (t) => t.includes("pub fn link_url") && t.includes("fn app_info") && t.includes("link_not_allowed")],
  ["NOTICE", "names the licence and third-party notices", (t) => t.includes("Apache License, Version 2.0") && t.includes("SIL Open Font License")],
  ["LICENSE", "is the Apache 2.0 text", (t) => t.includes("Apache License") && t.includes("Version 2.0")],
];

if (process.argv.includes("--self-test")) {
  // A rule that passes on empty input could never fail, so it proves nothing.
  const weak = rules.filter(([, , ok]) => ok(""));
  if (weak.length) {
    console.log("SELF-TEST: FAIL (these rules pass on empty input)");
    for (const [f, d] of weak) console.log(`  ${f}: ${d}`);
    process.exit(1);
  }
  console.log(`SELF-TEST: OK (${rules.length}/${rules.length} rules fail on empty input)`);
}

const failures = [];
for (const [file, desc, ok] of rules) {
  if (!existsSync(file)) {
    failures.push(`${file}: missing (${desc})`);
    continue;
  }
  if (!ok(readFileSync(file, "utf8"))) failures.push(`${file}: does not ${desc}`);
}
if (failures.length) {
  console.log("UX-WIRING: FAIL");
  for (const f of failures) console.log("  - " + f);
  process.exit(1);
}
console.log("UX-WIRING: OK");
