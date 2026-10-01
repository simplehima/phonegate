// Checks the phone app's list and settings screens on a running emulator/device by starting the
// debug-only PreviewActivity (synthetic data, no keys) and reading the UI tree with uiautomator.
// Needs: adb on PATH or in %LOCALAPPDATA%\Android\Sdk\platform-tools, one device online, and a
// debug APK built with `gradlew assembleDebug`.
//
// Prints "ANDROID-UI: OK" only when every assertion below holds, otherwise lists what failed.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

const adb = process.env.ADB ?? (process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, "Android", "Sdk", "platform-tools", "adb.exe") : "adb");
const apk = "android/app/build/outputs/apk/debug/app-debug.apk";
const failures = [];
const check = (ok, msg) => {
  if (!ok) failures.push(msg);
};
const run = (...args) => execFileSync(adb, args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (!existsSync(apk)) {
  console.log(`FAIL: ${apk} missing; run gradlew assembleDebug first`);
  process.exit(1);
}
const devices = run("devices").split("\n").slice(1).filter((l) => /\tdevice\b/.test(l));
if (devices.length === 0) {
  console.log("FAIL: no emulator or device online (start an AVD first)");
  process.exit(1);
}

// Wake the screen and drop the keyguard so the app is on top.
run("shell", "input", "keyevent", "224");
run("shell", "wm", "dismiss-keyguard");
try {
  run("install", "-r", apk);
} catch (e) {
  // A build signed with another key is already there (emulator only): replace it.
  run("uninstall", "dev.phonegate");
  run("install", "-r", apk);
}

/** Starts a preview screen and returns the parsed UI tree. */
async function dump(screen) {
  run("shell", "am", "start", "-S", "-n", "dev.phonegate/dev.phonegate.preview.PreviewActivity", "--es", "screen", screen);
  await sleep(3000);
  return read();
}
function read() {
  // uiautomator returns an empty tree while a screen is still starting; retry briefly.
  let xml = "";
  for (let i = 0; i < 6 && !xml.includes("<node"); i++) {
    try {
      run("shell", "uiautomator", "dump", "/sdcard/pg-ui.xml");
      xml = run("exec-out", "cat", "/sdcard/pg-ui.xml");
    } catch {
      /* try again */
    }
    if (!xml.includes("<node")) execFileSync(process.execPath, ["-e", "setTimeout(()=>{},1000)"]);
  }
  const nodes = [];
  for (const m of xml.matchAll(/<node\b[^>]*>/g)) {
    const t = m[0];
    const attr = (n) => (t.match(new RegExp(`\\b${n}="([^"]*)"`)) ?? [])[1] ?? "";
    const b = attr("bounds").match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
    if (!b) continue;
    nodes.push({ text: attr("text"), desc: attr("content-desc"), l: +b[1], t: +b[2], r: +b[3], b: +b[4] });
  }
  return nodes;
}
const withText = (nodes, text) => nodes.filter((n) => n.text === text || n.desc === text);
const h = (n) => n.b - n.t;
/** Open cards show a "Paired" row; collapsed ones do not. */
const openCards = (nodes) => nodes.filter((n) => /^paired$/i.test(n.text)).length;

// ------------------------------------------------------------------ four PCs
let ui = await dump("pcs_many");
check(withText(ui, "4 PCs, 1 needs attention").length > 0, "list header '4 PCs, 1 needs attention' is missing");
check(withText(ui, "Expand all").length > 0, "'Expand all' is missing");
// Only the PC that needs attention starts open, so exactly one card shows actions.
check(withText(ui, "Unpair").length === 1, `expected 1 expanded card (1 Unpair), found ${withText(ui, "Unpair").length}`);
const openBefore = openCards(ui);
check(openBefore === 1, `expected exactly 1 open card before expanding, found ${openBefore}`);
for (const label of ["Unpair", "Turn off protection", "Rename"]) {
  for (const n of withText(ui, label)) check(h(n) <= 160, `'${label}' is ${h(n)}px tall, so it has wrapped onto more than one line`);
}
check(withText(ui, "Sample Studio PC").length > 0, "the PC needing attention is not shown");

// Expand all, then the busy and connecting indicators must be visible somewhere on screen.
const expand = withText(ui, "Expand all")[0];
if (expand) {
  run("shell", "input", "tap", String(Math.round((expand.l + expand.r) / 2)), String(Math.round((expand.t + expand.b) / 2)));
  await sleep(1200);
  ui = read();
  check(withText(ui, "Collapse all").length > 0, "'Collapse all' did not replace 'Expand all' after tapping it");
  check(openCards(ui) > openBefore, `expanding all did not open more cards (${openBefore} -> ${openCards(ui)})`);
  for (const label of ["Unpair", "Turn off protection", "Rename"]) {
    for (const n of withText(ui, label)) check(h(n) <= 160, `after expanding, '${label}' is ${h(n)}px tall (wrapped)`);
  }
}
// The Laptop card is busy and connecting; scroll until its indicators are in view.
let sawBusy = withText(ui, "Waiting for your fingerprint...").length > 0;
let sawConnecting = withText(ui, "Connecting to the relay").some((n) => n.desc === "Connecting to the relay");
for (let i = 0; i < 4 && !(sawBusy && sawConnecting); i++) {
  run("shell", "input", "swipe", "540", "1700", "540", "700", "300");
  await sleep(700);
  ui = read();
  sawBusy ||= withText(ui, "Waiting for your fingerprint...").length > 0;
  sawConnecting ||= withText(ui, "Connecting to the relay").some((n) => n.desc === "Connecting to the relay");
}
check(sawBusy, "the busy indicator text 'Waiting for your fingerprint...' never appeared");
check(sawConnecting, "the connecting progress bar never appeared");

// ------------------------------------------------------------------ settings
ui = await dump("settings");
check(withText(ui, "Settings").length > 0, "Settings title is missing");
check(withText(ui, "0.3.0 (build 4)").length > 0, "version line '0.3.0 (build 4)' is missing");
check(withText(ui, "Apache License 2.0").length > 0, "licence line is missing");
check(withText(ui, "Checking GitHub...").length > 0 || ui.some((n) => n.text.includes("Checking GitHub")), "update 'Checking GitHub...' indicator is missing");
run("shell", "input", "swipe", "540", "1700", "540", "500", "300");
await sleep(700);
ui = read();
check(ui.some((n) => n.text === "Show over other apps"), "'Show over other apps' permission row is missing");
check(withText(ui, "Allow").length >= 1, "an 'Allow' button for the missing permission is missing");

if (failures.length) {
  console.log("ANDROID-UI: FAIL");
  for (const f of failures) console.log("  - " + f);
  process.exit(1);
}
console.log("ANDROID-UI: OK");
