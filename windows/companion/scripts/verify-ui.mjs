// Static contract checks for the companion UI. Prints UI-CONTRACT-OK only if every check passes.
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const check = (ok, msg) => ok || failures.push(msg);

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const src = walk(join(root, "ui/src")).filter((f) => /\.(ts|css)$/.test(f));
const all = src.map((f) => [f, readFileSync(f, "utf8")]);
const agentTs = readFileSync(join(root, "ui/src/agent.ts"), "utf8");
const libRs = readFileSync(join(root, "src-tauri/src/lib.rs"), "utf8");

// 1. every control-pipe op from the contract is typed in agent.ts and allowlisted in Rust
const ops = ["status", "settings_set", "pair_start", "pair_poll", "pair_decide", "recovery_generate", "recovery_confirm", "enable", "disable_begin", "disable_wait", "disable_recovery", "unpair", "history", "security_check",
  // feature 002: docs/specs/002-tamper-hardening/contracts/agent-control-additions.md
  "health", "bitlocker_status", "bitlocker_prepare", "bitlocker_enable", "netlogon_status", "netlogon_set", "netlogon_unblock_begin", "netlogon_unblock_wait", "netlogon_unblock_recovery"];
for (const op of ops) {
  check(agentTs.includes(`op: "${op}"`), `agent.ts does not send op ${op}`);
  const opsBlock = libRs.slice(libRs.indexOf("const OPS"), libRs.indexOf("pub fn is_allowed_op"));
  check(new RegExp(String.raw`\(\s*"${op}",`).test(opsBlock), `lib.rs allowlist lacks ${op}`);
}
// every agent.* wrapper is used by some view
const wrappers = [...agentTs.matchAll(/^  (\w+): \(/gm)].map((m) => m[1]);
const views = all.filter(([f]) => !f.endsWith("agent.ts")).map(([, t]) => t).join("\n");
for (const w of wrappers) check(views.includes(`agent.${w}(`), `agent.${w} is never called by the UI`);
check(wrappers.length === ops.length, `expected ${ops.length} agent wrappers, found ${wrappers.length}`);

// 2. no em dash or en dash anywhere in UI source or index.html
for (const [f, t] of [...all, [join(root, "ui/index.html"), readFileSync(join(root, "ui/index.html"), "utf8")]]) {
  check(!/[\u2013\u2014]/.test(t), `dash character in ${f}`);
}

// 3. fonts and licenses shipped
for (const f of ["fonts/Archivo.ttf", "fonts/JetBrainsMono.ttf", "licenses/Archivo-OFL.txt", "licenses/JetBrainsMono-OFL.txt", "licenses/Lucide-LICENSE.txt"]) {
  const p = join(root, "ui/public", f);
  check(existsSync(p) && statSync(p).size > 1000, `missing or empty ${f}`);
}

// 4. CSP has no remote origins and no unsafe-inline/eval; no shell/fs plugins
const conf = JSON.parse(readFileSync(join(root, "src-tauri/tauri.conf.json"), "utf8"));
const csp = conf.app.security.csp;
check(typeof csp === "string" && csp.includes("default-src 'self'"), "CSP missing default-src 'self'");
check(!/https?:\/\/(?!ipc\.localhost)/.test(csp), "CSP allows a remote origin");
check(!/unsafe-(inline|eval)/.test(csp), "CSP allows unsafe-inline or unsafe-eval");
check(conf.build.frontendDist === "../dist", "frontendDist is not ../dist");
const cargo = readFileSync(join(root, "src-tauri/Cargo.toml"), "utf8");
check(!/tauri-plugin-(shell|fs)/.test(cargo), "shell/fs plugin present");
const caps = JSON.parse(readFileSync(join(root, "src-tauri/capabilities/default.json"), "utf8"));
check(JSON.stringify(caps.permissions) === JSON.stringify(["allow-agent", "allow-qr-svg", "allow-apk-info", "allow-reveal-apk"]), "capabilities grant something other than the four app commands");
// feature 003: the APK commands take no input at all, so the UI can never choose a path
check(/async fn apk_info\(\) ->/.test(libRs) && /fn reveal_apk\(\) ->/.test(libRs), "apk_info / reveal_apk must take no parameters");
check(/invoke\("apk_info"\)/.test(agentTs) && /invoke\("reveal_apk"\)/.test(agentTs), "UI must invoke apk_info / reveal_apk without arguments");

// 5. manifest requires administrator and keeps Common Controls v6
const manifest = readFileSync(join(root, "src-tauri/phonegate.manifest"), "utf8");
check(manifest.includes('level="requireAdministrator"'), "manifest does not require administrator");
check(manifest.includes("Microsoft.Windows.Common-Controls"), "manifest lacks Common Controls v6");

// 6. mock only reachable outside Tauri and only in dev/preview builds; never in the shipped bundle
check(/import\("\.\/mock"\)/.test(agentTs) && agentTs.includes("inTauri"), "mock import not gated");
const importers = all.filter(([f, t]) => !f.endsWith("agent.ts") && /from "\.\.?\/mock"|import\("\.\.?\/mock"\)/.test(t));
check(importers.length === 0, `mock imported outside agent.ts: ${importers.map(([f]) => f)}`);
const distAssets = join(root, "dist/assets");
if (existsSync(distAssets)) {
  const js = readdirSync(distAssets).filter((f) => f.endsWith(".js")).map((f) => readFileSync(join(distAssets, f), "utf8")).join("\n");
  check(!js.includes("Pixel 8 Pro") && !js.includes("maya.okafor"), "production bundle contains preview mock data");
} else failures.push("dist/ missing: run npm run build first");

// 7. no innerHTML with data (text is always textContent)
for (const [f, t] of all) check(!/\.innerHTML\s*=/.test(t) && !/insertAdjacentHTML/.test(t), `innerHTML used in ${f}`);
// 9. the BitLocker PIN is never persisted or logged, and only goes to bitlocker_enable
const hard = readFileSync(join(root, "ui/src/views/hardening.ts"), "utf8");
check(!/localStorage|sessionStorage|indexedDB|console\./.test(hard), "hardening.ts touches storage or the console");
check((hard.match(/agent\.bitlockerEnable\(pin,/g) ?? []).length === 1, "PIN must be sent only via bitlockerEnable");
check(/type: "password",\s*inputmode: "numeric"/.test(hard), "PIN inputs must be masked numeric fields");
// 8. no emoji
for (const [f, t] of all) check(!/\p{Extended_Pictographic}/u.test(t), `emoji in ${f}`);

if (failures.length) {
  console.error(failures.map((f) => `FAIL: ${f}`).join("\n"));
  process.exit(1);
}
console.log(`checked ${ops.length} ops, ${all.length} source files`);
console.log("UI-CONTRACT-OK");
