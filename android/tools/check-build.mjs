// Builds the debug APK and runs lint; passes only with an APK present and zero lint errors.
import { execSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const apk = join(root, "app/build/outputs/apk/debug/app-debug.apk");
const lint = join(root, "app/build/reports/lint-results-debug.xml");
rmSync(apk, { force: true }); rmSync(lint, { force: true });
execSync(process.platform === "win32" ? "\"" + join(root, "gradlew.bat") + "\" assembleDebug lintDebug --console=plain" : "./gradlew assembleDebug lintDebug --console=plain", { cwd: root, stdio: "inherit" });
if (!existsSync(apk)) { console.log("APK missing"); process.exit(1); }
const x = readFileSync(lint, "utf8");
const errors = (x.match(/severity="(Error|Fatal)"/g) || []).length;
const warnings = (x.match(/severity="Warning"/g) || []).length;
console.log(JSON.stringify({ apk, lintErrors: errors, lintWarnings: warnings }));
if (errors !== 0) process.exit(1);
console.log("BUILD AND LINT OK");
