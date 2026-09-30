// Runs the JVM unit tests and verifies the JUnit XML results (counts are measured, not assumed).
import { execSync } from "node:child_process";
import { readdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const dir = join(root, "app/build/test-results/testDebugUnitTest");
rmSync(dir, { recursive: true, force: true });
execSync(process.platform === "win32" ? "\"" + join(root, "gradlew.bat") + "\" testDebugUnitTest --rerun-tasks --console=plain" : "./gradlew testDebugUnitTest --rerun-tasks --console=plain", { cwd: root, stdio: "inherit" });
let tests = 0, fails = 0, skipped = 0; const suites = {};
for (const f of readdirSync(dir).filter((f) => f.endsWith(".xml"))) {
  const x = readFileSync(join(dir, f), "utf8");
  const m = x.match(/<testsuite name="([^"]+)" tests="(\d+)" skipped="(\d+)" failures="(\d+)" errors="(\d+)"/);
  if (!m) continue;
  suites[m[1]] = +m[2]; tests += +m[2]; skipped += +m[3]; fails += +m[4] + +m[5];
}
console.log(JSON.stringify({ suites, tests, skipped, failures: fails }));
if (!(suites["dev.phonegate.protocol.ProtocolVectorsTest"] > 0)) { console.log("ProtocolVectorsTest missing"); process.exit(1); }
if (fails !== 0 || skipped !== 0 || tests === 0) process.exit(1);
console.log("TESTS OK");
