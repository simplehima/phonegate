// Source hygiene: no TODO/FIXME placeholders, no em/en dashes in UI strings, and the preview
// harness exists only in the debug source set.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const src = join(root, "app/src");
const files = [];
(function walk(d) { for (const f of readdirSync(d)) { const p = join(d, f); statSync(p).isDirectory() ? walk(p) : files.push(p); } })(src);
let bad = [];
for (const f of files.filter((f) => /\.(kt|xml)$/.test(f))) {
  const t = readFileSync(f, "utf8"); const r = relative(root, f).split(sep).join("/");
  if (/\b(TODO|FIXME|XXX)\b/.test(t)) bad.push("placeholder in " + r);
  if (/[—–]/.test(t)) bad.push("em/en dash in " + r);
  if (/PreviewActivity/.test(t) && !r.startsWith("app/src/debug/")) bad.push("preview referenced outside debug: " + r);
}
if (!files.some((f) => relative(root, f).split(sep).join("/") === "app/src/debug/java/dev/phonegate/preview/PreviewActivity.kt")) bad.push("PreviewActivity missing from debug");
console.log(JSON.stringify({ scanned: files.length, problems: bad }));
if (bad.length) process.exit(1);
console.log("SOURCE OK");
