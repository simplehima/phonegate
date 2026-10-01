// Confirms the review screenshots exist and are 1280x800 PNGs. Prints SCREENS-OK.
import { readFileSync, existsSync } from "node:fs";
const dir = "../../.impeccable/review";
const names = ["status", "pair-sas", "recovery"].flatMap((n) => ["light", "dark"].map((t) => `companion-${n}-${t}.png`));
const bad = [];
for (const n of names) {
  const p = `${dir}/${n}`;
  if (!existsSync(p)) { bad.push(`${n} missing`); continue; }
  const b = readFileSync(p);
  const png = b.subarray(1, 4).toString() === "PNG";
  const w = b.readUInt32BE(16), h = b.readUInt32BE(20);
  if (!png || w !== 1280 || h !== 800) bad.push(`${n} is ${w}x${h}`);
}
if (bad.length) { console.error(bad.join("\n")); process.exit(1); }
console.log(`${names.length} screenshots at 1280x800`);
console.log("SCREENS-OK");
