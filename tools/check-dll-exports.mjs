#!/usr/bin/env node
// Verifies a PE DLL exports the COM entry points LogonUI needs, by parsing the export table.
// Usage: node tools/check-dll-exports.mjs <path-to-dll>
import { readFileSync } from "node:fs";

const REQUIRED = ["DllGetClassObject", "DllCanUnloadNow"];
const path = process.argv[2];
if (!path) {
  console.error("usage: check-dll-exports.mjs <dll>");
  process.exit(2);
}
const b = readFileSync(path);
const fail = (m) => {
  console.error(`DLL-EXPORTS: FAIL (${m})`);
  process.exit(1);
};
if (b.readUInt16LE(0) !== 0x5a4d) fail("not an MZ image");
const pe = b.readUInt32LE(0x3c);
if (b.readUInt32LE(pe) !== 0x00004550) fail("no PE signature");
const machine = b.readUInt16LE(pe + 4);
const nSections = b.readUInt16LE(pe + 6);
const optSize = b.readUInt16LE(pe + 20);
const characteristics = b.readUInt16LE(pe + 22);
if (!(characteristics & 0x2000)) fail("image is not a DLL");
const opt = pe + 24;
const magic = b.readUInt16LE(opt);
if (magic !== 0x20b) fail("not PE32+ (64-bit)");
if (machine !== 0x8664) fail(`unexpected machine 0x${machine.toString(16)}`);
const exportRva = b.readUInt32LE(opt + 112);
if (!exportRva) fail("no export directory");
const secTable = opt + optSize;
const sections = [];
for (let i = 0; i < nSections; i++) {
  const s = secTable + i * 40;
  sections.push({ va: b.readUInt32LE(s + 12), vsize: b.readUInt32LE(s + 8), raw: b.readUInt32LE(s + 20) });
}
const off = (rva) => {
  const s = sections.find((x) => rva >= x.va && rva < x.va + Math.max(x.vsize, 1));
  if (!s) fail(`rva 0x${rva.toString(16)} outside sections`);
  return rva - s.va + s.raw;
};
const ed = off(exportRva);
const nNames = b.readUInt32LE(ed + 24);
const namesRva = b.readUInt32LE(ed + 32);
const names = [];
for (let i = 0; i < nNames; i++) {
  let p = off(b.readUInt32LE(off(namesRva) + i * 4));
  let s = "";
  while (b[p] !== 0) s += String.fromCharCode(b[p++]);
  names.push(s);
}
const missing = REQUIRED.filter((r) => !names.includes(r));
if (missing.length) fail(`missing exports: ${missing.join(", ")} (found: ${names.join(", ")})`);
console.log(`exports: ${names.join(", ")}`);
console.log("DLL-EXPORTS: OK");
