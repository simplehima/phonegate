// PREVIEW ONLY. An in-memory stand-in for the agent so the UI can be viewed and screenshotted in
// a plain browser. agent.ts imports this module only when not running inside Tauri, and the app
// shows a "Preview data" banner whenever it is active. Nothing here is real.

import type { AttemptRecord, Request } from "./agent";

export type Scene = "protected" | "new";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function scene(): Scene {
  const p = new URLSearchParams(location.search).get("preview");
  return p === "new" ? "new" : "protected";
}

function code(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(26));
  const s = Array.from(bytes, (b) => ALPHABET[b % 32]).join("");
  return s.match(/.{1,4}/g)!.join("-");
}

const norm = (c: string) =>
  c
    .toUpperCase()
    .replace(/[-\s]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");

const MIN = 60_000;
const now = Date.now();

function sampleHistory(): AttemptRecord[] {
  const pc = "Office desktop";
  const rows: [number, string, string, string][] = [
    [6 * MIN, "maya.okafor", "unlock", "approved"],
    [48 * MIN, "maya.okafor", "unlock", "approved"],
    [3 * 60 * MIN + 12 * MIN, "maya.okafor", "remote", "not_me"],
    [5 * 60 * MIN + 2 * MIN, "maya.okafor", "logon", "approved"],
    [9 * 60 * MIN + 41 * MIN, "maya.okafor", "unlock", "wrong_number"],
    [22 * 60 * MIN, "maya.okafor", "unlock", "expired"],
    [26 * 60 * MIN + 7 * MIN, "maya.okafor", "unlock", "denied"],
    [30 * 60 * MIN, "maya.okafor", "unlock", "offline_code"],
    [2 * 24 * 60 * MIN + 17 * MIN, "maya.okafor", "logon", "recovery_code"],
    [2 * 24 * 60 * MIN + 80 * MIN, "", "settings", "protection_enabled"],
    [2 * 24 * 60 * MIN + 95 * MIN, "", "pairing", "paired:Pixel 8 Pro"],
  ];
  return rows.map(([ago, account, scenario, outcome]) => ({ at: now - ago, pc_name: pc, account, scenario, outcome, req_id: null }));
}

const s = scene();
const state = {
  pc_name: s === "new" ? "DESKTOP-7Q2M4KD" : "Office desktop",
  relay_url: s === "new" ? "" : "https://relay.okafor.dev",
  relay: (s === "new" ? "down" : "up") as "up" | "down",
  key_backend: s === "new" ? "software" : "tpm",
  software_ack: false,
  paired: s !== "new",
  phone_name: s === "new" ? null : ("Pixel 8 Pro" as string | null),
  attestation: s === "new" ? null : ({ status: "verified" } as { status: "verified" } | { status: "unverified"; reason: string } | null),
  enforce: s !== "new",
  codes: s === "new" ? ([] as string[]) : Array.from({ length: 9 }, code),
  recovery_confirmed: s !== "new",
  history: s === "new" ? ([] as AttemptRecord[]) : sampleHistory(),
  pairing: null as null | { startedAt: number; expires: number; state: "waiting" | "confirm" | "completed" | "failed"; accepted: boolean; joined: boolean; error?: string },
  disable: null as null | { req: string; startedAt: number },
  failures: 0,
  // feature 002
  netlogonBlocked: false,
  passwordless: false,
  pwPending: null as null | { req: string; startedAt: number },
  netlogonUnblock: null as null | { req: string; startedAt: number },
  bitlocker: (s === "new" ? { supported: false, state: "off" } : { supported: true, state: "off" }) as { supported: boolean; state: string; percent?: number },
  recoveryPassword: null as string | null,
  seq: 18422,
};

const security =
  s === "new"
    ? { tpm: false, bitlocker: "unknown", secure_boot: null, rdp_enabled: false, passwordless_only: true, watchdog_present: false, safe_mode_registered: false }
    : { tpm: true, bitlocker: "off", secure_boot: true, rdp_enabled: true, passwordless_only: false, watchdog_present: true, safe_mode_registered: true };

const PHONE = "Pixel 8 Pro";
const UNVERIFIED = "the phone's approve key is not backed by secure hardware (software keystore)";

function log(scenario: string, outcome: string, account = "") {
  state.history.unshift({ at: Date.now(), pc_name: state.pc_name, account, scenario, outcome, req_id: null });
}

const fail = (err: string, detail: string) => ({ ok: false, err, detail });
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function mockTransport(req: Request): Promise<Record<string, unknown>> {
  await wait(120);
  switch (req.op) {
    case "status":
      return {
        ok: true,
        pc_name: state.pc_name,
        relay_url: state.relay_url,
        relay: state.relay,
        key_backend: state.key_backend,
        software_ack: state.software_ack,
        paired: state.paired,
        phone_name: state.phone_name,
        attestation: state.attestation,
        enforce: state.enforce,
        recovery_remaining: state.codes.length,
        recovery_confirmed: state.recovery_confirmed,
        pc_id: "k3VtQ2l0ZS1wcmV2aWV3LW9ubHk=",
      };
    case "security_check":
      return { ok: true, ...security, netlogon_blocked: state.netlogonBlocked };
    case "settings_set":
      if (state.enforce) return fail("refused", "invalid state: turn off protection before changing settings");
      if (req.relay_url !== undefined) {
        if (state.paired && req.relay_url !== state.relay_url) return fail("refused", "invalid state: unpair before changing the relay");
        state.relay_url = req.relay_url.replace(/\/+$/, "");
        state.relay = "up";
      }
      if (req.pc_name !== undefined) state.pc_name = req.pc_name.trim();
      if (req.software_ack !== undefined) state.software_ack = req.software_ack;
      return { ok: true };
    case "pair_start":
      if (state.enforce) return fail("refused", "invalid state: turn off protection before pairing a new phone");
      if (!state.relay_url) return fail("refused", "invalid state: set the relay server address first");
      if (state.key_backend === "software" && !state.software_ack) return fail("refused", "invalid state: this PC has no TPM; acknowledge software key protection first");
      state.pairing = { startedAt: Date.now(), expires: Date.now() + 5 * MIN, state: "waiting", accepted: false, joined: false };
      return { ok: true, qr: `phonegate://pair?v=1&r=${encodeURIComponent(state.relay_url)}&i=preview&k=preview&h=preview&n=${encodeURIComponent(state.pc_name)}`, expires_at: state.pairing.expires };
    case "pair_poll": {
      const p = state.pairing;
      if (!p) return { ok: true, state: "none", phone_confirmed: false };
      const t = Date.now() - p.startedAt;
      if (p.state === "waiting" && Date.now() >= p.expires) {
        p.state = "failed";
        p.error = "the QR code expired; start again";
      }
      if (p.state === "waiting" && t > 6000) {
        p.state = "confirm";
        p.joined = true;
      }
      const joined = p.joined;
      const phoneConfirmed = joined && t > 7000;
      if (p.state === "confirm" && p.accepted && phoneConfirmed) {
        p.state = "completed";
        state.paired = true;
        state.phone_name = PHONE;
        state.attestation = s === "new" ? { status: "unverified", reason: UNVERIFIED } : { status: "verified" };
        state.codes = [];
        state.recovery_confirmed = false;
        log("pairing", `paired:${PHONE}`);
      }
      return {
        ok: true,
        state: p.state,
        ...(joined ? { sas: "482913", phone_name: PHONE, attestation: s === "new" ? { status: "unverified", reason: UNVERIFIED } : { status: "verified" } } : {}),
        ...(p.error ? { error: p.error } : {}),
        phone_confirmed: phoneConfirmed,
      };
    }
    case "pair_decide": {
      const p = state.pairing;
      if (!p) return fail("refused", "invalid state: no pairing in progress");
      if (!req.accept) {
        p.state = "failed";
        p.error = "pairing cancelled";
        return { ok: true };
      }
      if (p.state !== "confirm") return fail("refused", "invalid state: phone has not joined yet");
      if (s === "new" && !req.accept_unverified) return fail("refused", "invalid state: phone key attestation could not be verified; explicit acceptance required");
      p.accepted = true;
      return { ok: true };
    }
    case "recovery_generate":
      if (state.enforce) return fail("refused", "invalid state: turn off protection before generating new recovery codes");
      if (!state.paired) return fail("refused", "invalid state: pair a phone first");
      state.codes = Array.from({ length: 10 }, code);
      state.recovery_confirmed = false;
      return { ok: true, codes: [...state.codes] };
    case "recovery_confirm": {
      const valid = state.codes.some((c) => norm(c) === norm(req.code));
      if (valid) state.recovery_confirmed = true;
      return { ok: true, valid };
    }
    case "enable":
      if (!state.paired) return fail("refused", "invalid state: not_paired");
      if (!state.recovery_confirmed) return fail("refused", "invalid state: recovery_unconfirmed");
      state.enforce = true;
      log("settings", "protection_enabled");
      return { ok: true };
    case "disable_begin":
      if (!state.enforce) return { ok: true, already_off: true };
      if (state.relay === "down") return { ok: false, err: "relay_down", detail: "" };
      state.disable = { req: "cHJldmlldy1kaXNhYmxlLTE=", startedAt: Date.now() };
      return { ok: true, req: state.disable.req, number: 47, expires_in_s: 60 };
    case "disable_wait": {
      await wait(Math.min(req.timeout_ms, 900));
      const d = state.disable;
      if (!d || d.req !== req.req) return { ok: true, state: "expired" };
      if (Date.now() - d.startedAt < 15000) return { ok: true, state: "pending" };
      state.disable = null;
      state.enforce = false;
      log("settings", "protection_disabled_by_phone");
      return { ok: true, state: "approved" };
    }
    case "disable_recovery": {
      const i = state.codes.findIndex((c) => norm(c) === norm(req.code));
      if (i < 0) {
        state.failures += 1;
        return { ok: true, valid: false, remaining: state.codes.length, attempts_left: 0, locked_s: state.failures >= 5 ? 60 : 0 };
      }
      state.codes.splice(i, 1);
      state.failures = 0;
      state.enforce = false;
      log("settings", "protection_disabled_by_recovery_code");
      return { ok: true, valid: true, remaining: state.codes.length, attempts_left: 0, locked_s: 0 };
    }
    case "unpair":
      if (state.enforce) return fail("refused", "invalid state: turn off protection before unpairing");
      state.paired = false;
      state.phone_name = null;
      state.attestation = null;
      state.codes = [];
      state.recovery_confirmed = false;
      log("settings", "unpaired");
      return { ok: true };
    case "history":
      return { ok: true, items: state.history.slice(0, req.limit) };

    // ---------------------------------------------------------------- feature 002
    case "health": {
      const sentAgo = s === "new" ? null : 2 * MIN + 14_000;
      return {
        ok: true,
        status: {
          seq: state.seq,
          at: Date.now() - (sentAgo ?? 0),
          enforce: state.enforce ? 1 : 0,
          cp_registered: 1,
          filter_registered: 1,
          files_intact: 1,
          watchdog_present: security.watchdog_present ? 1 : 0,
          bitlocker: state.bitlocker.state === "encrypting" ? "on-no-pin" : state.bitlocker.state,
          netlogon_blocked: state.netlogonBlocked ? 1 : 0,
          safe_mode: 0,
        },
        last_sent_at: sentAgo === null ? 0 : now - sentAgo,
        watchdog:
          s === "new"
            ? { present: false, last_run_at: null, last_repairs: [] }
            : {
                present: true,
                last_run_at: now - 3 * MIN - 40_000,
                last_repairs: [
                  { at: now - 3 * 24 * 60 * MIN - 47 * MIN, item: "credential_provider" },
                  { at: now - 11 * 24 * 60 * MIN - 5 * 60 * MIN, item: "service" },
                ],
              },
      };
    }
    case "bitlocker_status": {
      const b = state.bitlocker;
      if (b.state === "encrypting") b.percent = Math.min(99, (b.percent ?? 12) + 3);
      return { ok: true, supported: b.supported, state: b.state, ...(b.state === "encrypting" ? { percent: b.percent } : {}), ...(b.supported ? {} : { reason: "Windows 11 Home does not include BitLocker" }) };
    }
    case "bitlocker_prepare": {
      if (!state.bitlocker.supported) return fail("unsupported", "");
      const digits = crypto.getRandomValues(new Uint32Array(8));
      state.recoveryPassword = Array.from(digits, (d) => String(d % 1_000_000).padStart(6, "0")).join("-");
      return { ok: true, recovery_password: state.recoveryPassword, protector_id: "{9C2E0F41-6B7D-4B7B-A3E5-0D6A2C1B7F18}" };
    }
    case "bitlocker_enable": {
      if (!state.recoveryPassword) return fail("not_prepared", "");
      if (!/^\d{6,20}$/.test(req.pin)) return fail("bad_pin", "");
      if (req.recovery_last6 !== state.recoveryPassword.slice(-6)) return fail("recovery_mismatch", "");
      state.recoveryPassword = null;
      state.bitlocker = { supported: true, state: "encrypting", percent: 9 };
      return { ok: true, restart_required: true };
    }
    case "netlogon_status":
      return { ok: true, blocked: state.netlogonBlocked };
    case "netlogon_set":
      if (!req.block && state.enforce) return fail("approval_required", "");
      state.netlogonBlocked = req.block;
      log("settings", req.block ? "netlogon_blocked" : "netlogon_unblocked");
      return { ok: true };
    case "netlogon_unblock_begin":
      state.netlogonUnblock = { req: "cHJldmlldy1uZXRsb2dvbi0x", startedAt: Date.now() };
      return { ok: true, req: state.netlogonUnblock.req, number: 63, expires_in_s: 60 };
    case "netlogon_unblock_wait": {
      await wait(Math.min(req.timeout_ms, 900));
      const u = state.netlogonUnblock;
      if (!u || u.req !== req.req) return { ok: true, state: "expired" };
      if (Date.now() - u.startedAt < 15000) return { ok: true, state: "pending" };
      state.netlogonUnblock = null;
      state.netlogonBlocked = false;
      log("change-setting", "approved");
      return { ok: true, state: "approved" };
    }
    case "passwordless_status":
      return { ok: true, on: state.passwordless, account: state.passwordless ? "DESK\\maya" : undefined };
    case "passwordless_enable":
      state.pwPending = { req: "cHJldmlldy1wdy0x", startedAt: Date.now() };
      return { ok: true, req: state.pwPending.req, number: 27, expires_in_s: 60 };
    case "passwordless_enable_wait": {
      await wait(Math.min(req.timeout_ms, 900));
      const u = state.pwPending;
      if (!u || u.req !== req.req) return { ok: true, state: "expired" };
      if (Date.now() - u.startedAt < 12000) return { ok: true, state: "pending" };
      state.pwPending = null;
      state.passwordless = true;
      log("change-setting", "approved");
      return { ok: true, state: "approved" };
    }
    case "passwordless_disable":
      state.passwordless = false;
      return { ok: true };
    case "passwordless_update_password":
      if (!state.passwordless) return fail("not_armed", "");
      return { ok: true };
    case "netlogon_unblock_recovery": {
      const i = state.codes.findIndex((c) => norm(c) === norm(req.code));
      if (i < 0) {
        state.failures += 1;
        return { ok: true, valid: false, locked_s: state.failures >= 5 ? 60 : 0 };
      }
      state.codes.splice(i, 1);
      state.netlogonBlocked = false;
      return { ok: true, valid: true, locked_s: 0 };
    }
  }
}

/** Preview stand-in for `apk_info`. `?apk=missing` or `?apk=changed` shows the other states. */
export async function mockApkInfo(): Promise<import("./agent").ApkInfo> {
  await wait(150);
  const mode = new URLSearchParams(location.search).get("apk");
  const path = String.raw`C:\Program Files\PhoneGate\Android\PhoneGate.apk`;
  const sha = "7c1e9a04d3b85f62e0a4c7d91b3f58a26e04d9c7b1a3f5e82d6c0b49a7e31f5d";
  const signer = "b4a2f07e6c19d83a5f0e2b7c49d1a6e8f3c05b92d7e4a1f60c8b3e5d92a7f14c";
  if (mode === "missing") return { found: false, verified: false, reason: "missing" };
  if (mode === "changed") return { found: true, verified: false, reason: "changed", path, version: "0.1.0", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", expected_sha256: sha, signer_sha256: signer };
  return { found: true, verified: true, path, version: "0.1.0", sha256: sha, signer_sha256: signer };
}

/**
 * Preview stand-in for the Rust QR renderer: a deterministic module pattern with real finder
 * squares so the layout can be judged. It is NOT a scannable code, and the UI says so.
 */
export function mockQrSvg(text: string): string {
  const n = 33;
  let seed = 0;
  for (const ch of text) seed = (seed * 31 + ch.charCodeAt(0)) >>> 0;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
  const finder = (x: number, y: number) => `M${x} ${y}h7v7h-7zM${x + 1} ${y + 1}v5h5v-5zM${x + 2} ${y + 2}h3v3h-3z`;
  const inFinder = (x: number, y: number) => (x < 8 && y < 8) || (x >= n - 8 && y < 8) || (x < 8 && y >= n - 8);
  let d = finder(4, 4) + finder(n - 3, 4) + finder(4, n - 3);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (!inFinder(x, y) && rnd() > 0.52) d += `M${x + 4} ${y + 4}h1v1h-1z`;
  const size = n + 8;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="Preview QR stand-in, not scannable"><rect width="${size}" height="${size}" fill="#ffffff"/><path fill="#10131a" fill-rule="evenodd" d="${d}"/></svg>`;
}

/** Preview stand-in for `check_update`. `?update=new` shows the banner. */
export async function mockUpdate(): Promise<import("./agent").UpdateInfo> {
  const newer = new URLSearchParams(location.search).get("update") === "new";
  return { ok: true, current: "0.2.0", latest: newer ? "v0.3.0" : "v0.2.0", newer };
}
