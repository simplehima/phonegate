// Typed access to the PhoneGate agent's control pipe (contracts/agent-pipes.md).
//
// Inside Tauri every call goes through the Rust `agent` command, which allowlists the op and
// forwards it to \\.\pipe\phonegate.control. In a plain browser (design preview only) an
// in-memory mock answers instead; it is loaded lazily and never inside Tauri.

export type Attestation = { status: "verified" } | { status: "unverified"; reason: string };

export interface Status {
  ok: true;
  pc_name: string;
  relay_url: string;
  relay: "up" | "down";
  key_backend: string;
  software_ack: boolean;
  paired: boolean;
  phone_name: string | null;
  attestation: Attestation | null;
  enforce: boolean;
  recovery_remaining: number;
  recovery_confirmed: boolean;
  pc_id: string;
}

export interface Security {
  ok: true;
  tpm: boolean;
  bitlocker: "on" | "off" | "unknown";
  secure_boot: boolean | null;
  rdp_enabled: boolean;
  passwordless_only: boolean;
  // feature 002; absent from older agents
  netlogon_blocked?: boolean;
  watchdog_present?: boolean;
  safe_mode_registered?: boolean;
}

export type BitLockerState = "off" | "on-no-pin" | "on-pin" | "encrypting" | "unknown";

/** Integrity fields of the signed status report the PC sends the phone (protocol-v1-additions §1). */
export interface HealthStatus {
  seq?: number;
  at?: number;
  enforce?: boolean | number;
  cp_registered?: boolean | number;
  filter_registered?: boolean | number;
  files_intact?: boolean | number;
  watchdog_present?: boolean | number;
  bitlocker?: BitLockerState | string;
  netlogon_blocked?: boolean | number;
  safe_mode?: boolean | number;
}

export interface Health {
  ok: true;
  status: HealthStatus;
  last_sent_at: number;
  watchdog: { present: boolean; last_run_at?: number | null; last_repairs: { at: number; item: string }[] };
}

export interface BitLockerStatus {
  ok: true;
  supported: boolean;
  state: BitLockerState;
  percent?: number | null;
  reason?: string;
}

export type PairState = "none" | "waiting" | "confirm" | "completed" | "failed";

export interface PairPoll {
  ok: true;
  state: PairState;
  sas?: string;
  phone_name?: string;
  attestation?: Attestation;
  error?: string;
  phone_confirmed: boolean;
}

export type ReqState = "pending" | "approved" | "denied" | "not_me" | "expired" | "error";

export interface AttemptRecord {
  at: number;
  pc_name: string;
  account: string;
  scenario: string;
  outcome: string;
  req_id?: string | null;
}

export interface CodeCheck {
  ok: true;
  valid: boolean;
  remaining: number;
  locked_s: number;
}

export interface DisableBegin {
  ok: true;
  req?: string;
  number?: number;
  expires_in_s?: number;
  already_off?: boolean;
}

export type Request =
  | { op: "status" }
  | { op: "settings_set"; relay_url?: string; pc_name?: string; software_ack?: boolean }
  | { op: "pair_start" }
  | { op: "pair_poll" }
  | { op: "pair_decide"; accept: boolean; accept_unverified: boolean }
  | { op: "recovery_generate" }
  | { op: "recovery_confirm"; code: string }
  | { op: "enable" }
  | { op: "disable_begin" }
  | { op: "disable_wait"; req: string; timeout_ms: number }
  | { op: "disable_recovery"; code: string }
  | { op: "unpair" }
  | { op: "history"; limit: number }
  | { op: "security_check" }
  | { op: "health" }
  | { op: "bitlocker_status" }
  | { op: "bitlocker_prepare" }
  | { op: "bitlocker_enable"; pin: string; recovery_last6: string }
  | { op: "netlogon_status" }
  | { op: "netlogon_set"; block: boolean }
  | { op: "netlogon_unblock_begin" }
  | { op: "netlogon_unblock_wait"; req: string; timeout_ms: number }
  | { op: "netlogon_unblock_recovery"; code: string }
  // feature 004
  | { op: "passwordless_status" }
  | { op: "passwordless_enable"; account: string; password: string }
  | { op: "passwordless_enable_wait"; req: string; timeout_ms: number }
  | { op: "passwordless_disable" }
  | { op: "passwordless_update_password"; password: string };

/** A failure the UI can explain: what went wrong and what to do about it. */
export class AgentError extends Error {
  constructor(
    readonly code: string,
    readonly detail: string,
    readonly retryS?: number,
  ) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

type Transport = (req: Request) => Promise<Record<string, unknown>>;

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/**
 * The preview mock exists only in dev-server builds (or with VITE_PREVIEW=1). Production builds
 * that Tauri ships contain no mock code at all, and even in dev it is never used inside Tauri.
 */
export const previewMode = !inTauri && (import.meta.env.DEV || import.meta.env.VITE_PREVIEW === "1");

let transport: Promise<Transport> | null = null;

function getTransport(): Promise<Transport> {
  if (!transport) {
    transport = inTauri
      ? import("@tauri-apps/api/core").then(({ invoke }) => async (req: Request) => {
          try {
            return (await invoke("agent", { request: req })) as Record<string, unknown>;
          } catch (e) {
            throw new AgentError(typeof e === "string" ? e : "agent_io", "");
          }
        })
      : import.meta.env.DEV || import.meta.env.VITE_PREVIEW === "1"
        ? import("./mock").then((m) => m.mockTransport)
        : Promise.resolve(async () => {
            throw new AgentError("not_in_app", "");
          });
  }
  return transport;
}

// One request at a time: the agent serves one client per pipe instance, and ordering keeps
// polling loops from racing user actions.
let queue: Promise<unknown> = Promise.resolve();

// How many agent calls are in flight (queued or running), for the app-wide loading bar.
let inFlight = 0;
const busyListeners = new Set<(n: number) => void>();

/** Calls `cb` with the number of agent requests in flight whenever it changes. Returns an unsubscribe. */
export function onBusy(cb: (n: number) => void): () => void {
  busyListeners.add(cb);
  return () => busyListeners.delete(cb);
}

function setInFlight(delta: number): void {
  inFlight = Math.max(0, inFlight + delta);
  for (const cb of busyListeners) cb(inFlight);
}

async function call<T>(req: Request): Promise<T> {
  const run = async () => {
    const t = await getTransport();
    const res = await t(req);
    if (res.ok !== true) {
      throw new AgentError(String(res.err ?? "internal"), String(res.detail ?? ""), typeof res.retry_s === "number" ? res.retry_s : undefined);
    }
    return res as T;
  };
  setInFlight(1);
  const p = queue.then(run, run);
  queue = p.catch(() => undefined);
  void p.then(
    () => setInFlight(-1),
    () => setInFlight(-1),
  );
  return p;
}

export const agent = {
  status: () => call<Status>({ op: "status" }),
  security: () => call<Security>({ op: "security_check" }),
  settings: (s: { relay_url?: string; pc_name?: string; software_ack?: boolean }) => call<{ ok: true }>({ op: "settings_set", ...s }),
  pairStart: () => call<{ ok: true; qr: string; expires_at: number }>({ op: "pair_start" }),
  pairPoll: () => call<PairPoll>({ op: "pair_poll" }),
  pairDecide: (accept: boolean, acceptUnverified: boolean) =>
    call<{ ok: true }>({ op: "pair_decide", accept, accept_unverified: acceptUnverified }),
  recoveryGenerate: () => call<{ ok: true; codes: string[] }>({ op: "recovery_generate" }),
  recoveryConfirm: (code: string) => call<{ ok: true; valid: boolean }>({ op: "recovery_confirm", code }),
  enable: () => call<{ ok: true }>({ op: "enable" }),
  disableBegin: () => call<DisableBegin>({ op: "disable_begin" }),
  disableWait: (req: string) => call<{ ok: true; state: ReqState }>({ op: "disable_wait", req, timeout_ms: 1500 }),
  disableRecovery: (code: string) => call<CodeCheck>({ op: "disable_recovery", code }),
  unpair: () => call<{ ok: true }>({ op: "unpair" }),
  history: (limit = 500) => call<{ ok: true; items: AttemptRecord[] }>({ op: "history", limit }),
  health: () => call<Health>({ op: "health" }),
  bitlockerStatus: () => call<BitLockerStatus>({ op: "bitlocker_status" }),
  bitlockerPrepare: () => call<{ ok: true; recovery_password: string; protector_id: string }>({ op: "bitlocker_prepare" }),
  bitlockerEnable: (pin: string, recoveryLast6: string) => call<{ ok: true; restart_required: boolean }>({ op: "bitlocker_enable", pin, recovery_last6: recoveryLast6 }),
  netlogonStatus: () => call<{ ok: true; blocked: boolean }>({ op: "netlogon_status" }),
  netlogonSet: (block: boolean) => call<{ ok: true }>({ op: "netlogon_set", block }),
  netlogonUnblockBegin: () => call<{ ok: true; req: string; number: number; expires_in_s?: number }>({ op: "netlogon_unblock_begin" }),
  netlogonUnblockWait: (req: string) => call<{ ok: true; state: ReqState }>({ op: "netlogon_unblock_wait", req, timeout_ms: 1500 }),
  passwordlessStatus: () => call<{ ok: true; on: boolean; account?: string }>({ op: "passwordless_status" }),
  passwordlessEnable: (account: string, password: string) => call<{ ok: true; req: string; number: number; expires_in_s?: number }>({ op: "passwordless_enable", account, password }),
  passwordlessEnableWait: (req: string) => call<{ ok: true; state: ReqState }>({ op: "passwordless_enable_wait", req, timeout_ms: 1500 }),
  passwordlessDisable: () => call<{ ok: true }>({ op: "passwordless_disable" }),
  passwordlessUpdatePassword: (password: string) => call<{ ok: true }>({ op: "passwordless_update_password", password }),
  netlogonUnblockRecovery: (code: string) => call<{ ok: true; valid: boolean; locked_s: number; remaining?: number }>({ op: "netlogon_unblock_recovery", code }),
};

/** The bundled Android app (feature 003). Paths are never sent from the UI. */
export interface ApkInfo {
  found: boolean;
  verified: boolean;
  path?: string;
  version?: string;
  sha256?: string;
  expected_sha256?: string;
  signer_sha256?: string;
  reason?: string;
}

export async function apkInfo(): Promise<ApkInfo> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    return (await invoke("apk_info")) as ApkInfo;
  }
  if (import.meta.env.DEV || import.meta.env.VITE_PREVIEW === "1") return (await import("./mock")).mockApkInfo();
  return { found: false, verified: false, reason: "not_in_app" };
}

/** Opens Explorer with PhoneGate.apk selected. */
export async function revealApk(): Promise<void> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    try {
      await invoke("reveal_apk");
    } catch (e) {
      throw new AgentError(typeof e === "string" ? e : "explorer_failed", "");
    }
    return;
  }
  if (import.meta.env.DEV || import.meta.env.VITE_PREVIEW === "1") return;
  throw new AgentError("not_in_app", "");
}

/** Renders a pairing URI as an SVG string (Rust `qr_svg`; the preview mock draws a stand-in). */
export async function qrSvg(text: string): Promise<string> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    return (await invoke("qr_svg", { text })) as string;
  }
  if (import.meta.env.DEV || import.meta.env.VITE_PREVIEW === "1") {
    const m = await import("./mock");
    return m.mockQrSvg(text);
  }
  throw new AgentError("not_in_app", "");
}

/** Result of the GitHub release check. `ok: false` means "couldn't tell"; the UI stays silent. */
export interface UpdateInfo {
  ok: boolean;
  current?: string;
  latest?: string;
  newer?: boolean;
}

/** Asks the Rust side to compare against the latest GitHub release. Never throws. */
export async function checkUpdate(): Promise<UpdateInfo> {
  try {
    if (inTauri) {
      const { invoke } = await import("@tauri-apps/api/core");
      return (await invoke("check_update")) as UpdateInfo;
    }
    if (import.meta.env.DEV || import.meta.env.VITE_PREVIEW === "1") return (await import("./mock")).mockUpdate();
  } catch {
    /* offline or blocked: say nothing */
  }
  return { ok: false };
}

export type LinkKind = "releases" | "repo" | "license" | "security" | "issues";

/** Opens a named project page in the browser. The address itself is fixed on the Rust side. */
export async function openLink(kind: LinkKind): Promise<void> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("open_link", { kind });
  }
}

export interface AppInfo {
  version: string;
  license: string;
  repo: string;
}

/** The running app's version and licence, read from the build. */
export async function appInfo(): Promise<AppInfo> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    return (await invoke("app_info")) as AppInfo;
  }
  if (import.meta.env.DEV || import.meta.env.VITE_PREVIEW === "1") return (await import("./mock")).mockAppInfo();
  return { version: "", license: "Apache-2.0", repo: "https://github.com/simplehima/phonegate" };
}
