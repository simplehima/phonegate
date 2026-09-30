// Every string that explains a failure lives here, so each error names the problem and the way
// back. Agent detail strings come from windows/agent/src/engine.rs.

import { AgentError } from "./agent";

export interface Explained {
  title: string;
  body: string;
}

const TRANSPORT: Record<string, Explained> = {
  agent_unavailable: {
    title: "The PhoneGate service isn't running.",
    body: "Start it from Services (PhoneGate Agent) or reinstall PhoneGate. Your current protection setting stays as it was.",
  },
  agent_untrusted: {
    title: "Something other than the PhoneGate service answered.",
    body: "The companion refused to talk to it. Restart the PC; if this keeps happening, reinstall PhoneGate and check the PC for unwanted software.",
  },
  agent_io: {
    title: "The PhoneGate service stopped answering mid-request.",
    body: "Try again. If it repeats, restart the PhoneGate Agent service from Services.",
  },
  agent_bad_reply: {
    title: "The PhoneGate service sent a reply this app can't read.",
    body: "The service and this app may be different versions. Reinstall PhoneGate so both match.",
  },
  not_in_app: {
    title: "This page only works inside the PhoneGate app.",
    body: "Open PhoneGate from the Start menu. It asks for administrator permission because the service only talks to administrators.",
  },
  apk_missing: {
    title: "PhoneGate.apk isn't in the installation folder.",
    body: "Reinstall PhoneGate with the setup program to get the phone app back.",
  },
  apk_path_mismatch: {
    title: "The phone app isn't where PhoneGate expects it.",
    body: "The Android folder may have been moved or replaced with a link. Reinstall PhoneGate.",
  },
  explorer_failed: {
    title: "File Explorer didn't open.",
    body: "Open the PhoneGate folder in Program Files yourself; the app is in its Android folder.",
  },
  op_not_allowed: {
    title: "This app asked for something it isn't allowed to do.",
    body: "Nothing was changed. Reinstall PhoneGate if this repeats.",
  },
};

// Matched against the agent's `detail` text (it is prefixed, e.g. "invalid state: ...").
const DETAILS: [RegExp, Explained][] = [
  [/turn off protection before changing settings/, { title: "Settings are locked while protection is on.", body: "Turn protection off first (it needs your phone or a recovery code), then change settings." }],
  [/unpair before changing the relay/, { title: "The relay can't change while a phone is paired.", body: "Unpair the phone in Settings, change the relay address, then pair again." }],
  [/relay url must be https/, { title: "That relay address isn't accepted.", body: "Use an https:// address (plain http:// only works for localhost testing)." }],
  [/pc name must be 1-64/, { title: "The PC name must be 1 to 64 characters.", body: "Shorten or fill in the name and save again." }],
  [/turn off protection before pairing/, { title: "You can't pair a new phone while protection is on.", body: "Turn protection off first, then start pairing." }],
  [/set the relay server address first/, { title: "No relay server is set yet.", body: "Enter your relay's https address in step 1, then start pairing." }],
  [/acknowledge software key protection/, { title: "This PC has no TPM.", body: "Read the note about software key storage in step 1 and tick the acknowledgement, then continue." }],
  [/no pairing in progress/, { title: "There's no pairing in progress.", body: "The session ended (the service may have restarted). Start pairing again." }],
  [/phone has not joined yet/, { title: "The phone hasn't joined yet.", body: "Scan the QR code with PhoneGate on your phone first." }],
  [/attestation could not be verified/, { title: "Your phone's hardware key couldn't be verified.", body: "Tick the box to accept it anyway, or press Doesn't match to stop." }],
  [/turn off protection before generating/, { title: "New recovery codes need protection off.", body: "Turn protection off first, then generate a new set." }],
  [/pair a phone first/, { title: "No phone is paired.", body: "Pair your phone first; recovery codes are issued right after pairing." }],
  [/recovery_unconfirmed/, { title: "Recovery codes aren't confirmed yet.", body: "Open Recovery codes, save a set, and type one back. Then turn protection on." }],
  [/not_paired/, { title: "No phone is paired.", body: "Pair your phone from Set up first." }],
  [/turn off protection before unpairing/, { title: "You can't unpair while protection is on.", body: "Turn protection off first (phone approval or a recovery code), then unpair." }],
  [/pairing cancelled/, { title: "Pairing was stopped.", body: "Nothing was saved. Start again when you're ready." }],
  [/QR code expired/, { title: "The QR code expired.", body: "Codes last 5 minutes. Start again for a fresh code." }],
  [/pairing failed/, { title: "Pairing failed.", body: "The phone's reply didn't check out, so nothing was saved. Start again; if it keeps failing, someone may be interfering with the relay." }],
];

const CODES: Record<string, Explained> = {
  relay_down: { title: "The relay server can't be reached, so your phone can't be asked.", body: "Check this PC's internet connection and the relay, or use a recovery code instead." },
  not_paired: { title: "No phone is paired.", body: "Pair your phone from Set up first." },
  bad_pin: { title: "That PIN isn't accepted.", body: "Use 6 to 20 digits, numbers only. Start the helper again and choose a new PIN." },
  recovery_mismatch: { title: "Those 6 digits don't match the recovery key.", body: "Check the last group of your saved recovery key and type it again. Encryption hasn't started." },
  not_prepared: { title: "The recovery key for this attempt is no longer valid.", body: "The service may have restarted. Start the helper again; you'll get a new recovery key." },
  unsupported: { title: "This edition of Windows can't use BitLocker with a PIN.", body: "Use Settings > Privacy & security > Device encryption instead, if it's offered." },
  approval_required: { title: "Protection is on, so this change needs your phone or a recovery code.", body: "Approve it on your phone, or use a recovery code." },
  bad_request: { title: "The service rejected the request.", body: "Try again. Reinstall PhoneGate if this repeats." },
};

export function explain(e: unknown): Explained {
  if (e instanceof AgentError) {
    if (TRANSPORT[e.code]) return TRANSPORT[e.code];
    if (e.code === "cooldown") {
      return { title: "Too many refused attempts. PhoneGate is cooling down.", body: `Try again in ${duration(e.retryS ?? 60)}, or use a recovery code.` };
    }
    for (const [re, ex] of DETAILS) if (re.test(e.detail)) return ex;
    if (CODES[e.code]) return CODES[e.code];
    const detail = e.detail.replace(/^(invalid state|decode error|io error|verification failed): /, "");
    return { title: detail ? capital(detail) + "." : "The PhoneGate service refused the request.", body: "Nothing was changed. Try again; restart the PhoneGate Agent service if this repeats." };
  }
  return { title: "Something unexpected went wrong.", body: "Nothing was changed. Close and reopen PhoneGate, then try again." };
}

export function pairingFailure(error: string | undefined): Explained {
  if (!error) return { title: "Pairing failed.", body: "Nothing was saved. Start again." };
  for (const [re, ex] of DETAILS) if (re.test(error)) return ex;
  return { title: "Pairing failed.", body: `${capital(error)}. Nothing was saved. Start again.` };
}

function capital(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function duration(s: number): string {
  if (s < 60) return `${s} second${s === 1 ? "" : "s"}`;
  const m = Math.ceil(s / 60);
  if (m < 60) return `${m} minute${m === 1 ? "" : "s"}`;
  const h = Math.ceil(m / 60);
  return `${h} hour${h === 1 ? "" : "s"}`;
}

export function validateRelayUrl(raw: string): string | null {
  const u = raw.trim();
  if (!u) return "Enter your relay server's address, for example https://relay.example.com.";
  if (u.length > 256) return "That address is too long (256 characters at most).";
  const local = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/.test(u);
  if (!u.startsWith("https://") && !local) return "The address must start with https://. Plain http:// is only allowed for localhost testing.";
  try {
    const parsed = new URL(u);
    if (!parsed.hostname) return "That address has no server name.";
  } catch {
    return "That isn't a valid web address. Check for typos.";
  }
  return null;
}

export function validatePcName(raw: string): string | null {
  const n = raw.trim();
  if (!n) return "Give this PC a name your phone will show, for example Office desktop.";
  if (new TextEncoder().encode(n).length > 64) return "Keep the name to 64 characters or fewer.";
  return null;
}
