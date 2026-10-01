// Update check preference and result. The check is the only request this app makes outside the
// relay, so it can be switched off; the choice is a per-viewer convenience (storage may fail).

import { checkUpdate, openReleases, type UpdateInfo } from "./agent";
import { button, h, notice } from "./dom";

const KEY = "phonegate.updatecheck";

export function updateCheckEnabled(): boolean {
  try {
    return localStorage.getItem(KEY) !== "off";
  } catch {
    return true;
  }
}

export function setUpdateCheckEnabled(on: boolean): void {
  try {
    localStorage.setItem(KEY, on ? "on" : "off");
  } catch {
    /* private mode: lasts for this session only */
  }
}

let result: Promise<UpdateInfo> | null = null;

/** One check per app launch. Resolves to `{ ok: false }` when off, offline or rate-limited. */
export function updateResult(): Promise<UpdateInfo> {
  if (!updateCheckEnabled()) return Promise.resolve({ ok: false });
  result ??= checkUpdate();
  return result;
}

/** A banner for a newer release, or null. Never installs anything; it opens the releases page. */
export async function updateBanner(): Promise<HTMLElement | null> {
  const u = await updateResult();
  if (!u.ok || !u.newer || !u.latest) return null;
  return h(
    "div.update-banner",
    null,
    notice(
      "info",
      `PhoneGate ${u.latest.replace(/^v/i, "")} is available`,
      `You have ${u.current}. Download the new setup and the phone app from the releases page, then run the setup over this install.`,
      button("Open releases page", { kind: "secondary", icon: "arrow-right", onClick: () => void openReleases() }),
    ),
  );
}
