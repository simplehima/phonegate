import type { Security, Status } from "../agent";
import { agent } from "../agent";
import { announce, busy, button, field, h, icon, notice, stamp, type IconName } from "../dom";
import { explain } from "../copy";
import { go } from "../nav";
import { flow } from "../flow";
import { store } from "../store";
import { errorBlock, page, skeleton } from "./common";

interface DeskNotice {
  tone: "serious" | "caution" | "info";
  icon: IconName;
  title: string;
  body: string;
  todo: string;
}

/** Plain-language security notices from status + security_check (FR-028, Principle 3). */
export function deskNotices(st: Status, sec: Security | null): DeskNotice[] {
  const out: DeskNotice[] = [];
  if (st.paired && st.relay === "down") {
    out.push({
      tone: "serious",
      icon: "unplug",
      title: "The relay server can't be reached",
      body: "Your phone can't be asked right now, so unlocks will need a recovery code or the offline code on the lock screen.",
      todo: "Check this PC's internet connection and that your relay is running.",
    });
  }
  if (st.paired && st.attestation?.status === "unverified") {
    out.push({
      tone: "caution",
      icon: "shield-alert",
      title: "Your phone's hardware key wasn't verified",
      body: `You accepted it anyway at pairing. Reason given: ${st.attestation.reason}. Approvals are still signed by the phone, but PhoneGate can't prove the key is locked inside secure hardware.`,
      todo: "If your phone supports it, unpair and pair again after a system update.",
    });
  }
  if (st.paired && st.recovery_confirmed && st.recovery_remaining > 0 && st.recovery_remaining <= 3) {
    out.push({
      tone: "caution",
      icon: "key",
      title: `Only ${st.recovery_remaining} recovery code${st.recovery_remaining === 1 ? "" : "s"} left`,
      body: "Recovery codes are how you get in when your phone is lost or offline. Each works once.",
      todo: "Turn protection off, generate a fresh set in Recovery codes, then turn it back on.",
    });
  }
  if (sec) {
    if (!sec.tpm) {
      out.push({
        tone: "serious",
        icon: "cpu",
        title: "No TPM: this PC's keys are kept in software",
        body: "Without a TPM chip, the PC's pairing key is protected by Windows encryption only. Someone with administrator access or your disk could copy it.",
        todo: "Turn on the TPM (often called fTPM or PTT) in your PC's firmware settings if it has one, then unpair and pair again.",
      });
    }
    if (sec.bitlocker === "off") {
      out.push({
        tone: "serious",
        icon: "drive",
        title: "Drive encryption (BitLocker) is off",
        body: "Anyone with physical access could start the PC from a USB stick and remove PhoneGate or read your files, without ever seeing the lock screen.",
        todo: "Turn on BitLocker: Control Panel > BitLocker Drive Encryption, or Settings > Privacy & security > Device encryption.",
      });
    } else if (sec.bitlocker === "unknown") {
      out.push({
        tone: "caution",
        icon: "drive",
        title: "Couldn't confirm drive encryption",
        body: "PhoneGate couldn't read the BitLocker status. Without encryption, someone with physical access can bypass any lock screen.",
        todo: "Check Control Panel > BitLocker Drive Encryption and make sure the system drive shows BitLocker on.",
      });
    }
    if (sec.secure_boot === false) {
      out.push({
        tone: "caution",
        icon: "lock",
        title: "Secure Boot is off",
        body: "Secure Boot stops tampered start-up software from loading before Windows. Without it, a boot-level attack could sidestep PhoneGate.",
        todo: "Turn on Secure Boot in your PC's UEFI firmware settings.",
      });
    } else if (sec.secure_boot === null) {
      out.push({
        tone: "info",
        icon: "lock",
        title: "Secure Boot status unknown",
        body: "This PC may start in legacy BIOS mode, which has no Secure Boot.",
        todo: "Check System Information (msinfo32) for Secure Boot State.",
      });
    }
    if (sec.rdp_enabled) {
      out.push({
        tone: "info",
        icon: "server",
        title: "Remote Desktop is on",
        body: "Remote Desktop sign-ins also wait for your phone, and the number appears in the remote session. Leaving it on still exposes the sign-in screen to your network.",
        todo: "If you don't use it, turn it off in Settings > System > Remote Desktop.",
      });
    }
    if (sec.watchdog_present === false) {
      out.push({
        tone: "caution",
        icon: "wrench",
        title: "Self-repair isn't installed",
        body: "If someone stops or deletes PhoneGate, nothing puts it back. Your phone still gets an alert.",
        todo: "Reinstall PhoneGate to restore the watchdog. Details are under Hardening.",
      });
    }
    if (sec.safe_mode_registered === false) {
      out.push({
        tone: "caution",
        icon: "warning",
        title: "PhoneGate isn't registered for Safe Mode",
        body: "If the PC starts in Safe Mode, PhoneGate doesn't run there, so your phone only hears about it on the next normal start.",
        todo: "Reinstall PhoneGate to register it for Safe Mode.",
      });
    }
    if (sec.netlogon_blocked === false) {
      out.push({
        tone: "info",
        icon: "network",
        title: "Network sign-ins can use a password alone",
        body: "File sharing, remote PowerShell and some Remote Desktop setups let someone with your password sign in over the network, a path the lock screen never sees.",
        todo: "If you don't use them, turn on Block network sign-ins under Hardening.",
      });
    }
    if (sec.passwordless_only) {
      out.push({
        tone: "caution",
        icon: "key",
        title: "Windows Hello passwordless mode hides the password tile",
        body: "Windows is set to allow only Windows Hello sign-in for Microsoft accounts. PhoneGate adds its approval to password sign-in, so with this setting you may not see the tile PhoneGate protects.",
        todo: "Settings > Accounts > Sign-in options: turn off \"For improved security, only allow Windows Hello sign-in\".",
      });
    }
  }
  const rank = { serious: 0, caution: 1, info: 2 } as const;
  return out.sort((a, b) => rank[a.tone] - rank[b.tone]);
}

function protectionStamp(st: Status): HTMLElement {
  if (!st.paired) return stamp("Not set up", "muted", "shield-off", "lg");
  return st.enforce ? stamp("Protection on", "ok", "shield-check", "lg") : stamp("Protection off", "alert", "shield-off", "lg");
}

function protectionLine(st: Status): string {
  if (!st.paired) return "Pair your phone to make every unlock and sign-in on this PC wait for your approval.";
  if (st.enforce) return `Every unlock, sign-in and Remote Desktop sign-in on this PC waits for approval on ${st.phone_name ?? "your phone"}.`;
  if (!st.recovery_confirmed) return "Your phone is paired. Save your recovery codes and type one back, then turn protection on.";
  return "Your phone is paired, but Windows signs in without asking it. Turn protection on when you're ready.";
}

function timeAgo(ts: number | null): string {
  if (!ts) return "";
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function focusFirstAction(scope: HTMLElement): void {
  scope.querySelector<HTMLElement>(".slip-actions .btn")?.focus();
}

export function statusView(root: HTMLElement): () => void {
  const section = page(root, "Status", undefined, "page-status");
  const grid = h("div.status-grid");
  const slipCol = h("div.status-slip");
  const noticeCol = h("aside.status-notices", { "aria-labelledby": "notices-title" });
  grid.append(slipCol, noticeCol);
  section.append(grid);
  const actionMsg = h("div.action-msg");
  const checkedAt = h("span.checked-at");
  let lastKey = "";
  let limitsOpen = false;

  const render = () => {
    const snap = store.get();
    const st = snap.status;
    checkedAt.textContent = snap.checkedAt ? `Checked ${timeAgo(snap.checkedAt)}` : "";
    // Rebuild only when something visible changed, so polling never steals focus.
    const key = JSON.stringify([st, snap.security, snap.error ? explain(snap.error).title : null]);
    if (key === lastKey) return;
    lastKey = key;
    const hadFocus = slipCol.contains(document.activeElement) || noticeCol.contains(document.activeElement);
    if (!st) {
      if (snap.error) {
        slipCol.replaceChildren(h("div.slip", null, errorBlock(snap.error, () => store.refresh(true))));
      } else {
        slipCol.replaceChildren(h("div.slip", null, skeleton(6)));
      }
      noticeCol.replaceChildren();
      return;
    }
    const liveSlip = st.paired && st.enforce;
    const slip = h("article.slip", { class: liveSlip ? "slip-canary" : "slip-white", "aria-label": `Status for ${st.pc_name}` });
    slip.append(
      h("div.slip-head", null, h("span.slip-pc", null, st.pc_name)),
      h("div.stamp-zone", null, protectionStamp(st), h("p.stamp-line", null, protectionLine(st))),
      h("hr.perf"),
    );

    const phone = st.paired
      ? h(
          "span.value-with-mark",
          null,
          h("span.ink", null, st.phone_name ?? "Unnamed phone"),
          st.attestation?.status === "verified" ? stamp("Key verified", "ok", "check") : stamp("Key unverified", "alert", "shield-alert"),
        )
      : h("span.value-empty", null, "No phone paired");
    const relay = st.relay_url
      ? h(
          "span.value-with-mark",
          null,
          h("span.ink.mono-url", null, st.relay_url),
          st.relay === "up" ? h("span.reach.reach-up", null, icon("link"), "Reachable") : h("span.reach.reach-down", null, icon("unplug"), "Unreachable"),
        )
      : h("span.value-empty", null, "Not set");
    const codes = st.paired
      ? st.recovery_confirmed
        ? h("span.value-with-mark", null, h("span.num", null, String(st.recovery_remaining)), h("span.unit", null, st.recovery_remaining === 1 ? "code left" : "codes left"))
        : h("span.value-empty", null, "Not confirmed yet")
      : h("span.value-empty", null, "Issued after pairing");
    const keys = st.key_backend === "tpm" ? h("span.ink", null, "TPM (hardware)") : h("span.ink", null, "Software, no TPM");

    slip.append(h("dl.fields", null, field("Paired phone", phone), field("Relay server", relay), field("Recovery codes", codes), field("PC keys", keys)));

    const actions = h("div.slip-actions");
    if (!st.paired) {
      actions.append(
        button("Set up PhoneGate", { kind: "primary", icon: "arrow-right", onClick: () => go("setup") }),
        button("Get the phone app", {
          kind: "secondary",
          icon: "phone",
          onClick: () => {
            flow.phoneAppDone = false;
            go("setup");
          },
        }),
      );
    } else if (st.enforce) {
      actions.append(button("Turn off protection", { kind: "secondary", icon: "shield-off", onClick: () => go("turn-off") }));
    } else if (!st.recovery_confirmed) {
      actions.append(button("Finish recovery codes", { kind: "primary", icon: "key", onClick: () => go("recovery") }));
    } else {
      const on = button("Turn on protection", { kind: "primary", icon: "shield-check" });
      on.addEventListener("click", () =>
        busy(on, async () => {
          actionMsg.replaceChildren();
          try {
            await agent.enable();
            announce("Protection is on.");
            await store.refresh();
          } catch (e) {
            const ex = explain(e);
            actionMsg.replaceChildren(notice("error", ex.title, ex.body));
          }
        }),
      );
      actions.append(on);
    }
    const refresh = button("Check again", { kind: "quiet", icon: "refresh" });
    refresh.addEventListener("click", () => busy(refresh, () => store.refresh(true)));
    actions.append(refresh, checkedAt);
    slip.append(actions, actionMsg);
    if (snap.error) slip.append(errorBlock(snap.error, () => store.refresh(true)));
    slipCol.replaceChildren(slip);

    const list = deskNotices(st, snap.security);
    const head = h("div.notices-head", null, h("h2#notices-title", null, "Desk notices"), h("span.count", null, list.length ? String(list.length) : ""));
    const body = list.length
      ? h(
          "ul.notice-list",
          null,
          ...list.map((n) =>
            h(
              "li.desk-note",
              { class: `desk-note-${n.tone}` },
              h("div.desk-note-icon", null, icon(n.icon)),
              h("div.desk-note-text", null, h("h3", null, n.title), h("p", null, n.body), h("p.desk-note-todo", null, h("strong", null, "What to do: "), n.todo)),
            ),
          ),
        )
      : h("p.notices-empty", null, snap.security ? "No security notices. TPM, drive encryption and Secure Boot all check out." : "Checking TPM, drive encryption and Secure Boot...");
    const limits = h(
      "details.limits",
      { open: limitsOpen, ontoggle: (e: Event) => (limitsOpen = (e.target as HTMLDetailsElement).open) },
      h("summary", null, "What PhoneGate can't protect against"),
      h(
        "ul",
        null,
        h("li", null, "Someone with your disk and no BitLocker: they can read or change files without signing in."),
        h("li", null, "Safe Mode and recovery environments where Windows skips third-party sign-in checks."),
        h("li", null, "An administrator who is already signed in: they can uninstall PhoneGate."),
        h("li", null, "Attacks on the PC's hardware, such as DMA devices, while it's unlocked."),
      ),
    );
    noticeCol.replaceChildren(head, body, limits);
    if (hadFocus) focusFirstAction(slipCol);
  };

  const unsub = store.subscribe(render);
  const timer = window.setInterval(() => store.refresh(), 5000);
  const onFocus = () => store.refresh();
  window.addEventListener("focus", onFocus);
  store.refresh();
  return () => {
    unsub();
    window.clearInterval(timer);
    window.removeEventListener("focus", onFocus);
  };
}
