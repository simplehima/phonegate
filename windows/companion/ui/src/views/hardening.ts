// Hardening (feature 002): tamper alarm + self-repair status, BitLocker with a startup PIN, and the
// network sign-in block. Contract: specs/002-tamper-hardening/contracts/agent-control-additions.md.

import { agent, AgentError, type BitLockerStatus, type Health, type HealthStatus, type ReqState, type Status } from "../agent";
import { announce, append, busy, button, h, icon, nextId, notice, stamp } from "../dom";
import { duration, explain } from "../copy";
import { repairLabel } from "./history";
import { confirmDialog } from "./dialog";
import { countdown, errorBlock, page, skeleton } from "./common";

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dayTimeFmt = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function ago(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const hr = Math.round(m / 60);
  if (hr < 48) return `${hr} h ago`;
  return `${Math.round(hr / 24)} days ago`;
}

const flag = (v: boolean | number | undefined) => v === true || v === 1;

/** A small icon + text mark; color is never the only signal. */
function mark(ok: boolean, text: string, neutral = false): HTMLElement {
  return h("span.mark", { class: neutral ? "mark-neutral" : ok ? "mark-ok" : "mark-bad" }, icon(neutral ? "info" : ok ? "check" : "warning"), h("span", null, text));
}

const BL_LABEL: Record<string, string> = {
  off: "Off",
  "on-no-pin": "On, no startup PIN",
  "on-pin": "On, with startup PIN",
  encrypting: "Encrypting",
  unknown: "Unknown",
};

export function hardeningView(root: HTMLElement): () => void {
  const section = page(
    root,
    "Hardening",
    "An alarm on your phone if PhoneGate is tampered with, drive encryption with a startup PIN, and a block on password-only network sign-ins.",
    "page-hardening",
  );
  const grid = h("div.hardening-grid");
  const alarmSlot = h("div.alarm-col");
  const side = h("div.hardening-side");
  const blSlot = h("div");
  const netSlot = h("div");
  const netCodeSlot = h("div");
  side.append(blSlot, netSlot, netCodeSlot);
  grid.append(alarmSlot, side);
  const wizard = h("div.bl-wizard", { hidden: true });
  section.append(grid, wizard);

  let alive = true;
  let status: Status | null = null;
  let healthTimer = 0;
  let blTimer = 0;
  let netGen = 0;
  let netTick = 0;
  // The startup PIN lives only in this closure while the wizard needs it; it is never stored,
  // logged, or sent anywhere but the local agent pipe. `clearPin` runs on every exit path.
  let pin = "";
  const clearPin = () => {
    pin = "";
  };

  // ------------------------------------------------------------------ tamper alarm
  const renderAlarm = (hl: Health | null, err?: unknown) => {
    const slip = h("section.slip.slip-white.alarm-slip", { "aria-labelledby": "alarm-h" });
    slip.append(
      h("h2#alarm-h.section-title", null, icon("bell"), h("span", null, "Tamper alarm")),
      h("p", null, "Your phone gets a signed status report every 5 minutes and alerts you if PhoneGate is stopped, removed, damaged, or the PC boots in Safe Mode."),
      h("p.honest", null, icon("info"), h("span", null, "An administrator can still remove PhoneGate. They can't do it without your phone finding out.")),
    );
    if (err) {
      slip.append(errorBlock(err, () => void loadHealth()));
      alarmSlot.replaceChildren(slip);
      return;
    }
    if (!hl) {
      slip.append(skeleton(6));
      alarmSlot.replaceChildren(slip);
      return;
    }
    const st: HealthStatus = hl.status ?? {};
    const last = hl.last_sent_at
      ? h(
          "div.last-report",
          null,
          h("span.label", null, "Last report sent"),
          h("span.last-time.num", null, timeFmt.format(new Date(hl.last_sent_at))),
          h("span.last-ago", null, ago(hl.last_sent_at)),
          st.seq !== undefined ? h("span.last-seq", null, "Report no. ", h("span.num", null, String(st.seq))) : null,
        )
      : h(
          "div.last-report",
          null,
          h("span.label", null, "Last report sent"),
          h("span.value-empty", null, status?.paired ? "None yet. The relay may be unreachable." : "None yet. Reports start once your phone is paired."),
        );
    const bl = String(st.bitlocker ?? "unknown");
    const rows: [string, HTMLElement][] = [
      ["Protection", flag(st.enforce) ? mark(true, "On") : mark(false, "Off")],
      ["Sign-in tile", flag(st.cp_registered) ? mark(true, "Registered") : mark(false, "Missing")],
      ["Sign-in filter", flag(st.filter_registered) ? mark(true, "Registered") : mark(false, "Missing")],
      ["Program files", flag(st.files_intact) ? mark(true, "Intact") : mark(false, "Changed or missing")],
      ["Watchdog", flag(st.watchdog_present) ? mark(true, "Installed") : mark(false, "Not installed")],
      ["Drive encryption", mark(bl === "on-pin", BL_LABEL[bl] ?? bl, bl === "unknown")],
      ["Network sign-ins", flag(st.netlogon_blocked) ? mark(true, "Blocked") : mark(false, "Allowed", true)],
      ["This start", flag(st.safe_mode) ? mark(false, "Safe Mode") : mark(true, "Normal")],
    ];
    const wd = hl.watchdog ?? { present: false, last_repairs: [] };
    const repairs = wd.last_repairs ?? [];
    append(slip, [
      last,
      h("dl.fields.integrity", { "aria-label": "What the latest report says" }, ...rows.map(([k, v]) => h("div.field", null, h("dt", null, k), h("dd", null, v)))),
      h("hr.perf"),
      h("h3.sub-title", null, icon("wrench"), h("span", null, "Self-repair")),
      wd.present
        ? h(
            "p",
            null,
            "The watchdog restores PhoneGate's service, sign-in tile and files from a protected copy within 5 minutes, and tells your phone about each repair.",
            wd.last_run_at ? h("span.wd-run", null, " Last check ", h("span.num", null, timeFmt.format(new Date(wd.last_run_at))), ` (${ago(wd.last_run_at)}).`) : null,
          )
        : notice("warn", "The watchdog isn't installed.", "If PhoneGate is stopped or deleted, nothing puts it back. Your phone still raises the alarm. Reinstall PhoneGate to restore the watchdog."),
      repairs.length
        ? h(
            "ul.repair-list",
            { "aria-label": "Recent repairs" },
            ...repairs.map((r) => h("li", null, h("span.num.repair-at", null, dayTimeFmt.format(new Date(r.at))), h("span.repair-item", null, "Repaired: ", repairLabel(r.item)))),
          )
        : wd.present
          ? h("p.help", null, "No repairs so far.")
          : null,
    ]);
    alarmSlot.replaceChildren(slip);
  };

  const loadHealth = async () => {
    try {
      const hl = await agent.health();
      if (alive) renderAlarm(hl);
    } catch (e) {
      if (alive) renderAlarm(null, e);
    }
  };

  // ------------------------------------------------------------------ BitLocker overview
  const renderBitLocker = (b: BitLockerStatus | null, err?: unknown) => {
    window.clearTimeout(blTimer);
    const slip = h("section.slip.slip-white", { "aria-labelledby": "bl-h" });
    slip.append(h("h2#bl-h.section-title", null, icon("drive"), h("span", null, "Drive encryption")));
    if (err) {
      slip.append(errorBlock(err, () => void loadBitLocker()));
      blSlot.replaceChildren(slip);
      return;
    }
    if (!b) {
      slip.append(skeleton(3));
      blSlot.replaceChildren(slip);
      return;
    }
    if (!b.supported) {
      slip.append(
        stamp("Not available", "muted", "drive"),
        h("p", null, `This edition of Windows can't use BitLocker with a startup PIN${b.reason ? ` (${b.reason})` : ""}.`),
        h("p", null, "Some PCs offer Device encryption instead. Open ", h("strong", null, "Settings > Privacy & security > Device encryption"), " and turn it on if it's listed. Without encryption, someone with the disk can read your files and remove PhoneGate."),
      );
      blSlot.replaceChildren(slip);
      return;
    }
    const tone = b.state === "on-pin" ? "ok" : b.state === "encrypting" ? "ink" : b.state === "on-no-pin" ? "alert" : b.state === "off" ? "bad" : "muted";
    slip.append(stamp(BL_LABEL[b.state] ?? b.state, tone, b.state === "on-pin" ? "lock" : "drive"));
    if (b.state === "encrypting") {
      const pct = Math.max(0, Math.min(100, b.percent ?? 0));
      const fill = h("span.progress-fill");
      fill.style.transform = `scaleX(${pct / 100})`;
      slip.append(
        h("div.progress", { role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(pct), "aria-label": "Encryption progress" }, h("span.progress-track", { "aria-hidden": "true" }, fill)),
        h("p", null, h("span.num", null, `${pct}%`), " encrypted. You can keep using the PC; it finishes in the background."),
      );
      blTimer = window.setTimeout(() => void loadBitLocker(), 3000);
    } else if (b.state === "on-pin") {
      slip.append(h("p", null, "The drive stays locked until the startup PIN is typed, before Windows starts. Keep your recovery key somewhere safe."));
    } else if (b.state === "off" || b.state === "on-no-pin") {
      slip.append(
        h(
          "p",
          null,
          b.state === "off"
            ? "Without encryption, anyone who takes the disk or starts the PC from a USB stick can read your files and remove PhoneGate. A startup PIN keeps the drive locked until the PIN is typed."
            : "The drive is encrypted, but it unlocks by itself at start-up. Adding a startup PIN keeps it locked until the PIN is typed, before Windows starts.",
        ),
        h("div.slip-actions", null, button(b.state === "off" ? "Turn on BitLocker with a PIN" : "Add a startup PIN", { kind: "primary", icon: "lock", onClick: () => startWizard(b) })),
      );
    } else {
      slip.append(
        h("p", null, "PhoneGate couldn't read the encryption state. Check Control Panel > BitLocker Drive Encryption."),
        h("div.slip-actions", null, button("Check again", { kind: "quiet", icon: "refresh", onClick: () => void loadBitLocker() })),
      );
    }
    blSlot.replaceChildren(slip);
  };

  const loadBitLocker = async () => {
    try {
      const b = await agent.bitlockerStatus();
      if (alive) renderBitLocker(b);
    } catch (e) {
      if (alive) renderBitLocker(null, e);
    }
  };

  // ------------------------------------------------------------------ BitLocker wizard
  const WSTEPS = ["Before you start", "Choose a PIN", "Recovery key", "Restart"];
  const wizardFrame = (step: number, title: string, ...body: (Node | null)[]) => {
    const stepper = h(
      "ol.stepper",
      { "aria-label": "Drive encryption steps" },
      ...WSTEPS.map((label, i) => {
        const st = i < step ? "done" : i === step ? "current" : "todo";
        return h("li.step", { class: `step-${st}`, "aria-current": st === "current" ? "step" : undefined }, h("span.step-mark", { "aria-hidden": "true" }, st === "done" ? icon("check") : String(i + 1)), h("span.step-label", null, label));
      }),
    );
    const heading = h("h2.wizard-title", { tabindex: "-1" }, title);
    wizard.replaceChildren(stepper, h("div.slip.slip-white.wizard-slip", null, heading, ...body));
    requestAnimationFrame(() => heading.focus());
  };

  const closeWizard = () => {
    clearPin();
    document.querySelectorAll(".print-sheet").forEach((el) => el.remove());
    wizard.replaceChildren();
    wizard.hidden = true;
    grid.hidden = false;
    section.classList.remove("wizard-open");
    void loadBitLocker();
    void loadHealth();
  };

  const startWizard = (b: BitLockerStatus) => {
    clearPin();
    grid.hidden = true;
    wizard.hidden = false;
    section.classList.add("wizard-open");
    const cancel = button("Cancel", { kind: "quiet", onClick: closeWizard });
    const next = button("Continue", { kind: "primary", icon: "arrow-right", onClick: () => pinStep() });
    wizardFrame(
      0,
      b.state === "off" ? "Turn on BitLocker with a startup PIN" : "Add a startup PIN",
      h(
        "ul.howto-list",
        null,
        h("li", null, "You choose a PIN of 6 to 20 digits. The PC asks for it every time it starts, before Windows loads."),
        h("li", null, "You get a recovery key, shown once. It's the only way in if you forget the PIN, so save it away from this PC."),
        h("li", null, "You type its last 6 digits to prove you saved it. Nothing changes until then."),
        b.state === "off" ? h("li", null, "After a restart, the drive encrypts in the background while you keep working.") : h("li", null, "After a restart, the PIN replaces the automatic unlock."),
      ),
      notice("info", "PhoneGate never keeps your PIN.", "It goes straight to Windows and is cleared from this app as soon as it's used. It is never sent to your phone or the relay."),
      h("div.slip-actions", null, next, cancel),
    );
  };

  const pinStep = (err?: string) => {
    clearPin();
    const id1 = nextId("pin");
    const id2 = nextId("pin");
    const mk = (id: string) =>
      h("input.input.mono-input.pin-input", {
        id,
        type: "password",
        inputmode: "numeric",
        autocomplete: "off",
        spellcheck: "false",
        maxlength: "20",
        "aria-describedby": `${id1}-help ${id2}-err`,
      });
    const p1 = mk(id1);
    const p2 = mk(id2);
    for (const el of [p1, p2]) el.addEventListener("input", () => (el.value = el.value.replace(/\D/g, "")));
    const errEl = h("p.field-error", { id: `${id2}-err`, role: "alert" }, err ?? "");
    const submit = button("Continue", { kind: "primary", type: "submit", icon: "arrow-right" });
    const form = h(
      "form.pin-form",
      { novalidate: true },
      h("div.form-row", null, h("label.label", { for: id1 }, "Startup PIN"), p1, h("p.help", { id: `${id1}-help` }, "6 to 20 digits. Pick one you can type from memory; you'll need it at every start.")),
      h("div.form-row", null, h("label.label", { for: id2 }, "Type the PIN again"), p2, errEl),
      h("div.slip-actions", null, submit, button("Cancel", { kind: "quiet", onClick: closeWizard })),
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const a = p1.value;
      const b = p2.value;
      let msg = "";
      if (!/^\d{6,20}$/.test(a)) msg = "The PIN must be 6 to 20 digits.";
      else if (a !== b) msg = "The two PINs don't match. Type them again.";
      if (msg) {
        errEl.textContent = msg;
        p1.value = "";
        p2.value = "";
        p1.setAttribute("aria-invalid", "true");
        p1.focus();
        return;
      }
      pin = a;
      // Clear the PIN from the DOM before anything else happens.
      p1.value = "";
      p2.value = "";
      void busy(submit, async () => {
        try {
          const r = await agent.bitlockerPrepare();
          if (!alive) return clearPin();
          recoveryStep(r.recovery_password);
        } catch (e2) {
          clearPin();
          if (e2 instanceof AgentError && e2.code === "unsupported") {
            closeWizard();
            blSlot.prepend(errorBlock(e2));
            return;
          }
          errEl.textContent = `${explain(e2).title} ${explain(e2).body}`;
        }
      });
    });
    wizardFrame(1, "Choose a startup PIN", form);
    requestAnimationFrame(() => p1.focus());
  };

  const recoveryStep = (password: string) => {
    const groups = password.split(/[-\s]+/).filter(Boolean);
    const pcName = status?.pc_name ?? "this PC";
    const text = [
      `BitLocker recovery key for ${pcName} (system drive)`,
      `Created ${new Date().toLocaleString()} by PhoneGate`,
      "",
      password,
      "",
      "Use it if you forget the startup PIN or Windows asks for a recovery key.",
      "Keep it away from this PC.",
      "",
    ].join("\r\n");
    const msg = h("span.copy-msg", { role: "status" });
    const copy = button("Copy", { icon: "copy" });
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        msg.textContent = "Copied. Paste it into your password manager, then clear the clipboard.";
      } catch {
        msg.textContent = "Couldn't copy. Use Save as .txt or Print instead.";
      }
    });
    const save = button("Save as .txt", { icon: "download" });
    save.addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
      const a = h("a", { href: url, download: `BitLocker recovery key - ${pcName.replace(/[\\/:*?"<>|]/g, "")}.txt` });
      document.body.append(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
      msg.textContent = "Saved to your Downloads folder. Move it off this PC, for example to a USB stick you keep elsewhere.";
    });
    const print = button("Print", { icon: "printer", onClick: () => window.print() });
    const id = nextId("last6");
    const input = h("input.input.mono-input.last6-input", { id, type: "text", inputmode: "numeric", autocomplete: "off", spellcheck: "false", maxlength: "6", "aria-describedby": `${id}-help ${id}-err` });
    input.addEventListener("input", () => (input.value = input.value.replace(/\D/g, "")));
    const errEl = h("p.field-error", { id: `${id}-err`, role: "alert" });
    const go = button("Turn on BitLocker", { kind: "primary", type: "submit", icon: "lock" });
    const form = h(
      "form.last6-form",
      { novalidate: true },
      h("div.form-row", null, h("label.label", { for: id }, "Last 6 digits of the recovery key"), input, h("p.help", { id: `${id}-help` }, "Type them from your saved copy. Encryption doesn't start until they match."), errEl),
      h("div.slip-actions", null, go, button("Cancel", { kind: "quiet", onClick: closeWizard })),
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const v = input.value.trim();
      if (!/^\d{6}$/.test(v)) {
        errEl.textContent = "Type the 6 digits of the last group.";
        input.setAttribute("aria-invalid", "true");
        return input.focus();
      }
      if (!pin) {
        pinStep("Choose the PIN again; it was cleared.");
        return;
      }
      void busy(go, async () => {
        errEl.textContent = "";
        try {
          const r = await agent.bitlockerEnable(pin, v);
          clearPin();
          if (alive) restartStep(r.restart_required);
        } catch (e2) {
          const code = e2 instanceof AgentError ? e2.code : "";
          if (code === "recovery_mismatch") {
            errEl.textContent = "Those digits don't match the last group of the recovery key. Check your saved copy and try again.";
            input.setAttribute("aria-invalid", "true");
            input.select();
            return;
          }
          clearPin();
          if (code === "bad_pin") return pinStep("Windows didn't accept that PIN. Use 6 to 20 digits and try again.");
          if (code === "not_prepared") return pinStep("The recovery key expired (the service may have restarted). Choose the PIN again to get a new key.");
          if (code === "failed" && e2 instanceof AgentError) {
            errEl.textContent = `Windows couldn't turn on BitLocker${e2.detail ? `: ${e2.detail}` : ""}. Nothing was changed. Close the helper and try again later.`;
            return;
          }
          errEl.textContent = `${explain(e2).title} ${explain(e2).body}`;
        }
      });
    });
    wizardFrame(
      2,
      "Save your recovery key",
      notice("warn", "Shown once.", "PhoneGate doesn't keep this key. If you forget the PIN, it's the only way to unlock the drive."),
      h("p.recovery-key", { "aria-label": `Recovery key: ${groups.map((g) => g.split("").join(" ")).join(", ")}` }, ...groups.map((g) => h("span.key-group", { "aria-hidden": "true" }, g))),
      h("div.code-actions", null, copy, save, print, msg),
      h("hr.perf"),
      form,
    );
    document.querySelectorAll(".print-sheet").forEach((el) => el.remove());
    document.body.append(h("div.print-sheet", { "aria-hidden": "true" }, h("h1", null, `BitLocker recovery key: ${pcName}`), h("p", null, "Use it if you forget the startup PIN. Keep it away from this PC."), h("ol", null, h("li", null, password))));
  };

  const restartStep = (restartRequired: boolean) => {
    document.querySelectorAll(".print-sheet").forEach((el) => el.remove());
    announce("BitLocker is set up. Restart to finish.");
    const done = button("Done", { kind: "primary", icon: "check", onClick: closeWizard });
    wizardFrame(
      3,
      restartRequired ? "BitLocker is ready" : "Encryption has started",
      stamp("PIN set", "ok", "lock", "lg"),
      h(
        "p",
        null,
        restartRequired
          ? "Restart to finish; you'll be asked for the PIN before Windows starts. After that, the drive encrypts in the background."
          : "The drive is encrypting in the background. From the next start you'll be asked for the PIN before Windows starts.",
      ),
      h("div.slip-actions", null, done),
    );
  };

  // ------------------------------------------------------------------ network sign-ins
  const effects = () =>
    h(
      "ul.effects",
      null,
      h("li", null, "File sharing to this PC (\\\\PC\\share and mapped drives)"),
      h("li", null, "Remote PowerShell and WinRM"),
      h("li", null, "Remote Desktop with Network Level Authentication, for local accounts"),
    );

  const renderNet = (blocked: boolean | null, err?: unknown, msgEl?: HTMLElement) => {
    netGen += 1;
    window.clearInterval(netTick);
    netCodeSlot.replaceChildren();
    const slip = h("section.slip.slip-white", { "aria-labelledby": "net-h" });
    slip.append(h("h2#net-h.section-title", null, icon("network"), h("span", null, "Network sign-ins")));
    if (err) {
      slip.append(errorBlock(err, () => void loadNet()));
      netSlot.replaceChildren(slip);
      return;
    }
    if (blocked === null) {
      slip.append(skeleton(3));
      netSlot.replaceChildren(slip);
      return;
    }
    const swId = nextId("netsw");
    const sw = h(
      "button.switch",
      { id: swId, type: "button", role: "switch", "aria-checked": String(blocked), "aria-describedby": `${swId}-desc` },
      h("span.switch-track", { "aria-hidden": "true" }, h("span.switch-thumb")),
      h("span.switch-label", null, "Block network sign-ins"),
    );
    sw.addEventListener("click", () => void toggle(blocked, sw));
    append(slip, [
      h("div.switch-row", null, sw, blocked ? stamp("Blocked", "ok", "lock") : stamp("Allowed", "muted", "unlock")),
      h("p", { id: `${swId}-desc` }, "When blocked, nobody can use a password alone to sign in to this PC over the network, a path the lock screen never sees. Sign-ins at the PC still go through PhoneGate."),
      h("p.effects-title", null, blocked ? "Stopped while blocked:" : "What stops working when blocked:"),
      effects(),
      status?.enforce ? h("p.lock-note", null, icon("lock"), h("span", null, "Protection is on, so allowing them again needs your phone or a recovery code.")) : null,
      msgEl ?? null,
    ]);
    netSlot.replaceChildren(slip);
  };

  const loadNet = async (msgEl?: HTMLElement) => {
    try {
      const r = await agent.netlogonStatus();
      if (alive) renderNet(r.blocked, undefined, msgEl);
    } catch (e) {
      if (alive) renderNet(null, e);
    }
  };

  const toggle = async (blocked: boolean, sw: HTMLButtonElement) => {
    if (!blocked) {
      const ok = await confirmDialog({
        title: "Block network sign-ins?",
        body: h("div", null, h("p", null, "These stop working for local accounts on this PC:"), effects(), h("p", null, "You can allow them again later.")),
        confirm: "Block sign-ins",
        danger: true,
      });
      if (!ok) return;
      await busy(sw, async () => {
        try {
          await agent.netlogonSet(true);
          announce("Network sign-ins are blocked.");
          await loadNet(notice("ok", "Network sign-ins are blocked.", "Password-only sign-ins over the network are refused from now on."));
          void loadHealth();
        } catch (e) {
          renderNet(blocked, undefined, errorBlock(e));
        }
      });
      return;
    }
    if (status?.enforce) return unblockApproval();
    const ok = await confirmDialog({
      title: "Allow network sign-ins again?",
      body: "File sharing, remote PowerShell and Remote Desktop with network authentication will accept a password alone again.",
      confirm: "Allow sign-ins",
    });
    if (!ok) return;
    await busy(sw, async () => {
      try {
        await agent.netlogonSet(false);
        await loadNet();
        void loadHealth();
      } catch (e) {
        if (e instanceof AgentError && e.code === "approval_required") return unblockApproval();
        renderNet(blocked, undefined, errorBlock(e));
      }
    });
  };

  const unblockApproval = async () => {
    let r: { req: string; number: number; expires_in_s?: number };
    try {
      r = await agent.netlogonUnblockBegin();
    } catch (e) {
      renderNet(true, undefined, errorBlock(e));
      return;
    }
    if (!alive) return;
    netGen += 1;
    const my = netGen;
    window.clearInterval(netTick);
    const total = (r.expires_in_s ?? 60) * 1000;
    const cd = countdown(total, Date.now() + total, (s) => (s > 0 ? `${s} s left` : "Expired"));
    const digits = String(r.number).padStart(2, "0");
    netSlot.replaceChildren(
      h(
        "section.slip.slip-live.approve-slip",
        { "aria-labelledby": "net-h" },
        h("h2#net-h.section-title", null, icon("network"), h("span", null, "Allow network sign-ins")),
        h("p.approve-lead", null, "Type this number on your phone:"),
        h("p.badge-number", { "aria-label": `Number ${digits.split("").join(" ")}` }, ...digits.split("").map((d) => h("span.badge-cell", { "aria-hidden": "true" }, d))),
        cd.el,
        h("p.scan-state", { role: "status" }, h("span.pulse", { "aria-hidden": "true" }), "Waiting for your phone..."),
        h("div.slip-actions", null, button("Stop waiting", { kind: "quiet", onClick: () => void loadNet() })),
      ),
    );
    announce(`Type ${digits.split("").join(" ")} on your phone.`);
    netTick = window.setInterval(() => cd.tick(), 1000);
    netCodeSlot.replaceChildren(unblockCodeForm());
    const OUT: Record<Exclude<ReqState, "pending" | "approved">, [string, string]> = {
      denied: ["Your phone denied the change.", "Network sign-ins stay blocked."],
      not_me: ["Your phone marked this as \"This wasn't me\".", "Network sign-ins stay blocked and the attempt is logged as suspicious."],
      expired: ["The request expired before your phone answered.", "Ask again, or use a recovery code."],
      error: ["Your phone's answer didn't check out.", "Network sign-ins stay blocked. Ask again."],
    };
    while (alive && my === netGen) {
      let state: ReqState;
      try {
        state = (await agent.netlogonUnblockWait(r.req)).state;
      } catch (e) {
        if (my === netGen) renderNet(true, undefined, errorBlock(e));
        return;
      }
      if (!alive || my !== netGen) return;
      if (state === "pending") continue;
      if (state === "approved") {
        announce("Network sign-ins are allowed again.");
        await loadNet(notice("ok", "Network sign-ins are allowed again.", "Your phone approved the change."));
        void loadHealth();
        return;
      }
      const [t, b] = OUT[state];
      await loadNet(notice(state === "not_me" || state === "error" ? "error" : "warn", t, b));
      return;
    }
  };

  const unblockCodeForm = () => {
    const id = nextId("netcode");
    const input = h("input.input.mono-input.code-input", { id, type: "text", autocomplete: "off", spellcheck: "false", autocapitalize: "characters", placeholder: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX", "aria-describedby": `${id}-err` });
    const err = h("p.field-error", { id: `${id}-err`, role: "alert" });
    const use = button("Use recovery code", { kind: "secondary", type: "submit", icon: "key" });
    const form = h(
      "form.slip.slip-white",
      { novalidate: true },
      h("div.slip-head", null, h("h2.slip-title", null, "Use a recovery code"), h("span.slip-pc", null, "Phone unavailable")),
      h("div.form-row", null, h("label.label", { for: id }, "Recovery code"), input, err),
      h("div.slip-actions", null, use),
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const v = input.value.trim();
      if (!v) {
        err.textContent = "Type one of your recovery codes first.";
        return input.focus();
      }
      void busy(use, async () => {
        try {
          const r = await agent.netlogonUnblockRecovery(v);
          if (r.valid) {
            await loadNet(notice("ok", "Network sign-ins are allowed again.", "A recovery code was used up."));
            void loadHealth();
            return;
          }
          input.setAttribute("aria-invalid", "true");
          err.textContent = r.locked_s > 0 ? `Too many wrong codes. Code entry is locked for ${duration(r.locked_s)}.` : "That code isn't valid or was already used.";
        } catch (e2) {
          err.textContent = `${explain(e2).title} ${explain(e2).body}`;
        }
      });
    });
    return form;
  };

  // ------------------------------------------------------------------ start
  renderAlarm(null);
  renderBitLocker(null);
  renderNet(null);
  const start = async () => {
    try {
      status = await agent.status();
    } catch {
      status = null;
    }
    if (!alive) return;
    await loadHealth();
    await loadBitLocker();
    await loadNet();
  };
  void start();
  healthTimer = window.setInterval(() => {
    if (!grid.hidden) void loadHealth();
  }, 15_000);

  return () => {
    alive = false;
    clearPin();
    netGen += 1;
    window.clearInterval(healthTimer);
    window.clearInterval(netTick);
    window.clearTimeout(blTimer);
    document.querySelectorAll(".print-sheet").forEach((el) => el.remove());
  };
}
