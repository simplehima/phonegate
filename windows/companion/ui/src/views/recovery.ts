import { agent, type Status } from "../agent";
import { announce, busy, button, h, icon, nextId, notice, stamp } from "../dom";
import { explain } from "../copy";
import { flow } from "../flow";
import { go } from "../nav";
import { store } from "../store";
import { confirmDialog } from "./dialog";
import { errorBlock, page, skeleton } from "./common";

export function recoveryView(root: HTMLElement): () => void {
  const section = page(
    root,
    "Recovery codes",
    "Ten codes that get you in when your phone is lost, flat or offline. They work at the lock screen with no network, and each one works once.",
    "page-recovery",
  );
  const body = h("div.recovery-body");
  section.append(body);
  let alive = true;

  // ------------------------------------------------------------------------------------------
  const showCodes = (codes: string[], st: Status) => {
    const pcName = st.pc_name;
    const issued = new Date();
    const text = [
      `PhoneGate recovery codes for ${pcName}`,
      `Issued ${issued.toLocaleString()}`,
      "",
      "Each code works once. Keep these somewhere safe and away from this PC.",
      "At the lock screen choose \"Use a recovery code\" and type any unused code.",
      "",
      ...codes.map((c, i) => `${String(i + 1).padStart(2, " ")}. ${c}`),
      "",
    ].join("\r\n");

    const copyMsg = h("span.copy-msg", { role: "status" });
    const copy = button("Copy all", { icon: "copy" });
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        copyMsg.textContent = "Copied. Paste them into your password manager, then clear the clipboard.";
      } catch {
        copyMsg.textContent = "Couldn't copy. Use Save as .txt or Print instead.";
      }
    });
    const save = button("Save as .txt", { icon: "download" });
    save.addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
      const a = h("a", { href: url, download: `PhoneGate recovery codes - ${pcName.replace(/[\\/:*?"<>|]/g, "")}.txt` });
      document.body.append(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
      copyMsg.textContent = "Saved to your Downloads folder. Move the file somewhere safe, such as a USB stick you keep elsewhere.";
    });
    const print = button("Print", { icon: "printer", onClick: () => window.print() });

    const grid = h(
      "ol.code-grid",
      { "aria-label": "Recovery codes" },
      ...codes.map((c, i) => h("li.code", null, h("span.code-n", { "aria-hidden": "true" }, String(i + 1).padStart(2, "0")), h("span.code-v", { "aria-label": `Code ${i + 1}: ${c.split("").join(" ")}` }, c))),
    );

    const savedId = nextId("saved");
    const saved = h("input.check", { id: savedId, type: "checkbox" });
    const confirmId = nextId("confirm");
    const confirmInput = h("input.input.mono-input.code-input", {
      id: confirmId,
      type: "text",
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "characters",
      placeholder: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX",
      "aria-describedby": `${confirmId}-help ${confirmId}-err`,
    });
    const confirmErr = h("p.field-error", { id: `${confirmId}-err`, role: "alert" });
    const check = button("Check code", { kind: "primary", type: "submit", icon: "check" });
    const confirmForm = h(
      "form.confirm-form",
      { novalidate: true, hidden: true },
      h("h2", null, "Type one code back"),
      h("p", null, "This proves you kept a copy. Type any one of the codes above from your saved copy, not from this screen."),
      h("div.form-row", null, h("label.label", { for: confirmId }, "Recovery code"), confirmInput, h("p.help", { id: `${confirmId}-help` }, "Dashes, spaces and letter case don't matter."), confirmErr),
      h("div.slip-actions", null, check),
    );
    saved.addEventListener("change", () => {
      confirmForm.hidden = !saved.checked;
      if (saved.checked) confirmInput.focus();
    });
    const result = h("div");
    confirmForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const v = confirmInput.value.trim();
      if (!v) {
        confirmErr.textContent = "Type one of your codes first.";
        confirmInput.setAttribute("aria-invalid", "true");
        return confirmInput.focus();
      }
      void busy(check, async () => {
        confirmErr.textContent = "";
        try {
          const r = await agent.recoveryConfirm(v);
          if (!r.valid) {
            confirmErr.textContent = "That code doesn't match any of the 10 codes above. Check for typos and try again.";
            confirmInput.setAttribute("aria-invalid", "true");
            confirmInput.focus();
            return;
          }
          confirmInput.setAttribute("aria-invalid", "false");
          confirmForm.hidden = true;
          saved.disabled = true;
          grid.classList.add("codes-hidden");
          grid.setAttribute("aria-hidden", "true");
          await store.refresh();
          showConfirmed(result, st);
        } catch (err) {
          confirmErr.textContent = explain(err).title + " " + explain(err).body;
        }
      });
    });

    body.replaceChildren(
      h(
        "div.slip.slip-white.codes-slip",
        null,
        h("div.slip-head", null, h("span.slip-pc", null, pcName)),
        notice("warn", "Shown once.", "These codes won't be shown again after you leave this page. PhoneGate keeps only a one-way fingerprint of each code."),
        grid,
        h("div.code-actions", null, copy, save, print, copyMsg),
        h("hr.perf"),
        h("label.check-row", { for: savedId }, saved, h("span", null, "I've saved these codes somewhere safe, away from this PC.")),
        confirmForm,
        result,
      ),
    );
    // Print-only sheet (outside the app shell, which print CSS hides): codes and how to use them.
    document.querySelectorAll(".print-sheet").forEach((el) => el.remove());
    document.body.append(
      h(
        "div.print-sheet",
        { "aria-hidden": "true" },
        h("h1", null, `PhoneGate recovery codes: ${pcName}`),
        h("p", null, `Issued ${issued.toLocaleString()}. Each code works once. At the lock screen choose "Use a recovery code".`),
        h("ol", null, ...codes.map((c) => h("li", null, c))),
      ),
    );
  };

  const showConfirmed = (slot: HTMLElement, st: Status) => {
    announce("Recovery code confirmed.");
    const msg = h("div");
    const on = button("Turn on protection", { kind: "primary", icon: "shield-check" });
    on.addEventListener("click", () =>
      busy(on, async () => {
        msg.replaceChildren();
        try {
          await agent.enable();
          await store.refresh();
          announce("Protection is on.");
          go("status");
        } catch (e) {
          msg.replaceChildren(errorBlock(e));
        }
      }),
    );
    slot.replaceChildren(
      h(
        "div.confirmed",
        null,
        stamp("Codes confirmed", "ok", "check"),
        h("p", null, `From now on, turning protection on makes every sign-in on ${st.pc_name} wait for ${st.phone_name ?? "your phone"}.`),
        h("div.slip-actions", null, on, button("Not now", { kind: "quiet", onClick: () => go("status") })),
        msg,
      ),
    );
    requestAnimationFrame(() => on.focus());
  };

  // ------------------------------------------------------------------------------------------
  const generate = async (st: Status, trigger?: HTMLButtonElement) => {
    const run = async () => {
      try {
        const r = await agent.recoveryGenerate();
        if (!alive) return;
        showCodes(r.codes, st);
        announce("Ten new recovery codes are shown.");
        void store.refresh();
        requestAnimationFrame(() => body.querySelector<HTMLElement>(".code-grid")?.scrollIntoView({ block: "nearest" }));
      } catch (e) {
        body.prepend(errorBlock(e));
      }
    };
    if (trigger) await busy(trigger, run);
    else await run();
  };

  const showOverview = (st: Status) => {
    if (!st.paired) {
      body.replaceChildren(
        h(
          "div.slip.slip-white",
          null,
          h("p.empty-lead", null, "Recovery codes are issued right after you pair your phone."),
          h("div.slip-actions", null, button("Set up PhoneGate", { kind: "primary", icon: "arrow-right", onClick: () => go("setup") })),
        ),
      );
      return;
    }
    const gen = button("Generate a new set", { kind: st.recovery_confirmed ? "secondary" : "primary", icon: "refresh", disabled: st.enforce, describedBy: st.enforce ? "gen-locked" : undefined });
    gen.addEventListener("click", async () => {
      if (st.recovery_confirmed && st.recovery_remaining > 0) {
        const ok = await confirmDialog({
          title: "Replace your recovery codes?",
          body: `Your ${st.recovery_remaining} unused code${st.recovery_remaining === 1 ? "" : "s"} will stop working immediately. You'll need to save the new set and type one back before protection can be turned on again.`,
          confirm: "Replace codes",
          danger: true,
        });
        if (!ok) return;
      }
      await generate(st, gen);
    });
    body.replaceChildren(
      h(
        "div.slip.slip-white",
        null,
        h("div.slip-head", null, h("span.slip-pc", null, st.pc_name)),
        st.recovery_confirmed
          ? h("p.codes-left", null, h("span.num.num-xl", null, String(st.recovery_remaining)), h("span", null, st.recovery_remaining === 1 ? "unused code left" : "unused codes left"))
          : notice("warn", "Your recovery codes aren't confirmed.", "Protection can't be turned on until you save a set and type one back. Generate a set to finish."),
        h("hr.perf"),
        h("p", null, "Generating a new set replaces the old one straight away, so any codes you printed before stop working."),
        st.enforce ? h("p.help#gen-locked", null, icon("lock"), " Protection is on. Turn it off first (with your phone or a recovery code) to generate new codes.") : null,
        h("div.slip-actions", null, gen, st.enforce ? button("Turn off protection", { kind: "quiet", icon: "shield-off", onClick: () => go("turn-off") }) : null),
      ),
    );
  };

  const start = async () => {
    body.replaceChildren(h("div.slip.slip-white", null, skeleton(5)));
    try {
      const st = await agent.status();
      if (!alive) return;
      const fresh = flow.freshPairing;
      flow.freshPairing = false;
      if (fresh && st.paired && !st.enforce) {
        await generate(st);
        return;
      }
      showOverview(st);
    } catch (e) {
      body.replaceChildren(h("div.slip.slip-white", null, errorBlock(e, start)));
    }
  };
  void start();
  return () => {
    alive = false;
    // Shown once: nothing of the codes survives leaving the page.
    document.querySelectorAll(".print-sheet").forEach((el) => el.remove());
  };
}
