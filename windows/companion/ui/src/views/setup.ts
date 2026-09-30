import { agent, previewMode, qrSvg, type PairPoll, type Status } from "../agent";
import { announce, busy, button, h, icon, nextId, notice, stamp } from "../dom";
import { explain, pairingFailure, validatePcName, validateRelayUrl } from "../copy";
import { go } from "../nav";
import { flow } from "../flow";
import { store } from "../store";
import { countdown, errorBlock, mmss, page, skeleton } from "./common";
import { phoneAppStep } from "./phoneapp";

type Step = "app" | "details" | "scan" | "compare" | "done" | "failed";

const STEPS: [Exclude<Step, "failed">, string][] = [
  ["app", "Get the phone app"],
  ["details", "Desk details"],
  ["scan", "Scan the code"],
  ["compare", "Compare codes"],
  ["done", "Paired"],
];

const PAIR_WINDOW_MS = 5 * 60 * 1000;
const POLL_MS = 700;

export function setupView(root: HTMLElement): () => void {
  const section = page(root, "Set up PhoneGate", "Pair your phone with this PC. It takes about a minute: you'll scan a code, then compare a 6-digit number on both screens.", "page-setup");
  const stepper = h("ol.stepper", { "aria-label": "Setup steps" });
  const body = h("div.setup-body");
  section.append(stepper, body);

  let alive = true;
  let pollGen = 0;
  let pollTimer = 0;
  let tickTimer = 0;
  const stopTimers = () => {
    pollGen += 1;
    window.clearTimeout(pollTimer);
    window.clearInterval(tickTimer);
  };

  const setStep = (step: Step) => {
    // After step 1 the introduction has done its job; give the code and decision the room.
    section.classList.toggle("setup-compact", step !== "details");
    stepper.replaceChildren(
      ...STEPS.map(([, label], i) => {
        const idx = STEPS.findIndex(([s]) => s === (step === "failed" ? "scan" : step));
        const state = i < idx ? "done" : i === idx ? "current" : "todo";
        return h("li.step", { class: `step-${state}`, "aria-current": state === "current" ? "step" : undefined }, h("span.step-mark", { "aria-hidden": "true" }, state === "done" ? icon("check") : String(i + 1)), h("span.step-label", null, label));
      }),
    );
  };

  // ------------------------------------------------------------------------------------------
  const showPhoneApp = (st: Status) => {
    stopTimers();
    setStep("app");
    phoneAppStep(
      body,
      () => {
        flow.phoneAppDone = true;
        showDetails(st);
      },
      () => alive,
    );
  };

  // ------------------------------------------------------------------------------------------
  const showDetails = (st: Status) => {
    stopTimers();
    setStep("details");
    const relayId = nextId("relay");
    const nameId = nextId("pcname");
    const relayErr = h("p.field-error", { id: `${relayId}-err`, role: "alert" });
    const nameErr = h("p.field-error", { id: `${nameId}-err`, role: "alert" });
    const relay = h("input.input.mono-input", {
      id: relayId,
      type: "url",
      inputmode: "url",
      autocomplete: "off",
      spellcheck: "false",
      value: st.relay_url,
      placeholder: "https://relay.example.com",
      "aria-describedby": `${relayId}-help ${relayId}-err`,
    });
    const name = h("input.input", { id: nameId, type: "text", maxlength: "64", autocomplete: "off", value: st.pc_name, "aria-describedby": `${nameId}-help ${nameId}-err` });
    const formMsg = h("div.form-msg");
    const form = h("form.slip.slip-white.form-slip", { novalidate: true });

    form.append(
      h(
        "div.form-row",
        null,
        h("label.label", { for: relayId }, "Relay server address"),
        relay,
        h("p.help", { id: `${relayId}-help` }, "The address of the relay you host, starting with https://. Your phone and this PC meet there; it never sees your approvals in readable form."),
        relayErr,
      ),
      h(
        "div.form-row",
        null,
        h("label.label", { for: nameId }, "PC name"),
        name,
        h("p.help", { id: `${nameId}-help` }, "Your phone shows this name with every request, so pick one you'll recognise at a glance."),
        nameErr,
      ),
    );

    let ack: HTMLInputElement | null = null;
    const ackErr = h("p.field-error", { role: "alert" });
    if (st.key_backend === "software") {
      const ackId = nextId("ack");
      ack = h("input.check", { id: ackId, type: "checkbox", checked: st.software_ack, "aria-describedby": `${ackId}-why` });
      form.append(
        h(
          "fieldset.ack-box",
          null,
          h("legend", null, icon("cpu"), "This PC has no TPM"),
          h(
            "p",
            { id: `${ackId}-why` },
            "PhoneGate normally locks this PC's keys inside the TPM security chip, where they can't be copied. Without one, the keys are stored in software, protected by Windows encryption. An administrator on this PC, or someone with your unencrypted disk, could copy them and impersonate this PC to your phone. Your phone's approvals stay protected either way.",
          ),
          h("label.check-row", { for: ackId }, ack, h("span", null, "I understand this PC's keys will be stored in software.")),
          ackErr,
        ),
      );
    }

    const submit = button("Save and show QR code", { kind: "primary", type: "submit", icon: "qr" });
    const back = button("Back to the phone app", { kind: "quiet", icon: "arrow-left", onClick: () => showPhoneApp(st) });
    form.append(h("div.slip-actions", null, submit, back), formMsg);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const rErr = validateRelayUrl(relay.value);
      const nErr = validatePcName(name.value);
      relayErr.textContent = rErr ?? "";
      nameErr.textContent = nErr ?? "";
      relay.setAttribute("aria-invalid", String(!!rErr));
      name.setAttribute("aria-invalid", String(!!nErr));
      const aErr = ack && !ack.checked ? "Tick this box to continue without a TPM." : "";
      ackErr.textContent = aErr;
      if (rErr) return relay.focus();
      if (nErr) return name.focus();
      if (aErr) return ack!.focus();
      void busy(submit, async () => {
        formMsg.replaceChildren();
        try {
          const url = relay.value.trim().replace(/\/+$/, "");
          await agent.settings({
            ...(url !== st.relay_url ? { relay_url: url } : {}),
            pc_name: name.value.trim(),
            ...(ack ? { software_ack: ack.checked } : {}),
          });
          await startPairing();
        } catch (err) {
          formMsg.replaceChildren(errorBlock(err));
        }
      });
    });
    body.replaceChildren(form);
  };

  // ------------------------------------------------------------------------------------------
  const startPairing = async () => {
    const res = await agent.pairStart();
    if (!alive) return;
    const svg = await qrSvg(res.qr);
    if (!alive) return;
    showScan(svg, res.expires_at);
  };

  const showScan = (svg: string, expiresAt: number) => {
    stopTimers();
    setStep("scan");
    // The SVG comes from our own Rust renderer (or the preview mock), never from the network.
    const qrBox = h("div.qr-paper");
    const parsed = new DOMParser().parseFromString(svg, "image/svg+xml").documentElement;
    qrBox.append(document.importNode(parsed, true));
    const cd = countdown(PAIR_WINDOW_MS, expiresAt, (s) => (s > 0 ? `Code expires in ${mmss(s)}` : "Code expired"));
    const state = h("p.scan-state", { role: "status" }, h("span.pulse", { "aria-hidden": "true" }), "Waiting for your phone to scan...");
    const msg = h("div");
    const cancel = button("Cancel pairing", { kind: "quiet", icon: "x" });
    cancel.addEventListener("click", () =>
      busy(cancel, async () => {
        stopTimers();
        try {
          await agent.pairDecide(false, false);
        } catch {
          /* no session: nothing to cancel */
        }
        const st = await agent.status();
        showDetails(st);
      }),
    );
    body.replaceChildren(
      h(
        "div.scan-layout",
        null,
        h("figure.qr-figure", null, qrBox, h("figcaption", null, previewMode ? "Preview stand-in. Not a scannable code." : "Pairing code for this PC. It works once.")),
        h(
          "div.scan-steps",
          null,
          h("h2", null, "Scan this code with your phone"),
          h(
            "ol.howto",
            null,
            h("li", null, "Open ", h("strong", null, "PhoneGate"), " on your phone."),
            h("li", null, "Tap ", h("strong", null, "Add a PC"), "."),
            h("li", null, "Point the camera at this code and confirm with your fingerprint."),
          ),
          cd.el,
          state,
          msg,
          h("div.slip-actions", null, cancel),
        ),
      ),
    );
    tickTimer = window.setInterval(() => cd.tick(), 1000);
    poll((p) => {
      if (p.state === "waiting") return true;
      if (p.state === "confirm") {
        showCompare(p);
        return false;
      }
      handleEnd(p);
      return false;
    });
  };

  // ------------------------------------------------------------------------------------------
  const showCompare = (p: PairPoll) => {
    stopTimers();
    setStep("compare");
    announce("Your phone joined. Compare the 6-digit code on both screens.");
    const sas = (p.sas ?? "").replace(/\D/g, "");
    const verified = p.attestation?.status === "verified";
    const ackId = nextId("unverified");
    const unverifiedAck = verified ? null : h("input.check", { id: ackId, type: "checkbox" });
    const matches = button("Matches", { kind: "primary", icon: "check", disabled: !verified, describedBy: verified ? undefined : `${ackId}-need` });
    const mismatch = button("Doesn't match", { kind: "danger", icon: "x" });
    const msg = h("div");
    const waitLine = h("p.scan-state", { role: "status" });

    const attestationBlock = verified
      ? h("div.attest-ok", null, stamp("Hardware key verified", "ok", "shield-check"), h("p", null, "The phone proved its approval key lives in secure hardware and needs your fingerprint for every use."))
      : h(
          "div.attest-warn",
          null,
          notice(
            "warn",
            "This phone's hardware key couldn't be verified.",
            h("span", null, "Reason: ", h("span.reason", null, p.attestation && p.attestation.status === "unverified" ? p.attestation.reason : "no attestation was provided"), ". Approvals are still signed by this phone, but PhoneGate can't prove the key needs your fingerprint."),
          ),
          h("label.check-row", { for: ackId }, unverifiedAck!, h("span", null, "I understand, and I want to pair this phone anyway.")),
          h("p.sr-only", { id: `${ackId}-need` }, "Tick the box above to enable Matches."),
        );
    unverifiedAck?.addEventListener("change", () => (matches.disabled = !unverifiedAck.checked));

    matches.addEventListener("click", () =>
      busy(matches, async () => {
        msg.replaceChildren();
        try {
          await agent.pairDecide(true, !!unverifiedAck?.checked);
          mismatch.disabled = true;
          matches.disabled = true;
          waitLine.replaceChildren(h("span.pulse", { "aria-hidden": "true" }), "Waiting for your phone to confirm the code too...");
          poll((q) => {
            if (q.state === "confirm") return true;
            if (q.state === "completed") {
              showDone(q.phone_name ?? p.phone_name ?? "your phone");
              return false;
            }
            handleEnd(q);
            return false;
          });
        } catch (e) {
          msg.replaceChildren(errorBlock(e));
        }
      }),
    );
    mismatch.addEventListener("click", () =>
      busy(mismatch, async () => {
        stopTimers();
        try {
          await agent.pairDecide(false, false);
        } catch {
          /* already ended */
        }
        showFailed({ title: "Pairing stopped because the codes didn't match.", body: "Nothing was saved. A mismatch can mean someone else scanned the QR code or is interfering with the relay. Start again, and make sure only your phone scans the code." });
      }),
    );

    body.replaceChildren(
      h(
        "div.slip.slip-live.compare-slip",
        null,
        h("div.slip-head", null, h("span.slip-pc", null, `From ${p.phone_name ?? "your phone"}`)),
        h("h2.compare-q", null, "Does your phone show the same code?"),
        h("p.sas", { "aria-label": `Code ${sas.split("").join(" ")}` }, h("span", { "aria-hidden": "true" }, sas.slice(0, 3)), h("span", { "aria-hidden": "true" }, sas.slice(3))),
        h("hr.perf"),
        attestationBlock,
        h("div.decide", null, mismatch, matches),
        waitLine,
        msg,
      ),
    );
    const phoneLine = (q: PairPoll) => {
      if (q.phone_confirmed) waitLine.replaceChildren(icon("check"), "Your phone has confirmed the code. Confirm here if it matches.");
    };
    phoneLine(p);
    // Keep watching while the owner compares: the phone may confirm, cancel, or time out.
    poll((q) => {
      if (q.state === "confirm") {
        phoneLine(q);
        return true;
      }
      handleEnd(q);
      return false;
    });
  };

  // ------------------------------------------------------------------------------------------
  const showDone = (phoneName: string) => {
    stopTimers();
    setStep("done");
    flow.freshPairing = true;
    void store.refresh();
    announce(`Paired with ${phoneName}.`);
    const next = button("Continue to recovery codes", { kind: "primary", icon: "arrow-right", onClick: () => go("recovery") });
    body.replaceChildren(
      h(
        "div.slip.slip-white.done-slip",
        null,
        stamp("Paired", "ok", "link", "lg"),
        h("h2", null, "Paired with ", h("span.ink", null, phoneName)),
        h("p", null, "Next, save 10 recovery codes. They're your way in if your phone is lost, flat or offline. You'll type one back before protection can be turned on."),
        h("div.slip-actions", null, next),
      ),
    );
    requestAnimationFrame(() => next.focus());
  };

  const showFailed = (ex: { title: string; body: string }) => {
    stopTimers();
    setStep("failed");
    const again = button("Start again", { kind: "primary", icon: "refresh" });
    again.addEventListener("click", () =>
      busy(again, async () => {
        try {
          await startPairing();
        } catch (e) {
          const st = await agent.status().catch(() => null);
          if (st) showDetails(st);
          body.prepend(errorBlock(e));
        }
      }),
    );
    const edit = button("Change relay or name", { kind: "quiet", icon: "settings" });
    edit.addEventListener("click", async () => showDetails(await agent.status()));
    body.replaceChildren(h("div.slip.slip-pink.failed-slip", null, stamp("Not paired", "bad", "x", "lg"), notice("error", ex.title, ex.body), h("div.slip-actions", null, again, edit)));
    requestAnimationFrame(() => again.focus());
  };

  const handleEnd = (p: PairPoll) => {
    if (p.state === "none") {
      showFailed({ title: "The pairing session ended.", body: "The PhoneGate service may have restarted. Nothing was saved. Start again." });
    } else if (p.state === "completed") {
      showDone(p.phone_name ?? "your phone");
    } else {
      showFailed(pairingFailure(p.error));
    }
  };

  /** Polls pair_poll every ~700 ms while `onPoll` returns true. */
  const poll = (onPoll: (p: PairPoll) => boolean) => {
    window.clearTimeout(pollTimer);
    const gen = ++pollGen;
    let failures = 0;
    const once = async () => {
      if (!alive || gen !== pollGen) return;
      try {
        const p = await agent.pairPoll();
        failures = 0;
        if (!alive || gen !== pollGen) return;
        if (onPoll(p)) pollTimer = window.setTimeout(once, POLL_MS);
      } catch (e) {
        if (!alive || gen !== pollGen) return;
        failures += 1;
        if (failures >= 5) {
          stopTimers();
          const ex = explain(e);
          showFailed(ex);
        } else {
          pollTimer = window.setTimeout(once, POLL_MS * 2);
        }
      }
    };
    pollTimer = window.setTimeout(once, POLL_MS);
  };

  // ------------------------------------------------------------------------------------------
  const start = async () => {
    body.replaceChildren(h("div.slip.slip-white", null, skeleton(5)));
    try {
      const st = await agent.status();
      if (!alive) return;
      if (st.paired) {
        setStep("done");
        body.replaceChildren(
          h(
            "div.slip.slip-white.done-slip",
            null,
            stamp("Paired", "ok", "link", "lg"),
            h("h2", null, "This PC is paired with ", h("span.ink", null, st.phone_name ?? "a phone")),
            h("p", null, st.enforce ? "Protection is on. To pair a different phone, turn protection off, then unpair in Settings." : "To pair a different phone, unpair this one in Settings first."),
            h("div.slip-actions", null, button("Go to status", { kind: "primary", icon: "shield-check", onClick: () => go("status") }), button("Settings", { kind: "quiet", icon: "settings", onClick: () => go("settings") })),
          ),
        );
        return;
      }
      if (st.enforce) {
        showDetails(st);
        return;
      }
      const p = await agent.pairPoll().catch(() => null);
      if (!alive) return;
      if (p && p.state === "confirm") showCompare(p);
      else if (!flow.phoneAppDone) showPhoneApp(st);
      else showDetails(st);
    } catch (e) {
      body.replaceChildren(h("div.slip.slip-white", null, errorBlock(e, start)));
    }
  };
  setStep(flow.phoneAppDone ? "details" : "app");
  void start();

  return () => {
    alive = false;
    stopTimers();
  };
}
