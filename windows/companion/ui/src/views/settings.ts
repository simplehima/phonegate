import { agent, appInfo, openLink, type LinkKind, type Status } from "../agent";
import { announce, busy, button, h, icon, nextId, notice } from "../dom";
import { explain, validatePcName, validateRelayUrl } from "../copy";
import { go } from "../nav";
import { store } from "../store";
import { confirmDialog } from "./dialog";
import { errorBlock, page, skeleton } from "./common";
import { checkUpdateNow, setUpdateCheckEnabled, updateCheckEnabled } from "../updates";

export function settingsView(root: HTMLElement): () => void {
  const section = page(root, "Settings", undefined, "page-settings");
  const body = h("div.settings-body");
  section.append(body);
  let alive = true;

  const render = (st: Status) => {
    const locked = st.enforce;
    const lockNote = (text: string, id: string) => h("p.lock-note", { id }, icon("lock"), h("span", null, text));

    // PC name ---------------------------------------------------------------------------------
    const nameId = nextId("name");
    const nameErr = h("p.field-error", { id: `${nameId}-err`, role: "alert" });
    const nameMsg = h("div");
    const nameInput = h("input.input", { id: nameId, type: "text", maxlength: "64", value: st.pc_name, disabled: locked, "aria-describedby": `${nameId}-help ${nameId}-err${locked ? " name-lock" : ""}` });
    const saveName = button("Save name", { kind: "primary", type: "submit", disabled: locked });
    const nameForm = h(
      "form.slip.slip-white.settings-card",
      { novalidate: true, "aria-labelledby": "set-name-h" },
      h("h2#set-name-h", null, "PC name"),
      h("div.form-row", null, h("label.label", { for: nameId }, "Name shown on your phone"), nameInput, h("p.help", { id: `${nameId}-help` }, "Every request on your phone starts with this name."), nameErr),
      locked ? lockNote("Locked while protection is on. Turn protection off to rename this PC.", "name-lock") : null,
      locked ? null : h("div.slip-actions", null, saveName),
      nameMsg,
    );
    nameForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const err = validatePcName(nameInput.value);
      nameErr.textContent = err ?? "";
      nameInput.setAttribute("aria-invalid", String(!!err));
      if (err) return nameInput.focus();
      void busy(saveName, async () => {
        nameMsg.replaceChildren();
        try {
          await agent.settings({ pc_name: nameInput.value.trim() });
          await store.refresh();
          nameMsg.replaceChildren(notice("ok", "Name saved.", "Your phone shows the new name on the next request."));
          announce("PC name saved.");
        } catch (e2) {
          nameMsg.replaceChildren(errorBlock(e2));
        }
      });
    });

    // Relay -----------------------------------------------------------------------------------
    const relayLocked = locked || st.paired;
    const relayId = nextId("relay");
    const relayErr = h("p.field-error", { id: `${relayId}-err`, role: "alert" });
    const relayMsg = h("div");
    const relayInput = h("input.input.mono-input", {
      id: relayId,
      type: "url",
      value: st.relay_url,
      placeholder: "https://relay.example.com",
      spellcheck: "false",
      autocomplete: "off",
      disabled: relayLocked,
      "aria-describedby": `${relayId}-help ${relayId}-err${relayLocked ? " relay-lock" : ""}`,
    });
    const saveRelay = button("Save relay", { kind: "primary", type: "submit", disabled: relayLocked });
    const relayForm = h(
      "form.slip.slip-white.settings-card",
      { novalidate: true, "aria-labelledby": "set-relay-h" },
      h("h2#set-relay-h", null, "Relay server"),
      h(
        "div.form-row",
        null,
        h("label.label", { for: relayId }, "Relay address"),
        relayInput,
        h("p.help", { id: `${relayId}-help` }, st.relay_url ? (st.relay === "up" ? "Connected." : "Not reachable right now.") : "Not set."),
        relayErr,
      ),
      relayLocked
        ? lockNote(
            locked
              ? "Locked while protection is on. Your phone is paired through this relay; changing it needs protection off and a new pairing."
              : "Locked while a phone is paired, because the pairing is tied to this relay. Unpair below, change the relay, then pair again.",
            "relay-lock",
          )
        : null,
      relayLocked ? null : h("div.slip-actions", null, saveRelay),
      relayMsg,
    );
    relayForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const err = validateRelayUrl(relayInput.value);
      relayErr.textContent = err ?? "";
      relayInput.setAttribute("aria-invalid", String(!!err));
      if (err) return relayInput.focus();
      void busy(saveRelay, async () => {
        relayMsg.replaceChildren();
        try {
          await agent.settings({ relay_url: relayInput.value.trim().replace(/\/+$/, "") });
          await store.refresh();
          relayMsg.replaceChildren(notice("ok", "Relay saved.", "PhoneGate reconnects to the new address now."));
        } catch (e2) {
          relayMsg.replaceChildren(errorBlock(e2));
        }
      });
    });

    // Pairing ---------------------------------------------------------------------------------
    const unpairMsg = h("div");
    const unpair = button("Unpair phone", { kind: "danger", icon: "unlink", disabled: !st.paired || locked, describedBy: locked ? "unpair-lock" : undefined });
    unpair.addEventListener("click", async () => {
      const ok = await confirmDialog({
        title: `Unpair ${st.phone_name ?? "this phone"}?`,
        body: "The phone is told it's no longer paired and this PC forgets its keys. Your recovery codes stop mattering until you pair again. You'll need to pair and save new codes before protection can be turned on.",
        confirm: "Unpair",
        danger: true,
      });
      if (!ok) return;
      await busy(unpair, async () => {
        try {
          await agent.unpair();
          await store.refresh();
          announce("Phone unpaired.");
          void load();
        } catch (e2) {
          unpairMsg.replaceChildren(errorBlock(e2));
        }
      });
    });
    const pairCard = h(
      "section.slip.slip-white.settings-card",
      { "aria-labelledby": "set-pair-h" },
      h("h2#set-pair-h", null, "Paired phone"),
      st.paired
        ? h(
            "dl.fields",
            null,
            h("div.field", null, h("dt", null, "Phone"), h("dd", null, h("span.ink", null, st.phone_name ?? "Unnamed phone"))),
            h("div.field", null, h("dt", null, "Hardware key"), h("dd", null, st.attestation?.status === "verified" ? "Verified" : `Not verified${st.attestation?.status === "unverified" ? `: ${st.attestation.reason}` : ""}`)),
          )
        : h("p", null, "No phone is paired."),
      locked && st.paired ? lockNote("Turn protection off before unpairing.", "unpair-lock") : null,
      h(
        "div.slip-actions",
        null,
        st.paired ? unpair : button("Pair a phone", { kind: "primary", icon: "pair", onClick: () => go("setup") }),
        locked && st.paired ? button("Turn off protection", { kind: "quiet", icon: "shield-off", onClick: () => go("turn-off") }) : null,
      ),
      unpairMsg,
    );

    // Updates ---------------------------------------------------------------------------------
    const updId = nextId("upd");
    const updBox = h("input.check", { id: updId, type: "checkbox", checked: updateCheckEnabled(), "aria-describedby": `${updId}-help` });
    updBox.addEventListener("change", () => {
      setUpdateCheckEnabled(updBox.checked);
      announce(updBox.checked ? "Update checks on." : "Update checks off.");
    });
    const updResult = h("div.update-result", { role: "status", "aria-live": "polite" });
    const checkNow = button("Check now", { kind: "secondary", icon: "refresh" });
    checkNow.addEventListener("click", () => {
      void busy(checkNow, async () => {
        updResult.replaceChildren(h("p.loading-line", null, h("span.spinner", { "aria-hidden": "true" }), "Checking GitHub..."));
        const u = await checkUpdateNow();
        if (!u.ok) {
          updResult.replaceChildren(notice("warn", "Couldn't reach GitHub.", "Check your connection and try again."));
        } else if (u.newer) {
          updResult.replaceChildren(
            notice("info", `PhoneGate ${(u.latest ?? "").replace(/^v/i, "")} is available`, `You have ${u.current}.`, button("Open releases page", { kind: "secondary", icon: "arrow-right", onClick: () => void openLink("releases") })),
          );
        } else {
          updResult.replaceChildren(notice("ok", "You have the latest version.", u.current ? `PhoneGate ${u.current}.` : undefined));
        }
        announce("Update check finished.");
      });
    });
    const updates = h(
      "section.slip.slip-white.settings-card",
      { "aria-labelledby": "set-upd-h" },
      h("h2#set-upd-h", null, "Updates"),
      h("label.check-row", { for: updId }, updBox, h("span", null, "Check for a newer PhoneGate when this app opens")),
      h("p.help", { id: `${updId}-help` }, "This is the only time PhoneGate contacts anything besides your relay: one request to GitHub for the latest release number. It never downloads or installs anything by itself."),
      h("div.slip-actions", null, checkNow),
      updResult,
    );

    // About + help -----------------------------------------------------------------------------
    const verDd = h("dd", null, h("span.ink", null, "Loading..."));
    void appInfo().then((i) => {
      verDd.replaceChildren(h("span.ink", null, i.version || "unknown"));
    });
    const link = (label: string, kind: LinkKind) => button(label, { kind: "quiet", icon: "arrow-right", onClick: () => void openLink(kind) });
    const aboutApp = h(
      "section.slip.slip-white.settings-card",
      { "aria-labelledby": "set-app-h" },
      h("h2#set-app-h", null, "About PhoneGate"),
      h(
        "dl.fields",
        null,
        h("div.field", null, h("dt", null, "Version"), verDd),
        h("div.field", null, h("dt", null, "Licence"), h("dd", null, "Apache License 2.0")),
        h("div.field", null, h("dt", null, "Source"), h("dd", null, h("span.pc-id", null, "github.com/simplehima/phonegate"))),
      ),
      h("p", null, "PhoneGate is free, open source software. Nothing in it is secret: every key is made on your own devices."),
      h("div.link-list", null, link("Project page on GitHub", "repo"), link("Release notes and downloads", "releases"), link("Licence (Apache 2.0)", "license"), link("Report a bug", "issues"), link("Report a security problem privately", "security")),
    );

    // About -----------------------------------------------------------------------------------
    const about = h(
      "section.slip.slip-white.settings-card",
      { "aria-labelledby": "set-about-h" },
      h("h2#set-about-h", null, "This PC"),
      h(
        "dl.fields",
        null,
        h("div.field", null, h("dt", null, "PC keys"), h("dd", null, st.key_backend === "tpm" ? "Stored in the TPM" : "Stored in software (no TPM)")),
        h("div.field", null, h("dt", null, "PC ID"), h("dd", null, h("span.num.pc-id", null, st.pc_id))),
      ),
      h("p.help", null, "PhoneGate is open source. Fonts: Archivo and JetBrains Mono (SIL Open Font License). Icons: Lucide (ISC). License texts ship with the app in the licenses folder."),
    );

    body.replaceChildren(h("div.settings-grid", null, nameForm, relayForm, pairCard, updates, aboutApp, about));
  };

  const load = async () => {
    if (!body.firstChild) body.append(h("div.slip.slip-white", null, skeleton(5)));
    try {
      const st = await agent.status();
      if (alive) render(st);
    } catch (e) {
      const ex = explain(e);
      body.replaceChildren(h("div.slip.slip-white", null, notice("error", ex.title, ex.body, button("Try again", { icon: "refresh", onClick: () => void load() }))));
    }
  };
  void load();
  return () => {
    alive = false;
  };
}
