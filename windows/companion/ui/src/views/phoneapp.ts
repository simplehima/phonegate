// "Get the phone app" (feature 003, FR-307): where PhoneGate.apk is, how to move it to the phone,
// and its fingerprints so the owner can check they have the genuine file.

import { apkInfo, previewMode, revealApk, type ApkInfo } from "../agent";
import { busy, button, h, icon, notice, stamp } from "../dom";
import { explain } from "../copy";
import { errorBlock, skeleton } from "./common";

/** 64 hex chars as 16 groups of 4, in two rows of 8, for comparing by eye. */
function fingerprint(hex: string): HTMLElement {
  const groups = hex.toUpperCase().match(/.{1,4}/g) ?? [];
  return h(
    "p.fingerprint",
    null,
    h("span.fp-row", null, groups.slice(0, 8).join(" ")),
    h("span.fp-row", null, groups.slice(8).join(" ")),
  );
}

function fpBlock(label: string, hex: string): HTMLElement {
  const msg = h("span.copy-msg", { role: "status" });
  const copy = button("Copy", { kind: "quiet", icon: "copy" });
  copy.setAttribute("aria-label", `Copy ${label}`);
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(hex.toLowerCase());
      msg.textContent = "Copied.";
    } catch {
      msg.textContent = "Couldn't copy. Select the text and copy it instead.";
    }
  });
  return h("div.fp-block", null, h("div.fp-head", null, h("p.label", null, label), copy), fingerprint(hex), msg);
}

const STEPS = () =>
  h(
    "ol.big-steps",
    null,
    h(
      "li",
      null,
      h("h3", null, "Copy PhoneGate.apk to your phone"),
      h(
        "ul.ways",
        null,
        h("li", null, h("strong", null, "USB cable: "), "connect the phone, choose File transfer on it, and drag the file into its Download folder."),
        h("li", null, h("strong", null, "Quick Share or Nearby Share: "), "right-click the file, choose Share, and pick your phone."),
        h("li", null, h("strong", null, "Cloud drive: "), "put the file in OneDrive, Google Drive or similar, then download it on the phone."),
      ),
    ),
    h("li", null, h("h3", null, "Open it on your phone"), h("p", null, "Tap the file in your Files app or downloads. When Android asks, allow ", h("strong", null, "Install unknown apps"), " for that app.")),
    h("li", null, h("h3", null, "Install, then open PhoneGate"), h("p", null, "Tap Install. When it's done, open PhoneGate and come back here to pair.")),
  );

/**
 * Renders the step into `body`. `onContinue` moves on to pairing. The same content serves the
 * normal, missing and changed-file states.
 */
export function phoneAppStep(body: HTMLElement, onContinue: () => void, isAlive: () => boolean): void {
  body.replaceChildren(h("div.slip.slip-white", null, skeleton(6)));

  const render = (info: ApkInfo) => {
    const cont = button("I have the app, continue", { kind: "primary", icon: "arrow-right", onClick: onContinue });
    const actionMsg = h("div");
    const show = button("Show the file", { kind: "secondary", icon: "folder" });
    show.addEventListener("click", () =>
      busy(show, async () => {
        actionMsg.replaceChildren();
        try {
          await revealApk();
          if (previewMode) actionMsg.replaceChildren(notice("info", "Preview: File Explorer would open here with PhoneGate.apk selected."));
        } catch (e) {
          actionMsg.replaceChildren(errorBlock(e));
        }
      }),
    );

    if (info.found && info.reason === "changed") {
      body.replaceChildren(
        h(
          "div.slip.slip-pink.apk-slip",
          { role: "alert" },
          h("div.slip-head", null, h("h2.slip-title", null, "Get the phone app"), info.version ? h("span.slip-pc", null, `Version ${info.version}`) : null),
          stamp("Don't install", "bad", "x", "lg"),
          h("p.apk-lead", null, "This file changed after installation. Don't install it; reinstall PhoneGate."),
          h("p", null, "The copy of PhoneGate.apk on this PC no longer matches the fingerprint recorded when PhoneGate was built. Someone or something modified or replaced it."),
          info.sha256 ? fpBlock("Fingerprint of the file now (SHA-256)", info.sha256) : null,
          info.expected_sha256 ? fpBlock("Fingerprint it should have (SHA-256)", info.expected_sha256) : null,
          h("div.slip-actions", null, button("Continue without it", { kind: "quiet", icon: "arrow-right", onClick: onContinue })),
        ),
      );
      return;
    }

    if (!info.found) {
      body.replaceChildren(
        h(
          "div.slip.slip-white.apk-slip",
          null,
          h("div.slip-head", null, h("h2.slip-title", null, "Get the phone app")),
          notice(
            "warn",
            info.reason === "not_in_app" ? "The phone app is only available inside the PhoneGate app." : "The phone app isn't in this installation.",
            "This may be a developer build, or the Android folder was removed. Reinstall PhoneGate with the setup program, or build and sign the APK yourself as described in the README.",
          ),
          h("div.slip-actions", null, cont),
        ),
      );
      return;
    }

    const unverified = !info.verified;
    body.replaceChildren(
      h(
        "div.slip.slip-white.apk-slip",
        null,
        h("div.slip-head", null, h("h2.slip-title", null, "Get the phone app"), info.version ? h("span.slip-pc", null, `Version ${info.version}`) : null),
        h(
          "div.apk-grid",
          null,
          h("div.apk-steps", null, STEPS()),
          h(
            "div.apk-check",
            null,
            h("h3.sub-title", null, icon("shield-check"), h("span", null, "Check you have the genuine file")),
            unverified
              ? notice("warn", "PhoneGate couldn't check this file against its build record.", `The record next to it is missing or unreadable (${info.reason ?? "unknown"}). Compare the fingerprint below with the one published with the release before installing.`)
              : h("p.verified-line", null, icon("check"), h("span", null, "Matches the fingerprint recorded when this PhoneGate was built.")),
            previewMode ? h("p.help", null, "Preview data: these fingerprints are made up.") : null,
            info.sha256 ? fpBlock("App fingerprint (SHA-256)", info.sha256) : null,
            info.signer_sha256 ? fpBlock("Signed by (certificate SHA-256)", info.signer_sha256) : null,
            h(
              "p.help",
              null,
              "After installing, some phones show the signer in Settings > Apps > PhoneGate > App details. Compare both fingerprints with the ones published with the release. Letter case and separators may differ.",
            ),
          ),
        ),
        h("hr.perf"),
        h("div.slip-actions", null, cont, show),
        actionMsg,
      ),
    );
  };

  apkInfo()
    .then((info) => {
      if (isAlive()) render(info);
    })
    .catch((e) => {
      if (!isAlive()) return;
      const ex = explain(e);
      body.replaceChildren(h("div.slip.slip-white", null, notice("error", ex.title, ex.body, button("Continue", { kind: "primary", onClick: onContinue }))));
    });
}
