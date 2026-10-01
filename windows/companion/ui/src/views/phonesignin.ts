import { agent, type ReqState, type Status } from "../agent";
import { announce, busy, button, h, nextId, notice, stamp } from "../dom";
import { explain } from "../copy";
import { go } from "../nav";
import { countdown, errorBlock, page, skeleton } from "./common";
import { confirmDialog } from "./dialog";

const OUTCOME: Record<Exclude<ReqState, "pending" | "approved">, { title: string; body: string }> = {
  denied: { title: "Your phone denied the request.", body: "Phone sign-in stays off and no password was kept. Start again when you're ready." },
  not_me: { title: "Your phone marked this as \"This wasn't me\".", body: "Phone sign-in stays off and no password was kept." },
  expired: { title: "The request expired before your phone answered.", body: "Requests last 60 seconds. No password was kept. Start again." },
  error: { title: "Your phone's answer didn't check out.", body: "Phone sign-in stays off and no password was kept. Try again." },
};

/**
 * Opt-in "approve on your phone, no password" sign-in (feature 004). The password is typed here
 * once, sent over the admin-only pipe, wrapped by the PC's TPM, and never shown again.
 */
export function phoneSignInView(root: HTMLElement): () => void {
  const section = page(
    root,
    "Phone sign-in",
    "Sign in to Windows by approving on your phone, without typing your password. Off by default, per PC.",
    "page-phonesignin",
  );
  const body = h("div.settings-body");
  section.append(body);

  let alive = true;
  let gen = 0;
  let tick = 0;
  const stop = () => {
    gen += 1;
    window.clearInterval(tick);
  };

  // -------------------------------------------------------------------- password helpers
  const pwField = (label: string, help?: string) => {
    const id = nextId("pw");
    const input = h("input.input", { id, type: "password", autocomplete: "off", spellcheck: "false", "aria-describedby": `${id}-help ${id}-err` });
    const err = h("p.field-error", { id: `${id}-err`, role: "alert" });
    const row = h("div.form-row", null, h("label.label", { for: id }, label), input, h("p.help", { id: `${id}-help` }, help ?? ""), err);
    return { input, err, row };
  };

  /** Two matching, non-empty entries, or an inline error and null. */
  const readPasswords = (a: ReturnType<typeof pwField>, b: ReturnType<typeof pwField>): string | null => {
    a.err.textContent = "";
    b.err.textContent = "";
    a.input.removeAttribute("aria-invalid");
    b.input.removeAttribute("aria-invalid");
    if (!a.input.value) {
      a.err.textContent = "Type your Windows password.";
      a.input.setAttribute("aria-invalid", "true");
      a.input.focus();
      return null;
    }
    if (a.input.value !== b.input.value) {
      b.err.textContent = "The two entries don't match.";
      b.input.setAttribute("aria-invalid", "true");
      b.input.focus();
      return null;
    }
    return a.input.value;
  };

  // -------------------------------------------------------------------- off: explain, collect, arm
  const renderOff = (st: Status, msg?: HTMLElement) => {
    stop();
    const ack = h("input.check", { type: "checkbox", id: "pw-ack" }) as HTMLInputElement;
    const account = h("input.input", { id: "pw-account", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "PC-NAME\\your-user", "aria-describedby": "pw-account-help pw-account-err" });
    const accountErr = h("p.field-error", { id: "pw-account-err", role: "alert" });
    const p1 = pwField("Windows password", "Used only to sign you in. Stored on this PC, wrapped by the TPM when there is one.");
    const p2 = pwField("Type it again");
    const start = button("Turn on, then approve on my phone", { kind: "primary", type: "submit", icon: "phone" });
    const form = h(
      "form.slip.slip-white.settings-card",
      { novalidate: true, "aria-labelledby": "pw-h" },
      h("h2#pw-h", null, "Turn on phone sign-in"),
      notice(
        "warn",
        "What you are trading",
        "With this on, approving on your phone is enough to sign in, and your password is kept on this PC. Anyone who can make your phone approve, or who can pull the key out of this PC's hardware, could sign in. If you can, leave it off.",
      ),
      h("div.form-row", null, h("label.check-row", { for: "pw-ack" }, ack, h("span", null, "I understand this trade and want it on for this PC."))),
      h(
        "div.form-row",
        null,
        h("label.label", { for: "pw-account" }, "Windows account"),
        account,
        h("p.help", { id: "pw-account-help" }, "Exactly as you sign in, for example PC-NAME\\maya. Microsoft accounts use the email address."),
        accountErr,
      ),
      p1.row,
      p2.row,
      msg ?? null,
      h("div.slip-actions", null, start),
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      accountErr.textContent = "";
      if (!ack.checked) {
        ack.focus();
        announce("Tick the box to confirm you understand the trade.");
        return;
      }
      if (!account.value.trim()) {
        accountErr.textContent = "Type the account you sign in with.";
        account.setAttribute("aria-invalid", "true");
        return account.focus();
      }
      const pw = readPasswords(p1, p2);
      if (pw === null) return;
      void busy(start, async () => {
        try {
          const r = await agent.passwordlessEnable(account.value.trim(), pw);
          // The password has left this window; do not keep it in the DOM.
          p1.input.value = "";
          p2.input.value = "";
          if (alive) showNumber(st, r.req, r.number, r.expires_in_s ?? 60);
        } catch (e2) {
          renderOff(st, errorBlock(e2));
        }
      });
    });
    body.replaceChildren(form);
  };

  const showNumber = (st: Status, req: string, number: number, expiresS: number) => {
    stop();
    const my = gen;
    const total = expiresS * 1000;
    const cd = countdown(total, Date.now() + total, (s) => (s > 0 ? `${s} s left` : "Expired"));
    const digits = String(number).padStart(2, "0");
    const cancel = button("Stop waiting", { kind: "quiet", onClick: () => renderOff(st) });
    body.replaceChildren(
      h(
        "div.slip.slip-live.approve-slip",
        null,
        h("p.approve-lead", null, "Type this number on your phone:"),
        h("p.badge-number", { "aria-label": `Number ${digits.split("").join(" ")}` }, ...digits.split("").map((d) => h("span.badge-cell", { "aria-hidden": "true" }, d))),
        cd.el,
        h("p.scan-state", { role: "status" }, h("span.pulse", { "aria-hidden": "true" }), "Waiting for your phone..."),
        h("div.slip-actions", null, cancel),
      ),
    );
    announce(`Type ${digits.split("").join(" ")} on your phone.`);
    tick = window.setInterval(() => cd.tick(), 1000);
    const loop = async () => {
      while (alive && my === gen) {
        let state: ReqState;
        try {
          state = (await agent.passwordlessEnableWait(req)).state;
        } catch (e) {
          if (my === gen) renderOff(st, errorBlock(e));
          return;
        }
        if (!alive || my !== gen) return;
        if (state === "pending") continue;
        if (state === "approved") {
          announce("Phone sign-in is on.");
          void load();
          return;
        }
        const o = OUTCOME[state];
        renderOff(st, notice(state === "not_me" || state === "error" ? "error" : "warn", o.title, o.body));
        return;
      }
    };
    void loop();
  };

  // -------------------------------------------------------------------- on: status, update, turn off
  const renderOn = (account: string | undefined) => {
    stop();
    const n1 = pwField("New Windows password", "Use this after you change your password in Windows. Without it, the old one fails and Windows asks you to type it.");
    const n2 = pwField("Type it again");
    const msg = h("div");
    const save = button("Update stored password", { kind: "secondary", type: "submit", icon: "key" });
    const updateForm = h(
      "form.slip.slip-white.settings-card",
      { novalidate: true, "aria-labelledby": "pw-upd-h" },
      h("h2#pw-upd-h", null, "Changed your Windows password?"),
      n1.row,
      n2.row,
      h("div.slip-actions", null, save),
      msg,
    );
    updateForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const pw = readPasswords(n1, n2);
      if (pw === null) return;
      void busy(save, async () => {
        msg.replaceChildren();
        try {
          await agent.passwordlessUpdatePassword(pw);
          n1.input.value = "";
          n2.input.value = "";
          msg.replaceChildren(notice("ok", "Stored password updated.", "The next phone sign-in uses the new one."));
          announce("Stored password updated.");
        } catch (e2) {
          msg.replaceChildren(errorBlock(e2));
        }
      });
    });

    const offMsg = h("div");
    const off = button("Turn off phone sign-in", { kind: "danger", icon: "shield-off" });
    off.addEventListener("click", async () => {
      const ok = await confirmDialog({
        title: "Turn off phone sign-in?",
        body: "The stored password is erased from this PC. You'll type your password and approve on your phone, as before. No approval is needed to do this, because it only makes sign-in stricter.",
        confirm: "Turn off",
        danger: true,
      });
      if (!ok) return;
      await busy(off, async () => {
        try {
          await agent.passwordlessDisable();
          announce("Phone sign-in is off.");
          void load();
        } catch (e2) {
          offMsg.replaceChildren(errorBlock(e2));
        }
      });
    });

    body.replaceChildren(
      h(
        "div.settings-grid",
        null,
        h(
          "section.slip.slip-white.settings-card",
          { "aria-labelledby": "pw-on-h" },
          stamp("Phone sign-in on", "ok", "check"),
          h("h2#pw-on-h", null, "Phone sign-in is on"),
          h("dl.fields", null, h("div.field", null, h("dt", null, "Account"), h("dd", null, h("span.ink", null, account ?? "Not shown")))),
          h("p", null, "Approve on your phone and Windows signs in. If the stored password is ever wrong, Windows asks you to type it or use a recovery code. You are not locked out."),
          h("div.slip-actions", null, off),
          offMsg,
        ),
        updateForm,
      ),
    );
  };

  const load = async () => {
    if (!body.firstChild) body.append(h("div.slip.slip-white", null, skeleton(5)));
    try {
      const [st, pw] = await Promise.all([agent.status(), agent.passwordlessStatus()]);
      if (!alive) return;
      if (pw.on) return renderOn(pw.account);
      if (!st.paired) {
        body.replaceChildren(
          h(
            "div.slip.slip-white",
            null,
            h("p.empty-lead", null, "Pair a phone first."),
            h("p", null, "Phone sign-in needs a paired phone to approve each sign-in."),
            h("div.slip-actions", null, button("Pair a phone", { kind: "primary", icon: "pair", onClick: () => go("setup") })),
          ),
        );
        return;
      }
      renderOff(st);
    } catch (e) {
      const ex = explain(e);
      body.replaceChildren(h("div.slip.slip-white", null, notice("error", ex.title, ex.body, button("Try again", { icon: "refresh", onClick: () => void load() }))));
    }
  };
  void load();

  return () => {
    alive = false;
    stop();
  };
}
