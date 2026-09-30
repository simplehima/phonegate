import { agent, type ReqState } from "../agent";
import { announce, busy, button, h, nextId, notice, stamp } from "../dom";
import { duration, explain } from "../copy";
import { go } from "../nav";
import { store } from "../store";
import { countdown, errorBlock, page, skeleton } from "./common";

const OUTCOME: Record<Exclude<ReqState, "pending" | "approved">, { title: string; body: string }> = {
  denied: { title: "Your phone denied the request.", body: "Protection stays on. Ask again, or use a recovery code." },
  not_me: { title: "Your phone marked this as \"This wasn't me\".", body: "Protection stays on and the attempt is logged as suspicious. If it was you, ask again and type the number shown here." },
  expired: { title: "The request expired before your phone answered.", body: "Requests last 60 seconds. Ask again, or use a recovery code." },
  error: { title: "Your phone's answer didn't check out.", body: "Protection stays on. Ask again; if this repeats, unpair and pair your phone again once protection is off." },
};

export function turnOffView(root: HTMLElement): () => void {
  const section = page(root, "Turn off protection", "Turning protection off needs your phone's approval or one of your recovery codes, so nobody sitting at this PC can switch it off.", "page-turnoff");
  const layout = h("div.turnoff-grid");
  const phoneCol = h("div.turnoff-phone");
  const codeCol = h("div.turnoff-code");
  layout.append(phoneCol, codeCol);
  section.append(layout);

  let alive = true;
  let gen = 0;
  let tick = 0;
  const stop = () => {
    gen += 1;
    window.clearInterval(tick);
  };

  const finished = (how: string) => {
    stop();
    void store.refresh();
    announce("Protection is off.");
    const back = button("Back to status", { kind: "primary", icon: "arrow-left", onClick: () => go("status") });
    layout.replaceChildren(
      h(
        "div.slip.slip-white.done-slip",
        null,
        stamp("Protection off", "alert", "shield-off", "lg"),
        h("h2", null, "Protection is off"),
        h("p", null, `${how} Windows now signs in without asking your phone. Turn protection back on from Status when you're done.`),
        h("div.slip-actions", null, back),
      ),
    );
    requestAnimationFrame(() => back.focus());
  };

  // ---------------------------------------------------------------- phone approval
  const phoneIdle = (msg?: HTMLElement) => {
    stop();
    const ask = button("Ask my phone", { kind: "primary", icon: "phone" });
    ask.addEventListener("click", () => busy(ask, begin));
    phoneCol.replaceChildren(
      h(
        "div.slip.slip-white",
        null,
        h("h2.slip-title", null, "Ask your phone"),
        h("p", null, "Your phone gets a request with a 2-digit number. Type the number shown here on the phone, then use your fingerprint."),
        msg ?? null,
        h("div.slip-actions", null, ask),
      ),
    );
  };

  const begin = async () => {
    try {
      const r = await agent.disableBegin();
      if (!alive) return;
      if (r.already_off) {
        finished("It was already off.");
        return;
      }
      showNumber(r.req!, r.number ?? 0, r.expires_in_s ?? 60);
    } catch (e) {
      phoneIdle(errorBlock(e));
    }
  };

  const showNumber = (req: string, number: number, expiresS: number) => {
    stop();
    const my = gen;
    const total = expiresS * 1000;
    const cd = countdown(total, Date.now() + total, (s) => (s > 0 ? `${s} s left` : "Expired"));
    const digits = String(number).padStart(2, "0");
    const cancel = button("Stop waiting", { kind: "quiet", onClick: () => phoneIdle() });
    phoneCol.replaceChildren(
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
          state = (await agent.disableWait(req)).state;
        } catch (e) {
          if (my === gen) phoneIdle(errorBlock(e));
          return;
        }
        if (!alive || my !== gen) return;
        if (state === "pending") continue;
        if (state === "approved") return finished("Your phone approved it.");
        const o = OUTCOME[state];
        phoneIdle(notice(state === "not_me" || state === "error" ? "error" : "warn", o.title, o.body));
        return;
      }
    };
    void loop();
  };

  // ---------------------------------------------------------------- recovery code
  const codeForm = () => {
    const id = nextId("code");
    const input = h("input.input.mono-input.code-input", {
      id,
      type: "text",
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "characters",
      placeholder: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX",
      "aria-describedby": `${id}-help ${id}-err`,
    });
    const err = h("p.field-error", { id: `${id}-err`, role: "alert" });
    const use = button("Use recovery code", { kind: "secondary", type: "submit", icon: "key" });
    const form = h(
      "form.slip.slip-white",
      { novalidate: true },
      h("div.slip-head", null, h("h2.slip-title", null, "Use a recovery code"), h("span.slip-pc", null, "Phone unavailable")),
      h("p", null, "Use this if your phone is lost, flat or offline. The code is used up."),
      h("div.form-row", null, h("label.label", { for: id }, "Recovery code"), input, h("p.help", { id: `${id}-help` }, "Dashes, spaces and letter case don't matter."), err),
      h("div.slip-actions", null, use),
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const v = input.value.trim();
      if (!v) {
        err.textContent = "Type one of your recovery codes first.";
        input.setAttribute("aria-invalid", "true");
        return input.focus();
      }
      void busy(use, async () => {
        err.textContent = "";
        try {
          const r = await agent.disableRecovery(v);
          if (r.valid) {
            finished(`A recovery code was used; ${r.remaining} remain${r.remaining === 1 ? "s" : ""}.`);
            return;
          }
          input.setAttribute("aria-invalid", "true");
          err.textContent =
            r.locked_s > 0
              ? `Too many wrong codes. Code entry is locked for ${duration(r.locked_s)}; the wait grows with each lockout.`
              : "That code isn't valid or was already used. Check for typos and try another unused code.";
          input.select();
        } catch (e2) {
          const ex = explain(e2);
          err.textContent = `${ex.title} ${ex.body}`;
        }
      });
    });
    codeCol.replaceChildren(form);
  };

  const start = async () => {
    phoneCol.replaceChildren(h("div.slip.slip-white", null, skeleton(4)));
    try {
      const st = await agent.status();
      if (!alive) return;
      if (!st.enforce) {
        layout.replaceChildren(
          h(
            "div.slip.slip-white",
            null,
            h("p.empty-lead", null, "Protection is already off."),
            h("div.slip-actions", null, button("Back to status", { kind: "primary", icon: "arrow-left", onClick: () => go("status") })),
          ),
        );
        return;
      }
      phoneIdle(st.relay === "down" ? notice("warn", "The relay server is unreachable right now.", "Your phone may not get the request. Use a recovery code if it doesn't arrive.") : undefined);
      codeForm();
    } catch (e) {
      phoneCol.replaceChildren(h("div.slip.slip-white", null, errorBlock(e, start)));
    }
  };
  void start();

  return () => {
    alive = false;
    stop();
  };
}
