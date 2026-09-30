import { agent, type AttemptRecord } from "../agent";
import { button, h, icon, stamp, type IconName } from "../dom";
import { errorBlock, page } from "./common";

type Tone = "ok" | "bad" | "alert" | "ink" | "muted";

/** Outcome strings written by windows/agent/src/engine.rs `history(...)`. */
export function outcomeStamp(outcome: string): { text: string; tone: Tone; icon: IconName; suspicious: boolean; note?: string } {
  if (outcome.startsWith("paired:")) return { text: "Paired", tone: "ink", icon: "link", suspicious: false, note: outcome.slice(7) };
  if (outcome.startsWith("repaired:")) return { text: "Repaired", tone: "alert", icon: "wrench", suspicious: true, note: repairLabel(outcome.slice(9)) };
  switch (outcome) {
    case "approved":
      return { text: "Approved", tone: "ok", icon: "check", suspicious: false };
    case "denied":
      return { text: "Denied", tone: "bad", icon: "x", suspicious: false };
    case "not_me":
      return { text: "Not me", tone: "alert", icon: "octagon", suspicious: true };
    case "wrong_number":
      return { text: "Wrong number", tone: "alert", icon: "hash", suspicious: true, note: "The phone typed a different number, so it was refused." };
    case "expired":
      return { text: "Expired", tone: "muted", icon: "timer-off", suspicious: false };
    case "error":
      return { text: "Failed check", tone: "bad", icon: "warning", suspicious: true, note: "The reply didn't verify and was refused." };
    case "recovery_code":
      return { text: "Recovery code", tone: "ink", icon: "key", suspicious: false };
    case "offline_code":
      return { text: "Offline code", tone: "ink", icon: "qr", suspicious: false };
    case "protection_enabled":
      return { text: "Protection on", tone: "ok", icon: "shield-check", suspicious: false };
    case "protection_disabled_by_phone":
      return { text: "Protection off", tone: "muted", icon: "shield-off", suspicious: false, note: "Approved on the phone." };
    case "protection_disabled_by_recovery_code":
      return { text: "Protection off", tone: "muted", icon: "shield-off", suspicious: false, note: "With a recovery code." };
    case "unpaired":
      return { text: "Unpaired", tone: "muted", icon: "unlink", suspicious: false, note: "From this PC." };
    case "netlogon_blocked":
      return { text: "Network sign-ins blocked", tone: "ok", icon: "network", suspicious: false };
    case "netlogon_unblocked":
      return { text: "Network sign-ins allowed", tone: "muted", icon: "network", suspicious: false };
    case "safe_mode":
      return { text: "Safe Mode", tone: "alert", icon: "warning", suspicious: true, note: "The PC started in Safe Mode." };
    case "unpaired_by_phone":
      return { text: "Unpaired", tone: "muted", icon: "unlink", suspicious: false, note: "From the phone." };
    default:
      return { text: outcome.replace(/_/g, " "), tone: "muted", icon: "info", suspicious: false };
  }
}

export function kindLabel(scenario: string): string {
  switch (scenario) {
    case "unlock":
      return "Unlock";
    case "logon":
      return "Sign-in";
    case "remote":
      return "Remote sign-in";
    case "disable-protection":
      return "Turn off protection";
    case "change-setting":
      return "Change a setting";
    case "pairing":
      return "Pairing";
    case "settings":
      return "Settings";
    case "unpair":
      return "Unpair";
    default:
      return scenario;
  }
}

/** Plain names for watchdog repair items. */
export function repairLabel(item: string): string {
  const names: Record<string, string> = {
    service: "PhoneGate service",
    credential_provider: "Sign-in tile registration",
    cp: "Sign-in tile registration",
    filter: "Sign-in filter registration",
    credential_provider_filter: "Sign-in filter registration",
    files: "Program files",
    binaries: "Program files",
    safe_mode: "Safe Mode registration",
    watchdog: "Watchdog task",
  };
  return names[item] ?? item.replace(/_/g, " ");
}

const dayFmt = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short" });
const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });

export function historyView(root: HTMLElement): () => void {
  const section = page(root, "History", "Every unlock, sign-in and setting change on this PC, newest first. Your phone keeps the same log. Entries are kept for 90 days.", "page-history");
  let filter: "all" | "attention" = "all";
  let items: AttemptRecord[] | null = null;
  const toolbar = h("div.history-tools");
  const body = h("div.logbook-wrap");
  section.append(toolbar, body);
  let alive = true;

  const renderToolbar = () => {
    const count = items?.filter((i) => outcomeStamp(i.outcome).suspicious).length ?? 0;
    const seg = (id: typeof filter, label: string) =>
      h(
        "button.seg",
        {
          type: "button",
          "aria-pressed": String(filter === id),
          onclick: () => {
            filter = id;
            renderToolbar();
            renderRows();
          },
        },
        label,
      );
    const refresh = button("Refresh", { kind: "quiet", icon: "refresh", onClick: () => void load() });
    toolbar.replaceChildren(h("div.segmented", { role: "group", "aria-label": "Show" }, seg("all", "All entries"), seg("attention", count ? `Suspicious (${count})` : "Suspicious")), refresh);
  };

  const renderRows = () => {
    if (!items) return;
    const rows = filter === "all" ? items : items.filter((i) => outcomeStamp(i.outcome).suspicious);
    if (!rows.length) {
      body.replaceChildren(
        h(
          "div.slip.slip-white.empty-log",
          null,
          icon("book"),
          filter === "all"
            ? h("div", null, h("h2", null, "The logbook is empty"), h("p", null, "Once protection is on, every unlock, sign-in and Remote Desktop sign-in is written here with the account, the kind of sign-in and how it ended. Pairing and setting changes are logged too."))
            : h("div", null, h("h2", null, "Nothing suspicious"), h("p", null, "Attempts you marked \"This wasn't me\", wrong numbers and replies that failed their check would appear here.")),
        ),
      );
      return;
    }
    const table = h(
      "table.logbook",
      null,
      h("caption.sr-only", null, "Sign-in history, newest first"),
      h("thead", null, h("tr", null, h("th", { scope: "col" }, "When"), h("th", { scope: "col" }, "Account"), h("th", { scope: "col" }, "Kind"), h("th", { scope: "col" }, "Outcome"))),
    );
    const tbody = h("tbody");
    let lastDay = "";
    for (const r of rows) {
      const d = new Date(r.at);
      const day = dayFmt.format(d);
      const o = outcomeStamp(r.outcome);
      const tr = h(
        "tr",
        { class: o.suspicious ? "row-suspicious" : "" },
        h("td.when", null, h("span.when-day", { class: day === lastDay ? "same-day" : "" }, day), h("span.when-time", null, timeFmt.format(d))),
        h("td.acct", null, r.account ? h("span.ink", null, r.account) : h("span.value-empty", null, "No account")),
        h("td.kind", null, kindLabel(r.scenario)),
        h("td.outcome", null, stamp(o.text, o.tone, o.icon), o.note ? h("span.outcome-note", null, o.note) : null),
      );
      lastDay = day;
      tbody.append(tr);
    }
    table.append(tbody);
    body.replaceChildren(h("div.slip.slip-white.logbook-slip", null, table));
  };

  const load = async () => {
    if (!items) body.replaceChildren(h("div.slip.slip-white.logbook-slip", null, h("div.skeleton-rows", { "aria-hidden": "true" }, ...Array.from({ length: 6 }, () => h("span.skeleton-line")))));
    try {
      const r = await agent.history(1000);
      if (!alive) return;
      items = r.items;
      renderToolbar();
      renderRows();
    } catch (e) {
      body.replaceChildren(h("div.slip.slip-white", null, errorBlock(e, () => void load())));
    }
  };
  renderToolbar();
  void load();
  return () => {
    alive = false;
  };
}
