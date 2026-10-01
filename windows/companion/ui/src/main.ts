import "./styles.css";
import { previewMode } from "./agent";
import { h, icon, type IconName } from "./dom";
import { store } from "./store";
import { statusView } from "./views/status";
import { setupView } from "./views/setup";
import { recoveryView } from "./views/recovery";
import { turnOffView } from "./views/turnoff";
import { historyView } from "./views/history";
import { settingsView } from "./views/settings";
import { hardeningView } from "./views/hardening";
import { phoneSignInView } from "./views/phonesignin";
import { updateBanner } from "./updates";

export type Cleanup = () => void;
export type View = (root: HTMLElement) => Cleanup | void;

interface Route {
  path: string;
  label: string;
  icon: IconName;
  view: View;
  nav: boolean;
}

const ROUTES: Route[] = [
  { path: "status", label: "Status", icon: "shield-check", view: statusView, nav: true },
  { path: "setup", label: "Set up", icon: "pair", view: setupView, nav: true },
  { path: "recovery", label: "Recovery codes", icon: "key", view: recoveryView, nav: true },
  { path: "hardening", label: "Hardening", icon: "shield-alert", view: hardeningView, nav: true },
  { path: "phone-signin", label: "Phone sign-in", icon: "phone", view: phoneSignInView, nav: true },
  { path: "history", label: "History", icon: "book", view: historyView, nav: true },
  { path: "settings", label: "Settings", icon: "settings", view: settingsView, nav: true },
  { path: "turn-off", label: "Turn off protection", icon: "shield-off", view: turnOffView, nav: false },
];

// ---------------------------------------------------------------------------------------------
// Theme: follows Windows (prefers-color-scheme) unless the owner picks one. The choice is a
// per-viewer convenience, so storage failures are ignored.

type Theme = "system" | "light" | "dark";
const THEME_KEY = "phonegate.theme";

function readTheme(): Theme {
  try {
    const t = localStorage.getItem(THEME_KEY);
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

export function setTheme(t: Theme): void {
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  try {
    localStorage.setItem(THEME_KEY, t);
  } catch {
    /* private mode: the choice lasts for this session only */
  }
  for (const b of document.querySelectorAll<HTMLButtonElement>("[data-theme-choice]")) {
    b.setAttribute("aria-pressed", String(b.dataset.themeChoice === t));
  }
}

function themeSwitch(): HTMLElement {
  const choices: [Theme, string, IconName][] = [
    ["system", "Match Windows", "system"],
    ["light", "Day", "sun"],
    ["dark", "Night shift", "moon"],
  ];
  const current = readTheme();
  return h(
    "div.theme-switch",
    { role: "group", "aria-label": "Theme" },
    ...choices.map(([t, label, ic]) =>
      h("button.theme-choice", { type: "button", "data-theme-choice": t, "aria-pressed": String(current === t), title: label, onclick: () => setTheme(t) }, icon(ic), h("span.sr-only", null, label)),
    ),
  );
}

// ---------------------------------------------------------------------------------------------
// Shell and router

const app = document.getElementById("app")!;
let main: HTMLElement;
let cleanup: Cleanup | void;
const navLinks = new Map<string, HTMLAnchorElement>();
let pcLabel: HTMLElement;

function shell(): void {
  if (previewMode) {
    const scene = new URLSearchParams(location.search).get("preview") === "new" ? "new" : "protected";
    const select = h(
      "select#preview-scene",
      {
        onchange: (e: Event) => {
          const v = (e.target as HTMLSelectElement).value;
          location.search = v === "protected" ? "" : `?preview=${v}`;
        },
      },
      h("option", { value: "protected", selected: scene === "protected" }, "Protected PC"),
      h("option", { value: "new", selected: scene === "new" }, "New install, no TPM"),
    );
    app.append(
      h(
        "div.preview-banner",
        { role: "note" },
        icon("info"),
        h("strong", null, "Preview data."),
        h("span", null, "This is a browser preview with a pretend agent. Nothing here reflects a real PC."),
        h("label.preview-scene", { for: "preview-scene" }, "Scene"),
        select,
      ),
    );
  }

  const nav = h("nav.rail", { "aria-label": "PhoneGate" });
  pcLabel = h("span.brand-pc", null, "");
  nav.append(
    h("div.brand", null, h("img.brand-mark", { src: "/brand-mark.svg", alt: "", width: 36, height: 36 }), h("div.brand-text", null, h("span.brand-name", null, "PhoneGate"), pcLabel)),
  );
  const list = h("ul.nav-list");
  for (const r of ROUTES.filter((r) => r.nav)) {
    const a = h("a.nav-link", { href: `#/${r.path}` }, icon(r.icon), h("span", null, r.label));
    navLinks.set(r.path, a);
    list.append(h("li", null, a));
  }
  nav.append(list, h("div.rail-foot", null, themeSwitch()));
  main = h("main#main", { tabindex: "-1" });
  app.append(h("div.shell", null, nav, main));

  document.querySelector<HTMLAnchorElement>(".skip-link")!.addEventListener("click", (e) => {
    e.preventDefault();
    focusHeading();
  });
}

function focusHeading(): void {
  const h1 = main.querySelector<HTMLElement>("h1");
  (h1 ?? main).focus({ preventScroll: false });
}

function route(): void {
  const path = location.hash.replace(/^#\/?/, "").split("?")[0] || "status";
  const r = ROUTES.find((x) => x.path === path) ?? ROUTES[0];
  if (cleanup) cleanup();
  cleanup = undefined;
  main.replaceChildren();
  main.scrollTop = 0;
  for (const [p, a] of navLinks) {
    if (p === r.path) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  document.title = r.path === "status" ? "PhoneGate" : `${r.label} | PhoneGate`;
  cleanup = r.view(main);
  requestAnimationFrame(focusHeading);
  // A newer release, if the check is on and GitHub answered. Silent otherwise.
  void updateBanner().then((b) => {
    if (b && main.isConnected && !main.querySelector(".update-banner")) main.prepend(b);
  });
}

setTheme(readTheme());
shell();
store.subscribe((s) => {
  pcLabel.textContent = s.status ? s.status.pc_name : "";
});
window.addEventListener("hashchange", route);
route();
store.refresh();
