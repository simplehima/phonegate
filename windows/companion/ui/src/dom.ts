// Tiny DOM builder. Text always goes through textContent, never innerHTML, because values such as
// the phone name arrive from another device and must never be interpreted as markup.

import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Check,
  ClipboardList,
  Copy,
  Cpu,
  Download,
  FolderOpen,
  HardDrive,
  Hash,
  Info,
  KeyRound,
  Link,
  Lock,
  LockOpen,
  MonitorSmartphone,
  Moon,
  Network,
  OctagonAlert,
  Printer,
  QrCode,
  RefreshCw,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  Sun,
  SunMoon,
  TimerOff,
  TriangleAlert,
  Unlink,
  Unplug,
  Wrench,
  X,
  BellRing,
  Eye,
  EyeOff,
} from "lucide";

type IconNode = [tag: string, attrs: Record<string, string | number | undefined>][];

const ICONS = {
  "arrow-left": ArrowLeft,
  "arrow-right": ArrowRight,
  book: BookOpen,
  check: Check,
  clipboard: ClipboardList,
  copy: Copy,
  cpu: Cpu,
  download: Download,
  folder: FolderOpen,
  drive: HardDrive,
  hash: Hash,
  info: Info,
  key: KeyRound,
  link: Link,
  lock: Lock,
  unlock: LockOpen,
  pair: MonitorSmartphone,
  moon: Moon,
  network: Network,
  wrench: Wrench,
  bell: BellRing,
  eye: Eye,
  "eye-off": EyeOff,
  octagon: OctagonAlert,
  printer: Printer,
  qr: QrCode,
  refresh: RefreshCw,
  server: Server,
  settings: Settings,
  "shield-alert": ShieldAlert,
  "shield-check": ShieldCheck,
  "shield-off": ShieldOff,
  phone: Smartphone,
  sun: Sun,
  system: SunMoon,
  "timer-off": TimerOff,
  warning: TriangleAlert,
  unlink: Unlink,
  unplug: Unplug,
  x: X,
} satisfies Record<string, IconNode>;

export type IconName = keyof typeof ICONS;

const SVG_NS = "http://www.w3.org/2000/svg";

/** One Lucide icon at the app-wide 1.75 stroke. Decorative unless given a label. */
export function icon(name: IconName, label?: string): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.75");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("class", "icon");
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
  }
  for (const [tag, attrs] of ICONS[name] as IconNode) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) if (v !== undefined) el.setAttribute(k, String(v));
    svg.append(el);
  }
  return svg;
}

type Child = Node | string | number | false | null | undefined;
type Attrs = Record<string, string | number | boolean | EventListener | undefined>;

/** h("button.primary", { onclick }, "Save") */
export function h<K extends keyof HTMLElementTagNameMap>(spec: K | `${K}.${string}` | `${K}#${string}`, attrs?: Attrs | null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const [tagAndId, ...classes] = spec.split(".");
  const [tag, id] = tagAndId.split("#");
  const el = document.createElement(tag) as HTMLElementTagNameMap[K];
  if (id) el.id = id;
  if (classes.length) el.className = classes.join(" ");
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") {
        el.addEventListener(k.slice(2), v as EventListener);
      } else if (k === "class") {
        el.className = [el.className, String(v)].filter(Boolean).join(" ");
      } else if (v === true) {
        el.setAttribute(k, "");
      } else {
        el.setAttribute(k, String(v));
      }
    }
  }
  append(el, children);
  return el;
}

export function append(el: Element, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** A labelled field row on a slip: small tracked caps label, ink-blue value. */
export function field(label: string, value: Child, extra?: Child): HTMLElement {
  return h("div.field", null, h("dt", null, label), h("dd", null, value, extra ?? null));
}

/** Outcome stamp: bordered uppercase mark with an icon; color is never the only signal. */
export function stamp(text: string, tone: "ok" | "bad" | "alert" | "ink" | "muted", ic: IconName, size: "sm" | "lg" = "sm"): HTMLElement {
  return h(`span.stamp`, { class: `stamp-${tone} stamp-${size}` }, icon(ic), h("span", null, text));
}

/** Inline notice with a title (the problem) and body (the way back). */
export function notice(kind: "error" | "warn" | "info" | "ok", title: string, body?: Child, actions?: Child): HTMLElement {
  const ic: IconName = kind === "error" ? "octagon" : kind === "warn" ? "warning" : kind === "ok" ? "check" : "info";
  return h(
    "div.notice",
    { class: `notice-${kind}`, role: kind === "error" ? "alert" : "status" },
    icon(ic),
    h("div.notice-text", null, h("p.notice-title", null, title), body ? h("p.notice-body", null, body) : null, actions ? h("div.notice-actions", null, actions) : null),
  );
}

export function button(
  label: string,
  opts: { kind?: "primary" | "secondary" | "danger" | "quiet"; icon?: IconName; onClick?: (ev: MouseEvent) => void; disabled?: boolean; type?: "button" | "submit"; describedBy?: string } = {},
): HTMLButtonElement {
  const b = h(
    "button.btn",
    { class: `btn-${opts.kind ?? "secondary"}`, type: opts.type ?? "button", disabled: opts.disabled, "aria-describedby": opts.describedBy },
    opts.icon ? icon(opts.icon) : null,
    h("span", null, label),
  );
  if (opts.onClick) b.addEventListener("click", opts.onClick as EventListener);
  return b;
}

/** Marks a button busy while `work` runs; returns the work's result. */
export async function busy<T>(b: HTMLButtonElement, work: () => Promise<T>): Promise<T> {
  b.disabled = true;
  b.setAttribute("aria-busy", "true");
  try {
    return await work();
  } finally {
    b.disabled = false;
    b.removeAttribute("aria-busy");
  }
}

let liveTimer = 0;
/** Polite screen-reader announcement. */
export function announce(text: string): void {
  const region = document.getElementById("live");
  if (!region) return;
  region.textContent = "";
  window.clearTimeout(liveTimer);
  liveTimer = window.setTimeout(() => (region.textContent = text), 50);
}

let uid = 0;
export function nextId(prefix: string): string {
  uid += 1;
  return `${prefix}-${uid}`;
}
