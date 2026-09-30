import { button, h, notice } from "../dom";
import { explain } from "../copy";

/** Page frame: one h1 (focused on navigation) and an optional lede. */
export function page(root: HTMLElement, title: string, lede?: string, cls = ""): HTMLElement {
  const section = h("section.page", { class: cls, "aria-labelledby": "page-title" });
  section.append(h("header.page-head", null, h("h1#page-title.page-title", { tabindex: "-1" }, title), lede ? h("p.page-lede", null, lede) : null));
  root.append(section);
  return section;
}

/** Error block that explains the failure and offers a retry. */
export function errorBlock(e: unknown, retry?: () => void): HTMLElement {
  const ex = explain(e);
  return notice("error", ex.title, ex.body, retry ? button("Try again", { icon: "refresh", onClick: retry }) : undefined);
}

/** Replaces the children of `slot` with an explained error (or clears it). */
export function showError(slot: HTMLElement, e: unknown | null, retry?: () => void): void {
  slot.replaceChildren(...(e ? [errorBlock(e, retry)] : []));
}

/** A shrinking perforation rule that shows time left. */
export function countdown(totalMs: number, endsAt: number, label: (sLeft: number) => string): { el: HTMLElement; tick: () => number } {
  const bar = h("span.countdown-fill");
  const text = h("span.countdown-text");
  const el = h("div.countdown", null, h("span.countdown-track", { "aria-hidden": "true" }, bar), text);
  const tick = () => {
    const left = Math.max(0, endsAt - Date.now());
    bar.style.transform = `scaleX(${totalMs > 0 ? left / totalMs : 0})`;
    const s = Math.ceil(left / 1000);
    text.textContent = label(s);
    el.classList.toggle("countdown-low", s <= 30);
    return left;
  };
  tick();
  return { el, tick };
}

export function mmss(s: number): string {
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

/** Skeleton lines for first load, shaped like the slip they stand in for. */
export function skeleton(lines = 4): HTMLElement {
  return h("div.skeleton", { "aria-hidden": "true" }, ...Array.from({ length: lines }, (_, i) => h("span.skeleton-line", { class: i === 0 ? "skeleton-wide" : "" })));
}
