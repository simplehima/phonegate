import { button, h } from "../dom";

/**
 * Confirmation for destructive actions (replace codes, unpair). A real <dialog> so focus is
 * trapped, Escape cancels, and focus returns to the trigger. Cancel is focused first.
 */
export function confirmDialog(opts: { title: string; body: string | Node; confirm: string; danger?: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    const opener = document.activeElement as HTMLElement | null;
    const titleId = "dlg-title";
    const bodyId = "dlg-body";
    const cancel = button("Cancel", { kind: "secondary" });
    const ok = button(opts.confirm, { kind: opts.danger ? "danger" : "primary" });
    const dlg = h(
      "dialog.dialog",
      { "aria-labelledby": titleId, "aria-describedby": bodyId },
      h("h2", { id: titleId }, opts.title),
      typeof opts.body === "string" ? h("p", { id: bodyId }, opts.body) : h("div.dialog-body", { id: bodyId }, opts.body),
      h("div.dialog-actions", null, cancel, ok),
    );
    let result = false;
    cancel.addEventListener("click", () => dlg.close());
    ok.addEventListener("click", () => {
      result = true;
      dlg.close();
    });
    dlg.addEventListener("close", () => {
      dlg.remove();
      opener?.focus();
      resolve(result);
    });
    document.body.append(dlg);
    dlg.showModal();
    cancel.focus();
  });
}
