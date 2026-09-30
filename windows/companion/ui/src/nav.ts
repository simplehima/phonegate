/** Navigates to an app route (#/path). Re-renders when already there. */
export function go(path: string): void {
  if (location.hash === `#/${path}`) window.dispatchEvent(new HashChangeEvent("hashchange"));
  else location.hash = `#/${path}`;
}
