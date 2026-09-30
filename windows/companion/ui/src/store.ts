// Shared snapshot of the agent's status and the PC's security checks.

import { agent, type Security, type Status } from "./agent";

export interface Snapshot {
  status: Status | null;
  security: Security | null;
  error: unknown;
  loading: boolean;
  checkedAt: number | null;
}

type Listener = (s: Snapshot) => void;

const snap: Snapshot = { status: null, security: null, error: null, loading: false, checkedAt: null };
const listeners = new Set<Listener>();
let securityAt = 0;
let inflight: Promise<void> | null = null;

function emit(): void {
  for (const l of listeners) l(snap);
}

export const store = {
  get: () => snap,
  subscribe(l: Listener): () => void {
    listeners.add(l);
    l(snap);
    return () => listeners.delete(l);
  },
  /** Re-reads status (and the security checks at most once a minute unless forced). */
  refresh(forceSecurity = false): Promise<void> {
    if (inflight) return inflight;
    snap.loading = true;
    emit();
    inflight = (async () => {
      try {
        snap.status = await agent.status();
        snap.error = null;
        snap.checkedAt = Date.now();
        if (forceSecurity || !snap.security || Date.now() - securityAt > 60_000) {
          try {
            snap.security = await agent.security();
            securityAt = Date.now();
          } catch {
            /* keep the last known checks; status errors are what the UI reports */
          }
        }
      } catch (e) {
        snap.error = e;
      } finally {
        snap.loading = false;
        inflight = null;
        emit();
      }
    })();
    return inflight;
  },
};
