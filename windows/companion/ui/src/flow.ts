/** Hand-off between views within one app session (never persisted). */
export const flow = {
  /** Set when pairing just completed, so Recovery codes issues the first set straight away. */
  freshPairing: false,
  /** Set once the owner has been through "Get the phone app" in this session. */
  phoneAppDone: false,
};
