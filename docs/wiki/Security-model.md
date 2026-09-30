# Security model

PhoneGate is designed so that **publishing everything gives an attacker nothing**:

- Every key is created on your own devices:
  - on the PC, a non-exportable TPM key;
  - on the phone, a hardware-backed key (StrongBox or TEE) that needs your fingerprint for every
    approval. Its attestation is checked at pairing.

  Nothing secret is in the code or the builds.
- The PC accepts an approval only if it's signed by the phone key it pinned when you paired. Every
  approval is bound to one request, expires in 60 seconds, and is used once.
- The relay only routes encrypted, signed messages. It can't forge, read or replay an approval.
  If it's hostile or down, you fall back to offline approval or recovery codes.
- Pairing uses a one-time secret in the QR code plus a 6-digit code you compare on both screens.
- Typing the number shown on the PC stops "approve out of habit" (push fatigue).
- Everything fails closed.

## Honest limits

Software can't fully protect against:

- no disk encryption (offline removal);
- an administrator who is already signed in;
- Safe Mode;
- network sign-ins (unless blocked);
- a compromised phone.

For each of these, PhoneGate either has a mitigation (BitLocker helper, network sign-in block) or
makes sure the tampering isn't silent (the tamper alarm). The full threat model is in
[docs/SECURITY.md](https://github.com/simplehima/phonegate/blob/main/docs/SECURITY.md).

Found a vulnerability? Please use **Security → Report a vulnerability** on the repository instead
of a public issue.
