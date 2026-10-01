# Implementation Plan: Phone Sign-in, Phone Disable, Update Checks, Restore Point

**Branch**: `004-phone-login-updates` | **Date**: 2026-10-01 | **Spec**: [spec.md](./spec.md)

## Summary

Five pieces, smallest risk first; the passwordless credential release is the riskiest and is
isolated behind its own opt-in, tests and the 003 recovery regression guard.

1. **Phone-initiated disable** (US2): a new sealed `command` kind, phone→PC, whose authority is the
   pinned **approve** key (biometric), single-use and fresh. Reuses the envelope + seen-cache.
2. **Passwordless per-PC** (US1): opt-in stores the Windows password TPM-wrapped; after a verified
   approval the agent hands the sign-in tile a ready KERB serialization to submit. Off by default;
   wiping is instant; a wrong stored password falls back to typing it (never a lockout).
3. **Update checks** (US3): both apps GET the latest GitHub release and show a dismissible,
   toggleable banner. Plain unauthenticated request, silent on failure.
4. **Setup restore point** (US4): a wizard page (default on) that enables System Protection if
   needed and calls `Checkpoint-Computer` before any file is laid down.
5. **Publish** (US5): bump to 0.2.0, push to public `simplehima/phonegate`, cut `v0.2.0` with the
   setup, APK and SHA256SUMS.

Contracts: [protocol-v1-additions.md](./contracts/protocol-v1-additions.md),
[agent-control-additions.md](./contracts/agent-control-additions.md).

## Constitution Check

| Principle | How it holds |
|-----------|--------------|
| I. Kerckhoffs | No new secrets in the repo. The stored password is on the owner's PC, TPM-wrapped, SYSTEM-only; releases it never leave the machine. |
| II. Untrusted relay | The disable command's authority is the approve-key signature, verified on the PC; the relay still only routes opaque bytes. Update checks go to GitHub, not the relay, and carry nothing sensitive. |
| III. Hardware keys | Phone disable requires the biometric-bound approve key. Passwordless release requires the same approval as a normal unlock. |
| IV. Fail-secure / recovery | No approval → no credential release, PC stays locked. A wrong stored password falls back to typing it; recovery codes always work; no password oracle gates recovery (003 guard enforced). |
| V. Honest limits | SECURITY.md documents that passwordless stores the password and that an approved phone compromise can then sign in; it is opt-in per PC. |
| VI. Test-first | New protocol vectors; E2E for phone disable (incl. replay/forgery) and passwordless release (incl. no-release-without-approval); update-version-compare unit tests both sides. |
| VIII. UX | Clear opt-in warning; disable confirm needs biometric; update banner is non-blocking and off-switchable; restore point offered up front. |

## Project structure (changes)

```text
crates/pg-core/src/messages.rs         # Kind::Command, Command struct, command-auth signing
crates/pg-core/src/update.rs           # version compare + GitHub "latest release" parse (shared, pure)
crates/pg-core/tests/vectors.rs        # + command vectors
windows/agent/src/engine.rs            # passwordless store/arm/release, phone-command handling
windows/agent/src/credcache.rs         # TPM/DPAPI-wrapped password: pack KERB serialization
windows/agent/src/api.rs               # passwordless_* control ops; release op on the gate pipe
windows/credprov/src/credential.rs     # passwordless path: submit released serialization
tests/e2e/tests/phone_login.rs         # passwordless release + phone disable, adversarial
windows/installer/phonegate.iss        # restore-point wizard page + [Code]
windows/companion/...                  # passwordless opt-in wizard, update banner
android/...                            # per-PC "Turn off protection", update banner
tools/check-updatecheck.mjs            # gate: update compare logic agrees with pg-core vectors
.github/workflows/release.yml          # optional: build + attach on tag (manual publish is fine too)
```
