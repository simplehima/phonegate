# Tasks: Phone Sign-in, Phone Disable, Update Checks, Restore Point

- [X] T401 pg-core: `Kind::Command`, `Command` struct (encode/decode, command-auth bytes, verify against approve key), freshness/range checks, in `messages.rs`, with unit + negative tests
- [X] T402 pg-core: `update.rs` — `parse_latest_tag`, `is_newer` (dotted numeric, strict), with unit tests (v-prefix, missing parts, suffixes, equal, older, newer)
- [X] T403 pg-core: extend `tests/vectors.rs` with the `command` section + an `update` section (compare cases); regenerate `protocol/vectors/v1.json`, existing entries unchanged
- [X] T404 agent: `credcache.rs` — wrap/unwrap the Windows password via the key backend, pack a `KERB_INTERACTIVE_LOGON` serialization (shared packer with credprov `kerb`), persisted TPM-wrapped in state; wipe on disarm
- [X] T405 agent: engine passwordless store/arm/release — `passwordless_*` control ops, arm only after approval, `release` gate op one-shot after approval, `status.passwordless`, never log the password
- [X] T406 agent: handle incoming `command` (phone disable) in `handle_sealed` — verify approve-key auth, freshness, single-use; disable enforcement; history + `protection-disabled` notice; E2E-covered
- [X] T407 DECISION: update checks live in the apps (companion backend + Android), never the SYSTEM agent — keeps outbound HTTP out of the most privileged component. Implemented under T410/T411.
- [X] T408 credprov: passwordless path — when `status.passwordless` and the request is approved, call `release` and submit the returned serialization; on Windows rejecting it, show "re-enter password or use a recovery code"; the 003 no-oracle guard stays green
- [X] T409 E2E `tests/phone_login.rs`: passwordless release only after a matching approval; no release on deny/expire/forged; phone disable applies; replayed/wrong-key disable ignored
- [X] T410 [P] Android: per-PC "Turn off protection" (biometric → signed `command`), update banner (pg-core `update` ported + check toggle), `Kind.Command` in protocol + vectors test
- [X] T411 [P] companion: passwordless opt-in wizard (warn → password once → phone approve → armed; off; update stored password), update banner from `update_check`, settings toggle; new ops in the allowlist + tests + mock; recaptures
- [X] T412 installer: restore-point wizard page (default on) — enable System Protection if off, `Checkpoint-Computer` before install, handle 24h throttle, never block; `before-install` text mentions it
- [X] T413 docs: SECURITY.md (passwordless trade, phone disable authority, update-check network egress), README (phone sign-in, update checks); bump version to 0.2.0 across workspace + Android + companion
- [ ] T414 publish: push to public `simplehima/phonegate`, tag `v0.2.0`, build the setup, create the release with setup exe + APK + SHA256SUMS
- [ ] T415 final validation: all gates green (Rust tests+clippy, Android, companion, installer, secret scan, update-check gate)
