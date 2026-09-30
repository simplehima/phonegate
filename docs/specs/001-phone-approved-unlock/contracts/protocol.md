# Contract: PhoneGate End-to-End Protocol v1

Normative for `crates/pg-core` (Rust) and `android/app/.../protocol` (Kotlin). Shared test vectors
in `protocol/vectors/` MUST pass on both sides.

## 1. Primitives

| Name | Definition |
|------|------------|
| `H(x)` | SHA-256 |
| `HMAC(k, x)` | HMAC-SHA256 |
| `HKDF(ikm, salt, info, L=32)` | RFC 5869 with SHA-256 |
| `SIGN_k(x)` | ECDSA P-256 with SHA-256 over bytes `x`; wire form is raw `r‖s`, 64 bytes (IEEE P1363). `r`,`s` MUST be in `[1, n-1]`; both low-S and high-S are accepted (malleability is harmless because every signed message is single-use by id/nonce). |
| `AEAD` | AES-256-GCM, 12-byte random nonce, 16-byte tag appended to ciphertext |
| `ECDH` | P-256; shared secret = 32-byte big-endian x-coordinate |
| `PUB` | SEC1 **uncompressed** P-256 point, 65 bytes, first byte `0x04` |
| `ID(pub)` | `H(PUB)`, 32 bytes. Device id = mailbox id |
| `b64` | base64url, no padding (RFC 4648 §5) |
| time | unsigned 64-bit Unix time in **milliseconds** |

## 2. Canonical encoding `enc(f1, …, fn)`

Every field is written as `u32_be(len(f)) ‖ f`. Field types:

- bytes: raw
- string: UTF-8, NFC not required, max 256 bytes unless stated
- u64: 8 bytes big-endian
- list of bytes: the field value is itself `enc(item1, …, itemN)`

The first field of every signed, MAC'd, or hashed structure is an ASCII **label** beginning with
`phonegate/v1/`. Labels are unique per structure, which gives domain separation.

Decoding MUST reject: truncated length, trailing bytes, a wrong field count for the label, a label
mismatch, a total size over 64 KiB, a u64 field whose length is not 8, and a PUB whose length is not
65 or which is not on the curve.

## 3. Pairing

### 3.1 QR payload (PC screen)

```
phonegate://pair?v=1&r=<urlencoded relay https URL>&i=<b64 pairing_id 16B>&k=<b64 psk 32B>&h=<b64 H(pc_pub) 32B>&n=<urlencoded pc_name>
```

The QR is single-use and expires 300 s after creation.

### 3.2 Derived values

```
slot            = H(enc("phonegate/v1/pair-slot", pairing_id))
k_join          = HKDF(psk, pairing_id, "phonegate/v1/pair-join-key")
attest_chal     = HMAC(psk, enc("phonegate/v1/attest", pairing_id))
TH              = H(enc("phonegate/v1/pair-transcript", pairing_id, pc_pub, pc_eph_pub, pc_name,
                        phone_device_pub, phone_approve_pub, phone_eph_pub, phone_name))
k_pair          = HKDF(ECDH(eph_priv, peer_eph_pub), psk, enc("phonegate/v1/k-pair", TH))
sas             = decimal6( u32_be(HKDF(k_pair, "", "phonegate/v1/sas")[0..4]) mod 1_000_000 )
confirm_pc      = HMAC(k_pair, enc("phonegate/v1/confirm", "pc", TH))
confirm_phone   = HMAC(k_pair, enc("phonegate/v1/confirm", "phone", TH))
k_offline       = HKDF(k_pair, "", "phonegate/v1/offline")
```

`decimal6` is zero-padded to 6 digits.

### 3.3 Messages (sent to `slot`; wire kinds in §5)

1. **`pair-offer`** (PC → slot), plaintext:
   ```
   body = enc("phonegate/v1/pair-offer", pairing_id, pc_pub, pc_eph_pub, pc_name, expires_at)
   payload = enc("phonegate/v1/pair-offer-signed", body, SIGN_pc(body))
   ```
   The phone MUST check that `H(pc_pub) == h` from the QR, that the signature is valid, that
   `pairing_id` matches, and that `expires_at` is in the future.
2. **`pair-join`** (phone → slot):
   ```
   inner = enc("phonegate/v1/pair-join-body", pairing_id, phone_device_pub, phone_approve_pub,
               phone_eph_pub, phone_name, device_chain, approve_chain,
               SIGN_device(enc("phonegate/v1/pair-join-sig", TH)),
               SIGN_approve(enc("phonegate/v1/pair-join-sig", TH)))
   payload = enc("phonegate/v1/pair-join", nonce12, AEAD(k_join, nonce12, inner,
                 aad = enc("phonegate/v1/pair-join-aad", pairing_id)))
   ```
   `device_chain` and `approve_chain` are lists of DER X.509 certificates, leaf first, and may be
   empty lists. `SIGN_approve` requires a biometric on the phone.
   The PC MUST verify: the AEAD, both signatures over TH, the attestation (§3.4), and that the
   pairing is not expired and not already consumed.
3. The PC and phone both show `sas`. The owner confirms on the phone, which sends **`pair-confirm`**:
   `payload = enc("phonegate/v1/pair-confirm", confirm_phone)`.
4. The owner confirms on the PC. After the PC has received a valid `pair-confirm`, it stores the
   pairing and sends **`pair-complete`**: `payload = enc("phonegate/v1/pair-complete", confirm_pc)`.
   The phone stores the pairing only after verifying `confirm_pc`.

A MAC comparison MUST be constant-time. Any failure aborts the pairing and burns `pairing_id`.

### 3.4 Attestation check (PC side)

- The chain verifies up to one of the pinned Google hardware attestation roots in
  `crates/pg-core/roots/`.
- The leaf public key equals the declared PUB.
- In the KeyDescription extension (OID `1.3.6.1.4.1.11129.2.1.17`):
  - `attestationChallenge == attest_chal`
  - `attestationSecurityLevel ∈ {TrustedEnvironment(1), StrongBox(2)}`
  - `keymasterSecurityLevel ∈ {TrustedEnvironment(1), StrongBox(2)}`
- For the `approve` key only, the hardware-enforced list has no `noAuthRequired`, has a `userAuthType`
  that includes fingerprint/biometric (bit 2), and has no `authTimeout` or `authTimeout == 0`.

The outcome is `Verified`, or `Unverified(reason)`. On `Unverified` the companion requires explicit
owner acceptance, and the result is stored in the pairing record.

## 4. Sealed envelope (post-pairing traffic)

```
dir     = "pc->phone" | "phone->pc"
k_msg   = HKDF(k_pair, msg_id, enc("phonegate/v1/msg", dir))
aad     = enc("phonegate/v1/envelope", kind, msg_id, from_id, to_id)
ct      = AEAD(k_msg, nonce12, plaintext, aad)
sig     = SIGN_sender(enc("phonegate/v1/envelope-sig", aad, nonce12, ct))
payload = enc("phonegate/v1/envelope-wire", kind, msg_id, from_id, to_id, nonce12, ct, sig)
```

- PC envelopes are signed with the PC key. Phone envelopes are signed with the phone **device** key.
- Receivers MUST verify the signature against the pinned key **before** decrypting. They MUST check
  that `from_id`/`to_id` match the pairing and that `msg_id` is unseen within a 24 h window.

### 4.1 Plaintexts

| kind | plaintext |
|------|-----------|
| `approval-request` | `enc("phonegate/v1/approval-request", req_id16, nonce32, pc_id, phone_id, issued_at, expires_at, scenario, account, pc_name, remote_addr, match_number)` |
| `approval-response` | `enc("phonegate/v1/approval-response", request_digest, decision, typed_number, responded_at, decision_sig)` |
| `cancel` | `enc("phonegate/v1/cancel", req_id16)` |
| `notice` | `enc("phonegate/v1/notice", notice_kind, at, detail)` |
| `unpair` | `enc("phonegate/v1/unpair", at)` |

- `scenario` ∈ `unlock` · `logon` · `remote` · `disable-protection`.
- `match_number` ∈ `[10, 99]`, drawn uniformly.
- `expires_at − issued_at ≤ 60 000`.
- `request_digest = H(approval-request plaintext)`.
- `decision` ∈ `approve` · `deny` · `not-me`.
- `typed_number` is the number the owner typed (0 for deny / not-me).
- `decision_sig = SIGN_k(enc("phonegate/v1/decision", request_digest, decision, typed_number, responded_at))`
  where `k` = **approve** key if `decision == approve`, else the **device** key.
- `notice_kind` ∈ `recovery-code-used` · `offline-code-used` · `protection-enabled` · `protection-disabled` · `cooldown`.

### 4.2 PC acceptance rule for `approval-response`

Accept **only if all** of the following hold. Otherwise the response is treated as a denial for
that request (fail-secure):

1. The envelope is valid (§4).
2. `request_digest` matches an **outstanding** request.
3. The PC clock is before `expires_at`.
4. `decision_sig` verifies with the key required by `decision`.
5. For `approve`: `typed_number == match_number`.
6. The request is then marked consumed, so any later response for it is ignored.

### 4.3 Phone display rule for `approval-request`

Show only if all of these hold:

- The envelope is valid.
- `pc_id`/`phone_id` match the pairing.
- `|issued_at − phone_now| ≤ 300 000`.
- `phone_now < expires_at + 300 000`.
- `req_id` is unseen.

A newer request from the same PC supersedes older pending ones.

## 5. Relay wire body

Every relay `body` is `enc("phonegate/v1/wire", kind, payload)`, where `kind` ∈ `pair-offer`,
`pair-join`, `pair-confirm`, `pair-complete`, `approval-request`, `approval-response`, `cancel`,
`notice`, `unpair`.

## 6. Offline challenge / response

```
body   = enc("phonegate/v1/offline-challenge", pc_id, chal_id16, issued_at, expires_at, scenario, account)
qr     = "PGO1:" + b64(enc("phonegate/v1/offline-qr", body, SIGN_pc(body)))
mac    = HMAC(k_offline, enc("phonegate/v1/offline-response", body))
code   = decimal10( u64_be(mac[0..8]) mod 10_000_000_000 )
```

The PC allows 5 attempts per challenge and 60 s validity. A challenge is single-use, and failed
attempts feed the same lockout as recovery codes.

## 7. Recovery codes

- Each code is 16 random bytes, encoded as Crockford base32 without padding. That gives 26
  characters, grouped as 4-4-4-4-4-4-2 with `-`.
- Input normalization: uppercase; remove `-` and spaces; map `O→0`, `I→1`, `L→1`.
- Stored value: `H(enc("phonegate/v1/recovery", salt32, code_bytes16))`.
- Lockout: after 5 consecutive failures, `locked_until = now + min(60 s · 2^(k), 24 h)`, where `k`
  counts the lockouts already applied.

## 8. Relay authentication

After connecting, the server sends a 32-byte `challenge`. The client answers with `PUB` and
`SIGN(enc("phonegate/v1/relay-auth", challenge))`. The server then binds the connection to
`ID(PUB)`. The PC uses its PC key; the phone uses its device key.
