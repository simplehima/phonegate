package dev.phonegate.protocol

import dev.phonegate.protocol.ProtocolVectorsTest.Companion.h
import dev.phonegate.protocol.ProtocolVectorsTest.Companion.s
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.math.BigInteger

/** Negative tests: everything tampered, stale, replayed, foreign or malformed is rejected. */
class ProtocolNegativeTest {
    companion object {
        @BeforeClass
        @JvmStatic
        fun load() = ProtocolVectorsTest.load()

        const val NOW = 1_700_000_001_000L
    }

    private inline fun <reified T : Throwable> rejects(what: String, block: () -> Unit) {
        try {
            block()
        } catch (e: Throwable) {
            if (e is T) return
            throw AssertionError("$what: expected ${T::class.simpleName}, got $e", e)
        }
        fail("$what: was accepted")
    }

    private fun ctx() = PairingContext(h("keys", "pc_pub"), h("pairing", "k_pair"), h("keys", "phone_id"))

    private fun flip(b: ByteArray, i: Int): ByteArray = b.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }

    private fun pcSigner() = ProtocolVectorsTest.signer("pc")

    /** Builds a fresh approval-request wire body signed by the PC with the given fields. */
    private fun requestWire(
        issuedAt: Long = NOW - 1_000,
        expiresAt: Long = NOW + 59_000,
        match: Long = 42,
        phoneId: ByteArray = h("keys", "phone_id"),
        reqId: ByteArray = Crypto.random(16),
        signer: Signer = pcSigner(),
        kPair: ByteArray = h("pairing", "k_pair"),
    ): ByteArray {
        val pcId = h("keys", "pc_id")
        val r = ApprovalRequest(reqId, Crypto.random(32), pcId, phoneId, issuedAt, expiresAt, Scenario.Logon, "DESK\\owner", "Desk PC", "", match)
        val (env, _) = Envelope.seal(kPair, Dir.PcToPhone, Kind.ApprovalRequest, pcId, h("keys", "phone_id"), signer, r.encode())
        return Wire.wire(Kind.ApprovalRequest, env)
    }

    @Test
    fun freshRequestIsAccepted() {
        // Positive control for every negative below.
        val r = Inbox.receive(ctx(), h("keys", "pc_id"), requestWire(), NOW, MemoryReplayGuard())
        assertTrue(r is Inbound.Request)
    }

    @Test
    fun tamperedEnvelopeFieldsAreRejected() {
        val env = Envelope.parse(h("approval", "request_envelope"))
        val c = ctx()
        fun open(e: Envelope) = e.open(c.pcPub, c.kPair, Dir.PcToPhone, c.pcId, c.phoneId)
        open(env) // control
        rejects<ProtocolException.Verify>("ciphertext") { open(Envelope(env.kind, env.msgId, env.from, env.to, env.nonce, flip(env.ct, 3), env.sig)) }
        rejects<ProtocolException.Verify>("tag") { open(Envelope(env.kind, env.msgId, env.from, env.to, env.nonce, flip(env.ct, env.ct.size - 1), env.sig)) }
        rejects<ProtocolException.Verify>("nonce") { open(Envelope(env.kind, env.msgId, env.from, env.to, flip(env.nonce, 0), env.ct, env.sig)) }
        rejects<ProtocolException.Verify>("msg id") { open(Envelope(env.kind, flip(env.msgId, 0), env.from, env.to, env.nonce, env.ct, env.sig)) }
        rejects<ProtocolException.Verify>("kind") { open(Envelope(Kind.Notice, env.msgId, env.from, env.to, env.nonce, env.ct, env.sig)) }
        rejects<ProtocolException.Verify>("signature") { open(Envelope(env.kind, env.msgId, env.from, env.to, env.nonce, env.ct, flip(env.sig, 5))) }
        rejects<ProtocolException.Verify>("from id") { open(Envelope(env.kind, env.msgId, flip(env.from, 0), env.to, env.nonce, env.ct, env.sig)) }
        rejects<ProtocolException.Verify>("to id") { open(Envelope(env.kind, env.msgId, env.from, flip(env.to, 0), env.nonce, env.ct, env.sig)) }
        rejects<ProtocolException.Verify>("wrong sender key") { env.open(h("keys", "device_pub"), c.kPair, Dir.PcToPhone, c.pcId, c.phoneId) }
        rejects<ProtocolException.Verify>("wrong direction") { env.open(c.pcPub, c.kPair, Dir.PhoneToPc, c.pcId, c.phoneId) }
        rejects<ProtocolException.Verify>("wrong k_pair") { env.open(c.pcPub, ByteArray(32) { 8 }, Dir.PcToPhone, c.pcId, c.phoneId) }
        rejects<ProtocolException.Verify>("swapped ids") { env.open(c.pcPub, c.kPair, Dir.PcToPhone, c.phoneId, c.pcId) }
    }

    @Test
    fun signatureIsCheckedBeforeDecryption() {
        // A valid ciphertext under the right key but signed by an attacker: must fail on the
        // signature (Verify) even though AEAD would succeed.
        val attacker = SoftSigner.generate()
        val wire = requestWire(signer = attacker)
        rejects<ProtocolException.Verify>("attacker-signed") { Inbox.receive(ctx(), h("keys", "pc_id"), wire, NOW, MemoryReplayGuard()) }
    }

    @Test
    fun wireLevelTamperingIsRejected() {
        val c = ctx()
        val wire = h("approval", "request_wire")
        Inbox.receive(c, c.pcId, wire, NOW, MemoryReplayGuard()) // control
        for (i in listOf(40, 120, 300, wire.size - 10)) {
            rejects<ProtocolException>("byte $i") { Inbox.receive(c, c.pcId, flip(wire, i), NOW, MemoryReplayGuard()) }
        }
        rejects<ProtocolException.Verify>("relay from mismatch") { Inbox.receive(c, h("keys", "phone_id"), wire, NOW, MemoryReplayGuard()) }
        // Wire kind that disagrees with the envelope kind.
        val (_, payload) = Wire.unwire(wire)
        rejects<ProtocolException.Verify>("wire kind") { Inbox.receive(c, c.pcId, Wire.wire(Kind.Cancel, payload), NOW, MemoryReplayGuard()) }
    }

    @Test
    fun expiredOrFutureRequestsAreRejected() {
        val c = ctx()
        val issued = 1_700_000_000_000L
        val expires = 1_700_000_060_000L
        val wire = requestWire(issuedAt = issued, expiresAt = expires)
        rejects<ProtocolException.Expired>("after expiry + skew") { Inbox.receive(c, c.pcId, wire, expires + 300_001, MemoryReplayGuard()) }
        rejects<ProtocolException.Expired>("issued too far in future") { Inbox.receive(c, c.pcId, wire, issued - 300_001, MemoryReplayGuard()) }
        // Within skew is accepted.
        Inbox.receive(c, c.pcId, wire, expires + 299_000, MemoryReplayGuard())
        // Vector request is long expired relative to a real clock.
        rejects<ProtocolException.Expired>("vector request now") {
            Inbox.receive(c, c.pcId, h("approval", "request_wire"), 1_800_000_000_000L, MemoryReplayGuard())
        }
    }

    @Test
    fun invalidRequestContentIsRejected() {
        val c = ctx()
        rejects<ProtocolException.Decode>("match 9") { Inbox.receive(c, c.pcId, requestWire(match = 9), NOW, MemoryReplayGuard()) }
        rejects<ProtocolException.Decode>("match 100") { Inbox.receive(c, c.pcId, requestWire(match = 100), NOW, MemoryReplayGuard()) }
        rejects<ProtocolException.Decode>("lifetime > 60 s") {
            Inbox.receive(c, c.pcId, requestWire(issuedAt = NOW, expiresAt = NOW + 60_001), NOW, MemoryReplayGuard())
        }
        rejects<ProtocolException.Decode>("expires before issued") {
            Inbox.receive(c, c.pcId, requestWire(issuedAt = NOW, expiresAt = NOW), NOW, MemoryReplayGuard())
        }
        rejects<ProtocolException.Verify>("phone id mismatch inside plaintext") {
            Inbox.receive(c, c.pcId, requestWire(phoneId = ByteArray(32) { 9 }), NOW, MemoryReplayGuard())
        }
    }

    @Test
    fun replayedMessagesAreRejected() {
        val c = ctx()
        val guard = MemoryReplayGuard()
        val wire = requestWire()
        Inbox.receive(c, c.pcId, wire, NOW, guard)
        rejects<ProtocolException.Replay>("same msg id") { Inbox.receive(c, c.pcId, wire, NOW + 5, guard) }
        // Same req_id in a new envelope (new msg_id) is also a replay.
        val reqId = Crypto.random(16)
        Inbox.receive(c, c.pcId, requestWire(reqId = reqId), NOW, guard)
        rejects<ProtocolException.Replay>("same req id") { Inbox.receive(c, c.pcId, requestWire(reqId = reqId), NOW, guard) }
        // After the 24 h window the id may be forgotten (memory bounded).
        assertTrue(guard.firstSeen(byteArrayOf(1), 0))
        assertFalse(guard.firstSeen(byteArrayOf(1), 10))
        assertTrue(guard.firstSeen(byteArrayOf(1), MemoryReplayGuard.WINDOW_MS + 11))
    }

    @Test
    fun offerFromWrongPcIsRejected() {
        val q = ProtocolVectorsTest.qr()
        val now = 1_700_000_000_000L
        val payload = h("pairing", "offer_payload")
        PairOffer.verify(payload, q, now) // control
        // A QR pinning another PC key.
        val otherQr = PairingQr(q.relayUrl, q.pairingId, q.psk, ByteArray(32) { 1 }, q.pcName)
        rejects<ProtocolException.Verify>("pc hash mismatch") { PairOffer.verify(payload, otherQr, now) }
        // An offer re-signed by an attacker key, with the attacker pub in the body.
        val attacker = SoftSigner.generate()
        val f = Enc.decode(Enc.decode(payload, "phonegate/v1/pair-offer-signed", 3).bytes(1), "phonegate/v1/pair-offer", 6)
        val forgedBody = Enc("phonegate/v1/pair-offer").bytes(f.bytes(1)).bytes(attacker.public).bytes(f.bytes(3)).str("Desk PC").u64(f.u64(5)).finish()
        val forged = Enc("phonegate/v1/pair-offer-signed").bytes(forgedBody).bytes(attacker.sign(forgedBody)).finish()
        rejects<ProtocolException.Verify>("attacker key") { PairOffer.verify(forged, q, now) }
        // Original pub but attacker signature.
        val badSig = Enc("phonegate/v1/pair-offer-signed").bytes(Enc.decode(payload, "phonegate/v1/pair-offer-signed", 3).bytes(1)).bytes(attacker.sign(forgedBody)).finish()
        rejects<ProtocolException.Verify>("bad signature") { PairOffer.verify(badSig, q, now) }
        // Other pairing id.
        val otherId = PairingQr(q.relayUrl, ByteArray(16) { 7 }, q.psk, q.pcPubHash, q.pcName)
        rejects<ProtocolException.Verify>("pairing id") { PairOffer.verify(payload, otherId, now) }
        rejects<ProtocolException.Expired>("expired offer") { PairOffer.verify(payload, q, 1_700_000_300_000L) }
    }

    @Test
    fun pairCompleteWithWrongMacIsRejected() {
        val q = ProtocolVectorsTest.qr()
        val pp = PhonePairing(q)
        pp.acceptOffer(h("pairing", "offer_payload"), 1_700_000_000_000L)
        val eph = EphemeralKey.fromScalar(h("keys", "phone_eph_priv"), h("keys", "phone_eph_pub"))
        pp.prepare(h("keys", "device_pub"), h("keys", "approve_pub"), eph, "Pixel 9")
        val good = h("pairing", "complete_pc_payload")
        rejects<ProtocolException.Verify>("flipped mac") { pp.handleComplete(flip(good, good.size - 1)) }
        rejects<ProtocolException.Decode>("confirm label instead of complete") { pp.handleComplete(h("pairing", "confirm_phone_payload")) }
        pp.handleComplete(good)
        rejects<ProtocolException.State>("completed twice") { pp.handleComplete(good) }
    }

    @Test
    fun joinRefusesSignaturesThatWouldNotVerify() {
        val q = ProtocolVectorsTest.qr()
        val pp = PhonePairing(q)
        pp.acceptOffer(h("pairing", "offer_payload"), 1_700_000_000_000L)
        val eph = EphemeralKey.fromScalar(h("keys", "phone_eph_priv"), h("keys", "phone_eph_pub"))
        val prep = pp.prepare(h("keys", "device_pub"), h("keys", "approve_pub"), eph, "Pixel 9")
        val dev = ProtocolVectorsTest.signer("device").sign(prep.sigBytes)
        // Approve slot signed by the device key: rejected before sending.
        rejects<ProtocolException.Verify>("device sig in approve slot") { pp.buildJoin(emptyList(), emptyList(), dev, dev) }
    }

    @Test
    fun malformedEncodingsAreRejected() {
        val e = Enc("phonegate/v1/t").bytes("x".toByteArray()).finish()
        Enc.decode(e, "phonegate/v1/t", 2) // control
        rejects<ProtocolException.Decode>("truncated") { Enc.decode(e.copyOf(e.size - 3), "phonegate/v1/t", 2) }
        rejects<ProtocolException.Decode>("truncated prefix") { Enc.split(byteArrayOf(0, 0, 1)) }
        rejects<ProtocolException.Decode>("trailing") { Enc.decode(e + byteArrayOf(0), "phonegate/v1/t", 2) }
        rejects<ProtocolException.Decode>("wrong count") { Enc.decode(e, "phonegate/v1/t", 3) }
        rejects<ProtocolException.Decode>("label") { Enc.decode(e, "phonegate/v1/u", 2) }
        rejects<ProtocolException.Decode>("oversize") { Enc.split(ByteArray(Enc.MAX_ENCODED + 1)) }
        rejects<ProtocolException.Decode>("huge length prefix") { Enc.split(byteArrayOf(-1, -1, -1, -1, 0)) }
        val g = Enc.decode(Enc("phonegate/v1/t").bytes(byteArrayOf(1, 2, 3)).bytes(ByteArray(300) { 'a'.code.toByte() }).bytes(byteArrayOf(-1)).finish(), "phonegate/v1/t", 4)
        rejects<ProtocolException.Decode>("bad u64") { g.u64(1) }
        rejects<ProtocolException.Decode>("long string") { g.string(2) }
        rejects<ProtocolException.Decode>("invalid utf-8") { g.string(3) }
        rejects<ProtocolException.Decode>("unknown kind") { Wire.unwire(Enc("phonegate/v1/wire").str("bogus").bytes(ByteArray(0)).finish()) }
        rejects<ProtocolException.Decode>("unsealed kind in envelope") {
            val env = Envelope.parse(h("approval", "request_envelope"))
            Envelope.parse(Envelope(Kind.ApprovalRequest, env.msgId, env.from, env.to, env.nonce, env.ct, env.sig).encode().let {
                // Replace the kind string with pair-offer by re-encoding.
                Enc("phonegate/v1/envelope-wire").str("pair-offer").bytes(env.msgId).bytes(env.from).bytes(env.to).bytes(env.nonce).bytes(env.ct).bytes(env.sig).finish()
            })
        }
        rejects<ProtocolException.Decode>("short msg id") {
            val env = Envelope.parse(h("approval", "request_envelope"))
            Envelope.parse(Enc("phonegate/v1/envelope-wire").str("cancel").bytes(ByteArray(15)).bytes(env.from).bytes(env.to).bytes(env.nonce).bytes(env.ct).bytes(env.sig).finish())
        }
        rejects<ProtocolException.Decode>("b64 padding") { B64.decode("AA==") }
        rejects<ProtocolException.Decode>("b64 alphabet") { B64.decode("A+/A") }
        rejects<ProtocolException.Decode>("b64 length") { B64.decodeFixed("AAAA", 4) }
    }

    @Test
    fun publicKeyValidation() {
        val pub = h("keys", "pc_pub")
        Crypto.parsePub(pub) // control
        rejects<ProtocolException.Decode>("compressed prefix") { Crypto.parsePub(pub.copyOf().also { it[0] = 2 }) }
        rejects<ProtocolException.Decode>("off curve") { Crypto.parsePub(flip(pub, 64)) }
        rejects<ProtocolException.Decode>("short") { Crypto.parsePub(pub.copyOf(64)) }
        rejects<ProtocolException.Decode>("x >= p") {
            Crypto.parsePub(byteArrayOf(4) + Crypto.fixed32(Crypto.P) + pub.copyOfRange(33, 65))
        }
    }

    @Test
    fun signatureEdgeCases() {
        val signer = SoftSigner.generate()
        val sig = signer.sign("msg".toByteArray())
        Crypto.verify(signer.public, "msg".toByteArray(), sig)
        rejects<ProtocolException.Verify>("other message") { Crypto.verify(signer.public, "msh".toByteArray(), sig) }
        rejects<ProtocolException.Verify>("other key") { Crypto.verify(SoftSigner.generate().public, "msg".toByteArray(), sig) }
        rejects<ProtocolException.Verify>("r = 0") { Crypto.verify(signer.public, "msg".toByteArray(), ByteArray(32) + sig.copyOfRange(32, 64)) }
        rejects<ProtocolException.Verify>("zero sig") { Crypto.verify(signer.public, "msg".toByteArray(), ByteArray(64)) }
        rejects<ProtocolException.Verify>("63 bytes") { Crypto.verify(signer.public, "msg".toByteArray(), sig.copyOf(63)) }
        rejects<ProtocolException.Verify>("s = n") {
            Crypto.verify(signer.public, "msg".toByteArray(), sig.copyOfRange(0, 32) + Crypto.fixed32(Crypto.N))
        }
        // High-S (n - s) is accepted: Keystore does not normalize S (protocol §1).
        val s = BigInteger(1, sig.copyOfRange(32, 64))
        val high = sig.copyOfRange(0, 32) + Crypto.fixed32(Crypto.N.subtract(s))
        Crypto.verify(signer.public, "msg".toByteArray(), high)
        // DER round trip.
        assertArrayEquals(sig, Crypto.derToRaw(Crypto.rawToDer(sig)))
        rejects<ProtocolException.Decode>("bad der") { Crypto.derToRaw(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)) }
    }

    @Test
    fun offlineChallengeRejections() {
        val pcPub = h("keys", "pc_pub")
        val qr = s("offline", "qr")
        OfflineChallenge.parseQr(qr, pcPub, 1_700_000_000_000L) // control
        rejects<ProtocolException.Verify>("other pc key") { OfflineChallenge.parseQr(qr, h("keys", "device_pub"), 1_700_000_000_000L) }
        rejects<ProtocolException.Expired>("stale") { OfflineChallenge.parseQr(qr, pcPub, 1_700_000_060_000L + 300_001) }
        rejects<ProtocolException.Expired>("future") { OfflineChallenge.parseQr(qr, pcPub, 1_700_000_000_000L - 300_001) }
        rejects<ProtocolException.Decode>("prefix") { OfflineChallenge.parseQr("PGO2:" + qr.substring(5), pcPub, 1_700_000_000_000L) }
        // Tampered body (flip a byte in the decoded blob, re-encode).
        val raw = B64.decode(qr.substring(5))
        rejects<ProtocolException>("tampered") { OfflineChallenge.parseQr("PGO1:" + B64.encode(flip(raw, 60)), pcPub, 1_700_000_000_000L) }
        // Code differs for another k_offline.
        val c = OfflineChallenge.parseQr(qr, pcPub, 1_700_000_000_000L)
        assertEquals(s("offline", "code"), c.responseCode(h("pairing", "k_offline")))
        assertTrue(c.responseCode(ByteArray(32) { 6 }) != s("offline", "code"))
    }

    @Test
    fun qrUriValidation() {
        val good = s("pairing", "qr_uri")
        PairingQr.parse(good) // control
        rejects<ProtocolException.Decode>("http relay") {
            PairingQr.parse(good.replace("https%3A%2F%2Frelay", "http%3A%2F%2Frelay"))
        }
        val local = PairingQr.parse(good.replace("https%3A%2F%2Frelay.example.com", "http%3A%2F%2F127.0.0.1%3A8080"))
        assertEquals("http://127.0.0.1:8080", local.relayUrl)
        rejects<ProtocolException.Decode>("version") { PairingQr.parse(good.replace("v=1", "v=2")) }
        rejects<ProtocolException.Decode>("duplicate") { PairingQr.parse("$good&v=1") }
        rejects<ProtocolException.Decode>("scheme") { PairingQr.parse(good.replace("phonegate://", "https://")) }
        rejects<ProtocolException.Decode>("bad escape") { PairingQr.parse(good.replace("n=Desk%20PC", "n=Desk%2")) }
        rejects<ProtocolException.Decode>("short psk") { PairingQr.parse(good.replace(Regex("k=[^&]+"), "k=AAAA")) }
        // Round trip of awkward names.
        val q = PairingQr("https://relay.example/x?y=z", ByteArray(16) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 }, "Ali's PC & more")
        val back = PairingQr.parse(q.toUri())
        assertEquals(q.relayUrl, back.relayUrl)
        assertEquals(q.pcName, back.pcName)
    }
}
