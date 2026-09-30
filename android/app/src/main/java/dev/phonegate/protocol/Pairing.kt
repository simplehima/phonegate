package dev.phonegate.protocol

import java.io.ByteArrayOutputStream

/**
 * QR pairing, phone role (protocol §3), mirroring `pg-core/src/pairing.rs`. The QR code is the
 * only authentic channel: it carries the one-time `psk` and the hash of the PC key.
 */
const val PAIRING_LIFETIME_MS = 300_000L
const val MAX_NAME = 64

class PairingQr(
    val relayUrl: String,
    val pairingId: ByteArray,
    val psk: ByteArray,
    val pcPubHash: ByteArray,
    val pcName: String,
) {
    fun toUri(): String =
        "phonegate://pair?v=1&r=${pctEncode(relayUrl)}&i=${B64.encode(pairingId)}&k=${B64.encode(psk)}" +
            "&h=${B64.encode(pcPubHash)}&n=${pctEncode(pcName)}"

    companion object {
        fun parse(uri: String): PairingQr {
            val prefix = "phonegate://pair?"
            if (!uri.startsWith(prefix)) throw ProtocolException.Decode("not a pairing uri")
            val q = uri.substring(prefix.length)
            val params = HashMap<String, String>()
            for (part in q.split('&')) {
                val eq = part.indexOf('=')
                if (eq < 0) throw ProtocolException.Decode("bad query")
                val key = part.substring(0, eq)
                val value = part.substring(eq + 1)
                if (key !in setOf("v", "r", "i", "k", "h", "n")) continue // forward compatible
                if (params.containsKey(key)) throw ProtocolException.Decode("duplicate query parameter")
                params[key] = value
            }
            if (params["v"] != "1") throw ProtocolException.Decode("unsupported pairing version")
            val relayUrl = pctDecode(params["r"] ?: throw ProtocolException.Decode("missing relay"))
            validateRelayUrl(relayUrl)
            val pcName = pctDecode(params["n"] ?: throw ProtocolException.Decode("missing name"))
            if (pcName.isEmpty() || pcName.toByteArray(Charsets.UTF_8).size > MAX_NAME) {
                throw ProtocolException.Decode("bad pc name")
            }
            return PairingQr(
                relayUrl = relayUrl,
                pairingId = B64.decodeFixed(params["i"] ?: throw ProtocolException.Decode("missing id"), 16),
                psk = B64.decodeFixed(params["k"] ?: throw ProtocolException.Decode("missing psk"), 32),
                pcPubHash = B64.decodeFixed(params["h"] ?: throw ProtocolException.Decode("missing hash"), 32),
                pcName = pcName,
            )
        }

        fun pctEncode(s: String): String {
            val sb = StringBuilder()
            for (b in s.toByteArray(Charsets.UTF_8)) {
                val c = b.toInt() and 0xff
                val ch = c.toChar()
                if ((ch in 'A'..'Z') || (ch in 'a'..'z') || (ch in '0'..'9') || ch == '-' || ch == '.' || ch == '_' || ch == '~') {
                    sb.append(ch)
                } else {
                    sb.append('%').append("%02X".format(c))
                }
            }
            return sb.toString()
        }

        fun pctDecode(s: String): String {
            val b = s.toByteArray(Charsets.UTF_8)
            val out = ByteArrayOutputStream(b.size)
            var i = 0
            while (i < b.size) {
                if (b[i] == '%'.code.toByte()) {
                    if (i + 2 >= b.size) throw ProtocolException.Decode("truncated percent escape")
                    val hi = Character.digit(b[i + 1].toInt().toChar(), 16)
                    val lo = Character.digit(b[i + 2].toInt().toChar(), 16)
                    if (hi < 0 || lo < 0) throw ProtocolException.Decode("bad escape")
                    out.write(hi * 16 + lo)
                    i += 3
                } else {
                    out.write(b[i].toInt())
                    i += 1
                }
            }
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            return try {
                decoder.decode(java.nio.ByteBuffer.wrap(out.toByteArray())).toString()
            } catch (e: java.nio.charset.CharacterCodingException) {
                throw ProtocolException.Decode("invalid utf-8 in uri")
            }
        }

        /** Relay URLs must be https; plain http only for localhost development relays. */
        fun validateRelayUrl(url: String) {
            val ok = url.startsWith("https://") || url.startsWith("http://localhost") || url.startsWith("http://127.0.0.1")
            if (!ok || url.length > 256) throw ProtocolException.Decode("relay url must be https (http only for localhost)")
        }
    }
}

object PairingKdf {
    const val CONFIRM_LABEL = "phonegate/v1/pair-confirm"
    const val COMPLETE_LABEL = "phonegate/v1/pair-complete"

    fun slot(pairingId: ByteArray): ByteArray = Crypto.sha256(Enc("phonegate/v1/pair-slot").bytes(pairingId).finish())

    fun kJoin(psk: ByteArray, pairingId: ByteArray): ByteArray =
        Crypto.hkdf(psk, pairingId, "phonegate/v1/pair-join-key".toByteArray(Charsets.US_ASCII))

    fun attestChallenge(psk: ByteArray, pairingId: ByteArray): ByteArray =
        Crypto.hmac(psk, Enc("phonegate/v1/attest").bytes(pairingId).finish())

    fun transcript(
        pairingId: ByteArray,
        pcPub: ByteArray,
        pcEphPub: ByteArray,
        pcName: String,
        phoneDevicePub: ByteArray,
        phoneApprovePub: ByteArray,
        phoneEphPub: ByteArray,
        phoneName: String,
    ): ByteArray = Crypto.sha256(
        Enc("phonegate/v1/pair-transcript")
            .bytes(pairingId)
            .bytes(pcPub)
            .bytes(pcEphPub)
            .str(pcName)
            .bytes(phoneDevicePub)
            .bytes(phoneApprovePub)
            .bytes(phoneEphPub)
            .str(phoneName)
            .finish(),
    )

    fun kPair(shared: ByteArray, psk: ByteArray, th: ByteArray): ByteArray =
        Crypto.hkdf(shared, psk, Enc("phonegate/v1/k-pair").bytes(th).finish())

    fun sas(kPair: ByteArray): String {
        val d = Crypto.hkdf(kPair, ByteArray(0), "phonegate/v1/sas".toByteArray(Charsets.US_ASCII))
        val v = (((d[0].toLong() and 0xff) shl 24) or ((d[1].toLong() and 0xff) shl 16) or
            ((d[2].toLong() and 0xff) shl 8) or (d[3].toLong() and 0xff)) % 1_000_000L
        return "%06d".format(v)
    }

    fun confirmMac(kPair: ByteArray, role: String, th: ByteArray): ByteArray =
        Crypto.hmac(kPair, Enc("phonegate/v1/confirm").str(role).bytes(th).finish())

    fun kOffline(kPair: ByteArray): ByteArray =
        Crypto.hkdf(kPair, ByteArray(0), "phonegate/v1/offline".toByteArray(Charsets.US_ASCII))

    fun joinSigBytes(th: ByteArray): ByteArray = Enc("phonegate/v1/pair-join-sig").bytes(th).finish()

    fun joinAad(pairingId: ByteArray): ByteArray = Enc("phonegate/v1/pair-join-aad").bytes(pairingId).finish()

    fun encodeConfirm(label: String, mac: ByteArray): ByteArray = Enc(label).bytes(mac).finish()

    fun decodeConfirm(payload: ByteArray, label: String): ByteArray = Enc.decode(payload, label, 2).fixed(1, 32)
}

class PairOffer(
    val pairingId: ByteArray,
    val pcPub: ByteArray,
    val pcEphPub: ByteArray,
    val pcName: String,
    val expiresAt: Long,
) {
    companion object {
        /** Parses and verifies against the QR (hash of PC key, pairing id) and the clock. */
        fun verify(payload: ByteArray, qr: PairingQr, now: Long): PairOffer {
            val outer = Enc.decode(payload, "phonegate/v1/pair-offer-signed", 3)
            val body = outer.bytes(1)
            val sig = outer.bytes(2)
            val f = Enc.decode(body, "phonegate/v1/pair-offer", 6)
            val offer = PairOffer(
                pairingId = f.fixed(1, 16),
                pcPub = f.fixed(2, 65),
                pcEphPub = f.fixed(3, 65),
                pcName = f.stringMax(4, MAX_NAME),
                expiresAt = f.u64(5),
            )
            if (!Crypto.ctEq(Crypto.idOf(offer.pcPub), qr.pcPubHash)) {
                throw ProtocolException.Verify("pc key does not match the QR code")
            }
            if (!offer.pairingId.contentEquals(qr.pairingId)) throw ProtocolException.Verify("pairing id mismatch")
            Crypto.verify(offer.pcPub, body, sig)
            Crypto.parsePub(offer.pcEphPub)
            if (now >= offer.expiresAt) throw ProtocolException.Expired()
            return offer
        }
    }
}

class PairJoin(
    val pairingId: ByteArray,
    val phoneDevicePub: ByteArray,
    val phoneApprovePub: ByteArray,
    val phoneEphPub: ByteArray,
    val phoneName: String,
    val deviceChain: List<ByteArray>,
    val approveChain: List<ByteArray>,
    val sigDevice: ByteArray,
    val sigApprove: ByteArray,
) {
    fun encodeInner(): ByteArray = Enc("phonegate/v1/pair-join-body")
        .bytes(pairingId)
        .bytes(phoneDevicePub)
        .bytes(phoneApprovePub)
        .bytes(phoneEphPub)
        .str(phoneName)
        .list(deviceChain)
        .list(approveChain)
        .bytes(sigDevice)
        .bytes(sigApprove)
        .finish()

    fun seal(psk: ByteArray, nonce: ByteArray): ByteArray {
        val key = PairingKdf.kJoin(psk, pairingId)
        val ct = Crypto.aeadSeal(key, nonce, encodeInner(), PairingKdf.joinAad(pairingId))
        return Enc("phonegate/v1/pair-join").bytes(nonce).bytes(ct).finish()
    }

    companion object {
        /** PC-side parse (used by tests to check what the phone produced). */
        fun open(payload: ByteArray, psk: ByteArray, pairingId: ByteArray): PairJoin {
            val outer = Enc.decode(payload, "phonegate/v1/pair-join", 3)
            val nonce = outer.fixed(1, 12)
            val inner = Crypto.aeadOpen(PairingKdf.kJoin(psk, pairingId), nonce, outer.bytes(2), PairingKdf.joinAad(pairingId))
            val f = Enc.decode(inner, "phonegate/v1/pair-join-body", 10)
            val j = PairJoin(
                pairingId = f.fixed(1, 16),
                phoneDevicePub = f.fixed(2, 65),
                phoneApprovePub = f.fixed(3, 65),
                phoneEphPub = f.fixed(4, 65),
                phoneName = f.stringMax(5, MAX_NAME),
                deviceChain = f.list(6),
                approveChain = f.list(7),
                sigDevice = f.fixed(8, 64),
                sigApprove = f.fixed(9, 64),
            )
            if (!j.pairingId.contentEquals(pairingId)) throw ProtocolException.Verify("pairing id mismatch")
            listOf(j.phoneDevicePub, j.phoneApprovePub, j.phoneEphPub).forEach { Crypto.parsePub(it) }
            if (j.phoneDevicePub.contentEquals(j.phoneApprovePub)) throw ProtocolException.Verify("device and approve keys must differ")
            return j
        }
    }
}

class PhonePairingResult(val pcPub: ByteArray, val pcName: String, val relayUrl: String, val kPair: ByteArray) {
    val pcId: ByteArray get() = Crypto.idOf(pcPub)
}

/** What the phone learns after binding its keys to the transcript; the SAS to show the owner. */
class PreparedJoin(val sigBytes: ByteArray, val sas: String, val kPair: ByteArray, val th: ByteArray)

/**
 * Phone pairing state machine. Split into steps because the approve-key signature needs an
 * interactive biometric prompt between [prepare] and [buildJoin].
 */
class PhonePairing(val qr: PairingQr) {
    private var offer: PairOffer? = null
    private var th: ByteArray? = null
    private var kPair: ByteArray? = null
    private var devicePub: ByteArray? = null
    private var approvePub: ByteArray? = null
    private var ephPub: ByteArray? = null
    private var phoneName: String? = null
    private var completed = false

    val slot: ByteArray get() = PairingKdf.slot(qr.pairingId)
    val attestChallenge: ByteArray get() = PairingKdf.attestChallenge(qr.psk, qr.pairingId)
    val pcId: ByteArray get() = qr.pcPubHash
    val verifiedOffer: PairOffer? get() = offer

    fun acceptOffer(payload: ByteArray, now: Long): PairOffer {
        if (offer != null) throw ProtocolException.State("offer already handled")
        val o = PairOffer.verify(payload, qr, now)
        offer = o
        return o
    }

    fun prepare(devicePub: ByteArray, approvePub: ByteArray, eph: EphemeralKey, phoneName: String): PreparedJoin {
        val o = offer ?: throw ProtocolException.State("no offer yet")
        if (th != null) throw ProtocolException.State("join already prepared")
        if (phoneName.isEmpty() || phoneName.toByteArray(Charsets.UTF_8).size > MAX_NAME) {
            throw ProtocolException.Decode("bad phone name")
        }
        val t = PairingKdf.transcript(qr.pairingId, o.pcPub, o.pcEphPub, o.pcName, devicePub, approvePub, eph.public, phoneName)
        val kp = PairingKdf.kPair(eph.agree(o.pcEphPub), qr.psk, t)
        th = t
        kPair = kp
        this.devicePub = devicePub
        this.approvePub = approvePub
        this.ephPub = eph.public
        this.phoneName = phoneName
        return PreparedJoin(PairingKdf.joinSigBytes(t), PairingKdf.sas(kp), kp, t)
    }

    fun buildJoin(deviceChain: List<ByteArray>, approveChain: List<ByteArray>, sigDevice: ByteArray, sigApprove: ByteArray, nonce: ByteArray = Crypto.random(12)): ByteArray {
        val t = th ?: throw ProtocolException.State("join not prepared")
        val sb = PairingKdf.joinSigBytes(t)
        // Self-check: never send a join whose signatures would not verify on the PC.
        Crypto.verify(devicePub!!, sb, sigDevice)
        Crypto.verify(approvePub!!, sb, sigApprove)
        return PairJoin(qr.pairingId, devicePub!!, approvePub!!, ephPub!!, phoneName!!, deviceChain, approveChain, sigDevice, sigApprove)
            .seal(qr.psk, nonce)
    }

    /** Convenience mirroring Rust `handle_offer_with` for software signers (tests). */
    fun handleOfferWith(payload: ByteArray, now: Long, device: Signer, approve: Signer, deviceChain: List<ByteArray>, approveChain: List<ByteArray>, phoneName: String, eph: EphemeralKey, nonce: ByteArray): Pair<ByteArray, String> {
        acceptOffer(payload, now)
        val p = prepare(device.public, approve.public, eph, phoneName)
        return buildJoin(deviceChain, approveChain, device.sign(p.sigBytes), approve.sign(p.sigBytes), nonce) to p.sas
    }

    /** Owner confirmed the SAS on the phone. */
    fun confirm(): ByteArray {
        val kp = kPair ?: throw ProtocolException.State("no offer yet")
        return PairingKdf.encodeConfirm(PairingKdf.CONFIRM_LABEL, PairingKdf.confirmMac(kp, "phone", th!!))
    }

    fun handleComplete(payload: ByteArray): PhonePairingResult {
        if (completed) throw ProtocolException.State("already completed")
        val kp = kPair ?: throw ProtocolException.State("no offer yet")
        val o = offer ?: throw ProtocolException.State("no offer yet")
        val mac = PairingKdf.decodeConfirm(payload, PairingKdf.COMPLETE_LABEL)
        if (!Crypto.ctEq(mac, PairingKdf.confirmMac(kp, "pc", th!!))) {
            throw ProtocolException.Verify("pc confirmation mac mismatch")
        }
        completed = true
        return PhonePairingResult(o.pcPub, o.pcName, qr.relayUrl, kp)
    }
}
