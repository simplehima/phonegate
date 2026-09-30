package dev.phonegate.protocol

/**
 * Sealed envelope for post-pairing traffic (protocol §4), mirroring `pg-core/src/envelope.rs`.
 * The sender signature is verified **before** decryption.
 */
enum class Dir(val wire: String) {
    PcToPhone("pc->phone"),
    PhoneToPc("phone->pc"),
}

class Envelope(
    val kind: Kind,
    val msgId: ByteArray,
    val from: ByteArray,
    val to: ByteArray,
    val nonce: ByteArray,
    val ct: ByteArray,
    val sig: ByteArray,
) {
    fun encode(): ByteArray = Enc("phonegate/v1/envelope-wire")
        .str(kind.wire)
        .bytes(msgId)
        .bytes(from)
        .bytes(to)
        .bytes(nonce)
        .bytes(ct)
        .bytes(sig)
        .finish()

    /** Verifies routing ids and the sender signature, then decrypts. */
    fun open(senderPub: ByteArray, kPair: ByteArray, dir: Dir, expectFrom: ByteArray, expectTo: ByteArray): ByteArray {
        if (!Crypto.ctEq(from, expectFrom) || !Crypto.ctEq(to, expectTo)) {
            throw ProtocolException.Verify("envelope routing ids do not match pairing")
        }
        val aad = aad(kind, msgId, from, to)
        Crypto.verify(senderPub, sigBytes(aad, nonce, ct), sig)
        return Crypto.aeadOpen(msgKey(kPair, msgId, dir), nonce, ct, aad)
    }

    companion object {
        fun aad(kind: Kind, msgId: ByteArray, from: ByteArray, to: ByteArray): ByteArray =
            Enc("phonegate/v1/envelope").str(kind.wire).bytes(msgId).bytes(from).bytes(to).finish()

        fun sigBytes(aad: ByteArray, nonce: ByteArray, ct: ByteArray): ByteArray =
            Enc("phonegate/v1/envelope-sig").bytes(aad).bytes(nonce).bytes(ct).finish()

        fun msgKey(kPair: ByteArray, msgId: ByteArray, dir: Dir): ByteArray =
            Crypto.hkdf(kPair, msgId, Enc("phonegate/v1/msg").str(dir.wire).finish())

        fun parse(payload: ByteArray): Envelope {
            val f = Enc.decode(payload, "phonegate/v1/envelope-wire", 8)
            val kind = Kind.parse(f.string(1))
            if (!kind.isSealed) throw ProtocolException.Decode("kind is not a sealed kind")
            return Envelope(
                kind = kind,
                msgId = f.fixed(2, 16),
                from = f.fixed(3, 32),
                to = f.fixed(4, 32),
                nonce = f.fixed(5, 12),
                ct = f.bytes(6),
                sig = f.fixed(7, 64),
            )
        }

        /** Seals with fresh random `msg_id` and nonce. Returns (payload, msg_id). */
        fun seal(kPair: ByteArray, dir: Dir, kind: Kind, from: ByteArray, to: ByteArray, signer: Signer, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
            val msgId = Crypto.random(16)
            return sealWith(kPair, dir, kind, from, to, signer, plaintext, msgId, Crypto.random(12)) to msgId
        }

        /** Deterministic sealing (test vectors). */
        fun sealWith(
            kPair: ByteArray,
            dir: Dir,
            kind: Kind,
            from: ByteArray,
            to: ByteArray,
            signer: Signer,
            plaintext: ByteArray,
            msgId: ByteArray,
            nonce: ByteArray,
        ): ByteArray {
            if (!kind.isSealed) throw ProtocolException.State("kind is not a sealed kind")
            val aad = aad(kind, msgId, from, to)
            val ct = Crypto.aeadSeal(msgKey(kPair, msgId, dir), nonce, plaintext, aad)
            val sig = signer.sign(sigBytes(aad, nonce, ct))
            return Envelope(kind, msgId, from, to, nonce, ct, sig).encode()
        }
    }
}
