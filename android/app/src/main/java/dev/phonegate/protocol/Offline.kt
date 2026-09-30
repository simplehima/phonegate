package dev.phonegate.protocol

/**
 * Offline phone approval (protocol §6, FR-026a), phone side. Mirrors `pg-core/src/offline.rs`.
 */
class OfflineChallenge(
    val pcId: ByteArray,
    val chalId: ByteArray,
    val issuedAt: Long,
    val expiresAt: Long,
    val scenario: Scenario,
    val account: String,
) {
    fun body(): ByteArray = Enc("phonegate/v1/offline-challenge")
        .bytes(pcId)
        .bytes(chalId)
        .u64(issuedAt)
        .u64(expiresAt)
        .str(scenario.wire)
        .str(account)
        .finish()

    fun responseCode(kOffline: ByteArray): String {
        val mac = Crypto.hmac(kOffline, Enc("phonegate/v1/offline-response").bytes(body()).finish())
        val v = java.lang.Long.remainderUnsigned(Enc.readU64be(mac.copyOfRange(0, 8)), 10_000_000_000L)
        return "%010d".format(v)
    }

    companion object {
        const val LIFETIME_MS = 60_000L
        const val QR_PREFIX = "PGO1:"
        const val CLOCK_SKEW_MS = 300_000L

        /** Reads the PC id a QR claims, without trusting it, so the right pairing can be selected. */
        fun peekPcId(qr: String): ByteArray {
            if (!qr.startsWith(QR_PREFIX)) throw ProtocolException.Decode("not an offline challenge")
            val outer = Enc.decode(B64.decode(qr.substring(QR_PREFIX.length)), "phonegate/v1/offline-qr", 3)
            return Enc.decode(outer.bytes(1), "phonegate/v1/offline-challenge", 7).fixed(1, 32)
        }

        /** Parse, check it came from the paired PC, and check freshness. */
        fun parseQr(qr: String, pcPub: ByteArray, phoneNow: Long): OfflineChallenge {
            if (!qr.startsWith(QR_PREFIX)) throw ProtocolException.Decode("not an offline challenge")
            val raw = B64.decode(qr.substring(QR_PREFIX.length))
            val outer = Enc.decode(raw, "phonegate/v1/offline-qr", 3)
            val body = outer.bytes(1)
            Crypto.verify(pcPub, body, outer.bytes(2))
            val f = Enc.decode(body, "phonegate/v1/offline-challenge", 7)
            val c = OfflineChallenge(
                pcId = f.fixed(1, 32),
                chalId = f.fixed(2, 16),
                issuedAt = f.u64(3),
                expiresAt = f.u64(4),
                scenario = Scenario.parse(f.string(5)),
                account = f.string(6),
            )
            if (!c.pcId.contentEquals(Crypto.idOf(pcPub))) throw ProtocolException.Verify("challenge is for another PC")
            if (c.issuedAt < 0 || c.expiresAt <= c.issuedAt || c.expiresAt - c.issuedAt > LIFETIME_MS) {
                throw ProtocolException.Decode("invalid challenge lifetime")
            }
            if (c.issuedAt > phoneNow + CLOCK_SKEW_MS || phoneNow > c.expiresAt + CLOCK_SKEW_MS) {
                throw ProtocolException.Expired()
            }
            return c
        }
    }
}
