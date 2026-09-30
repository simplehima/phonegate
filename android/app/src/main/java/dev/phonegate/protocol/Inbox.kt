package dev.phonegate.protocol

/** The pinned material of one pairing, as seen by the phone. */
class PairingContext(
    val pcPub: ByteArray,
    val kPair: ByteArray,
    /** ID of this pairing's phone device key (= mailbox id on the relay). */
    val phoneId: ByteArray,
) {
    val pcId: ByteArray get() = Crypto.idOf(pcPub)
}

/** Remembers message ids for the 24 h replay window. */
interface ReplayGuard {
    /** Returns true and records [id] if unseen; false if it was already seen. */
    fun firstSeen(id: ByteArray, now: Long): Boolean
}

/** An in-memory replay window (tests and a cache in front of the persistent one). */
class MemoryReplayGuard : ReplayGuard {
    private val seen = HashMap<String, Long>()

    @Synchronized
    override fun firstSeen(id: ByteArray, now: Long): Boolean {
        seen.entries.removeAll { now - it.value > WINDOW_MS }
        return seen.putIfAbsent(B64.encode(id), now) == null
    }

    companion object {
        const val WINDOW_MS = 24L * 60 * 60 * 1000
    }
}

sealed class Inbound {
    class Request(val request: ApprovalRequest) : Inbound()
    class CancelMsg(val reqId: ByteArray) : Inbound()
    class NoticeMsg(val notice: Notice) : Inbound()
    class UnpairMsg(val at: Long) : Inbound()
    class StatusMsg(val status: Status) : Inbound()
}

/**
 * Verifies one relay `msg` for a pairing (protocol §4, §4.3). Any failure throws; callers
 * discard silently and never show or answer the message.
 */
object Inbox {
    const val SKEW_MS = 300_000L

    fun receive(ctx: PairingContext, relayFrom: ByteArray, wireBody: ByteArray, now: Long, replay: ReplayGuard): Inbound {
        if (!Crypto.ctEq(relayFrom, ctx.pcId)) throw ProtocolException.Verify("message from unpaired sender")
        val (kind, payload) = Wire.unwire(wireBody)
        val env = Envelope.parse(payload)
        if (env.kind != kind) throw ProtocolException.Verify("wire kind does not match envelope")
        val plain = env.open(ctx.pcPub, ctx.kPair, Dir.PcToPhone, ctx.pcId, ctx.phoneId)
        return when (kind) {
            Kind.ApprovalRequest -> {
                val r = ApprovalRequest.decode(plain)
                if (!Crypto.ctEq(r.pcId, ctx.pcId) || !Crypto.ctEq(r.phoneId, ctx.phoneId)) {
                    throw ProtocolException.Verify("request ids do not match pairing")
                }
                if (r.issuedAt > now + SKEW_MS || now > r.expiresAt + SKEW_MS) throw ProtocolException.Expired()
                if (!replay.firstSeen(env.msgId, now)) throw ProtocolException.Replay()
                if (!replay.firstSeen(byteArrayOf(0x72) + r.reqId, now)) throw ProtocolException.Replay()
                Inbound.Request(r)
            }
            Kind.Cancel -> {
                val c = Cancel.decode(plain)
                if (!replay.firstSeen(env.msgId, now)) throw ProtocolException.Replay()
                Inbound.CancelMsg(c.reqId)
            }
            Kind.Notice -> {
                val n = Notice.decode(plain)
                if (!replay.firstSeen(env.msgId, now)) throw ProtocolException.Replay()
                Inbound.NoticeMsg(n)
            }
            Kind.Unpair -> {
                val u = Unpair.decode(plain)
                if (!replay.firstSeen(env.msgId, now)) throw ProtocolException.Replay()
                Inbound.UnpairMsg(u.at)
            }
            Kind.Status -> {
                // Strict decode (flags 0/1, known bitlocker); sequence freshness is checked by
                // the health model, which owns last_seq per PC.
                val st = Status.decode(plain)
                if (!replay.firstSeen(env.msgId, now)) throw ProtocolException.Replay()
                Inbound.StatusMsg(st)
            }
            else -> throw ProtocolException.Decode("unexpected kind from pc")
        }
    }

    /** Builds the sealed wire body of a phone → PC message (signed by the device key). */
    fun sealToPc(ctx: PairingContext, device: Signer, kind: Kind, plaintext: ByteArray): ByteArray {
        val (env, _) = Envelope.seal(ctx.kPair, Dir.PhoneToPc, kind, ctx.phoneId, ctx.pcId, device, plaintext)
        return Wire.wire(kind, env)
    }
}
