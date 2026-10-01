package dev.phonegate.protocol

/** Typed protocol messages (protocol §4.1, §5), mirroring `pg-core/src/messages.rs`. */

const val MAX_REQUEST_LIFETIME_MS = 60_000L
const val MATCH_MIN = 10L
const val MATCH_MAX = 99L

enum class Scenario(val wire: String) {
    Unlock("unlock"),
    Logon("logon"),
    Remote("remote"),
    DisableProtection("disable-protection"),

    /** Weakening a security setting while protection is on (feature 002, FR-116). */
    ChangeSetting("change-setting");

    companion object {
        fun parse(s: String): Scenario =
            entries.firstOrNull { it.wire == s } ?: throw ProtocolException.Decode("unknown scenario")
    }
}

enum class Decision(val wire: String) {
    Approve("approve"),
    Deny("deny"),
    NotMe("not-me");

    companion object {
        fun parse(s: String): Decision =
            entries.firstOrNull { it.wire == s } ?: throw ProtocolException.Decode("unknown decision")
    }
}

enum class Kind(val wire: String) {
    PairOffer("pair-offer"),
    PairJoin("pair-join"),
    PairConfirm("pair-confirm"),
    PairComplete("pair-complete"),
    ApprovalRequest("approval-request"),
    ApprovalResponse("approval-response"),
    Cancel("cancel"),
    Notice("notice"),
    Unpair("unpair"),

    /** Signed integrity report, PC to phone (feature 002). */
    Status("status"),

    /** Phone-initiated command, phone to PC (feature 004). */
    Command("command");

    /** Kinds that travel inside a sealed envelope (post-pairing). */
    val isSealed: Boolean
        get() = this == ApprovalRequest || this == ApprovalResponse || this == Cancel || this == Notice ||
            this == Unpair || this == Status || this == Command

    companion object {
        fun parse(s: String): Kind =
            entries.firstOrNull { it.wire == s } ?: throw ProtocolException.Decode("unknown kind")
    }
}

object Wire {
    fun wire(kind: Kind, payload: ByteArray): ByteArray =
        Enc("phonegate/v1/wire").str(kind.wire).bytes(payload).finish()

    fun unwire(body: ByteArray): Pair<Kind, ByteArray> {
        val f = Enc.decode(body, "phonegate/v1/wire", 3)
        return Kind.parse(f.string(1)) to f.bytes(2)
    }
}

class ApprovalRequest(
    val reqId: ByteArray,
    val nonce: ByteArray,
    val pcId: ByteArray,
    val phoneId: ByteArray,
    val issuedAt: Long,
    val expiresAt: Long,
    val scenario: Scenario,
    val account: String,
    val pcName: String,
    val remoteAddr: String,
    val matchNumber: Long,
) {
    fun encode(): ByteArray = Enc(LABEL)
        .bytes(reqId)
        .bytes(nonce)
        .bytes(pcId)
        .bytes(phoneId)
        .u64(issuedAt)
        .u64(expiresAt)
        .str(scenario.wire)
        .str(account)
        .str(pcName)
        .str(remoteAddr)
        .u64(matchNumber)
        .finish()

    fun digest(): ByteArray = Crypto.sha256(encode())

    fun validate() {
        if (matchNumber !in MATCH_MIN..MATCH_MAX) throw ProtocolException.Decode("match number out of range")
        // Unsigned comparison semantics as in Rust (u64): values are non-negative ms timestamps.
        if (issuedAt < 0 || expiresAt <= issuedAt || expiresAt - issuedAt > MAX_REQUEST_LIFETIME_MS) {
            throw ProtocolException.Decode("invalid request lifetime")
        }
    }

    companion object {
        const val LABEL = "phonegate/v1/approval-request"

        fun decode(b: ByteArray): ApprovalRequest {
            val f = Enc.decode(b, LABEL, 12)
            val r = ApprovalRequest(
                reqId = f.fixed(1, 16),
                nonce = f.fixed(2, 32),
                pcId = f.fixed(3, 32),
                phoneId = f.fixed(4, 32),
                issuedAt = f.u64(5),
                expiresAt = f.u64(6),
                scenario = Scenario.parse(f.string(7)),
                account = f.string(8),
                pcName = f.string(9),
                remoteAddr = f.string(10),
                matchNumber = f.u64(11),
            )
            r.validate()
            return r
        }
    }
}

fun decisionSignedBytes(digest: ByteArray, decision: Decision, typedNumber: Long, at: Long): ByteArray =
    Enc("phonegate/v1/decision").bytes(digest).str(decision.wire).u64(typedNumber).u64(at).finish()

class ApprovalResponse(
    val requestDigest: ByteArray,
    val decision: Decision,
    val typedNumber: Long,
    val respondedAt: Long,
    val decisionSig: ByteArray,
) {
    fun encode(): ByteArray = Enc(LABEL)
        .bytes(requestDigest)
        .str(decision.wire)
        .u64(typedNumber)
        .u64(respondedAt)
        .bytes(decisionSig)
        .finish()

    /** Verifies `decision_sig` with the approve key for Approve, the device key otherwise. */
    fun verifyDecision(approvePub: ByteArray, devicePub: ByteArray) {
        val key = if (decision == Decision.Approve) approvePub else devicePub
        Crypto.verify(key, decisionSignedBytes(requestDigest, decision, typedNumber, respondedAt), decisionSig)
    }

    companion object {
        const val LABEL = "phonegate/v1/approval-response"

        /**
         * Builds a response from an already computed raw signature over [decisionSignedBytes].
         * `typedNumber` is forced to 0 for deny / not-me, as in the Rust reference.
         */
        fun normalizedNumber(decision: Decision, typed: Long): Long = if (decision == Decision.Approve) typed else 0L

        fun decode(b: ByteArray): ApprovalResponse {
            val f = Enc.decode(b, LABEL, 6)
            return ApprovalResponse(
                requestDigest = f.fixed(1, 32),
                decision = Decision.parse(f.string(2)),
                typedNumber = f.u64(3),
                respondedAt = f.u64(4),
                decisionSig = f.fixed(5, 64),
            )
        }
    }
}

class Cancel(val reqId: ByteArray) {
    fun encode(): ByteArray = Enc("phonegate/v1/cancel").bytes(reqId).finish()

    companion object {
        fun decode(b: ByteArray): Cancel = Cancel(Enc.decode(b, "phonegate/v1/cancel", 2).fixed(1, 16))
    }
}

enum class NoticeKind(val wire: String) {
    RecoveryCodeUsed("recovery-code-used"),
    OfflineCodeUsed("offline-code-used"),
    ProtectionEnabled("protection-enabled"),
    ProtectionDisabled("protection-disabled"),
    Cooldown("cooldown"),

    // Feature 002 lifecycle and tamper notices.
    AgentStarted("agent-started"),
    AgentStopped("agent-stopped"),
    Shutdown("shutdown"),
    Sleep("sleep"),
    Resume("resume"),
    Repaired("repaired"),
    SafeModeBoot("safe-mode-boot"),
    SettingChanged("setting-changed");

    companion object {
        fun parse(s: String): NoticeKind =
            entries.firstOrNull { it.wire == s } ?: throw ProtocolException.Decode("unknown notice kind")
    }
}

class Notice(val kind: NoticeKind, val at: Long, val detail: String) {
    fun encode(): ByteArray = Enc("phonegate/v1/notice").str(kind.wire).u64(at).str(detail).finish()

    companion object {
        fun decode(b: ByteArray): Notice {
            val f = Enc.decode(b, "phonegate/v1/notice", 4)
            return Notice(NoticeKind.parse(f.string(1)), f.u64(2), f.string(3))
        }
    }
}

class Unpair(val at: Long) {
    fun encode(): ByteArray = Enc("phonegate/v1/unpair").u64(at).finish()

    companion object {
        fun decode(b: ByteArray): Unpair = Unpair(Enc.decode(b, "phonegate/v1/unpair", 2).u64(1))
    }
}

enum class BitLocker(val wire: String) {
    Off("off"),
    OnNoPin("on-no-pin"),
    OnPin("on-pin"),
    Unknown("unknown");

    companion object {
        fun parse(s: String): BitLocker =
            entries.firstOrNull { it.wire == s } ?: throw ProtocolException.Decode("unknown bitlocker state")
    }
}

/** Periodic signed integrity report, PC to phone (feature 002 contract §1). */
data class Status(
    val seq: Long,
    val at: Long,
    val enforce: Boolean,
    val cpRegistered: Boolean,
    val filterRegistered: Boolean,
    val filesIntact: Boolean,
    val watchdogPresent: Boolean,
    val bitlocker: BitLocker,
    val netlogonBlocked: Boolean,
    val safeMode: Boolean,
) {
    /** Integrity is healthy when every protection component is present. */
    val integrityOk: Boolean get() = cpRegistered && filterRegistered && filesIntact

    fun encode(): ByteArray = Enc(LABEL)
        .u64(seq)
        .u64(at)
        .u64(enforce.u)
        .u64(cpRegistered.u)
        .u64(filterRegistered.u)
        .u64(filesIntact.u)
        .u64(watchdogPresent.u)
        .str(bitlocker.wire)
        .u64(netlogonBlocked.u)
        .u64(safeMode.u)
        .finish()

    companion object {
        const val LABEL = "phonegate/v1/status"

        private val Boolean.u: Long get() = if (this) 1L else 0L

        private fun flag(f: Fields, i: Int): Boolean = when (f.u64(i)) {
            0L -> false
            1L -> true
            else -> throw ProtocolException.Decode("flag must be 0 or 1")
        }

        fun decode(b: ByteArray): Status {
            val f = Enc.decode(b, LABEL, 11)
            return Status(
                seq = f.u64(1),
                at = f.u64(2),
                enforce = flag(f, 3),
                cpRegistered = flag(f, 4),
                filterRegistered = flag(f, 5),
                filesIntact = flag(f, 6),
                watchdogPresent = flag(f, 7),
                bitlocker = BitLocker.parse(f.string(8)),
                netlogonBlocked = flag(f, 9),
                safeMode = flag(f, 10),
            )
        }
    }
}

const val MAX_COMMAND_LIFETIME_MS = 120_000L

/**
 * The bytes the approve key signs. Independent of pc_id/phone_id so the authority is over the
 * action, bound by nonce/expiry and verified against this pairing's approve key.
 */
fun commandAuthBytes(cmdId: ByteArray, nonce: ByteArray, command: String, issuedAt: Long, expiresAt: Long): ByteArray =
    Enc("phonegate/v1/command-auth")
        .bytes(cmdId)
        .bytes(nonce)
        .str(command)
        .u64(issuedAt)
        .u64(expiresAt)
        .finish()

/**
 * A phone-initiated command (phone to PC), e.g. "turn off protection" (feature 004 §1). Its
 * authority is the biometric-bound approve key, so the device key sealing the envelope is not
 * enough on its own: the PC verifies [approveSig] against the pinned approve key.
 */
data class Command(
    val cmdId: ByteArray,
    val nonce: ByteArray,
    val pcId: ByteArray,
    val phoneId: ByteArray,
    val issuedAt: Long,
    val expiresAt: Long,
    val command: String,
    val approveSig: ByteArray,
) {
    fun encode(): ByteArray = Enc(LABEL)
        .bytes(cmdId)
        .bytes(nonce)
        .bytes(pcId)
        .bytes(phoneId)
        .u64(issuedAt)
        .u64(expiresAt)
        .str(command)
        .bytes(approveSig)
        .finish()

    /** Verifies the approve-key authority signature over [commandAuthBytes]. */
    fun verifyAuth(approvePub: ByteArray) {
        Crypto.verify(approvePub, commandAuthBytes(cmdId, nonce, command, issuedAt, expiresAt), approveSig)
    }

    companion object {
        const val LABEL = "phonegate/v1/command"
        const val DISABLE_PROTECTION = "disable-protection"

        fun decode(b: ByteArray): Command {
            val f = Enc.decode(b, LABEL, 9)
            val c = Command(
                cmdId = f.fixed(1, 16),
                nonce = f.fixed(2, 32),
                pcId = f.fixed(3, 32),
                phoneId = f.fixed(4, 32),
                issuedAt = f.u64(5),
                expiresAt = f.u64(6),
                command = f.string(7),
                approveSig = f.fixed(8, 64),
            )
            if (c.issuedAt < 0 || c.expiresAt <= c.issuedAt || c.expiresAt - c.issuedAt > MAX_COMMAND_LIFETIME_MS) {
                throw ProtocolException.Decode("invalid command lifetime")
            }
            return c
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Command) return false
        return cmdId.contentEquals(other.cmdId) && nonce.contentEquals(other.nonce) &&
            pcId.contentEquals(other.pcId) && phoneId.contentEquals(other.phoneId) &&
            issuedAt == other.issuedAt && expiresAt == other.expiresAt &&
            command == other.command && approveSig.contentEquals(other.approveSig)
    }

    override fun hashCode(): Int = cmdId.contentHashCode()
}
