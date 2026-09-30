package dev.phonegate.protocol

import org.json.JSONObject

/**
 * Phone-side health model and alert rule (feature 002, contract §4). A line-by-line port of
 * `crates/pg-core/src/health.rs`.
 *
 * Silence is measured on the phone's clock, so neither the PC nor the relay can suppress the
 * "stopped reporting" alarm: withholding reports can only cause an alarm, never hide one.
 * The model is immutable; every event returns the next model plus the alert it raised, if any.
 */
const val SILENCE_MS: Long = 20 * 60_000L
const val DISABLE_GRACE_MS: Long = 10 * 60_000L

sealed class Alert {
    data object AgentStopped : Alert()
    data class Repaired(val what: String) : Alert()
    data class SafeModeBoot(val `when`: String) : Alert()
    data class IntegrityBroken(val what: String) : Alert()
    data object ProtectionOffWithoutApproval : Alert()
    data object StoppedReporting : Alert()

    /** Owner-facing sentence; reference wording from `Alert::message`. */
    fun message(pc: String): String = when (this) {
        AgentStopped -> "PhoneGate on $pc was stopped. If you didn't do this, someone may be tampering with the PC."
        is Repaired -> "PhoneGate on $pc had to repair itself: $what."
        is SafeModeBoot -> "$pc was started in Safe Mode ($`when`). Safe Mode skips the phone check."
        is IntegrityBroken -> "PhoneGate protection on $pc is damaged: $what."
        ProtectionOffWithoutApproval -> "Protection on $pc was turned off without your approval."
        StoppedReporting -> "$pc stopped reporting. It may be offline, or PhoneGate may have been removed."
    }

    /** Stable id for storage. */
    val type: String
        get() = when (this) {
            AgentStopped -> "agent_stopped"
            is Repaired -> "repaired"
            is SafeModeBoot -> "safe_mode_boot"
            is IntegrityBroken -> "integrity_broken"
            ProtectionOffWithoutApproval -> "protection_off_without_approval"
            StoppedReporting -> "stopped_reporting"
        }

    val detail: String?
        get() = when (this) {
            is Repaired -> what
            is SafeModeBoot -> `when`
            is IntegrityBroken -> what
            else -> null
        }

    companion object {
        fun of(type: String, detail: String?): Alert? = when (type) {
            "agent_stopped" -> AgentStopped
            "repaired" -> Repaired(detail ?: "")
            "safe_mode_boot" -> SafeModeBoot(detail ?: "")
            "integrity_broken" -> IntegrityBroken(detail ?: "")
            "protection_off_without_approval" -> ProtectionOffWithoutApproval
            "stopped_reporting" -> StoppedReporting
            else -> null
        }
    }
}

enum class PcState { Ok, Asleep, Off, StoppedReporting, TamperAlert }

enum class Lifecycle { Running, Shutdown, Sleep }

/** Result of feeding one event to the model. */
data class HealthStep(val health: Health, val alert: Alert?)

data class Health(
    val lastSeq: Long? = null,
    val lastSeenAt: Long,
    val lastEnforce: Boolean? = null,
    val lifecycle: Lifecycle = Lifecycle.Running,
    val lastDisableNoticeAt: Long? = null,
    val inAlert: Boolean = false,
    val silenceAlerted: Boolean = false,
    val bitlockerOff: Boolean = false,
    val netlogonBlocked: Boolean = false,
) {
    /** One alert per episode. */
    private fun raise(a: Alert): HealthStep =
        if (inAlert) HealthStep(this, null) else HealthStep(copy(inAlert = true), a)

    /** A verified `status` report. Throws [ProtocolException.Replay] if its sequence is not newer. */
    fun onStatus(st: Status, now: Long): HealthStep {
        if (lastSeq != null && java.lang.Long.compareUnsigned(st.seq, lastSeq) <= 0) throw ProtocolException.Replay()
        val prevEnforce = lastEnforce
        val h = copy(
            lastSeq = st.seq,
            lastSeenAt = now,
            silenceAlerted = false,
            lifecycle = Lifecycle.Running,
            bitlockerOff = st.bitlocker == BitLocker.Off,
            netlogonBlocked = st.netlogonBlocked,
            lastEnforce = st.enforce,
        )
        if (st.enforce && !st.integrityOk) {
            val missing = buildList {
                if (!st.cpRegistered) add("sign-in tile unregistered")
                if (!st.filterRegistered) add("tile filter unregistered")
                if (!st.filesIntact) add("program files changed")
            }
            return h.raise(Alert.IntegrityBroken(missing.joinToString(", ")))
        }
        if (prevEnforce == true && !st.enforce) {
            val approved = h.lastDisableNoticeAt != null && satSub(now, h.lastDisableNoticeAt) <= DISABLE_GRACE_MS
            if (!approved) return h.raise(Alert.ProtectionOffWithoutApproval)
        }
        // A fully healthy report ends the episode.
        return HealthStep(h.copy(inAlert = false), null)
    }

    /** A verified lifecycle / setting notice. */
    fun onNotice(kind: NoticeKind, detail: String, now: Long): HealthStep = when (kind) {
        NoticeKind.Shutdown -> HealthStep(copy(lifecycle = Lifecycle.Shutdown), null)
        NoticeKind.Sleep -> HealthStep(copy(lifecycle = Lifecycle.Sleep), null)
        NoticeKind.Resume, NoticeKind.AgentStarted -> HealthStep(copy(lifecycle = Lifecycle.Running), null)
        NoticeKind.ProtectionDisabled -> HealthStep(copy(lastDisableNoticeAt = now), null)
        NoticeKind.AgentStopped -> raise(Alert.AgentStopped)
        NoticeKind.Repaired -> raise(Alert.Repaired(detail))
        NoticeKind.SafeModeBoot -> raise(Alert.SafeModeBoot(detail))
        else -> HealthStep(this, null)
    }

    /** Periodic check (every minute) for the silence alarm. */
    fun tick(now: Long): HealthStep {
        val asleep = lifecycle == Lifecycle.Shutdown || lifecycle == Lifecycle.Sleep
        if (!asleep && !silenceAlerted && satSub(now, lastSeenAt) > SILENCE_MS) {
            return copy(silenceAlerted = true).raise(Alert.StoppedReporting)
        }
        return HealthStep(this, null)
    }

    fun state(now: Long): PcState {
        if (inAlert) return PcState.TamperAlert
        return when (lifecycle) {
            Lifecycle.Shutdown -> PcState.Off
            Lifecycle.Sleep -> PcState.Asleep
            Lifecycle.Running -> if (satSub(now, lastSeenAt) > SILENCE_MS) PcState.StoppedReporting else PcState.Ok
        }
    }

    fun toJson(): JSONObject = JSONObject()
        .put("last_seen_at", lastSeenAt)
        .put("lifecycle", lifecycle.name)
        .put("in_alert", inAlert)
        .put("silence_alerted", silenceAlerted)
        .put("bitlocker_off", bitlockerOff)
        .put("netlogon_blocked", netlogonBlocked)
        .apply {
            if (lastSeq != null) put("last_seq", lastSeq)
            if (lastEnforce != null) put("last_enforce", lastEnforce)
            if (lastDisableNoticeAt != null) put("last_disable_notice_at", lastDisableNoticeAt)
        }

    companion object {
        /** Starts tracking at `now` (e.g. pairing time) so a PC that never reports still alarms. */
        fun new(now: Long): Health = Health(lastSeenAt = now)

        /** u64 saturating subtraction, as in the Rust reference. */
        private fun satSub(a: Long, b: Long): Long = if (a > b) a - b else 0L

        fun fromJson(o: JSONObject): Health = Health(
            lastSeq = if (o.has("last_seq")) o.getLong("last_seq") else null,
            lastSeenAt = o.getLong("last_seen_at"),
            lastEnforce = if (o.has("last_enforce")) o.getBoolean("last_enforce") else null,
            lifecycle = runCatching { Lifecycle.valueOf(o.getString("lifecycle")) }.getOrDefault(Lifecycle.Running),
            lastDisableNoticeAt = if (o.has("last_disable_notice_at")) o.getLong("last_disable_notice_at") else null,
            inAlert = o.optBoolean("in_alert", false),
            silenceAlerted = o.optBoolean("silence_alerted", false),
            bitlockerOff = o.optBoolean("bitlocker_off", false),
            netlogonBlocked = o.optBoolean("netlogon_blocked", false),
        )
    }
}
