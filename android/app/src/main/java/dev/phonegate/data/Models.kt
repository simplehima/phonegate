package dev.phonegate.data

import dev.phonegate.protocol.B64
import dev.phonegate.protocol.Alert
import dev.phonegate.protocol.Crypto
import dev.phonegate.protocol.Health
import org.json.JSONArray
import org.json.JSONObject

/** Phone-side persistent state (data-model.md), serialized to JSON then encrypted at rest. */
data class PhoneState(
    val version: Int = 1,
    val deviceName: String,
    val pcs: List<PairedPc> = emptyList(),
    val history: List<AttemptRecord> = emptyList(),
    /** b64(id) → first-seen ms, 24 h replay window. */
    val seen: Map<String, Long> = emptyMap(),
) {
    fun pc(pcIdB64: String): PairedPc? = pcs.firstOrNull { it.pcId == pcIdB64 }

    /** Drops history older than 90 days and replay ids older than 24 h. */
    fun pruned(now: Long): PhoneState = copy(
        history = history.filter { now - it.at <= HISTORY_RETENTION_MS }.sortedByDescending { it.at }.take(MAX_HISTORY),
        seen = seen.filterValues { now - it <= SEEN_WINDOW_MS },
    )

    fun toJson(): JSONObject = JSONObject()
        .put("version", version)
        .put("device_name", deviceName)
        .put("pcs", JSONArray().apply { pcs.forEach { put(it.toJson()) } })
        .put("history", JSONArray().apply { history.forEach { put(it.toJson()) } })
        .put("seen_msg_ids", JSONObject().apply { seen.forEach { (k, v) -> put(k, v) } })

    companion object {
        const val HISTORY_RETENTION_MS = 90L * 24 * 60 * 60 * 1000
        const val SEEN_WINDOW_MS = 24L * 60 * 60 * 1000
        const val MAX_HISTORY = 5000

        fun fromJson(o: JSONObject): PhoneState {
            val pcs = o.optJSONArray("pcs") ?: JSONArray()
            val hist = o.optJSONArray("history") ?: JSONArray()
            val seenObj = o.optJSONObject("seen_msg_ids") ?: JSONObject()
            val seen = HashMap<String, Long>()
            seenObj.keys().forEach { k -> seen[k] = seenObj.getLong(k) }
            return PhoneState(
                version = o.optInt("version", 1),
                deviceName = o.getString("device_name"),
                pcs = (0 until pcs.length()).map { PairedPc.fromJson(pcs.getJSONObject(it)) },
                history = (0 until hist.length()).map { AttemptRecord.fromJson(hist.getJSONObject(it)) },
                seen = seen,
            )
        }
    }
}

enum class KeyLevel(val label: String) {
    StrongBox("StrongBox"),
    Tee("Secure hardware (TEE)"),
    Software("Software only"),
    Unknown("Unknown"),
}

data class PairedPc(
    val pcId: String,
    val pcPub: String,
    val pcName: String,
    val relayUrl: String,
    val kPair: String,
    val kOfflineWrapped: String,
    val deviceAlias: String,
    val approveAlias: String,
    val offlineAlias: String,
    val pairedAt: Long,
    val keyLevel: KeyLevel,
    /** Null when healthy; otherwise why the PC must be paired again (e.g. keys invalidated). */
    val repairReason: String? = null,
    /** Feature 002 health model (reports, lifecycle, alert episode). */
    val health: Health = Health.new(pairedAt),
    /** The alert of the current or most recent episode, as shown to the owner. */
    val alert: AlertRecord? = null,
) {
    val pcPubBytes: ByteArray get() = B64.decodeFixed(pcPub, 65)
    val pcIdBytes: ByteArray get() = B64.decodeFixed(pcId, 32)
    val kPairBytes: ByteArray get() = B64.decodeFixed(kPair, 32)
    val needsRepair: Boolean get() = repairReason != null

    fun toJson(): JSONObject = JSONObject()
        .put("pc_id", pcId)
        .put("pc_pub", pcPub)
        .put("pc_name", pcName)
        .put("relay_url", relayUrl)
        .put("k_pair", kPair)
        .put("k_offline_wrapped", kOfflineWrapped)
        .put("device_key_alias", deviceAlias)
        .put("approve_key_alias", approveAlias)
        .put("offline_key_alias", offlineAlias)
        .put("paired_at", pairedAt)
        .put("key_level", keyLevel.name)
        .put("health", health.toJson())
        .apply {
            if (repairReason != null) put("repair_reason", repairReason)
            if (alert != null) put("alert", alert.toJson())
        }

    companion object {
        fun fromJson(o: JSONObject): PairedPc {
            val pc = PairedPc(
                pcId = o.getString("pc_id"),
                pcPub = o.getString("pc_pub"),
                pcName = o.getString("pc_name"),
                relayUrl = o.getString("relay_url"),
                kPair = o.getString("k_pair"),
                kOfflineWrapped = o.getString("k_offline_wrapped"),
                deviceAlias = o.getString("device_key_alias"),
                approveAlias = o.getString("approve_key_alias"),
                offlineAlias = o.getString("offline_key_alias"),
                pairedAt = o.getLong("paired_at"),
                keyLevel = runCatching { KeyLevel.valueOf(o.getString("key_level")) }.getOrDefault(KeyLevel.Unknown),
                repairReason = if (o.has("repair_reason")) o.getString("repair_reason") else null,
                // Pairings stored before feature 002 start tracking from the moment they load.
                health = o.optJSONObject("health")?.let { Health.fromJson(it) } ?: Health.new(System.currentTimeMillis()),
                alert = o.optJSONObject("alert")?.let { AlertRecord.fromJson(it) },
            )
            // The stored id must still be the hash of the pinned key.
            require(Crypto.idOf(pc.pcPubBytes).contentEquals(pc.pcIdBytes)) { "pc id does not match pinned key" }
            return pc
        }
    }
}

/** An alert as raised for the owner; `seenAt` only records that the owner looked at it. */
data class AlertRecord(val type: String, val detail: String?, val message: String, val raisedAt: Long, val seenAt: Long? = null) {
    val alert: Alert? get() = Alert.of(type, detail)

    fun toJson(): JSONObject = JSONObject()
        .put("type", type)
        .put("message", message)
        .put("raised_at", raisedAt)
        .apply {
            if (detail != null) put("detail", detail)
            if (seenAt != null) put("seen_at", seenAt)
        }

    companion object {
        fun of(a: Alert, pcName: String, now: Long) = AlertRecord(a.type, a.detail, a.message(pcName), now)

        fun fromJson(o: JSONObject) = AlertRecord(
            type = o.getString("type"),
            detail = if (o.has("detail")) o.getString("detail") else null,
            message = o.getString("message"),
            raisedAt = o.getLong("raised_at"),
            seenAt = if (o.has("seen_at")) o.getLong("seen_at") else null,
        )
    }
}

enum class Outcome(val wire: String, val stamp: String) {
    Approved("approved", "APPROVED"),
    Denied("denied", "DENIED"),
    NotMe("not_me", "NOT ME"),
    Expired("expired", "EXPIRED"),
    RecoveryCode("recovery_code", "RECOVERY CODE"),
    OfflineCode("offline_code", "OFFLINE CODE"),
    WrongNumber("wrong_number", "WRONG NUMBER"),
    Error("error", "NOT SENT"),
    Paired("paired", "PAIRED"),
    Unpaired("unpaired", "UNPAIRED"),
    Notice("notice", "NOTICE"),
    Tamper("tamper", "TAMPER ALERT"),
    PcEvent("pc_event", "PC EVENT");

    companion object {
        fun parse(s: String): Outcome = entries.firstOrNull { it.wire == s } ?: Error
    }
}

data class AttemptRecord(
    val at: Long,
    val pcName: String,
    val account: String,
    val scenario: String,
    val outcome: Outcome,
    val reqId: String? = null,
    val detail: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("at", at)
        .put("pc_name", pcName)
        .put("account", account)
        .put("scenario", scenario)
        .put("outcome", outcome.wire)
        .apply {
            if (reqId != null) put("req_id", reqId)
            if (detail != null) put("detail", detail)
        }

    companion object {
        fun fromJson(o: JSONObject) = AttemptRecord(
            at = o.getLong("at"),
            pcName = o.getString("pc_name"),
            account = o.optString("account", ""),
            scenario = o.optString("scenario", ""),
            outcome = Outcome.parse(o.getString("outcome")),
            reqId = if (o.has("req_id")) o.getString("req_id") else null,
            detail = if (o.has("detail")) o.getString("detail") else null,
        )
    }
}
