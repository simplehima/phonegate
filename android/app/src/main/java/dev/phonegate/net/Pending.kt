package dev.phonegate.net

import dev.phonegate.protocol.ApprovalRequest
import dev.phonegate.protocol.B64
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlin.math.abs

/** A verified approval request waiting for the owner. Only verified requests ever get here. */
class PendingRequest(
    val pcId: String,
    val request: ApprovalRequest,
    val receivedAt: Long,
) {
    val reqId: String = B64.encode(request.reqId)
    val lifetimeMs: Long = request.expiresAt - request.issuedAt

    /**
     * Local deadline for the countdown. With a sane phone clock the PC's `expires_at` is used;
     * with a skewed clock (still within the 5 min acceptance window) the lifetime is counted
     * from when the phone received the request.
     */
    val localDeadline: Long =
        if (abs(receivedAt - request.issuedAt) <= 10_000) request.expiresAt else receivedAt + lifetimeMs

    val notificationId: Int = reqId.hashCode()
}

sealed class Resolution {
    data object Superseded : Resolution()
    data object Cancelled : Resolution()
    data object Expired : Resolution()
    data class Answered(val stamp: String) : Resolution()
}

/** In-memory registry of live requests (one per PC: a newer request supersedes older ones). */
object Pending {
    private val _byPc = MutableStateFlow<Map<String, PendingRequest>>(emptyMap())
    val byPc: StateFlow<Map<String, PendingRequest>> = _byPc.asStateFlow()

    private val _resolved = MutableStateFlow<Map<String, Resolution>>(emptyMap())
    /** reqId → how it ended, so an open approval screen can show the right final state. */
    val resolved: StateFlow<Map<String, Resolution>> = _resolved.asStateFlow()

    /** Adds a request; returns the superseded one, if any. */
    fun put(p: PendingRequest): PendingRequest? {
        var old: PendingRequest? = null
        _byPc.update { m ->
            old = m[p.pcId]
            m + (p.pcId to p)
        }
        old?.let { resolve(it.reqId, Resolution.Superseded) }
        return old
    }

    fun find(reqId: String): PendingRequest? = _byPc.value.values.firstOrNull { it.reqId == reqId }

    fun findByReqBytes(pcId: String, reqId: ByteArray): PendingRequest? =
        _byPc.value[pcId]?.takeIf { it.request.reqId.contentEquals(reqId) }

    /** Removes a request if it is still the live one; returns true if it was. */
    fun remove(reqId: String, how: Resolution): Boolean {
        var removed = false
        _byPc.update { m ->
            val entry = m.entries.firstOrNull { it.value.reqId == reqId }
            if (entry == null) m else {
                removed = true
                m - entry.key
            }
        }
        if (removed) resolve(reqId, how)
        return removed
    }

    fun removePc(pcId: String) {
        _byPc.value[pcId]?.let { remove(it.reqId, Resolution.Cancelled) }
    }

    private fun resolve(reqId: String, how: Resolution) {
        _resolved.update { m -> (m + (reqId to how)).entries.toList().takeLast(32).associate { it.key to it.value } }
    }
}
