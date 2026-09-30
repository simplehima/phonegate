package dev.phonegate.net

import android.content.Context
import dev.phonegate.data.AttemptRecord
import dev.phonegate.data.Outcome
import dev.phonegate.data.PhoneStore
import dev.phonegate.keys.KeyManager
import dev.phonegate.protocol.ApprovalResponse
import dev.phonegate.protocol.Decision
import dev.phonegate.protocol.Kind
import dev.phonegate.protocol.decisionSignedBytes

/**
 * Builds and sends approval responses (protocol §4.1). Approve is signed ONLY by the approve key
 * after a biometric (the caller passes the raw signature from the authenticated Signature);
 * deny / not-me are signed by the device key without a biometric (FR-017).
 */
object Responder {
    enum class Result { Sent, NotSent, NoLongerPending }

    /** Deny or "This wasn't me", signed with the device key. */
    suspend fun refuse(context: Context, p: PendingRequest, decision: Decision, detail: String? = null): Result {
        require(decision != Decision.Approve) { "approve must go through the approve key" }
        val store = PhoneStore.get(context)
        val pc = store.state.value.pc(p.pcId) ?: return Result.NotSent
        if (Pending.find(p.reqId) == null) return Result.NoLongerPending
        val at = System.currentTimeMillis()
        val digest = p.request.digest()
        val sig = KeyManager.deviceSigner(pc.deviceAlias).sign(decisionSignedBytes(digest, decision, 0, at))
        val resp = ApprovalResponse(digest, decision, 0, at, sig)
        val sent = RelayHub.sendSealed(p.pcId, Kind.ApprovalResponse, resp.encode())
        val outcome = if (decision == Decision.Deny) Outcome.Denied else Outcome.NotMe
        finish(context, p, if (sent) outcome else Outcome.Error, detail, if (decision == Decision.Deny) "DENIED" else "NOT ME")
        return if (sent) Result.Sent else Result.NotSent
    }

    /** Bytes the approve key must sign for this request, typed number and time. */
    fun approveBytes(p: PendingRequest, typed: Long, at: Long): ByteArray =
        decisionSignedBytes(p.request.digest(), Decision.Approve, typed, at)

    /** Sends an approval whose decision signature was produced by the biometric-gated key. */
    suspend fun sendApprove(context: Context, p: PendingRequest, typed: Long, at: Long, approveSig: ByteArray): Result {
        if (Pending.find(p.reqId) == null) return Result.NoLongerPending
        val resp = ApprovalResponse(p.request.digest(), Decision.Approve, typed, at, approveSig)
        val sent = RelayHub.sendSealed(p.pcId, Kind.ApprovalResponse, resp.encode())
        finish(context, p, if (sent) Outcome.Approved else Outcome.Error, null, "APPROVED")
        return if (sent) Result.Sent else Result.NotSent
    }

    private fun finish(context: Context, p: PendingRequest, outcome: Outcome, detail: String?, stamp: String) {
        Pending.remove(p.reqId, Resolution.Answered(if (outcome == Outcome.Error) "NOT SENT" else stamp))
        Notifications.cancel(context, p.notificationId)
        val store = PhoneStore.get(context)
        val pcName = store.state.value.pc(p.pcId)?.pcName ?: p.request.pcName
        store.record(AttemptRecord(System.currentTimeMillis(), pcName, p.request.account, p.request.scenario.wire, outcome, p.reqId, detail))
    }
}
