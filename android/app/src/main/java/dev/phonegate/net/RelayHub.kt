package dev.phonegate.net

import android.content.Context
import android.os.Handler
import android.os.Looper
import dev.phonegate.R
import dev.phonegate.data.AttemptRecord
import dev.phonegate.data.Outcome
import dev.phonegate.data.PairedPc
import dev.phonegate.data.PhoneStore
import dev.phonegate.keys.KeyManager
import dev.phonegate.protocol.Crypto
import dev.phonegate.protocol.Inbound
import dev.phonegate.protocol.Inbox
import dev.phonegate.protocol.NoticeKind
import dev.phonegate.protocol.PairingContext
import dev.phonegate.protocol.ProtocolException
import dev.phonegate.protocol.RelayClient
import dev.phonegate.protocol.Signer
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * One authenticated relay connection per paired PC, each using that PC's device key (so each
 * pairing has its own mailbox id). Every incoming frame goes through [Inbox]; anything that
 * fails verification is dropped silently.
 */
object RelayHub {
    private class Conn(val pc: PairedPc, val client: RelayClient, val ctx: PairingContext, val device: Signer)

    private val conns = HashMap<String, Conn>()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var appContext: Context

    private val _status = MutableStateFlow<Map<String, RelayClient.Status>>(emptyMap())
    val status: StateFlow<Map<String, RelayClient.Status>> = _status.asStateFlow()

    var onStatusChanged: (() -> Unit)? = null

    @Synchronized
    fun sync(context: Context) {
        appContext = context.applicationContext
        val store = PhoneStore.get(appContext)
        val wanted = store.state.value.pcs.filter { !it.needsRepair }.associateBy { it.pcId }
        // Close connections for removed / broken / changed pairings.
        for (id in conns.keys.toList()) {
            val c = conns[id]!!
            val w = wanted[id]
            if (w == null || w.deviceAlias != c.pc.deviceAlias || w.relayUrl != c.pc.relayUrl || w.kPair != c.pc.kPair) {
                c.client.close()
                conns.remove(id)
                _status.update { it - id }
            }
        }
        for ((id, pc) in wanted) {
            if (conns.containsKey(id)) continue
            if (!KeyManager.exists(pc.deviceAlias)) {
                store.markNeedsRepair(id, appContext.getString(R.string.repair_key_missing))
                continue
            }
            val device = KeyManager.deviceSigner(pc.deviceAlias)
            val ctx = PairingContext(pc.pcPubBytes, pc.kPairBytes, Crypto.idOf(device.public))
            val client = RelayClient(pc.relayUrl, device, Listener(id))
            conns[id] = Conn(pc, client, ctx, device)
            client.start()
        }
        onStatusChanged?.invoke()
    }

    @Synchronized
    fun stopAll() {
        conns.values.forEach { it.client.close() }
        conns.clear()
        _status.value = emptyMap()
    }

    fun connectedCount(): Int = _status.value.values.count { it == RelayClient.Status.Ready }

    @Synchronized
    private fun conn(pcId: String): Conn? = conns[pcId]

    /** Seals and sends a phone → PC message, waiting briefly for the connection if needed. */
    suspend fun sendSealed(pcId: String, kind: dev.phonegate.protocol.Kind, plaintext: ByteArray, ttlS: Int = 60): Boolean {
        val deadline = System.currentTimeMillis() + 8_000
        while (true) {
            val c = conn(pcId)
            if (c != null && c.client.isReady) {
                val body = Inbox.sealToPc(c.ctx, c.device, kind, plaintext)
                if (c.client.send(c.ctx.pcId, body, ttlS) != null) return true
            }
            if (System.currentTimeMillis() > deadline) return false
            delay(250)
        }
    }

    private class Listener(val pcId: String) : RelayClient.Listener {
        override fun onStatus(status: RelayClient.Status) {
            _status.update { it + (pcId to status) }
            main.post { onStatusChanged?.invoke() }
        }

        override fun onMessage(from: ByteArray, to: ByteArray, body: ByteArray) {
            val c = conn(pcId) ?: return
            val store = PhoneStore.get(appContext)
            val inbound = try {
                Inbox.receive(c.ctx, from, body, System.currentTimeMillis(), store)
            } catch (e: ProtocolException) {
                return // Unverified, stale, replayed or malformed: discard silently.
            } catch (e: Exception) {
                return
            }
            main.post { handle(c, inbound) }
        }
    }

    private fun handle(c: Conn, inbound: Inbound) {
        val ctx = appContext
        val store = PhoneStore.get(ctx)
        val pcId = c.pc.pcId
        val pcName = store.state.value.pc(pcId)?.pcName ?: c.pc.pcName
        when (inbound) {
            is Inbound.Request -> {
                val p = PendingRequest(pcId, inbound.request, System.currentTimeMillis())
                Pending.put(p)?.let { Notifications.cancel(ctx, it.notificationId) }
                Notifications.postRequest(ctx, p)
                val wait = (p.localDeadline - System.currentTimeMillis()).coerceAtLeast(0)
                main.postDelayed({
                    if (Pending.remove(p.reqId, Resolution.Expired)) {
                        Notifications.cancel(ctx, p.notificationId)
                        store.record(
                            AttemptRecord(System.currentTimeMillis(), pcName, p.request.account, p.request.scenario.wire, Outcome.Expired, p.reqId),
                        )
                    }
                }, wait)
            }
            is Inbound.CancelMsg -> {
                Pending.findByReqBytes(pcId, inbound.reqId)?.let {
                    if (Pending.remove(it.reqId, Resolution.Cancelled)) Notifications.cancel(ctx, it.notificationId)
                }
            }
            is Inbound.NoticeMsg -> {
                val n = inbound.notice
                val text = noticeText(ctx, n.kind, n.detail)
                val legacy = when (n.kind) {
                    NoticeKind.RecoveryCodeUsed, NoticeKind.OfflineCodeUsed, NoticeKind.ProtectionEnabled,
                    NoticeKind.ProtectionDisabled, NoticeKind.Cooldown -> true
                    else -> false
                }
                if (legacy) {
                    val outcome = when (n.kind) {
                        NoticeKind.RecoveryCodeUsed -> Outcome.RecoveryCode
                        NoticeKind.OfflineCodeUsed -> Outcome.OfflineCode
                        else -> Outcome.Notice
                    }
                    store.record(AttemptRecord(n.at, pcName, "", "", outcome, detail = text))
                    if (n.kind == NoticeKind.RecoveryCodeUsed || n.kind == NoticeKind.OfflineCodeUsed) {
                        Notifications.postNotice(ctx, (pcId + n.at).hashCode(), ctx.getString(R.string.notice_title, pcName), text)
                    }
                    // protection-disabled opens the 10-minute grace window in the health model.
                    HealthMonitor.onNotice(ctx, pcId, n, eventText = null)
                } else {
                    // Lifecycle and tamper notices: the health model decides whether to alert,
                    // and every one is written to history.
                    HealthMonitor.onNotice(ctx, pcId, n, eventText = text)
                }
            }
            is Inbound.StatusMsg -> HealthMonitor.onStatus(ctx, pcId, inbound.status)
            is Inbound.UnpairMsg -> {
                Pending.removePc(pcId)
                store.removePc(pcId)
                store.record(AttemptRecord(System.currentTimeMillis(), pcName, "", "", Outcome.Unpaired, detail = ctx.getString(R.string.unpaired_by_pc)))
                Notifications.postNotice(ctx, pcId.hashCode(), ctx.getString(R.string.notice_title, pcName), ctx.getString(R.string.unpaired_by_pc))
                sync(ctx)
            }
        }
    }

    fun noticeText(context: Context, kind: NoticeKind, detail: String): String {
        val base = when (kind) {
            NoticeKind.RecoveryCodeUsed -> context.getString(R.string.notice_recovery)
            NoticeKind.OfflineCodeUsed -> context.getString(R.string.notice_offline)
            NoticeKind.ProtectionEnabled -> context.getString(R.string.notice_enabled)
            NoticeKind.ProtectionDisabled -> context.getString(R.string.notice_disabled)
            NoticeKind.Cooldown -> context.getString(R.string.notice_cooldown)
            NoticeKind.AgentStarted -> context.getString(R.string.notice_agent_started)
            NoticeKind.AgentStopped -> context.getString(R.string.notice_agent_stopped)
            NoticeKind.Shutdown -> context.getString(R.string.notice_shutdown)
            NoticeKind.Sleep -> context.getString(R.string.notice_sleep)
            NoticeKind.Resume -> context.getString(R.string.notice_resume)
            NoticeKind.Repaired -> context.getString(R.string.notice_repaired)
            NoticeKind.SafeModeBoot -> context.getString(R.string.notice_safe_mode)
            NoticeKind.SettingChanged -> context.getString(R.string.notice_setting_changed)
        }
        return if (detail.isBlank()) base else "$base $detail"
    }
}
