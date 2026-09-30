package dev.phonegate.net

import android.content.Context
import dev.phonegate.data.AlertRecord
import dev.phonegate.data.AttemptRecord
import dev.phonegate.data.Outcome
import dev.phonegate.data.PairedPc
import dev.phonegate.data.PhoneStore
import dev.phonegate.protocol.Alert
import dev.phonegate.protocol.HealthStep
import dev.phonegate.protocol.Notice
import dev.phonegate.protocol.ProtocolException
import dev.phonegate.protocol.Status

/**
 * Applies verified status reports, lifecycle notices and the 1-minute ticker to each PC's
 * [dev.phonegate.protocol.Health] model, persists the result, and raises one high-priority
 * tamper notification per episode. Called on the main thread only (RelayHub posts there and the
 * ticker runs in the service's main-dispatcher scope), so updates never interleave.
 */
object HealthMonitor {
    /** A verified `status`. Stale or replayed sequence numbers are dropped silently. */
    fun onStatus(context: Context, pcId: String, st: Status) {
        val store = PhoneStore.get(context)
        val pc = store.state.value.pc(pcId) ?: return
        val now = System.currentTimeMillis()
        val step = try {
            pc.health.onStatus(st, now)
        } catch (e: ProtocolException.Replay) {
            return
        }
        apply(context, pc, step, now, event = null)
        if (pc.health.inAlert && !step.health.inAlert) {
            // Episode over: the PC reports healthy again.
            Notifications.cancel(context, tamperNotificationId(pcId))
            store.record(AttemptRecord(now, pc.pcName, "", "", Outcome.PcEvent, detail = "Reports healthy again. The tamper alert has ended."))
        }
    }

    /** A verified notice: every one goes to history; some also feed the health model. */
    fun onNotice(context: Context, pcId: String, n: Notice, eventText: String?) {
        val store = PhoneStore.get(context)
        val pc = store.state.value.pc(pcId) ?: return
        val now = System.currentTimeMillis()
        apply(context, pc, pc.health.onNotice(n.kind, n.detail, now), now, event = eventText)
    }

    /** The 1-minute silence check for every paired PC. */
    fun tickAll(context: Context) {
        val store = PhoneStore.get(context)
        val now = System.currentTimeMillis()
        for (pc in store.state.value.pcs) {
            if (pc.needsRepair) continue
            val step = pc.health.tick(now)
            if (step.health != pc.health) apply(context, pc, step, now, event = null)
        }
    }

    /** Owner looked at the alert. This does NOT end the episode; only a healthy report does. */
    fun markSeen(context: Context, pcId: String) {
        val now = System.currentTimeMillis()
        PhoneStore.get(context).updatePc(pcId) { it.copy(alert = it.alert?.copy(seenAt = it.alert.seenAt ?: now)) }
        Notifications.cancel(context, tamperNotificationId(pcId))
    }

    private fun apply(context: Context, pc: PairedPc, step: HealthStep, now: Long, event: String?) {
        val store = PhoneStore.get(context)
        val alert: Alert? = step.alert
        store.updatePc(pc.pcId) { cur ->
            cur.copy(health = step.health, alert = if (alert != null) AlertRecord.of(alert, cur.pcName, now) else cur.alert)
        }
        if (alert != null) {
            val message = alert.message(pc.pcName)
            store.record(AttemptRecord(now, pc.pcName, "", "", Outcome.Tamper, detail = message))
            Notifications.postTamper(context, tamperNotificationId(pc.pcId), pc.pcId, pc.pcName, message)
        } else if (event != null) {
            store.record(AttemptRecord(now, pc.pcName, "", "", Outcome.PcEvent, detail = event))
        }
    }

    fun tamperNotificationId(pcId: String): Int = ("tamper:$pcId").hashCode()
}
