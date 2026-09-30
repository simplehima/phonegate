package dev.phonegate.net

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dev.phonegate.protocol.Decision
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** "Deny" and "This wasn't me" straight from the notification: device key, no biometric. */
class ActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val reqId = intent.getStringExtra(EXTRA_REQ_ID) ?: return
        val decision = when (intent.action) {
            ACTION_DENY -> Decision.Deny
            ACTION_NOT_ME -> Decision.NotMe
            else -> return
        }
        val p = Pending.find(reqId) ?: run {
            intent.getIntExtra(EXTRA_NOTIF_ID, 0).takeIf { it != 0 }?.let { Notifications.cancel(context, it) }
            return
        }
        val pending = goAsync()
        scope.launch {
            try {
                Responder.refuse(context.applicationContext, p, decision)
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_DENY = "dev.phonegate.action.DENY"
        const val ACTION_NOT_ME = "dev.phonegate.action.NOT_ME"
        private const val EXTRA_REQ_ID = "req_id"
        private const val EXTRA_NOTIF_ID = "notif_id"
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        fun intent(context: Context, p: PendingRequest, action: String): PendingIntent {
            val i = Intent(context, ActionReceiver::class.java)
                .setAction(action)
                .putExtra(EXTRA_REQ_ID, p.reqId)
                .putExtra(EXTRA_NOTIF_ID, p.notificationId)
            val code = p.notificationId * 2 + if (action == ACTION_DENY) 0 else 1
            return PendingIntent.getBroadcast(context, code, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
    }
}
