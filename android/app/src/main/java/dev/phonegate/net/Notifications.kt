package dev.phonegate.net

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import dev.phonegate.MainActivity
import dev.phonegate.R
import dev.phonegate.protocol.Scenario
import dev.phonegate.ui.approve.ApproveActivity

object Notifications {
    const val CHANNEL_RELAY = "relay"
    const val CHANNEL_REQUESTS = "requests"
    const val CHANNEL_NOTICES = "notices"
    const val CHANNEL_TAMPER = "tamper"
    const val ONGOING_ID = 1

    fun createChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_RELAY, context.getString(R.string.channel_relay), NotificationManager.IMPORTANCE_MIN).apply {
                description = context.getString(R.string.channel_relay_desc)
                setShowBadge(false)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_REQUESTS, context.getString(R.string.channel_requests), NotificationManager.IMPORTANCE_HIGH).apply {
                description = context.getString(R.string.channel_requests_desc)
                enableVibration(true)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_TAMPER, context.getString(R.string.channel_tamper), NotificationManager.IMPORTANCE_HIGH).apply {
                description = context.getString(R.string.channel_tamper_desc)
                enableVibration(true)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_NOTICES, context.getString(R.string.channel_notices), NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = context.getString(R.string.channel_notices_desc)
            },
        )
    }

    fun ongoing(context: Context, connected: Int, total: Int): Notification {
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val text = if (total == 0) {
            context.getString(R.string.ongoing_none)
        } else {
            context.resources.getQuantityString(R.plurals.ongoing_status, total, connected, total)
        }
        return NotificationCompat.Builder(context, CHANNEL_RELAY)
            .setSmallIcon(R.drawable.ic_stat_gate)
            .setContentTitle(context.getString(R.string.ongoing_title))
            .setContentText(text)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(open)
            .build()
    }

    fun scenarioLabel(context: Context, s: Scenario): String = when (s) {
        Scenario.Unlock -> context.getString(R.string.scenario_unlock)
        Scenario.Logon -> context.getString(R.string.scenario_logon)
        Scenario.Remote -> context.getString(R.string.scenario_remote)
        Scenario.DisableProtection -> context.getString(R.string.scenario_disable)
        Scenario.ChangeSetting -> context.getString(R.string.scenario_change_setting)
    }

    private fun canPost(context: Context): Boolean =
        android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    /** Heads-up + full-screen notification for a verified request. Never shows the badge number. */
    fun postRequest(context: Context, p: PendingRequest) {
        if (!canPost(context)) return
        val r = p.request
        val approve = Intent(context, ApproveActivity::class.java)
            .putExtra(ApproveActivity.EXTRA_REQ_ID, p.reqId)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val content = PendingIntent.getActivity(context, p.notificationId, approve, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val deny = ActionReceiver.intent(context, p, ActionReceiver.ACTION_DENY)
        val notMe = ActionReceiver.intent(context, p, ActionReceiver.ACTION_NOT_ME)
        val scenario = scenarioLabel(context, r.scenario)
        val title = context.getString(R.string.notif_request_title, r.pcName)
        val text = context.getString(R.string.notif_request_text, r.account, scenario)
        val remaining = (p.localDeadline - System.currentTimeMillis()).coerceAtLeast(1_000)

        val public = NotificationCompat.Builder(context, CHANNEL_REQUESTS)
            .setSmallIcon(R.drawable.ic_stat_gate)
            .setContentTitle(context.getString(R.string.notif_request_public))
            .setContentText(context.getString(R.string.notif_request_public_text))
            .build()

        val n = NotificationCompat.Builder(context, CHANNEL_REQUESTS)
            .setSmallIcon(R.drawable.ic_stat_gate)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text + "\n" + context.getString(R.string.notif_request_hint)))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setContentIntent(content)
            .setFullScreenIntent(content, true)
            .setTimeoutAfter(remaining)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .addAction(0, context.getString(R.string.action_deny), deny)
            .addAction(0, context.getString(R.string.action_not_me), notMe)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(p.notificationId, n)
        } catch (e: SecurityException) {
            // Notification permission revoked between the check and the post.
        }
    }

    fun cancel(context: Context, id: Int) {
        NotificationManagerCompat.from(context).cancel(id)
    }

    /** High-priority tamper alert, posted once per episode by the health model. */
    fun postTamper(context: Context, id: Int, pcId: String, pcName: String, message: String) {
        if (!canPost(context)) return
        val open = PendingIntent.getActivity(
            context, id,
            Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                .putExtra(MainActivity.EXTRA_ALERT_PC, pcId),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(context, CHANNEL_TAMPER)
            .setSmallIcon(R.drawable.ic_stat_gate)
            .setContentTitle(context.getString(R.string.tamper_title, pcName))
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(id, n)
        } catch (e: SecurityException) {
            // Permission revoked.
        }
    }

    fun postNotice(context: Context, id: Int, title: String, text: String) {
        if (!canPost(context)) return
        val open = PendingIntent.getActivity(
            context, 1, Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_TAB, "history"),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val n = NotificationCompat.Builder(context, CHANNEL_NOTICES)
            .setSmallIcon(R.drawable.ic_stat_gate)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(id, n)
        } catch (e: SecurityException) {
            // Permission revoked.
        }
    }
}
