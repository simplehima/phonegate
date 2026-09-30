package dev.phonegate.net

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import dev.phonegate.data.PhoneStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.launch

/**
 * Foreground service (type specialUse) keeping one relay WebSocket per paired PC so approval
 * requests arrive within seconds even with the screen off (FR-013). Shows a low-priority
 * ongoing notification with the connection status.
 */
class RelayService : LifecycleService() {
    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        val store = PhoneStore.get(this)
        ServiceCompat.startForeground(
            this,
            Notifications.ONGOING_ID,
            Notifications.ongoing(this, 0, store.state.value.pcs.size),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0,
        )
        RelayHub.onStatusChanged = { refreshOngoing() }
        // Feature 002: silence is measured on the phone clock, once a minute.
        lifecycleScope.launch {
            while (true) {
                HealthMonitor.tickAll(this@RelayService)
                delay(60_000)
            }
        }
        lifecycleScope.launch {
            store.state.distinctUntilChangedBy { s -> s.pcs.map { Triple(it.pcId, it.deviceAlias, it.repairReason) } }.collect { s ->
                if (s.pcs.isEmpty()) {
                    RelayHub.stopAll()
                    stopSelf()
                } else {
                    RelayHub.sync(this@RelayService)
                    refreshOngoing()
                }
            }
        }
    }

    private fun refreshOngoing() {
        val total = PhoneStore.get(this).state.value.pcs.count { !it.needsRepair }
        getSystemService(NotificationManager::class.java)
            .notify(Notifications.ONGOING_ID, Notifications.ongoing(this, RelayHub.connectedCount(), total))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        return START_STICKY
    }

    override fun onDestroy() {
        RelayHub.onStatusChanged = null
        RelayHub.stopAll()
        super.onDestroy()
    }

    companion object {
        /** Starts the service if at least one PC is paired. */
        fun startIfPaired(context: Context) {
            if (PhoneStore.get(context).state.value.pcs.isEmpty()) return
            ContextCompat.startForegroundService(context, Intent(context, RelayService::class.java))
        }
    }
}

/** Restarts the relay service after a reboot or app update when a PC is paired. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            RelayService.startIfPaired(context)
        }
    }
}
