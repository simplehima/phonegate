package dev.phonegate

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import dev.phonegate.data.PhoneStore
import android.widget.Toast
import dev.phonegate.net.DisableSender
import dev.phonegate.net.UpdateChecker
import dev.phonegate.ui.settings.PermissionRow
import dev.phonegate.ui.settings.SettingsLinks
import dev.phonegate.ui.settings.SettingsScreen
import dev.phonegate.ui.settings.UpdateUi
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.mutableStateMapOf
import dev.phonegate.net.HealthMonitor
import dev.phonegate.net.Notifications
import dev.phonegate.net.RelayHub
import dev.phonegate.net.RelayService
import dev.phonegate.protocol.Kind
import dev.phonegate.protocol.RelayClient
import dev.phonegate.protocol.Unpair
import dev.phonegate.ui.history.HistoryItem
import dev.phonegate.ui.history.HistoryScreen
import dev.phonegate.ui.offline.OfflineController
import dev.phonegate.ui.offline.OfflineScreen
import dev.phonegate.ui.pair.PairController
import dev.phonegate.ui.pair.PairScreen
import dev.phonegate.ui.pcs.AlertInfo
import dev.phonegate.ui.pcs.Banner
import dev.phonegate.ui.pcs.PcItem
import dev.phonegate.ui.pcs.PcStatus
import dev.phonegate.ui.pcs.PcsScreen
import dev.phonegate.ui.theme.PhoneGateTheme
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        RelayService.startIfPaired(this)
        val startTab = if (intent.getStringExtra(EXTRA_TAB) == "history") 1 else 0
        alertPc.value = intent.getStringExtra(EXTRA_ALERT_PC)
        setContent {
            PhoneGateTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    AppRoot(this, startTab, alertPc.value) { alertPc.value = null }
                }
            }
        }
    }

    /** A tamper notification tapped while the activity is already open. */
    private val alertPc = mutableStateOf<String?>(null)

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.getStringExtra(EXTRA_ALERT_PC)?.let { alertPc.value = it }
    }

    companion object {
        const val EXTRA_TAB = "tab"
        const val EXTRA_ALERT_PC = "alert_pc"
    }
}

private val dateFmt = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault())
private val stampFmt = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT).withZone(ZoneId.systemDefault())

@Composable
private fun AppRoot(activity: FragmentActivity, startTab: Int, alertPc: String?, onAlertShown: () -> Unit) {
    val store = remember { PhoneStore.get(activity) }
    val state by store.state.collectAsState()
    val relayStatus by RelayHub.status.collectAsState()
    var tab by rememberSaveable { mutableIntStateOf(startTab) }
    var pairing by rememberSaveable { mutableStateOf(false) }
    // "Last report N min ago" and the Stopped reporting state depend on the phone clock.
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(30_000)
            now = System.currentTimeMillis()
            HealthMonitor.tickAll(activity)
        }
    }
    LaunchedEffect(alertPc) { if (alertPc != null) tab = 0 }

    // Re-check permissions whenever the app comes back to the foreground.
    var resumeTick by remember { mutableIntStateOf(0) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) resumeTick++ }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs) }
    }
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { resumeTick++ }

    if (pairing) {
        val controller = remember { PairController(activity) }
        DisposableEffect(controller) { onDispose { controller.dispose() } }
        val ps by controller.state.collectAsState()
        PairScreen(
            state = ps,
            onScanned = controller::onScanned,
            onSign = { controller.signJoin(activity) },
            onConfirm = { controller.confirmSas(activity) },
            onReject = controller::rejectSas,
            onRestart = controller::restart,
            onDone = { pairing = false; tab = 0 },
            onBack = { pairing = false },
        )
        return
    }

    val offline = remember { OfflineController(activity) }
    val offlineState by offline.state.collectAsState()

    val busyPcs = remember { mutableStateMapOf<String, String>() }
    var updateChecks by remember { mutableStateOf(UpdateChecker.enabled(activity)) }
    var newer by remember { mutableStateOf<String?>(null) }
    var updateUi by remember { mutableStateOf<UpdateUi>(UpdateUi.Idle) }
    val installed = remember { activity.packageManager.getPackageInfo(activity.packageName, 0) }
    val versionName = installed.versionName ?: "0"
    val scope = rememberCoroutineScope()
    LaunchedEffect(updateChecks) { newer = if (updateChecks) UpdateChecker.newerRelease(versionName) else null }
    val checkNow: () -> Unit = {
        updateUi = UpdateUi.Checking
        scope.launch {
            updateUi = when (val r = UpdateChecker.check(versionName)) {
                is UpdateChecker.Result.Newer -> { newer = r.tag; UpdateUi.Available(r.tag) }
                is UpdateChecker.Result.Current -> UpdateUi.UpToDate(versionName)
                UpdateChecker.Result.Failed -> UpdateUi.Failed
            }
        }
    }

    val banners = run {
        @Suppress("UNUSED_EXPRESSION") resumeTick
        val list = ArrayList<Banner>()
        newer?.let { tag ->
            list += Banner("PhoneGate ${tag.removePrefix("v")} is available. Download the new phone app from the releases page and install it over this one.", "Open releases page") {
                activity.startActivity(Intent(Intent.ACTION_VIEW, UpdateChecker.RELEASES_URL.toUri()))
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            list += Banner("Sign-in requests arrive as notifications. Without them you won't see a request in time.", "Allow notifications") {
                notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE &&
            !activity.getSystemService(NotificationManager::class.java).canUseFullScreenIntent()
        ) {
            list += Banner("Allow full-screen alerts so a request opens straight away, even when the phone is locked.", "Open settings") {
                activity.startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, ("package:" + activity.packageName).toUri()))
            }
        }
        if (!Settings.canDrawOverlays(activity)) {
            list += Banner("Allow PhoneGate to show over other apps so a sign-in request can open right away, even while you are using another app.", "Allow") {
                activity.startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, ("package:" + activity.packageName).toUri()))
            }
        }
        list
    }

    val pcs = state.pcs.sortedBy { it.pcName.lowercase() }.map { pc ->
        val st = when {
            pc.needsRepair -> PcStatus.NeedsRepair
            relayStatus[pc.pcId] == RelayClient.Status.Ready -> PcStatus.Connected
            relayStatus[pc.pcId] == RelayClient.Status.Disconnected -> PcStatus.Offline
            else -> PcStatus.Connecting
        }
        PcItem(
            pcId = pc.pcId,
            name = pc.pcName,
            relay = pc.relayUrl.removePrefix("https://"),
            paired = dateFmt.format(Instant.ofEpochMilli(pc.pairedAt)),
            keys = "${pc.keyLevel.label}, attested at pairing",
            status = st,
            repairReason = pc.repairReason,
            state = pc.health.state(now),
            lastReport = lastReportText(pc.health.lastSeq != null, pc.health.lastSeenAt, now),
            bitlockerOff = pc.health.bitlockerOff,
            netlogonBlocked = pc.health.netlogonBlocked,
            disablePending = pc.disable != null,
            busy = busyPcs[pc.pcId],
            alert = pc.alert?.takeIf { pc.health.inAlert }?.let {
                AlertInfo(
                    message = it.message,
                    raised = stampFmt.format(Instant.ofEpochMilli(it.raisedAt)),
                    seen = it.seenAt?.let { t -> stampFmt.format(Instant.ofEpochMilli(t)) },
                )
            },
        )
    }
    val history = state.history.mapIndexed { i, h ->
        HistoryItem(
            key = "${h.at}-$i",
            outcome = h.outcome,
            pcName = h.pcName,
            account = h.account,
            kind = runCatching { dev.phonegate.protocol.Scenario.parse(h.scenario) }.getOrNull()?.let { Notifications.scenarioLabel(activity, it) } ?: "",
            time = stampFmt.format(Instant.ofEpochMilli(h.at)),
            detail = h.detail,
        )
    }

    NavigationSuiteScaffold(
        navigationSuiteItems = {
            item(selected = tab == 0, onClick = { tab = 0 }, icon = { Icon(Icons.Filled.Home, null) }, label = { Text("PCs") })
            item(selected = tab == 1, onClick = { tab = 1 }, icon = { Icon(Icons.AutoMirrored.Filled.List, null) }, label = { Text("History") })
            item(selected = tab == 2, onClick = { tab = 2 }, icon = { Icon(Icons.Filled.Lock, null) }, label = { Text("Offline code") })
            item(selected = tab == 3, onClick = { tab = 3 }, icon = { Icon(Icons.Filled.Settings, null) }, label = { Text("Settings") })
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) {
        val m = Modifier.safeDrawingPadding()
        when (tab) {
            0 -> PcsScreen(
                items = pcs,
                banners = banners,
                onAdd = { pairing = true },
                onRename = store::rename,
                onUnpair = { id ->
                    busyPcs[id] = "Unpairing..."
                    unpair(activity, id) { busyPcs.remove(id) }
                },
                modifier = m,
                onMarkSeen = { id -> HealthMonitor.markSeen(activity, id) },
                openAlertFor = alertPc,
                onOpenHandled = onAlertShown,
                onTurnOff = { id ->
                    busyPcs[id] = "Waiting for your fingerprint..."
                    DisableSender.requestDisable(activity, id) { r ->
                        busyPcs.remove(id)
                        val msg = when (r) {
                            is DisableSender.Outcome2.Sent -> "Turn-off request sent."
                            is DisableSender.Outcome2.Failed -> r.reason
                            DisableSender.Outcome2.Cancelled -> null
                        }
                        if (msg != null) Toast.makeText(activity, msg, Toast.LENGTH_LONG).show()
                    }
                },
            )
            1 -> HistoryScreen(history, m)
            2 -> OfflineScreen(offlineState, offline::onScanned, { offline.unlock(activity) }, offline::reset, m)
            else -> SettingsScreen(
                versionName = versionName,
                versionCode = installed.longVersionCode,
                updateChecks = updateChecks,
                onUpdateChecks = { on ->
                    UpdateChecker.setEnabled(activity, on)
                    updateChecks = on
                    if (!on) { newer = null; updateUi = UpdateUi.Idle }
                },
                update = updateUi,
                onCheckNow = checkNow,
                permissions = remember(resumeTick) { permissionRows(activity, notifLauncher::launch) },
                links = SettingsLinks(UpdateChecker.REPO_URL, UpdateChecker.RELEASES_URL, UpdateChecker.LICENSE_URL, UpdateChecker.SECURITY_URL, UpdateChecker.ISSUES_URL),
                onOpenLink = { url -> activity.startActivity(Intent(Intent.ACTION_VIEW, url.toUri())) },
                modifier = m,
            )
        }
    }
    LaunchedEffect(state.pcs.size) { RelayService.startIfPaired(activity) }
}

private fun lastReportText(everReported: Boolean, lastSeenAt: Long, now: Long): String {
    val min = ((now - lastSeenAt).coerceAtLeast(0) / 60_000).toInt()
    val ago = when {
        min < 1 -> "just now"
        min < 60 -> "$min min ago"
        min < 48 * 60 -> "${min / 60} h ago"
        else -> "${min / (24 * 60)} days ago"
    }
    return if (everReported) ago else "No report yet (tracking since $ago)"
}

private fun unpair(activity: FragmentActivity, pcId: String, done: () -> Unit = {}) {
    val app = activity.applicationContext
    CoroutineScope(Dispatchers.IO).launch {
        // Best effort: tell the PC first (signed with the device key), then delete local keys.
        RelayHub.sendSealed(pcId, Kind.Unpair, Unpair(System.currentTimeMillis()).encode())
        val store = PhoneStore.get(app)
        val pc = store.removePc(pcId)
        if (pc != null) {
            store.record(dev.phonegate.data.AttemptRecord(System.currentTimeMillis(), pc.pcName, "", "", dev.phonegate.data.Outcome.Unpaired, detail = "Unpaired from this phone"))
        }
        RelayHub.sync(app)
        withContext(Dispatchers.Main) { done() }
    }
}

/** The permissions PhoneGate uses, each with why it is asked for and how to grant it. */
private fun permissionRows(activity: FragmentActivity, requestNotifications: (String) -> Unit): List<PermissionRow> {
    val rows = ArrayList<PermissionRow>()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        rows += PermissionRow(
            "Notifications",
            "Sign-in requests and tamper alerts arrive as notifications.",
            ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED,
        ) { requestNotifications(Manifest.permission.POST_NOTIFICATIONS) }
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        rows += PermissionRow(
            "Full-screen alerts",
            "Lets a request open straight away when the phone is locked.",
            activity.getSystemService(NotificationManager::class.java).canUseFullScreenIntent(),
        ) { activity.startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, ("package:" + activity.packageName).toUri())) }
    }
    rows += PermissionRow(
        "Show over other apps",
        "Lets a request pop up on top of whatever you are doing.",
        Settings.canDrawOverlays(activity),
    ) { activity.startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, ("package:" + activity.packageName).toUri())) }
    rows += PermissionRow(
        "Camera",
        "Only to read the QR code on your PC screen.",
        ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
    ) { activity.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, ("package:" + activity.packageName).toUri())) }
    return rows
}
