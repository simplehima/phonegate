package dev.phonegate.preview

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.phonegate.data.Outcome
import dev.phonegate.ui.approve.ApproveScreen
import dev.phonegate.ui.approve.SlipModel
import dev.phonegate.ui.approve.SlipPhase
import dev.phonegate.ui.history.HistoryItem
import dev.phonegate.ui.history.HistoryScreen
import dev.phonegate.ui.offline.OfflineScreen
import dev.phonegate.ui.offline.OfflineState
import dev.phonegate.ui.pair.PairScreen
import dev.phonegate.ui.pair.PairState
import dev.phonegate.protocol.PcState
import dev.phonegate.ui.pcs.AlertInfo
import dev.phonegate.ui.pcs.PcItem
import dev.phonegate.ui.pcs.PcStatus
import dev.phonegate.ui.pcs.PcsScreen
import dev.phonegate.ui.theme.Desk
import dev.phonegate.ui.theme.PhoneGateTheme

/**
 * DEBUG BUILDS ONLY (src/debug). Renders the real screens with clearly labelled synthetic data
 * for screenshots. It has no access to keys, the store or the relay: every callback is a no-op,
 * so nothing can be signed, approved or sent from here.
 *
 * adb shell am start -n dev.phonegate/dev.phonegate.preview.PreviewActivity --es screen approve
 * screens: approve, approve_wrong, expired, done, sas, pcs, tamper, history, offline
 */
class PreviewActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val screen = intent.getStringExtra("screen") ?: "approve"
        val start = System.currentTimeMillis()
        setContent {
            PhoneGateTheme {
                // The label sits under the status bar; the screen below must not pad for the
                // status bar a second time, while keeping the bottom (IME) insets untouched.
                Column(Modifier.fillMaxSize().background(Desk.colors.ground)) {
                    SampleLabel()
                    Box(Modifier.weight(1f).consumeWindowInsets(WindowInsets.statusBars)) { Screen(screen, start) }
                }
            }
        }
    }
}

@Composable
private fun SampleLabel() {
    Box(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .statusBarsPadding()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text("Preview with sample data. Nothing here can approve.", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun Screen(screen: String, start: Long) {
    val slip = SlipModel(
        pcName = "Sample Desk PC",
        account = "DESK\\sample-owner",
        signInKind = "Unlock",
        time = "09:41:07",
        remote = "None, at the PC itself",
        // Frozen at 42 s left so screenshots are stable.
        deadline = start + 42_000,
        lifetimeMs = 60_000,
    )
    val frozen = { start }
    val noop = {}
    when (screen) {
        "approve_wrong" -> ApproveScreen(slip, SlipPhase.Open, frozen, { false }, {}, noop, {}, noop, initialDigits = "", initialWrong = 1)
        "expired" -> ApproveScreen(slip, SlipPhase.Expired, frozen, { false }, {}, noop, {}, noop)
        "done" -> ApproveScreen(slip, SlipPhase.Done(Outcome.Denied, "Denied. The PC stays locked."), frozen, { false }, {}, noop, {}, noop)
        "sas" -> PairScreen(PairState.Sas("482913", "Sample Desk PC"), {}, noop, noop, noop, noop, noop, noop)
        "pcs" -> PcsScreen(
            items = listOf(
                PcItem("a", "Sample Desk PC", "relay.example.org", "Sep 12, 2026", "StrongBox, attested at pairing", PcStatus.Connected),
                PcItem("b", "Sample Laptop", "relay.example.org", "Aug 30, 2026", "Secure hardware (TEE), attested at pairing", PcStatus.NeedsRepair, "Biometrics on this phone changed."),
            ),
            banners = emptyList(),
            onAdd = noop,
            onRename = { _, _ -> },
            onUnpair = {},
        )
        "tamper" -> PcsScreen(
            items = listOf(
                PcItem(
                    "t", "Sample Desk PC", "relay.example.org", "Sep 12, 2026", "StrongBox, attested at pairing", PcStatus.Connected,
                    state = PcState.TamperAlert,
                    lastReport = "3 min ago",
                    bitlockerOff = true,
                    alert = AlertInfo(
                        message = "PhoneGate on Sample Desk PC was stopped. If you didn't do this, someone may be tampering with the PC.",
                        raised = "9/27/26, 9:41 AM",
                        seen = null,
                    ),
                ),
                PcItem(
                    "o", "Sample Laptop", "relay.example.org", "Aug 30, 2026", "Secure hardware (TEE), attested at pairing", PcStatus.Connected,
                    state = PcState.Asleep,
                    lastReport = "42 min ago",
                    netlogonBlocked = true,
                ),
            ),
            banners = emptyList(),
            onAdd = noop,
            onRename = { _, _ -> },
            onUnpair = {},
        )
        "history" -> HistoryScreen(
            listOf(
                HistoryItem("1", Outcome.Approved, "Sample Desk PC", "DESK\\sample-owner", "Unlock", "9/27/26, 9:41 AM", null),
                HistoryItem("2", Outcome.NotMe, "Sample Desk PC", "DESK\\sample-owner", "Remote Desktop sign-in", "9/26/26, 11:02 PM", "Wrong number typed twice"),
                HistoryItem("3", Outcome.Denied, "Sample Laptop", "LAPTOP\\sample-owner", "Sign-in", "9/26/26, 6:15 PM", null),
                HistoryItem("4", Outcome.Expired, "Sample Laptop", "LAPTOP\\sample-owner", "Unlock", "9/25/26, 8:03 AM", null),
                HistoryItem("5", Outcome.RecoveryCode, "Sample Desk PC", "", "", "9/24/26, 7:30 PM", "A recovery code was used to sign in."),
            ),
        )
        "offline" -> OfflineScreen(OfflineState.Code("Sample Desk PC", "DESK\\sample-owner", "0483920175", start + 38_000, 60_000), {}, noop, noop)
        else -> ApproveScreen(slip, SlipPhase.Open, frozen, { false }, {}, noop, {}, noop, initialDigits = "4")
    }
}
