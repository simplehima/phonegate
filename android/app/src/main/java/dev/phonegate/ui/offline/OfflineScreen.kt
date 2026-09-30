package dev.phonegate.ui.offline

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import dev.phonegate.data.AttemptRecord
import dev.phonegate.data.Outcome
import dev.phonegate.data.PhoneStore
import dev.phonegate.keys.BiometricGate
import dev.phonegate.keys.KeyManager
import dev.phonegate.net.Notifications
import dev.phonegate.protocol.B64
import dev.phonegate.protocol.OfflineChallenge
import dev.phonegate.protocol.ProtocolException
import dev.phonegate.ui.components.FormLabel
import dev.phonegate.ui.components.Gap
import dev.phonegate.ui.components.PerforationCountdown
import dev.phonegate.ui.components.QrScanOrPaste
import dev.phonegate.ui.components.RecordSheet
import dev.phonegate.ui.components.RuledField
import dev.phonegate.ui.components.ScreenTitle
import dev.phonegate.ui.components.VisitorSlip
import dev.phonegate.ui.theme.Desk
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

sealed class OfflineState {
    data object Scan : OfflineState()
    data class Verified(val pcName: String, val account: String, val kind: String, val pcId: String, val challenge: OfflineChallenge) : OfflineState()
    data class Code(val pcName: String, val account: String, val code: String, val deadline: Long, val lifetimeMs: Long) : OfflineState()
    data class Failed(val reason: String) : OfflineState()
}

/**
 * Offline approval (FR-026a): verify the PC-signed `PGO1:` challenge, unlock `k_offline` with a
 * biometric, and show the 10-digit response. No network is involved.
 */
class OfflineController(context: Context) {
    private val app = context.applicationContext
    private val _state = MutableStateFlow<OfflineState>(OfflineState.Scan)
    val state: StateFlow<OfflineState> = _state.asStateFlow()

    fun onScanned(text: String) {
        val qr = text.trim()
        val store = PhoneStore.get(app)
        val claimed = try {
            OfflineChallenge.peekPcId(qr)
        } catch (e: ProtocolException) {
            _state.value = OfflineState.Failed("That isn't a PhoneGate offline code. On the lock screen, choose Phone offline to show it.")
            return
        }
        val pc = store.state.value.pc(B64.encode(claimed))
        if (pc == null) {
            _state.value = OfflineState.Failed("This code is from a PC that isn't paired with this phone.")
            return
        }
        if (pc.needsRepair) {
            _state.value = OfflineState.Failed("${pc.pcName} needs pairing again: ${pc.repairReason}. Use a recovery code on the PC.")
            return
        }
        val challenge = try {
            OfflineChallenge.parseQr(qr, pc.pcPubBytes, System.currentTimeMillis())
        } catch (e: ProtocolException.Expired) {
            _state.value = OfflineState.Failed("This offline code has expired, or the phone's clock is far off. Show a new one on the PC.")
            return
        } catch (e: ProtocolException) {
            _state.value = OfflineState.Failed("This code failed its signature check, so it did not come from ${pc.pcName}. No code was generated.")
            return
        }
        _state.value = OfflineState.Verified(pc.pcName, challenge.account, Notifications.scenarioLabel(app, challenge.scenario), pc.pcId, challenge)
    }

    fun unlock(activity: FragmentActivity) {
        val v = _state.value as? OfflineState.Verified ?: return
        val store = PhoneStore.get(app)
        val pc = store.state.value.pc(v.pcId) ?: return
        val wrapped = B64.decode(pc.kOfflineWrapped)
        val cipher = try {
            KeyManager.offlineDecryptCipher(pc.offlineAlias, wrapped)
        } catch (e: KeyManager.KeyInvalidated) {
            store.markNeedsRepair(pc.pcId, e.reason)
            _state.value = OfflineState.Failed("${e.reason} Use a recovery code on the PC, then pair again.")
            return
        } catch (e: Exception) {
            _state.value = OfflineState.Failed("The offline key could not be used. Use a recovery code on the PC.")
            return
        }
        BiometricGate.authenticate(
            activity,
            title = "Offline code for ${v.pcName}",
            subtitle = "Confirm it's you to show the code",
            crypto = BiometricPrompt.CryptoObject(cipher),
            onSuccess = { crypto ->
                try {
                    val kOffline = KeyManager.unwrapWith(crypto.cipher!!, wrapped)
                    val code = v.challenge.responseCode(kOffline)
                    kOffline.fill(0)
                    val lifetime = v.challenge.expiresAt - v.challenge.issuedAt
                    val now = System.currentTimeMillis()
                    val deadline = if (kotlin.math.abs(now - v.challenge.issuedAt) <= 10_000) v.challenge.expiresAt else now + lifetime
                    store.record(AttemptRecord(now, v.pcName, v.account, v.challenge.scenario.wire, Outcome.OfflineCode, detail = "Code shown on this phone"))
                    _state.value = OfflineState.Code(v.pcName, v.account, code, deadline, lifetime)
                } catch (e: Exception) {
                    _state.value = OfflineState.Failed("The offline key could not be unlocked. Use a recovery code on the PC.")
                }
            },
            onFailure = { msg, cancelled -> if (!cancelled) _state.value = OfflineState.Failed("Fingerprint check failed: $msg") },
        )
    }

    fun reset() {
        _state.value = OfflineState.Scan
    }
}

@Composable
fun OfflineScreen(state: OfflineState, onScanned: (String) -> Unit, onUnlock: () -> Unit, onReset: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(Modifier.widthIn(max = 560.dp).fillMaxWidth()) {
            ScreenTitle("Offline code")
            Gap(6.dp)
            when (state) {
                OfflineState.Scan -> {
                    Text(
                        "When the PC can't reach the relay, its lock screen offers Phone offline and shows a QR code. Scan it here to get a one-time code to type on the PC.",
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Gap(16.dp)
                    QrScanOrPaste(
                        pasteLabel = "Or paste the code text",
                        pasteHint = "PGO1:...",
                        scanDescription = "Camera viewfinder for the offline QR code",
                        onResult = onScanned,
                    )
                }
                is OfflineState.Verified -> VisitorSlip(Modifier.fillMaxWidth()) {
                    FormLabel("Offline request")
                    Text(state.pcName, style = MaterialTheme.typography.headlineSmall, color = Desk.colors.onSlip)
                    Gap(6.dp)
                    RuledField("Account", state.account.ifBlank { "Not given" })
                    RuledField("Sign-in kind", state.kind)
                    Gap(12.dp)
                    Text("Only continue if you are at this PC right now.", style = MaterialTheme.typography.bodyMedium, color = Desk.colors.slipLabel)
                    Gap(12.dp)
                    Button(onClick = onUnlock, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) { Text("Show code with fingerprint") }
                    Gap(8.dp)
                    OutlinedButton(onClick = onReset, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("Cancel") }
                }
                is OfflineState.Code -> CodeSlip(state, onReset)
                is OfflineState.Failed -> RecordSheet(Modifier.fillMaxWidth(), tint = Desk.colors.pinkCopy) {
                    Text("No code", style = MaterialTheme.typography.headlineSmall, color = Desk.colors.onPinkCopy)
                    Gap(6.dp)
                    Text(state.reason, style = MaterialTheme.typography.bodyLarge, color = Desk.colors.onPinkCopy, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive })
                    Gap(12.dp)
                    Button(onClick = onReset, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) { Text("Scan again") }
                }
            }
        }
    }
}

@Composable
private fun CodeSlip(state: OfflineState.Code, onReset: () -> Unit) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(state.deadline) {
        while (now < state.deadline) {
            delay(250)
            now = System.currentTimeMillis()
        }
    }
    val remaining = (state.deadline - now).coerceAtLeast(0)
    val grouped = state.code.chunked(5).joinToString(" ")
    VisitorSlip(Modifier.fillMaxWidth()) {
        FormLabel("Type this on ${state.pcName}")
        Gap(8.dp)
        if (remaining > 0) {
            Text(
                grouped,
                style = Desk.type.code,
                color = Desk.colors.onSlip,
                modifier = Modifier.semantics { contentDescription = "Offline code " + state.code.toCharArray().joinToString(" ") },
            )
            Gap(10.dp)
            PerforationCountdown(remaining.toFloat() / state.lifetimeMs, ((remaining + 999) / 1000).toInt())
            Gap(8.dp)
            Text("Works once, for this sign-in only.", style = MaterialTheme.typography.bodyMedium, color = Desk.colors.slipLabel)
        } else {
            Text("This code has expired. Show a new QR code on the PC.", style = MaterialTheme.typography.titleMedium, color = Desk.colors.onSlip)
        }
        Gap(12.dp)
        OutlinedButton(onClick = onReset, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("Done") }
    }
}
