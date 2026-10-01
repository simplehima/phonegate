package dev.phonegate.ui.approve

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import dev.phonegate.R
import dev.phonegate.data.Outcome
import dev.phonegate.data.PhoneStore
import dev.phonegate.keys.BiometricGate
import dev.phonegate.keys.KeyManager
import dev.phonegate.net.Notifications
import dev.phonegate.net.Pending
import dev.phonegate.net.PendingRequest
import dev.phonegate.net.Resolution
import dev.phonegate.net.Responder
import dev.phonegate.protocol.Decision
import dev.phonegate.ui.theme.PhoneGateTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/**
 * Full-screen approval, opened from the heads-up notification (also over the lock screen).
 * Only requests that passed [dev.phonegate.protocol.Inbox] verification exist in [Pending].
 */
class ApproveActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        // With "show over other apps" granted, another app could draw a fake button over Approve.
        // Drop any touch that passes through a window covering this screen.
        window.decorView.filterTouchesWhenObscured = true
        val reqId = intent.getStringExtra(EXTRA_REQ_ID)
        val initial = reqId?.let { Pending.find(it) }

        setContent {
            PhoneGateTheme {
                var phase by remember { mutableStateOf(if (initial == null) SlipPhase.Gone else SlipPhase.Open) }
                val resolved by Pending.resolved.collectAsState()
                val live by Pending.byPc.collectAsState()

                // Reflect cancellations, supersession and expiry that happen while open.
                LaunchedEffect(resolved, live) {
                    if (initial == null || phase !is SlipPhase.Open) return@LaunchedEffect
                    when (resolved[initial.reqId]) {
                        Resolution.Superseded -> phase = SlipPhase.Superseded
                        Resolution.Cancelled -> phase = SlipPhase.Gone
                        Resolution.Expired -> phase = SlipPhase.Expired
                        else -> Unit
                    }
                }
                LaunchedEffect(phase) {
                    if (initial != null && phase is SlipPhase.Open) {
                        val wait = initial.localDeadline - System.currentTimeMillis()
                        if (wait > 0) delay(wait)
                        if (phase is SlipPhase.Open) phase = SlipPhase.Expired
                    }
                    if (phase is SlipPhase.Done || phase is SlipPhase.Superseded) {
                        delay(4_000)
                        finish()
                    }
                }

                ApproveScreen(
                    model = initial?.let { toModel(it) },
                    phase = phase,
                    now = System::currentTimeMillis,
                    matches = { typed -> initial != null && typed == initial.request.matchNumber },
                    onApprove = { typed -> initial?.let { approve(it, typed) { p -> phase = p } } },
                    onDeny = { initial?.let { refuse(it, Decision.Deny, null) { p -> phase = p } } },
                    onNotMe = { auto ->
                        initial?.let {
                            refuse(it, Decision.NotMe, if (auto) getString(R.string.auto_not_me_detail) else null) { p -> phase = p }
                        }
                    },
                    onClose = { finish() },
                )
            }
        }
    }

    private fun toModel(p: PendingRequest): SlipModel {
        val r = p.request
        val time = DateTimeFormatter.ofLocalizedTime(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(r.issuedAt))
        return SlipModel(
            pcName = r.pcName,
            account = r.account,
            signInKind = Notifications.scenarioLabel(this, r.scenario),
            time = time,
            remote = r.remoteAddr.ifBlank { getString(R.string.remote_none) },
            deadline = p.localDeadline,
            lifetimeMs = p.lifetimeMs,
            accountLabel = if (r.scenario == dev.phonegate.protocol.Scenario.ChangeSetting) getString(R.string.field_setting) else null,
        )
    }

    private fun refuse(p: PendingRequest, decision: Decision, detail: String?, setPhase: (SlipPhase) -> Unit) {
        setPhase(SlipPhase.Working)
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { Responder.refuse(applicationContext, p, decision, detail) }
            setPhase(
                when (result) {
                    Responder.Result.Sent -> if (decision == Decision.Deny) {
                        SlipPhase.Done(Outcome.Denied, getString(R.string.done_denied))
                    } else {
                        SlipPhase.Done(Outcome.NotMe, getString(R.string.done_not_me))
                    }
                    Responder.Result.NotSent -> SlipPhase.Done(Outcome.Error, getString(R.string.done_not_sent))
                    Responder.Result.NoLongerPending -> SlipPhase.Gone
                },
            )
        }
    }

    private fun approve(p: PendingRequest, typed: Long, setPhase: (SlipPhase) -> Unit) {
        val store = PhoneStore.get(this)
        val pc = store.state.value.pc(p.pcId) ?: run { setPhase(SlipPhase.Gone); return }
        val signature = try {
            KeyManager.approveSignature(pc.approveAlias)
        } catch (e: KeyManager.KeyInvalidated) {
            store.markNeedsRepair(pc.pcId, e.reason)
            setPhase(SlipPhase.Done(Outcome.Error, getString(R.string.done_key_invalidated, e.reason)))
            return
        } catch (e: Exception) {
            setPhase(SlipPhase.Done(Outcome.Error, getString(R.string.done_key_error)))
            return
        }
        setPhase(SlipPhase.Working)
        BiometricGate.authenticate(
            this,
            title = getString(R.string.bio_approve_title, p.request.pcName),
            subtitle = getString(R.string.bio_approve_subtitle, p.request.account),
            crypto = BiometricPrompt.CryptoObject(signature),
            onSuccess = { crypto ->
                lifecycleScope.launch {
                    val result = withContext(Dispatchers.IO) {
                        val at = System.currentTimeMillis()
                        val sig = KeyManager.finishSign(crypto.signature!!, Responder.approveBytes(p, typed, at))
                        Responder.sendApprove(applicationContext, p, typed, at, sig)
                    }
                    setPhase(
                        when (result) {
                            Responder.Result.Sent -> SlipPhase.Done(Outcome.Approved, getString(R.string.done_approved))
                            Responder.Result.NotSent -> SlipPhase.Done(Outcome.Error, getString(R.string.done_not_sent))
                            Responder.Result.NoLongerPending -> SlipPhase.Gone
                        },
                    )
                }
            },
            onFailure = { _, _ ->
                // Cancelled or failed biometric: nothing was signed; the slip stays open.
                setPhase(if (Pending.find(p.reqId) != null) SlipPhase.Open else SlipPhase.Gone)
            },
        )
    }

    companion object {
        const val EXTRA_REQ_ID = "req_id"
    }
}
