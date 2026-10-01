package dev.phonegate.net

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import dev.phonegate.data.AttemptRecord
import dev.phonegate.data.DisableState
import dev.phonegate.data.Outcome
import dev.phonegate.data.PhoneStore
import dev.phonegate.keys.BiometricGate
import dev.phonegate.keys.KeyManager
import dev.phonegate.protocol.Command
import dev.phonegate.protocol.Crypto
import dev.phonegate.protocol.Kind
import dev.phonegate.protocol.commandAuthBytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Phone-initiated "turn off protection" (feature 004, US2). The authority is the biometric-bound
 * approve key: it signs [commandAuthBytes], and the device key then seals the envelope like all
 * phone->PC traffic. Applied-state is observed later (a status with enforce=false, or a
 * protection-disabled notice) by [HealthMonitor], which clears the pending record.
 */
object DisableSender {
    private val scope = CoroutineScope(Dispatchers.Main)

    sealed class Outcome2 {
        /** The relay accepted it. The PC applies it now, or when it next connects. */
        data object Sent : Outcome2()
        data class Failed(val reason: String) : Outcome2()

        /** The owner dismissed the fingerprint prompt. Nothing was sent. */
        data object Cancelled : Outcome2()
    }

    /**
     * Runs the biometric prompt, builds and sends the command. [onResult] is called on the main
     * thread. A key invalidated by new biometric enrollment marks the PC for re-pairing.
     */
    fun requestDisable(activity: FragmentActivity, pcId: String, onResult: (Outcome2) -> Unit) {
        val app = activity.applicationContext
        val store = PhoneStore.get(app)
        val pc = store.state.value.pc(pcId) ?: run { onResult(Outcome2.Failed("This PC is no longer paired.")); return }
        if (pc.needsRepair) {
            onResult(Outcome2.Failed("This PC needs pairing again before it can be changed."))
            return
        }
        val signature = try {
            KeyManager.approveSignature(pc.approveAlias)
        } catch (e: KeyManager.KeyInvalidated) {
            store.markNeedsRepair(pcId, e.reason)
            onResult(Outcome2.Failed(e.reason))
            return
        } catch (e: Exception) {
            onResult(Outcome2.Failed("The approval key could not be used."))
            return
        }
        val cmdId = Crypto.random(16)
        val nonce = Crypto.random(32)
        val issuedAt = System.currentTimeMillis()
        val expiresAt = issuedAt + dev.phonegate.protocol.MAX_COMMAND_LIFETIME_MS
        val authBytes = commandAuthBytes(cmdId, nonce, Command.DISABLE_PROTECTION, issuedAt, expiresAt)

        BiometricGate.authenticate(
            activity,
            title = "Turn off protection on ${pc.pcName}",
            subtitle = "Confirm it's you. The PC will stop requiring phone approval.",
            crypto = BiometricPrompt.CryptoObject(signature),
            onSuccess = { crypto ->
                scope.launch {
                    val result = withContext(Dispatchers.IO) {
                        val approveSig = KeyManager.finishSign(crypto.signature!!, authBytes)
                        val cmd = Command(cmdId, nonce, pc.pcIdBytes, Crypto.idOf(KeyManager.deviceSigner(pc.deviceAlias).public), issuedAt, expiresAt, Command.DISABLE_PROTECTION, approveSig)
                        // 120 s TTL so a briefly-offline PC still receives it from the relay queue.
                        RelayHub.sendSealed(pcId, Kind.Command, cmd.encode(), ttlS = 120)
                    }
                    store.updatePc(pcId) { it.copy(disable = DisableState(requestedAt = System.currentTimeMillis(), sent = result)) }
                    store.record(
                        AttemptRecord(
                            System.currentTimeMillis(), pc.pcName, "", "disable-protection", Outcome.Disabled,
                            detail = if (result) "Turn-off request sent to the PC." else "Turn-off request could not reach the relay.",
                        ),
                    )
                    onResult(if (result) Outcome2.Sent else Outcome2.Failed("Couldn't reach the relay. Try again when this phone is online."))
                }
            },
            onFailure = { msg, cancelled ->
                onResult(if (cancelled) Outcome2.Cancelled else Outcome2.Failed(msg))
            },
        )
    }
}
