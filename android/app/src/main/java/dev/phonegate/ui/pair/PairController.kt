package dev.phonegate.ui.pair

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import dev.phonegate.data.AttemptRecord
import dev.phonegate.data.Outcome
import dev.phonegate.data.PairedPc
import dev.phonegate.data.PhoneStore
import dev.phonegate.keys.BiometricGate
import dev.phonegate.keys.KeyManager
import dev.phonegate.net.RelayService
import dev.phonegate.protocol.B64
import dev.phonegate.protocol.EphemeralKey
import dev.phonegate.protocol.Kind
import dev.phonegate.protocol.PAIRING_LIFETIME_MS
import dev.phonegate.protocol.PairingKdf
import dev.phonegate.protocol.PairingQr
import dev.phonegate.protocol.PhonePairing
import dev.phonegate.protocol.PreparedJoin
import dev.phonegate.protocol.ProtocolException
import dev.phonegate.protocol.RelayClient
import dev.phonegate.protocol.Signer
import dev.phonegate.protocol.Wire
import dev.phonegate.protocol.hex
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed class PairState {
    data object Scan : PairState()
    data class Working(val step: String) : PairState()
    data class NeedSign(val pcName: String) : PairState()
    data class Sas(val code: String, val pcName: String) : PairState()
    data class WaitingComplete(val pcName: String) : PairState()
    data class Success(val pcName: String) : PairState()
    data class Failed(val reason: String) : PairState()
}

/**
 * Phone side of QR pairing (protocol §3): scan → keys with attestation → relay slot → verify
 * offer → biometric-signed join → SAS comparison → biometric wrap of k_offline → confirm →
 * verified pair-complete → store. Any failure aborts and deletes the new keys.
 */
class PairController(context: Context) {
    private val app = context.applicationContext
    private val store = PhoneStore.get(app)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val _state = MutableStateFlow<PairState>(PairState.Scan)
    val state: StateFlow<PairState> = _state.asStateFlow()

    private var pairing: PhonePairing? = null
    private var keys: KeyManager.PairKeys? = null
    private var device: Signer? = null
    private var client: RelayClient? = null
    private var prepared: PreparedJoin? = null
    private var offerPcName: String = ""
    private var wrappedOffline: ByteArray? = null
    private var timeout: Job? = null

    fun onScanned(text: String) {
        if (_state.value !is PairState.Scan) return
        val qr = try {
            PairingQr.parse(text.trim())
        } catch (e: ProtocolException) {
            fail("That isn't a PhoneGate pairing code. Open PhoneGate on the PC and scan the code shown under Pair a phone.")
            return
        }
        _state.value = PairState.Working("Creating this phone's keys for ${qr.pcName}")
        scope.launch {
            try {
                val pcIdB64 = B64.encode(qr.pcPubHash)
                val existing = store.state.value.pc(pcIdB64) != null
                val p = PhonePairing(qr)
                val k = withContext(Dispatchers.Default) {
                    KeyManager.generatePairKeys(KeyManager.aliasBase(qr.pcPubHash.hex(), existing), p.attestChallenge)
                }
                pairing = p
                keys = k
                device = KeyManager.deviceSigner(k.deviceAlias)
                _state.value = PairState.Working("Connecting to the relay")
                connect(qr, p)
                timeout = scope.launch {
                    delay(PAIRING_LIFETIME_MS)
                    if (_state.value !is PairState.Success && _state.value !is PairState.Failed) {
                        fail("Pairing took longer than 5 minutes, so the code expired. Start again on the PC.")
                    }
                }
            } catch (e: Exception) {
                fail("This phone could not create its security keys. ${e.message ?: ""}".trim())
            }
        }
    }

    private fun connect(qr: PairingQr, p: PhonePairing) {
        val c = RelayClient(qr.relayUrl, device!!, object : RelayClient.Listener {
            override fun onReady(client: RelayClient) {
                client.subscribe(p.slot)
                scope.launch {
                    if (_state.value is PairState.Working) _state.value = PairState.Working("Waiting for ${qr.pcName}")
                }
            }

            override fun onMessage(from: ByteArray, to: ByteArray, body: ByteArray) {
                if (!to.contentEquals(p.slot)) return
                scope.launch { handleSlot(p, body) }
            }

            override fun onError(ref: String?, code: String) {
                if (code == "auth_failed" || code == "too_many_slots") {
                    scope.launch { fail("The relay refused the connection ($code).") }
                }
            }
        })
        client = c
        c.start()
    }

    private fun handleSlot(p: PhonePairing, body: ByteArray) {
        val (kind, payload) = try { Wire.unwire(body) } catch (e: ProtocolException) { return }
        when (kind) {
            Kind.PairOffer -> {
                if (p.verifiedOffer != null) return
                val offer = try {
                    p.acceptOffer(payload, System.currentTimeMillis())
                } catch (e: ProtocolException.Expired) {
                    fail("The pairing code on the PC has expired. Start again on the PC.")
                    return
                } catch (e: ProtocolException) {
                    fail("The PC's reply did not match the QR code, so nothing was paired. Someone may be interfering with the relay. Start again on the PC.")
                    return
                }
                val k = keys ?: return
                try {
                    prepared = p.prepare(k.devicePub, k.approvePub, EphemeralKey.generate(), store.state.value.deviceName)
                } catch (e: ProtocolException) {
                    fail("Pairing failed: ${e.message}")
                    return
                }
                offerPcName = offer.pcName
                _state.value = PairState.NeedSign(offer.pcName)
            }
            Kind.PairComplete -> {
                if (_state.value !is PairState.WaitingComplete) return
                val result = try {
                    p.handleComplete(payload)
                } catch (e: ProtocolException) {
                    fail("The PC's confirmation did not check out, so nothing was saved. Start again on the PC.")
                    return
                }
                val k = keys!!
                val wrapped = wrappedOffline ?: run { fail("Internal state lost. Start again."); return }
                val pcIdB64 = B64.encode(result.pcId)
                val old = store.state.value.pc(pcIdB64)
                val pc = PairedPc(
                    pcId = pcIdB64,
                    pcPub = B64.encode(result.pcPub),
                    pcName = result.pcName,
                    relayUrl = result.relayUrl,
                    kPair = B64.encode(result.kPair),
                    kOfflineWrapped = B64.encode(wrapped),
                    deviceAlias = k.deviceAlias,
                    approveAlias = k.approveAlias,
                    offlineAlias = k.offlineAlias,
                    pairedAt = System.currentTimeMillis(),
                    keyLevel = k.level,
                )
                store.upsertPc(pc)
                if (old != null && old.deviceAlias != pc.deviceAlias) {
                    KeyManager.deleteAliases(listOf(old.deviceAlias, old.approveAlias, old.offlineAlias))
                }
                store.record(AttemptRecord(System.currentTimeMillis(), result.pcName, "", "", Outcome.Paired))
                keys = null // now owned by the stored pairing
                close()
                RelayService.startIfPaired(app)
                _state.value = PairState.Success(result.pcName)
            }
            else -> Unit
        }
    }

    /** Signs the join with the approve key (biometric) and the device key, then sends it. */
    fun signJoin(activity: FragmentActivity) {
        val p = pairing ?: return
        val k = keys ?: return
        val prep = prepared ?: return
        val sig = try {
            KeyManager.approveSignature(k.approveAlias)
        } catch (e: Exception) {
            fail("The new approval key could not be used. ${e.message ?: ""}".trim())
            return
        }
        BiometricGate.authenticate(
            activity,
            title = "Pair with $offerPcName",
            subtitle = "Confirm it's you to create this phone's approval key",
            crypto = BiometricPrompt.CryptoObject(sig),
            onSuccess = { crypto ->
                scope.launch {
                    try {
                        val payload = withContext(Dispatchers.Default) {
                            val approveSig = KeyManager.finishSign(crypto.signature!!, prep.sigBytes)
                            val deviceSig = device!!.sign(prep.sigBytes)
                            p.buildJoin(k.deviceChain, k.approveChain, deviceSig, approveSig)
                        }
                        if (client?.sendSlot(p.slot, Wire.wire(Kind.PairJoin, payload)) == null) {
                            fail("Lost the connection to the relay. Start again on the PC.")
                            return@launch
                        }
                        _state.value = PairState.Sas(prep.sas, offerPcName)
                    } catch (e: Exception) {
                        fail("Pairing failed while signing. ${e.message ?: ""}".trim())
                    }
                }
            },
            onFailure = { msg, cancelled ->
                if (!cancelled) fail("Fingerprint check failed: $msg")
            },
        )
    }

    /** Owner says the codes match: wrap k_offline under the biometric key, then confirm. */
    fun confirmSas(activity: FragmentActivity) {
        val p = pairing ?: return
        val k = keys ?: return
        val prep = prepared ?: return
        val cipher = try {
            KeyManager.offlineEncryptCipher(k.offlineAlias)
        } catch (e: Exception) {
            fail("The offline-code key could not be used. ${e.message ?: ""}".trim())
            return
        }
        BiometricGate.authenticate(
            activity,
            title = "Codes match",
            subtitle = "Confirm it's you to finish pairing with $offerPcName",
            crypto = BiometricPrompt.CryptoObject(cipher),
            onSuccess = { crypto ->
                try {
                    wrappedOffline = KeyManager.wrapWith(crypto.cipher!!, PairingKdf.kOffline(prep.kPair))
                    if (client?.sendSlot(p.slot, Wire.wire(Kind.PairConfirm, p.confirm())) == null) {
                        fail("Lost the connection to the relay. Start again on the PC.")
                        return@authenticate
                    }
                    _state.value = PairState.WaitingComplete(offerPcName)
                } catch (e: Exception) {
                    fail("Pairing failed while saving the offline key. ${e.message ?: ""}".trim())
                }
            },
            onFailure = { msg, cancelled ->
                if (!cancelled) fail("Fingerprint check failed: $msg")
            },
        )
    }

    fun rejectSas() {
        fail("The codes didn't match, so nothing was paired. Someone may be interfering. Cancel on the PC and start again.")
    }

    fun restart() {
        cleanup()
        _state.value = PairState.Scan
    }

    private fun fail(reason: String) {
        cleanup()
        _state.value = PairState.Failed(reason)
    }

    private fun close() {
        timeout?.cancel()
        client?.close()
        client = null
    }

    private fun cleanup() {
        close()
        keys?.let { KeyManager.deleteAliases(listOf(it.deviceAlias, it.approveAlias, it.offlineAlias)) }
        keys = null
        pairing = null
        prepared = null
        device = null
        wrappedOffline = null
    }

    fun dispose() {
        if (_state.value !is PairState.Success) cleanup()
        scope.cancel()
    }
}
