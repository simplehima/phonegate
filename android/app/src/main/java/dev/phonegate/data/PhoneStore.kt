package dev.phonegate.data

import android.content.Context
import android.os.Build
import dev.phonegate.keys.KeyManager
import dev.phonegate.protocol.B64
import dev.phonegate.protocol.ReplayGuard
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import java.io.File

/**
 * Encrypted app state: JSON sealed with the Keystore `store_wrap` key, written atomically
 * (temp file + rename). Also the persistent 24 h replay window for incoming message ids.
 */
class PhoneStore private constructor(private val file: File) : ReplayGuard {
    private val lock = Any()
    private val _state: MutableStateFlow<PhoneState>
    val state: StateFlow<PhoneState> get() = _state.asStateFlow()

    init {
        _state = MutableStateFlow(load())
    }

    private fun defaultState() = PhoneState(deviceName = Build.MODEL.take(64).ifBlank { "Android phone" })

    private fun load(): PhoneState {
        if (!file.exists()) return defaultState()
        return try {
            val json = String(KeyManager.openState(file.readBytes()), Charsets.UTF_8)
            PhoneState.fromJson(JSONObject(json)).pruned(System.currentTimeMillis())
        } catch (e: Exception) {
            // Unreadable state (e.g. the wrap key was wiped with a factory reset of the keystore):
            // keep the corrupt blob aside and start clean rather than trusting partial data.
            file.renameTo(File(file.parentFile, "state.corrupt.${System.currentTimeMillis()}"))
            defaultState()
        }
    }

    private fun persist(s: PhoneState) {
        val blob = KeyManager.sealState(s.toJson().toString().toByteArray(Charsets.UTF_8))
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(blob)
        if (!tmp.renameTo(file)) {
            file.delete()
            if (!tmp.renameTo(file)) throw java.io.IOException("could not replace state file")
        }
    }

    fun update(f: (PhoneState) -> PhoneState): PhoneState = synchronized(lock) {
        val next = f(_state.value).pruned(System.currentTimeMillis())
        persist(next)
        _state.value = next
        next
    }

    fun record(r: AttemptRecord) {
        update { s -> s.copy(history = listOf(r) + s.history) }
    }

    fun upsertPc(pc: PairedPc) {
        update { s -> s.copy(pcs = s.pcs.filter { it.pcId != pc.pcId } + pc) }
    }

    fun removePc(pcId: String): PairedPc? {
        var removed: PairedPc? = null
        update { s ->
            removed = s.pc(pcId)
            s.copy(pcs = s.pcs.filter { it.pcId != pcId })
        }
        removed?.let { KeyManager.deleteAliases(listOf(it.deviceAlias, it.approveAlias, it.offlineAlias)) }
        return removed
    }

    /** Replaces one PC record atomically; returns the updated record, or null if not paired. */
    fun updatePc(pcId: String, f: (PairedPc) -> PairedPc): PairedPc? {
        var out: PairedPc? = null
        update { s ->
            s.copy(pcs = s.pcs.map { if (it.pcId == pcId) f(it).also { n -> out = n } else it })
        }
        return out
    }

    fun markNeedsRepair(pcId: String, reason: String) {
        update { s -> s.copy(pcs = s.pcs.map { if (it.pcId == pcId) it.copy(repairReason = reason) else it }) }
    }

    fun rename(pcId: String, name: String) {
        val clean = name.trim().take(64)
        if (clean.isEmpty()) return
        update { s -> s.copy(pcs = s.pcs.map { if (it.pcId == pcId) it.copy(pcName = clean) else it }) }
    }

    override fun firstSeen(id: ByteArray, now: Long): Boolean = synchronized(lock) {
        val key = B64.encode(id)
        val seen = _state.value.seen
        val prev = seen[key]
        if (prev != null && now - prev <= PhoneState.SEEN_WINDOW_MS) return false
        update { s -> s.copy(seen = s.seen + (key to now)) }
        true
    }

    companion object {
        @Volatile private var instance: PhoneStore? = null

        fun get(context: Context): PhoneStore = instance ?: synchronized(this) {
            instance ?: PhoneStore(File(context.applicationContext.noBackupFilesDir, "state.bin")).also { instance = it }
        }
    }
}
