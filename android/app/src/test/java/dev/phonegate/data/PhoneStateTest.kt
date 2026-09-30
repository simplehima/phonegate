package dev.phonegate.data

import dev.phonegate.protocol.B64
import dev.phonegate.protocol.Crypto
import dev.phonegate.protocol.SoftSigner
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class PhoneStateTest {
    private fun pc(): PairedPc {
        val pub = SoftSigner.generate().public
        return PairedPc(
            pcId = B64.encode(Crypto.idOf(pub)), pcPub = B64.encode(pub), pcName = "Desk", relayUrl = "https://r.example",
            kPair = B64.encode(ByteArray(32) { 1 }), kOfflineWrapped = B64.encode(ByteArray(40)),
            deviceAlias = "pc_x_device", approveAlias = "pc_x_approve", offlineAlias = "pc_x_offline_wrap",
            pairedAt = 5, keyLevel = KeyLevel.StrongBox,
        )
    }

    @Test
    fun jsonRoundTrip() {
        val p = pc()
        val s = PhoneState(
            deviceName = "Pixel",
            pcs = listOf(
                p,
                p.copy(
                    pcName = "Other",
                    health = dev.phonegate.protocol.Health.new(5).onNotice(dev.phonegate.protocol.NoticeKind.AgentStopped, "", 9).health,
                    alert = AlertRecord.of(dev.phonegate.protocol.Alert.Repaired("service"), "Other", 9).copy(seenAt = 12),
                ),
            ),
            history = listOf(AttemptRecord(10, "Desk", "DESK\\me", "unlock", Outcome.NotMe, "abc", "Wrong number typed twice")),
            seen = mapOf("id" to 9L),
        )
        val back = PhoneState.fromJson(JSONObject(s.toJson().toString()))
        assertEquals(s, back)
        assertNull(back.pcs[0].repairReason)
    }

    @Test
    fun retentionPrunesHistoryAfter90DaysAndSeenAfter24h() {
        val now = 1_000L * 24 * 60 * 60 * 1000
        val day = 24L * 60 * 60 * 1000
        val s = PhoneState(
            deviceName = "Pixel",
            history = listOf(
                AttemptRecord(now - 89 * day, "A", "", "", Outcome.Approved),
                AttemptRecord(now - 91 * day, "B", "", "", Outcome.Denied),
            ),
            seen = mapOf("fresh" to now - day + 1, "stale" to now - day - 1),
        ).pruned(now)
        assertEquals(listOf("A"), s.history.map { it.pcName })
        assertEquals(setOf("fresh"), s.seen.keys)
    }

    @Test
    fun storedPcWhoseIdDoesNotMatchItsKeyIsRejected() {
        val bad = pc().copy(pcId = B64.encode(ByteArray(32)))
        try {
            PairedPc.fromJson(bad.toJson())
            fail("tampered pc id accepted")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("pinned"))
        }
    }
}
