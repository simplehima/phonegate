package dev.phonegate.protocol

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Mirrors every test in `crates/pg-core/src/health.rs`, in the same order. */
class HealthTest {
    private val min = 60_000L

    private fun st(seq: Long, enforce: Boolean) = Status(
        seq = seq, at = seq, enforce = enforce,
        cpRegistered = true, filterRegistered = true, filesIntact = true, watchdogPresent = true,
        bitlocker = BitLocker.OnPin, netlogonBlocked = false, safeMode = false,
    )

    /** Small mutable driver so the tests read like the Rust ones. */
    private class H(var h: Health) {
        fun status(s: Status, now: Long): Alert? = h.onStatus(s, now).also { h = it.health }.alert
        fun notice(k: NoticeKind, d: String, now: Long): Alert? = h.onNotice(k, d, now).also { h = it.health }.alert
        fun tick(now: Long): Alert? = h.tick(now).also { h = it.health }.alert
        fun state(now: Long) = h.state(now)
    }

    private fun fresh(now: Long) = H(Health.new(now))

    @Test
    fun healthyReportsNeverAlarm() {
        val h = fresh(0)
        for (i in 1L..10L) {
            assertNull(h.status(st(i, true), i * 5 * min))
            assertNull(h.tick(i * 5 * min + min))
        }
        assertEquals(PcState.Ok, h.state(50 * min + min))
    }

    @Test
    fun replayedOrOldSequenceRejected() {
        val h = fresh(0)
        h.status(st(5, true), 1)
        for (seq in listOf(5L, 4L)) {
            try {
                h.status(st(seq, true), 2)
                fail("seq $seq accepted")
            } catch (e: ProtocolException.Replay) { /* expected */ }
        }
        h.status(st(6, true), 4) // newer is fine
    }

    @Test
    fun silenceAlarmsOnceButNotAfterSleepOrShutdown() {
        val h = fresh(0)
        h.status(st(1, true), 0)
        assertNull("exactly at the window is not yet silent", h.tick(SILENCE_MS))
        assertEquals(Alert.StoppedReporting, h.tick(SILENCE_MS + 1))
        assertNull("one alert per episode", h.tick(SILENCE_MS + 10 * min))
        assertEquals(PcState.TamperAlert, h.state(SILENCE_MS + 10 * min))
        // Report resumes: episode ends.
        h.status(st(2, true), SILENCE_MS + 11 * min)
        assertEquals(PcState.Ok, h.state(SILENCE_MS + 11 * min))

        for (kind in listOf(NoticeKind.Sleep, NoticeKind.Shutdown)) {
            val g = fresh(0)
            g.status(st(1, true), 0)
            g.notice(kind, "", min)
            assertNull("$kind suppresses the silence alarm", g.tick(10 * SILENCE_MS))
            assertEquals(if (kind == NoticeKind.Sleep) PcState.Asleep else PcState.Off, g.state(10 * SILENCE_MS))
            g.notice(NoticeKind.Resume, "", 10 * SILENCE_MS)
            assertEquals("silence after resume alarms again", Alert.StoppedReporting, g.tick(10 * SILENCE_MS + SILENCE_MS + 1))
        }
    }

    @Test
    fun neverReportingPcAlarms() {
        val h = fresh(1_000)
        assertEquals(Alert.StoppedReporting, h.tick(1_000 + SILENCE_MS + 1))
    }

    @Test
    fun stopRepairAndSafeModeAlert() {
        assertEquals(Alert.AgentStopped, fresh(0).notice(NoticeKind.AgentStopped, "", 1))
        assertEquals(Alert.Repaired("service"), fresh(0).notice(NoticeKind.Repaired, "service", 1))
        val h = fresh(0)
        assertTrue(h.notice(NoticeKind.SafeModeBoot, "03:12", 1) is Alert.SafeModeBoot)
        assertNull(h.notice(NoticeKind.RecoveryCodeUsed, "", 2))
    }

    @Test
    fun integrityBreakWhileEnforcingAlarms() {
        val h = fresh(0)
        h.status(st(1, true), 0)
        when (val a = h.status(st(2, true).copy(cpRegistered = false), 1)) {
            is Alert.IntegrityBroken -> assertTrue(a.what.contains("sign-in tile"))
            else -> fail("$a")
        }
        // Not enforcing: an unregistered tile is expected (protection off), no alarm.
        assertNull(fresh(0).status(st(1, false).copy(cpRegistered = false), 0))
    }

    @Test
    fun protectionOffRequiresRecentDisableNotice() {
        var h = fresh(0)
        h.status(st(1, true), 0)
        assertEquals(Alert.ProtectionOffWithoutApproval, h.status(st(2, false), min))

        h = fresh(0)
        h.status(st(1, true), 0)
        h.notice(NoticeKind.ProtectionDisabled, "protection_disabled_by_phone", min)
        assertNull(h.status(st(2, false), 2 * min))

        h = fresh(0)
        h.status(st(1, true), 0)
        h.notice(NoticeKind.ProtectionDisabled, "", min)
        assertEquals("stale notice doesn't count", Alert.ProtectionOffWithoutApproval, h.status(st(2, false), min + DISABLE_GRACE_MS + 1))
    }

    @Test
    fun warningsTrackedAndSerializable() {
        val h = fresh(0)
        h.status(st(1, true).copy(bitlocker = BitLocker.Off, netlogonBlocked = true), 0)
        assertTrue(h.h.bitlockerOff && h.h.netlogonBlocked)
        assertEquals(h.h, Health.fromJson(JSONObject(h.h.toJson().toString())))
    }

    // --- extra Kotlin-side checks -------------------------------------------------------------

    @Test
    fun alertWordingMatchesReference() {
        assertEquals(
            "PhoneGate on Desk was stopped. If you didn't do this, someone may be tampering with the PC.",
            Alert.AgentStopped.message("Desk"),
        )
        assertEquals("Desk stopped reporting. It may be offline, or PhoneGate may have been removed.", Alert.StoppedReporting.message("Desk"))
        assertEquals("Protection on Desk was turned off without your approval.", Alert.ProtectionOffWithoutApproval.message("Desk"))
        assertEquals("PhoneGate protection on Desk is damaged: sign-in tile unregistered.", Alert.IntegrityBroken("sign-in tile unregistered").message("Desk"))
        assertEquals("PhoneGate on Desk had to repair itself: service.", Alert.Repaired("service").message("Desk"))
        assertEquals("Desk was started in Safe Mode (03:12). Safe Mode skips the phone check.", Alert.SafeModeBoot("03:12").message("Desk"))
        for (a in listOf(Alert.AgentStopped, Alert.Repaired("x"), Alert.SafeModeBoot("y"), Alert.IntegrityBroken("z"), Alert.ProtectionOffWithoutApproval, Alert.StoppedReporting)) {
            assertEquals(a, Alert.of(a.type, a.detail))
        }
    }

    @Test
    fun alertDuringEpisodeIsNotRepeatedAcrossKinds() {
        val h = fresh(0)
        assertEquals(Alert.AgentStopped, h.notice(NoticeKind.AgentStopped, "", 1))
        assertNull("second trigger in the same episode", h.notice(NoticeKind.Repaired, "files", 2))
        assertNull(h.tick(SILENCE_MS + 10))
        // Healthy report ends the episode; a new trigger alerts again.
        h.status(st(1, true), SILENCE_MS + 20)
        assertEquals(Alert.AgentStopped, h.notice(NoticeKind.AgentStopped, "", SILENCE_MS + 30))
    }
}
