package dev.phonegate.protocol

import dev.phonegate.protocol.ProtocolVectorsTest.Companion.h
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test

/** Feature 002 entries of `protocol/vectors/v1.json` ("status" section) and strict decoding. */
class StatusVectorsTest {
    companion object {
        @BeforeClass
        @JvmStatic
        fun load() = ProtocolVectorsTest.load()
    }

    private val expected = Status(
        seq = 42, at = 1_700_000_300_000L, enforce = true,
        cpRegistered = true, filterRegistered = true, filesIntact = true, watchdogPresent = true,
        bitlocker = BitLocker.OnPin, netlogonBlocked = false, safeMode = false,
    )

    private fun ctx() = PairingContext(h("keys", "pc_pub"), h("pairing", "k_pair"), h("keys", "phone_id"))

    @Test
    fun plainDecodesAndReencodesExactly() {
        val plain = h("status", "plain")
        assertEquals(42L, ProtocolVectorsTest.v.getJSONObject("status").getLong("seq"))
        val st = Status.decode(plain)
        assertEquals(expected, st)
        assertArrayEquals(plain, expected.encode())
        assertTrue(st.integrityOk)
    }

    @Test
    fun envelopeAndWireOpenToThePlaintext() {
        val c = ctx()
        val env = Envelope.parse(h("status", "envelope"))
        assertEquals(Kind.Status, env.kind)
        assertArrayEquals(h("status", "plain"), env.open(c.pcPub, c.kPair, Dir.PcToPhone, c.pcId, c.phoneId))
        assertArrayEquals(h("status", "wire"), Wire.wire(Kind.Status, env.encode()))
        // Re-sealing with the vector's msg_id and nonce yields the same ciphertext.
        val again = Envelope.parse(
            Envelope.sealWith(c.kPair, Dir.PcToPhone, Kind.Status, c.pcId, c.phoneId, ProtocolVectorsTest.signer("pc"), h("status", "plain"), env.msgId, env.nonce),
        )
        assertArrayEquals(env.ct, again.ct)
        // Through the inbox as the relay service would receive it.
        val r = Inbox.receive(c, c.pcId, h("status", "wire"), 1_700_000_300_500L, MemoryReplayGuard())
        assertTrue(r is Inbound.StatusMsg)
        assertEquals(expected, (r as Inbound.StatusMsg).status)
    }

    @Test
    fun agentStoppedNoticeAndChangeSettingRequest() {
        val n = Notice.decode(h("status", "notice_agent_stopped"))
        assertEquals(NoticeKind.AgentStopped, n.kind)
        assertEquals(1_700_000_400_000L, n.at)
        assertEquals("service stop", n.detail)
        assertArrayEquals(h("status", "notice_agent_stopped"), n.encode())

        val req = ApprovalRequest.decode(h("status", "request_change_setting"))
        assertEquals(Scenario.ChangeSetting, req.scenario)
        assertEquals("Allow network sign-ins", req.account)
        assertArrayEquals(h("status", "request_change_setting"), req.encode())
    }

    @Test
    fun strictFlagsAndBitlockerValues() {
        fun raw(enforce: Long = 1, bitlocker: String = "off", safeMode: Long = 0) =
            Enc("phonegate/v1/status").u64(1).u64(1).u64(enforce).u64(1).u64(1).u64(1).u64(1).str(bitlocker).u64(0).u64(safeMode).finish()
        Status.decode(raw()) // control
        for ((what, bytes) in listOf("flag 2" to raw(enforce = 2), "safe_mode 7" to raw(safeMode = 7), "bitlocker maybe" to raw(bitlocker = "maybe"), "bitlocker case" to raw(bitlocker = "Off"))) {
            try {
                Status.decode(bytes)
                fail("$what accepted")
            } catch (e: ProtocolException.Decode) { /* expected */ }
        }
        for (b in BitLocker.entries) assertEquals(b, Status.decode(raw(bitlocker = b.wire)).bitlocker)
        try {
            Status.decode(Enc("phonegate/v1/status").u64(1).finish())
            fail("wrong field count accepted")
        } catch (e: ProtocolException.Decode) { /* expected */ }
    }

    @Test
    fun newKindsAndNoticesParse() {
        assertTrue(Kind.Status.isSealed)
        assertEquals(Scenario.ChangeSetting, Scenario.parse("change-setting"))
        for (k in listOf("agent-stopped", "shutdown", "sleep", "resume", "repaired", "safe-mode-boot", "setting-changed", "agent-started")) {
            assertEquals(k, NoticeKind.parse(k).wire)
        }
    }

    @Test
    fun tamperedOrReplayedStatusRejected() {
        val c = ctx()
        val wire = h("status", "wire")
        val guard = MemoryReplayGuard()
        Inbox.receive(c, c.pcId, wire, 1_700_000_300_500L, guard)
        try {
            Inbox.receive(c, c.pcId, wire, 1_700_000_300_600L, guard)
            fail("replayed status accepted")
        } catch (e: ProtocolException.Replay) { /* expected */ }
        val bad = wire.copyOf().also { it[it.size - 80] = (it[it.size - 80].toInt() xor 1).toByte() }
        try {
            Inbox.receive(c, c.pcId, bad, 1_700_000_300_500L, MemoryReplayGuard())
            fail("tampered status accepted")
        } catch (e: ProtocolException) { /* expected */ }
        // The health model also rejects an old sequence number that arrives in a fresh envelope.
        val h1 = Health.new(0).onStatus(expected, 1).health
        try {
            h1.onStatus(expected.copy(seq = 41), 2)
            fail("older seq accepted")
        } catch (e: ProtocolException.Replay) { /* expected */ }
    }
}
