package dev.phonegate.protocol

import dev.phonegate.protocol.ProtocolVectorsTest.Companion.h
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test

/** Feature 004 entries of `protocol/vectors/v1.json` ("command" section) and the update compares. */
class CommandVectorsTest {
    companion object {
        @BeforeClass
        @JvmStatic
        fun load() = ProtocolVectorsTest.load()
    }

    private fun ctx() = PairingContext(h("keys", "pc_pub"), h("pairing", "k_pair"), h("keys", "phone_id"))

    @Test
    fun authBytesMatchVector() {
        val auth = commandAuthBytes(ByteArray(16) { 0x6D }, ByteArray(32) { 0x7E }, "disable-protection", 1_700_000_000_000L, 1_700_000_060_000L)
        assertArrayEquals(h("command", "auth"), auth)
    }

    @Test
    fun plainDecodesReencodesAndVerifies() {
        val plain = h("command", "plain")
        val cmd = Command.decode(plain)
        assertEquals("disable-protection", cmd.command)
        assertArrayEquals(h("keys", "pc_id"), cmd.pcId)
        assertArrayEquals(h("keys", "phone_id"), cmd.phoneId)
        assertEquals(1_700_000_000_000L, cmd.issuedAt)
        assertEquals(1_700_000_060_000L, cmd.expiresAt)
        assertArrayEquals(plain, cmd.encode())
        // Authority is the approve key, not the device key.
        cmd.verifyAuth(h("keys", "approve_pub"))
        try {
            cmd.verifyAuth(h("keys", "device_pub"))
            fail("device key must not satisfy the command authority")
        } catch (e: ProtocolException.Verify) { /* expected */ }
    }

    @Test
    fun envelopeAndWireOpenToThePlaintext() {
        val c = ctx()
        val env = Envelope.parse(h("command", "envelope"))
        assertEquals(Kind.Command, env.kind)
        // Phone->PC traffic is signed by the device key; opened here as the PC would.
        val plain = env.open(h("keys", "device_pub"), c.kPair, Dir.PhoneToPc, c.phoneId, c.pcId)
        assertArrayEquals(h("command", "plain"), plain)
        assertArrayEquals(h("command", "wire"), Wire.wire(Kind.Command, env.encode()))
        // Re-seal with the vector's msg_id and nonce: identical ciphertext.
        val again = Envelope.parse(
            Envelope.sealWith(c.kPair, Dir.PhoneToPc, Kind.Command, c.phoneId, c.pcId, ProtocolVectorsTest.signer("device"), plain, env.msgId, env.nonce),
        )
        assertArrayEquals(env.ct, again.ct)
    }

    @Test
    fun lifetimeIsEnforced() {
        assertTrue(Kind.Command.isSealed)
        val sig = ByteArray(64)
        fun raw(issued: Long, expires: Long) = Enc(Command.LABEL)
            .bytes(ByteArray(16)).bytes(ByteArray(32)).bytes(ByteArray(32)).bytes(ByteArray(32))
            .u64(issued).u64(expires).str("disable-protection").bytes(sig).finish()
        for ((what, bytes) in listOf(
            "over 120s" to raw(1_000, 1_000 + MAX_COMMAND_LIFETIME_MS + 1),
            "expires before issued" to raw(5_000, 5_000),
        )) {
            try {
                Command.decode(bytes)
                fail("$what accepted")
            } catch (e: ProtocolException.Decode) { /* expected */ }
        }
    }

    @Test
    fun updateCompareVectors() {
        val u = ProtocolVectorsTest.v.getJSONObject("command").getJSONObject("update")
        val older = u.getString("older")
        val current = u.getString("current")
        val newer = u.getString("newer")
        assertTrue(Update.isNewer(current, newer))
        assertTrue(Update.isNewer(older, current))
        assertFalse(Update.isNewer(current, older))
        assertFalse(Update.isNewer(current, current))
    }
}
