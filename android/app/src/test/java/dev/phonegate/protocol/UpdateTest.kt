package dev.phonegate.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mirrors every test in `crates/pg-core/src/update.rs`. */
class UpdateTest {
    @Test
    fun comparesStrictlyAndToleratesFormatting() {
        assertTrue(Update.isNewer("0.1.0", "0.2.0"))
        assertTrue(Update.isNewer("v0.1.0", "v0.1.1"))
        assertTrue(Update.isNewer("1.0.0", "2.0.0"))
        assertTrue(Update.isNewer("0.9.9", "1.0.0"))
        assertFalse("equal is not newer", Update.isNewer("0.2.0", "0.2.0"))
        assertFalse("older is not newer", Update.isNewer("0.2.0", "0.1.9"))
        assertFalse("1.0 == 1.0.0", Update.isNewer("1.0.0", "1.0"))
        assertTrue(Update.isNewer("1.0", "1.0.1"))
        assertTrue("numeric core wins, suffix ignored", Update.isNewer("v0.2.0", "v0.2.1-rc1"))
        assertFalse("same core, suffix ignored", Update.isNewer("v0.2.1", "v0.2.1-rc1"))
        assertFalse("unparsable latest is treated as 0.0.0", Update.isNewer("0.2.0", "garbage"))
    }

    @Test
    fun readsGithubTag() {
        assertEquals("v0.2.0", Update.parseLatestTag("""{"tag_name":"v0.2.0","name":"PhoneGate 0.2.0"}"""))
        assertNull(Update.parseLatestTag("""{"message":"Not Found"}"""))
        assertNull(Update.parseLatestTag("not json"))
        assertNull(Update.parseLatestTag("""{"tag_name":"  "}"""))
    }
}
