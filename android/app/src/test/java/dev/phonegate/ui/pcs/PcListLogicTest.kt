package dev.phonegate.ui.pcs

import dev.phonegate.protocol.PcState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PcListLogicTest {
    private fun pc(
        id: String,
        name: String = id,
        state: PcState = PcState.Ok,
        status: PcStatus = PcStatus.Connected,
        alert: AlertInfo? = null,
        pending: Boolean = false,
    ) = PcItem(pcId = id, name = name, relay = "r", paired = "p", keys = "k", status = status, state = state, alert = alert, disablePending = pending)

    @Test
    fun attentionRules() {
        assertFalse(PcListLogic.needsAttention(pc("a")))
        assertFalse(PcListLogic.needsAttention(pc("a", state = PcState.Asleep)))
        assertFalse(PcListLogic.needsAttention(pc("a", state = PcState.Off)))
        assertTrue(PcListLogic.needsAttention(pc("a", state = PcState.TamperAlert)))
        assertTrue(PcListLogic.needsAttention(pc("a", state = PcState.StoppedReporting)))
        assertTrue(PcListLogic.needsAttention(pc("a", status = PcStatus.NeedsRepair)))
        assertTrue(PcListLogic.needsAttention(pc("a", pending = true)))
        assertTrue(PcListLogic.needsAttention(pc("a", alert = AlertInfo("m", "t", null))))
    }

    @Test
    fun attentionSortsFirstThenByNameIgnoringCase() {
        val items = listOf(pc("1", "zeta"), pc("2", "Alpha"), pc("3", "mid", state = PcState.TamperAlert), pc("4", "beta"))
        assertEquals(listOf("3", "2", "4", "1"), PcListLogic.ordered(items).map { it.pcId })
    }

    @Test
    fun singlePcIsAlwaysOpenAndSeveralOpenOnlyWhatNeedsYou() {
        val one = listOf(pc("a"))
        assertEquals(setOf("a"), PcListLogic.defaultExpanded(one))
        val many = listOf(pc("a"), pc("b", state = PcState.TamperAlert), pc("c"))
        assertEquals(setOf("b"), PcListLogic.defaultExpanded(many))
        assertEquals(emptySet<String>(), PcListLogic.defaultExpanded(listOf(pc("a"), pc("b"))))
    }

    @Test
    fun ownerFlipsAreRelativeToTheDefault() {
        val defaults = setOf("b")
        assertTrue(PcListLogic.isExpanded("b", defaults, emptyList()))
        assertFalse(PcListLogic.isExpanded("b", defaults, listOf("b"))) // owner closed it
        assertFalse(PcListLogic.isExpanded("a", defaults, emptyList()))
        assertTrue(PcListLogic.isExpanded("a", defaults, listOf("a"))) // owner opened it
        // A PC that starts needing attention later opens by itself even though the owner never touched it.
        assertTrue(PcListLogic.isExpanded("c", defaults + "c", emptyList()))
    }

    @Test
    fun expandAllAndCollapseAll() {
        val items = listOf(pc("a"), pc("b", state = PcState.TamperAlert), pc("c"))
        val defaults = PcListLogic.defaultExpanded(items)
        val opened = PcListLogic.flipTo(true, items, defaults, emptyList())
        assertTrue(items.all { PcListLogic.isExpanded(it.pcId, defaults, opened) })
        val closed = PcListLogic.flipTo(false, items, defaults, opened)
        assertTrue(items.none { PcListLogic.isExpanded(it.pcId, defaults, closed) })
        // Idempotent.
        assertEquals(opened.toSet(), PcListLogic.flipTo(true, items, defaults, opened).toSet())
    }

    @Test
    fun headline() {
        assertEquals("", PcListLogic.headline(emptyList()))
        assertEquals("1 PC, all well", PcListLogic.headline(listOf(pc("a"))))
        assertEquals("3 PCs, all well", PcListLogic.headline(listOf(pc("a"), pc("b"), pc("c"))))
        assertEquals("3 PCs, 1 needs attention", PcListLogic.headline(listOf(pc("a"), pc("b", state = PcState.TamperAlert), pc("c"))))
        assertEquals("3 PCs, 2 need attention", PcListLogic.headline(listOf(pc("a", pending = true), pc("b", state = PcState.TamperAlert), pc("c"))))
    }
}
