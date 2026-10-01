package dev.phonegate.ui.pcs

import dev.phonegate.protocol.PcState

/**
 * Pure rules for the PCs list, kept out of Compose so they can be unit tested.
 *
 * With one PC the full card is always shown. With several, only the ones that need the owner
 * (a tamper alert, a PC that stopped reporting, one that needs pairing again, or a pending
 * turn-off) start expanded and sort first; the rest are one-line rows the owner can open.
 */
object PcListLogic {
    /** True when this PC should get the owner's eyes first. */
    fun needsAttention(pc: PcItem): Boolean =
        pc.alert != null ||
            pc.state == PcState.TamperAlert ||
            pc.state == PcState.StoppedReporting ||
            pc.status == PcStatus.NeedsRepair ||
            pc.disablePending

    /** Attention first, then by name (case-insensitive), stable. */
    fun ordered(items: List<PcItem>): List<PcItem> =
        items.sortedWith(compareBy<PcItem> { !needsAttention(it) }.thenBy { it.name.lowercase() })

    /** Which cards start open: all of them for a single PC, otherwise only those needing attention. */
    fun defaultExpanded(items: List<PcItem>): Set<String> =
        if (items.size <= 1) items.map { it.pcId }.toSet() else items.filter(::needsAttention).map { it.pcId }.toSet()

    /**
     * Ids whose open/closed state the owner has flipped away from the default. Stored instead of
     * the open set so that a PC which newly needs attention opens by itself.
     */
    fun isExpanded(pcId: String, defaults: Set<String>, flipped: Collection<String>): Boolean =
        (pcId in defaults) != (pcId in flipped)

    /** "Expand all" / "Collapse all": flips whichever PCs are not already in the wanted state. */
    fun flipTo(expand: Boolean, items: List<PcItem>, defaults: Set<String>, flipped: Collection<String>): List<String> =
        items.map { it.pcId }.filter { isExpanded(it, defaults, flipped) != expand }.let { toFlip ->
            val keep = flipped.filter { it !in toFlip }
            keep + toFlip.filter { it !in flipped }
        }

    /** One line for the list header, for example "4 PCs, 1 needs attention". */
    fun headline(items: List<PcItem>): String {
        if (items.isEmpty()) return ""
        val n = items.size
        val attention = items.count(::needsAttention)
        val pcs = if (n == 1) "1 PC" else "$n PCs"
        return when (attention) {
            0 -> "$pcs, all well"
            1 -> "$pcs, 1 needs attention"
            else -> "$pcs, $attention need attention"
        }
    }
}
