package dev.phonegate.ui.history

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.phonegate.data.Outcome
import dev.phonegate.ui.components.Gap
import dev.phonegate.ui.components.GridRow
import dev.phonegate.ui.components.OutcomeStamp
import dev.phonegate.ui.components.RecordSheet
import dev.phonegate.ui.components.ScreenTitle
import dev.phonegate.ui.theme.Desk

data class HistoryItem(
    val key: String,
    val outcome: Outcome,
    val pcName: String,
    val account: String,
    val kind: String,
    val time: String,
    val detail: String?,
)

/** The desk logbook: one carbon record per attempt, stamped with its outcome (icon + text). */
@Composable
fun HistoryScreen(items: List<HistoryItem>, modifier: Modifier = Modifier) {
    LazyColumn(
        modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        item {
            ScreenTitle("Logbook", Modifier.widthIn(max = 640.dp).fillMaxWidth())
            Gap(2.dp)
            Text(
                "Sign-in attempts from the last 90 days.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.widthIn(max = 640.dp).fillMaxWidth(),
            )
        }
        if (items.isEmpty()) {
            item {
                RecordSheet(Modifier.widthIn(max = 640.dp).fillMaxWidth()) {
                    Text("Nothing logged yet", style = MaterialTheme.typography.titleLarge)
                    Gap(6.dp)
                    Text("Every approval, denial, expired request and recovery-code use will be recorded here.", style = MaterialTheme.typography.bodyLarge)
                }
            }
        }
        items(items, key = { it.key }) { h ->
            val tint = if (h.outcome == Outcome.NotMe) Desk.colors.pinkCopy else Desk.colors.record
            val tintText = if (h.outcome == Outcome.NotMe) Desk.colors.onPinkCopy else Desk.colors.onRecord
            RecordSheet(
                Modifier
                    .widthIn(max = 640.dp)
                    .fillMaxWidth()
                    .semantics(mergeDescendants = true) {
                        contentDescription = listOfNotNull(h.outcome.stamp.lowercase(), h.pcName, h.account.ifBlank { null }, h.kind.ifBlank { null }, h.time, h.detail).joinToString(", ")
                    },
                tint = tint,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutcomeStamp(h.outcome)
                    Text(
                        h.time,
                        style = Desk.type.codeSmall,
                        color = tintText,
                        modifier = Modifier.weight(1f).widthIn(min = 0.dp),
                        textAlign = androidx.compose.ui.text.style.TextAlign.End,
                    )
                }
                Gap(6.dp)
                GridRow("PC", h.pcName, valueColor = tintText)
                if (h.account.isNotBlank()) GridRow("Account", h.account, valueColor = tintText)
                if (h.kind.isNotBlank()) GridRow("Sign-in", h.kind, valueColor = tintText)
                if (!h.detail.isNullOrBlank()) GridRow("Note", h.detail, valueColor = tintText)
            }
        }
    }
}
