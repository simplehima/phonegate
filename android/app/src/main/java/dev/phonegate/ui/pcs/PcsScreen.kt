package dev.phonegate.ui.pcs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import dev.phonegate.protocol.PcState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.phonegate.ui.components.Gap
import dev.phonegate.ui.components.GridRow
import dev.phonegate.ui.components.PerforatedRule
import dev.phonegate.ui.components.RecordSheet
import dev.phonegate.ui.components.ScreenTitle
import dev.phonegate.ui.theme.Desk

enum class PcStatus { Connected, Connecting, Offline, NeedsRepair }

/** The alert of the current episode, as shown on the card and in the detail sheet. */
data class AlertInfo(val message: String, val raised: String, val seen: String?)

data class PcItem(
    val pcId: String,
    val name: String,
    val relay: String,
    val paired: String,
    val keys: String,
    val status: PcStatus,
    val repairReason: String? = null,
    val state: PcState = PcState.Ok,
    /** For example "4 min ago", or "No report yet". */
    val lastReport: String = "",
    val bitlockerOff: Boolean = false,
    val netlogonBlocked: Boolean = false,
    /** Non-null only while the PC is in a tamper-alert episode. */
    val alert: AlertInfo? = null,
    /** A "turn off protection" request this phone sent that the PC has not confirmed yet. */
    val disablePending: Boolean = false,
)

data class Banner(val text: String, val action: String, val onAction: () -> Unit)

@Composable
fun PcsScreen(
    items: List<PcItem>,
    banners: List<Banner>,
    onAdd: () -> Unit,
    onRename: (String, String) -> Unit,
    onUnpair: (String) -> Unit,
    modifier: Modifier = Modifier,
    onMarkSeen: (String) -> Unit = {},
    openAlertFor: String? = null,
    onOpenHandled: () -> Unit = {},
    onTurnOff: (String) -> Unit = {},
    updateChecks: Boolean = true,
    onUpdateChecks: (Boolean) -> Unit = {},
) {
    var renaming by rememberSaveable { mutableStateOf<String?>(null) }
    var unpairing by rememberSaveable { mutableStateOf<String?>(null) }
    var alertFor by rememberSaveable { mutableStateOf<String?>(null) }
    var turningOff by rememberSaveable { mutableStateOf<String?>(null) }
    // One-shot hand-off from a tapped tamper notification.
    LaunchedEffect(openAlertFor) {
        if (openAlertFor != null) {
            alertFor = openAlertFor
            onOpenHandled()
        }
    }

    Scaffold(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.background,
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onAdd,
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("Add a PC") },
                containerColor = Desk.colors.ink,
                contentColor = Desk.colors.onInk,
            )
        },
    ) { pad ->
        LazyColumn(
            Modifier.fillMaxSize().padding(pad),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 96.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            item { ScreenTitle("Paired PCs", Modifier.widthIn(max = 640.dp).fillMaxWidth()) }
            items(banners) { b ->
                RecordSheet(Modifier.widthIn(max = 640.dp).fillMaxWidth(), tint = Desk.colors.slip) {
                    Text(b.text, style = MaterialTheme.typography.bodyMedium, color = Desk.colors.onSlip)
                    Gap(8.dp)
                    Button(onClick = b.onAction, modifier = Modifier.heightIn(min = 48.dp)) { Text(b.action) }
                }
            }
            if (items.isEmpty()) {
                item {
                    RecordSheet(Modifier.widthIn(max = 640.dp).fillMaxWidth()) {
                        Text("No PCs yet", style = MaterialTheme.typography.titleLarge)
                        Gap(6.dp)
                        Text(
                            "Install PhoneGate on your Windows PC, choose Pair a phone there, then tap Add a PC and scan its QR code.",
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                }
            }
            items(items, key = { it.pcId }) { pc ->
                PcRecord(
                    pc,
                    onRename = { renaming = pc.pcId },
                    onUnpair = { unpairing = pc.pcId },
                    onViewAlert = { alertFor = pc.pcId },
                    onTurnOff = { turningOff = pc.pcId },
                    modifier = Modifier.widthIn(max = 640.dp).fillMaxWidth(),
                )
            }
            item {
                Row(
                    Modifier.widthIn(max = 640.dp).fillMaxWidth().heightIn(min = 48.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f).padding(end = 12.dp)) {
                        Text("Check for updates", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            "One request to GitHub when the app opens. Nothing is installed for you.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Switch(checked = updateChecks, onCheckedChange = onUpdateChecks)
                }
            }
        }
    }

    turningOff?.let { id ->
        val pc = items.firstOrNull { it.pcId == id }
        AlertDialog(
            onDismissRequest = { turningOff = null },
            title = { Text("Turn off protection on ${pc?.name ?: "this PC"}?") },
            text = {
                Text(
                    "You'll confirm with your fingerprint. After that the PC signs in with just its Windows password until you turn protection back on at the PC.",
                )
            },
            confirmButton = {
                TextButton(onClick = { onTurnOff(id); turningOff = null }) { Text("Continue", color = Desk.colors.denied) }
            },
            dismissButton = { TextButton(onClick = { turningOff = null }) { Text("Keep protection on") } },
        )
    }

    renaming?.let { id ->
        val pc = items.firstOrNull { it.pcId == id }
        if (pc == null) {
            renaming = null
        } else {
            var name by rememberSaveable(id) { mutableStateOf(pc.name) }
            AlertDialog(
                onDismissRequest = { renaming = null },
                title = { Text("Rename PC") },
                text = {
                    OutlinedTextField(value = name, onValueChange = { name = it.take(64) }, label = { Text("Name on this phone") }, singleLine = true)
                },
                confirmButton = {
                    TextButton(onClick = { onRename(id, name); renaming = null }, enabled = name.isNotBlank()) { Text("Save") }
                },
                dismissButton = { TextButton(onClick = { renaming = null }) { Text("Cancel") } },
            )
        }
    }
    alertFor?.let { id ->
        val pc = items.firstOrNull { it.pcId == id }
        val alert = pc?.alert
        if (alert == null) {
            alertFor = null
        } else {
            AlertSheet(pc, alert, onMarkSeen = { onMarkSeen(id) }, onDismiss = { alertFor = null })
        }
    }
    unpairing?.let { id ->
        val pc = items.firstOrNull { it.pcId == id }
        AlertDialog(
            onDismissRequest = { unpairing = null },
            title = { Text("Unpair ${pc?.name ?: "this PC"}?") },
            text = {
                Text(
                    "This phone deletes its keys for the PC and tells the PC. If protection is on, the PC then needs a recovery code to sign in until you pair again.",
                )
            },
            confirmButton = {
                TextButton(onClick = { onUnpair(id); unpairing = null }) { Text("Unpair", color = Desk.colors.denied) }
            },
            dismissButton = { TextButton(onClick = { unpairing = null }) { Text("Keep") } },
        )
    }
}

@Composable
private fun PcRecord(pc: PcItem, onRename: () -> Unit, onUnpair: () -> Unit, onViewAlert: () -> Unit, onTurnOff: () -> Unit, modifier: Modifier) {
    val c = Desk.colors
    val tamper = pc.state == PcState.TamperAlert
    // On the pink carbon copy every line uses the pink ink so contrast holds in both themes.
    val ink = if (tamper) c.onPinkCopy else c.onRecord
    val label = if (tamper) c.onPinkCopy else c.recordLabel
    RecordSheet(modifier, tint = if (tamper) c.pinkCopy else c.record) {
        Row(verticalAlignment = Alignment.Top) {
            Text(pc.name, style = MaterialTheme.typography.titleLarge, color = ink, modifier = Modifier.weight(1f).padding(end = 12.dp))
            HealthStamp(pc.state)
        }
        val alert = pc.alert
        if (alert != null) {
            Gap(10.dp)
            Text(alert.message, style = MaterialTheme.typography.bodyLarge, color = ink)
            Gap(8.dp)
            Button(
                onClick = onViewAlert,
                modifier = Modifier.heightIn(min = 48.dp),
                shape = MaterialTheme.shapes.small,
                colors = ButtonDefaults.buttonColors(containerColor = c.onPinkCopy, contentColor = c.pinkCopy),
            ) { Text(if (alert.seen == null) "View alert" else "View alert (seen)") }
        }
        Gap(8.dp)
        PerforatedRule(color = if (tamper) c.onPinkCopy.copy(alpha = 0.4f) else MaterialTheme.colorScheme.outlineVariant, thickness = 1.dp)
        Gap(6.dp)
        val (linkText, linkColor) = when (pc.status) {
            PcStatus.Connected -> "Listening for sign-ins" to (if (tamper) ink else c.approved)
            PcStatus.Connecting -> "Connecting to the relay" to ink
            PcStatus.Offline -> "Relay unreachable, retrying. Offline codes still work." to (if (tamper) ink else c.denied)
            PcStatus.NeedsRepair -> "Needs pairing again: ${pc.repairReason ?: "keys unavailable"}" to (if (tamper) ink else c.denied)
        }
        GridRow("Last report", pc.lastReport, valueColor = ink, labelColor = label)
        GridRow("Link", linkText, valueColor = linkColor, labelColor = label)
        GridRow("Relay", pc.relay, mono = true, valueColor = ink, labelColor = label)
        GridRow("Paired", pc.paired, valueColor = ink, labelColor = label)
        GridRow("Keys", pc.keys, valueColor = ink, labelColor = label)
        if (pc.bitlockerOff || pc.netlogonBlocked) Gap(6.dp)
        if (pc.bitlockerOff) {
            WarningLine(Icons.Filled.Warning, "Drive encryption is off. Anyone with the disk can read it without signing in.", if (tamper) ink else c.denied)
        }
        if (pc.netlogonBlocked) {
            WarningLine(Icons.Filled.Info, "Network sign-ins blocked. File shares and remote tools that sign in over the network won't work.", ink)
        }
        if (pc.disablePending) {
            Gap(6.dp)
            WarningLine(Icons.Filled.Info, "Turn-off request sent. Waiting for the PC to confirm.", ink)
        }
        Gap(4.dp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (pc.status != PcStatus.NeedsRepair && !pc.disablePending) {
                TextButton(onClick = onTurnOff, modifier = Modifier.heightIn(min = 48.dp)) { Text("Turn off protection", color = if (tamper) ink else c.denied) }
            }
            TextButton(onClick = onRename, modifier = Modifier.heightIn(min = 48.dp)) { Text("Rename", color = if (tamper) ink else c.ink) }
            TextButton(onClick = onUnpair, modifier = Modifier.heightIn(min = 48.dp)) { Text("Unpair", color = if (tamper) ink else c.denied) }
        }
    }
}

@Composable
private fun WarningLine(icon: ImageVector, text: String, color: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp).semantics(mergeDescendants = true) {}, verticalAlignment = Alignment.Top) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp).padding(top = 1.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, color = color)
    }
}

/** PC state as a bordered mark: icon + text, never color alone. */
@Composable
fun HealthStamp(state: PcState, modifier: Modifier = Modifier) {
    val c = Desk.colors
    val (icon, text, color) = when (state) {
        PcState.Ok -> Triple(Icons.Filled.Check, "OK", c.approved)
        PcState.Asleep -> Triple(Icons.Filled.Info, "ASLEEP", c.neutralStamp)
        PcState.Off -> Triple(Icons.Filled.Info, "OFF", c.neutralStamp)
        PcState.StoppedReporting -> Triple(Icons.Filled.Warning, "STOPPED REPORTING", c.denied)
        PcState.TamperAlert -> Triple(Icons.Filled.Warning, "TAMPER ALERT", c.onPinkCopy)
    }
    Row(
        modifier
            .border(if (state == PcState.TamperAlert) 3.dp else 2.dp, color, MaterialTheme.shapes.small)
            .padding(horizontal = 8.dp, vertical = 4.dp)
            .semantics(mergeDescendants = true) { contentDescription = "State: " + text.lowercase() },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(4.dp))
        Text(text, style = MaterialTheme.typography.labelMedium, color = color)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AlertSheet(pc: PcItem, alert: AlertInfo, onMarkSeen: () -> Unit, onDismiss: () -> Unit) {
    val c = Desk.colors
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = c.pinkCopy, contentColor = c.onPinkCopy) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 24.dp)) {
            HealthStamp(PcState.TamperAlert)
            Gap(10.dp)
            Text(pc.name, style = MaterialTheme.typography.headlineSmall, color = c.onPinkCopy, modifier = Modifier.semantics { heading() })
            Gap(8.dp)
            Text(alert.message, style = MaterialTheme.typography.bodyLarge, color = c.onPinkCopy)
            Gap(10.dp)
            GridRow("Raised", alert.raised, valueColor = c.onPinkCopy, labelColor = c.onPinkCopy)
            if (alert.seen != null) GridRow("Seen", alert.seen, valueColor = c.onPinkCopy, labelColor = c.onPinkCopy)
            Gap(8.dp)
            Text(
                "The alert stays until ${pc.name} reports healthy again. If you didn't expect this, check the PC in person and use a recovery code if needed.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.onPinkCopy,
            )
            Gap(16.dp)
            if (alert.seen == null) {
                Button(
                    onClick = onMarkSeen,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                    shape = MaterialTheme.shapes.small,
                colors = ButtonDefaults.buttonColors(containerColor = c.onPinkCopy, contentColor = c.pinkCopy),
                ) { Text("Mark as seen") }
                Gap(8.dp)
            }
            OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp), shape = MaterialTheme.shapes.small) { Text("Close", color = c.onPinkCopy) }
        }
    }
}
