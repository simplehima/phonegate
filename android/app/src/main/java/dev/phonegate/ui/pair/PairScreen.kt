package dev.phonegate.ui.pair

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.phonegate.data.Outcome
import dev.phonegate.ui.components.FormLabel
import dev.phonegate.ui.components.Gap
import dev.phonegate.ui.components.OutcomeStamp
import dev.phonegate.ui.components.QrScanOrPaste
import dev.phonegate.ui.components.RecordSheet
import dev.phonegate.ui.components.VisitorSlip
import dev.phonegate.ui.theme.Desk

/** Issuing a desk pass: scan, sign, compare the code, done. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairScreen(
    state: PairState,
    onScanned: (String) -> Unit,
    onSign: () -> Unit,
    onConfirm: () -> Unit,
    onReject: () -> Unit,
    onRestart: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
) {
    BackHandler(onBack = onBack)
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Add a PC") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
            )
        },
    ) { pad ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(Modifier.widthIn(max = 560.dp).fillMaxWidth()) {
                when (state) {
                    PairState.Scan -> {
                        Text(
                            "On the PC, open PhoneGate and choose Pair a phone. Point the camera at the QR code it shows.",
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Gap(16.dp)
                        QrScanOrPaste(
                            pasteLabel = "No camera? Paste the pairing link",
                            pasteHint = "phonegate://pair?...",
                            scanDescription = "Camera viewfinder for the pairing QR code",
                            onResult = onScanned,
                        )
                    }
                    is PairState.Working -> RecordSheet(Modifier.fillMaxWidth()) {
                        Text(state.step, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                        Gap(12.dp)
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                        Gap(12.dp)
                        Text("Keep the PC's pairing screen open.", style = MaterialTheme.typography.bodyMedium)
                    }
                    is PairState.NeedSign -> RecordSheet(Modifier.fillMaxWidth()) {
                        FormLabel("PC", color = Desk.colors.recordLabel)
                        Text(state.pcName, style = MaterialTheme.typography.headlineSmall)
                        Gap(8.dp)
                        Text(
                            "The PC checked out against its QR code. Confirm it's you to create this phone's approval key for it.",
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Gap(16.dp)
                        Button(onClick = onSign, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
                            Text("Continue with fingerprint")
                        }
                        Gap(8.dp)
                        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("Cancel") }
                    }
                    is PairState.Sas -> VisitorSlip(Modifier.fillMaxWidth()) {
                        FormLabel("Pairing code")
                        Gap(8.dp)
                        Text(
                            state.code.chunked(3).joinToString(" "),
                            style = Desk.type.code,
                            color = Desk.colors.onSlip,
                            modifier = Modifier.semantics { contentDescription = "Pairing code " + state.code.toCharArray().joinToString(" ") },
                        )
                        Gap(12.dp)
                        Text("Does ${state.pcName} show the same code?", style = MaterialTheme.typography.titleMedium, color = Desk.colors.onSlip)
                        Gap(4.dp)
                        Text("Only confirm if all six digits match.", style = MaterialTheme.typography.bodyMedium, color = Desk.colors.slipLabel)
                        Gap(16.dp)
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            OutlinedButton(onClick = onReject, modifier = Modifier.weight(1f).heightIn(min = 56.dp)) { Text("Doesn't match") }
                            Button(onClick = onConfirm, modifier = Modifier.weight(1f).heightIn(min = 56.dp)) { Text("Codes match") }
                        }
                    }
                    is PairState.WaitingComplete -> RecordSheet(Modifier.fillMaxWidth()) {
                        Text("Now confirm the code on ${state.pcName}", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                        Gap(12.dp)
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                        Gap(12.dp)
                        Text("Pairing finishes once the PC confirms too.", style = MaterialTheme.typography.bodyMedium)
                    }
                    is PairState.Success -> RecordSheet(Modifier.fillMaxWidth()) {
                        OutcomeStamp(Outcome.Paired, large = true)
                        Gap(12.dp)
                        Text("${state.pcName} is paired", style = MaterialTheme.typography.headlineSmall)
                        Gap(8.dp)
                        Text(
                            "Finish setup on the PC: save the recovery codes, then turn protection on. Sign-in requests will appear here.",
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Gap(16.dp)
                        Button(onClick = onDone, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) { Text("Done") }
                    }
                    is PairState.Failed -> RecordSheet(Modifier.fillMaxWidth(), tint = Desk.colors.pinkCopy) {
                        Text("Not paired", style = MaterialTheme.typography.headlineSmall, color = Desk.colors.onPinkCopy)
                        Gap(8.dp)
                        Text(state.reason, style = MaterialTheme.typography.bodyLarge, color = Desk.colors.onPinkCopy, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive })
                        Gap(16.dp)
                        Button(onClick = onRestart, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) { Text("Scan again") }
                    }
                }
            }
        }
    }
}
