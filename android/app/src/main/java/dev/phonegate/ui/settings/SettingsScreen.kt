package dev.phonegate.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.phonegate.ui.components.Gap
import dev.phonegate.ui.components.GridRow
import dev.phonegate.ui.components.RecordSheet
import dev.phonegate.ui.components.ScreenTitle
import dev.phonegate.ui.theme.Desk

/** One Android permission PhoneGate uses, with why, and how to grant it. */
data class PermissionRow(val title: String, val why: String, val granted: Boolean, val onGrant: () -> Unit)

/** State of the "check for updates" action. */
sealed class UpdateUi {
    data object Idle : UpdateUi()
    data object Checking : UpdateUi()
    data class UpToDate(val tag: String) : UpdateUi()
    data class Available(val tag: String) : UpdateUi()
    data object Failed : UpdateUi()
}

/** Links shown in Settings. Fixed here; nothing the PC or relay sends can change them. */
data class SettingsLinks(val repo: String, val releases: String, val license: String, val security: String, val issues: String)

@Composable
fun SettingsScreen(
    versionName: String,
    versionCode: Long,
    updateChecks: Boolean,
    onUpdateChecks: (Boolean) -> Unit,
    update: UpdateUi,
    onCheckNow: () -> Unit,
    permissions: List<PermissionRow>,
    links: SettingsLinks,
    onOpenLink: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ScreenTitle("Settings", Modifier.widthIn(max = 640.dp).fillMaxWidth())

        // About ---------------------------------------------------------------------------------
        Section("About PhoneGate") {
            GridRow("Version", "$versionName (build $versionCode)")
            GridRow("Licence", "Apache License 2.0")
            GridRow("Source", "github.com/simplehima/phonegate")
            Gap(6.dp)
            Text(
                "PhoneGate is free, open source software. Nothing in this app is secret: the keys are made on this phone and never leave it.",
                style = MaterialTheme.typography.bodyMedium,
                color = Desk.colors.onRecord,
            )
        }

        // Updates -------------------------------------------------------------------------------
        Section("Updates") {
            Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f).padding(end = 12.dp)) {
                    Text("Check when the app opens", style = MaterialTheme.typography.bodyLarge, color = Desk.colors.onRecord)
                    Text(
                        "One request to GitHub for the latest release number. Nothing is installed for you.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Desk.colors.recordLabel,
                    )
                }
                Switch(checked = updateChecks, onCheckedChange = onUpdateChecks)
            }
            Gap(8.dp)
            Row(Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite }, verticalAlignment = Alignment.CenterVertically) {
                when (update) {
                    UpdateUi.Checking -> {
                        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = Desk.colors.onRecord)
                        Text("  Checking GitHub...", style = MaterialTheme.typography.bodyMedium, color = Desk.colors.onRecord)
                    }
                    is UpdateUi.UpToDate -> {
                        Icon(Icons.Filled.Check, contentDescription = null, tint = Desk.colors.approved, modifier = Modifier.size(20.dp))
                        Text("  You have the latest version (${update.tag.removePrefix("v")}).", style = MaterialTheme.typography.bodyMedium, color = Desk.colors.onRecord)
                    }
                    is UpdateUi.Available -> Text(
                        "PhoneGate ${update.tag.removePrefix("v")} is available.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = Desk.colors.onRecord,
                    )
                    UpdateUi.Failed -> Text(
                        "Couldn't reach GitHub. Check your connection and try again.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = Desk.colors.denied,
                    )
                    UpdateUi.Idle -> Unit
                }
            }
            Gap(8.dp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onCheckNow, enabled = update != UpdateUi.Checking, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text("Check now", maxLines = 1)
                }
                if (update is UpdateUi.Available) {
                    Button(onClick = { onOpenLink(links.releases) }, modifier = Modifier.heightIn(min = 48.dp)) { Text("Download", maxLines = 1) }
                }
            }
        }

        // Permissions ---------------------------------------------------------------------------
        Section("Permissions") {
            permissions.forEachIndexed { i, p ->
                if (i > 0) Gap(10.dp)
                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f).padding(end = 12.dp)) {
                        Text(p.title, style = MaterialTheme.typography.bodyLarge, color = Desk.colors.onRecord)
                        Text(p.why, style = MaterialTheme.typography.bodySmall, color = Desk.colors.recordLabel)
                    }
                    if (p.granted) {
                        Icon(Icons.Filled.Check, contentDescription = null, tint = Desk.colors.approved, modifier = Modifier.size(18.dp))
                        Text(" Allowed", style = MaterialTheme.typography.labelLarge, color = Desk.colors.approved, maxLines = 1)
                    } else {
                        Button(onClick = p.onGrant, modifier = Modifier.heightIn(min = 48.dp)) { Text("Allow", maxLines = 1) }
                    }
                }
            }
        }

        // Links and licence ---------------------------------------------------------------------
        Section("Help and licence") {
            LinkRow("Project page on GitHub") { onOpenLink(links.repo) }
            LinkRow("Release notes and downloads") { onOpenLink(links.releases) }
            LinkRow("Licence (Apache 2.0)") { onOpenLink(links.license) }
            LinkRow("Report a bug") { onOpenLink(links.issues) }
            LinkRow("Report a security problem privately") { onOpenLink(links.security) }
            Gap(6.dp)
            Text(
                "Includes Archivo and JetBrains Mono (SIL Open Font License), ZXing, OkHttp, CameraX and Jetpack Compose (Apache 2.0).",
                style = MaterialTheme.typography.bodySmall,
                color = Desk.colors.recordLabel,
            )
        }
        Gap(8.dp)
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    RecordSheet(Modifier.widthIn(max = 640.dp).fillMaxWidth()) {
        Text(title, style = MaterialTheme.typography.titleLarge, color = Desk.colors.onRecord, modifier = Modifier.semantics { heading() })
        Gap(8.dp)
        content()
    }
}

@Composable
private fun LinkRow(text: String, onClick: () -> Unit) {
    TextButton(onClick = onClick, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
        Text(text, color = Desk.colors.ink, modifier = Modifier.fillMaxWidth())
    }
}
