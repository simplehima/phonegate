package dev.phonegate.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.phonegate.data.Outcome
import dev.phonegate.ui.theme.Desk

/** The live visitor slip: a canary carbonless sheet with a darker perforated top edge. */
@Composable
fun VisitorSlip(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val c = Desk.colors
    Surface(
        modifier = modifier,
        color = c.slip,
        contentColor = c.onSlip,
        shape = MaterialTheme.shapes.extraSmall,
        border = BorderStroke(1.dp, c.slipEdge),
        shadowElevation = 2.dp,
    ) {
        Column(Modifier.padding(horizontal = 20.dp, vertical = 16.dp), content = content)
    }
}

/** A white record sheet (paired PCs, history entries, pairing steps). */
@Composable
fun RecordSheet(modifier: Modifier = Modifier, tint: Color = Desk.colors.record, content: @Composable ColumnScope.() -> Unit) {
    val c = Desk.colors
    Surface(
        modifier = modifier,
        color = tint,
        contentColor = c.onRecord,
        shape = MaterialTheme.shapes.extraSmall,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 14.dp), content = content)
    }
}

/** Small tracked caps label in graphite, as printed on the form. */
@Composable
fun FormLabel(text: String, modifier: Modifier = Modifier, color: Color = Desk.colors.slipLabel) {
    Text(text.uppercase(), modifier = modifier, style = MaterialTheme.typography.labelSmall, color = color)
}

/** A dashed perforation rule. */
@Composable
fun PerforatedRule(modifier: Modifier = Modifier, color: Color = Desk.colors.slipEdge, thickness: Dp = 1.5.dp) {
    Canvas(modifier.fillMaxWidth().height(thickness)) {
        drawLine(
            color = color,
            start = androidx.compose.ui.geometry.Offset(0f, size.height / 2),
            end = androidx.compose.ui.geometry.Offset(size.width, size.height / 2),
            strokeWidth = size.height,
            pathEffect = PathEffect.dashPathEffect(floatArrayOf(10f, 7f)),
        )
    }
}

/**
 * The countdown: a perforation that tears away from the right as time runs out. The torn part
 * stays as a faint trace so the full length remains readable.
 */
@Composable
fun PerforationCountdown(fraction: Float, secondsLeft: Int, modifier: Modifier = Modifier) {
    val c = Desk.colors
    Row(
        modifier.clearAndSetSemantics { contentDescription = "$secondsLeft seconds left" },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Canvas(Modifier.weight(1f).height(10.dp)) {
            val y = size.height / 2
            val end = size.width * fraction.coerceIn(0f, 1f)
            drawLine(
                color = c.slipEdge.copy(alpha = 0.35f),
                start = androidx.compose.ui.geometry.Offset(0f, y),
                end = androidx.compose.ui.geometry.Offset(size.width, y),
                strokeWidth = 2.dp.toPx(),
                pathEffect = PathEffect.dashPathEffect(floatArrayOf(6.dp.toPx(), 5.dp.toPx())),
            )
            drawLine(
                color = c.onSlip,
                start = androidx.compose.ui.geometry.Offset(0f, y),
                end = androidx.compose.ui.geometry.Offset(end, y),
                strokeWidth = 6.dp.toPx(),
                cap = StrokeCap.Butt,
                pathEffect = PathEffect.dashPathEffect(floatArrayOf(6.dp.toPx(), 5.dp.toPx())),
            )
        }
        Spacer(Modifier.width(12.dp))
        Text("${secondsLeft}s", style = Desk.type.codeSmall, color = c.onSlip)
    }
}

/** A ruled form field: tracked caps label, ink value, dashed rule beneath. */
@Composable
fun RuledField(label: String, value: String, modifier: Modifier = Modifier, mono: Boolean = false) {
    val c = Desk.colors
    Column(modifier.fillMaxWidth().semantics(mergeDescendants = true) {}.padding(vertical = 4.dp)) {
        FormLabel(label)
        Spacer(Modifier.height(2.dp))
        Text(value, style = if (mono) Desk.type.codeSmall.copy(fontSize = Desk.type.value.fontSize) else Desk.type.value, color = c.onSlip)
        Spacer(Modifier.height(4.dp))
        PerforatedRule(color = c.slipEdge.copy(alpha = 0.8f), thickness = 1.dp)
    }
}

/** One row of the ruled label grid used for every PC and history record. */
@Composable
fun GridRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    mono: Boolean = false,
    valueColor: Color = Desk.colors.onRecord,
    labelColor: Color = Desk.colors.recordLabel,
) {
    val c = Desk.colors
    Row(
        modifier.fillMaxWidth().heightIn(min = 32.dp).semantics(mergeDescendants = true) {}.padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top,
    ) {
        FormLabel(label, Modifier.width(104.dp).padding(top = 3.dp), color = labelColor)
        Text(
            value,
            modifier = Modifier.weight(1f),
            style = if (mono) Desk.type.codeSmall else MaterialTheme.typography.bodyMedium,
            color = valueColor,
        )
    }
}

enum class StampKind { Deny, Approve }

private val StampPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp)

/** Stamp text stays on one line; it steps down in size instead of clipping at large font scales. */
@Composable
private fun StampLabel(text: String, color: Color) {
    val style = Desk.type.stamp
    BasicText(
        text,
        style = style.copy(color = color),
        maxLines = 1,
        autoSize = TextAutoSize.StepBased(minFontSize = 6.sp, maxFontSize = style.fontSize, stepSize = 0.5.sp),
    )
}

/** The two decision stamps. Equal size by construction: callers give both the same weight. */
@Composable
fun DecisionStamp(text: String, kind: StampKind, enabled: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val c = Desk.colors
    val shape = MaterialTheme.shapes.small
    when (kind) {
        StampKind.Deny -> OutlinedButton(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.heightIn(min = 60.dp),
            shape = shape,
            contentPadding = StampPadding,
            border = BorderStroke(2.5.dp, c.deniedOnSlip),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = c.deniedOnSlip, containerColor = Color.Transparent),
        ) {
            Icon(Icons.Filled.Close, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(6.dp))
            StampLabel(text, c.deniedOnSlip)
        }
        StampKind.Approve -> Button(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.heightIn(min = 60.dp),
            shape = shape,
            contentPadding = StampPadding,
            border = BorderStroke(2.5.dp, if (enabled) c.ink else c.ink.copy(alpha = 0.35f)),
            colors = ButtonDefaults.buttonColors(
                containerColor = c.ink,
                contentColor = c.onInk,
                disabledContainerColor = c.ink.copy(alpha = 0.16f),
                disabledContentColor = c.onSlip.copy(alpha = 0.62f),
            ),
        ) {
            Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(6.dp))
            StampLabel(text, if (enabled) c.onInk else c.onSlip.copy(alpha = 0.62f))
        }
    }
}

/** Full-width pink carbon-copy action for "This wasn't me". */
@Composable
fun NotMeButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val c = Desk.colors
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth().heightIn(min = 56.dp),
        shape = MaterialTheme.shapes.small,
        border = BorderStroke(1.5.dp, c.onPinkCopy.copy(alpha = 0.55f)),
        colors = ButtonDefaults.buttonColors(containerColor = c.pinkCopy, contentColor = c.onPinkCopy),
    ) {
        Icon(Icons.Filled.Warning, contentDescription = null, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.titleMedium)
    }
}

fun outcomeIcon(o: Outcome): ImageVector = when (o) {
    Outcome.Approved, Outcome.Paired -> Icons.Filled.Check
    Outcome.Denied, Outcome.Unpaired -> Icons.Filled.Close
    Outcome.NotMe, Outcome.WrongNumber, Outcome.Error -> Icons.Filled.Warning
    Outcome.Expired -> Icons.Filled.Refresh
    Outcome.RecoveryCode, Outcome.OfflineCode -> Icons.Filled.Lock
    Outcome.Notice, Outcome.PcEvent -> Icons.Filled.Info
    Outcome.Disabled -> Icons.Filled.Warning
    Outcome.Tamper -> Icons.Filled.Warning
}

@Composable
fun outcomeColor(o: Outcome): Color {
    val c = Desk.colors
    return when (o) {
        Outcome.Approved, Outcome.Paired -> c.approved
        Outcome.Denied, Outcome.Error, Outcome.Tamper, Outcome.Disabled -> c.denied
        Outcome.NotMe, Outcome.WrongNumber -> c.onPinkCopy
        else -> c.neutralStamp
    }
}

/** A bordered uppercase outcome mark: icon + text, never color alone. */
@Composable
fun OutcomeStamp(outcome: Outcome, modifier: Modifier = Modifier, large: Boolean = false) {
    val c = Desk.colors
    val color = outcomeColor(outcome)
    val bg = if (outcome == Outcome.NotMe || outcome == Outcome.WrongNumber) c.pinkCopy else Color.Transparent
    Row(
        modifier
            .background(bg, MaterialTheme.shapes.small)
            .border(if (large) 3.dp else 2.dp, color, MaterialTheme.shapes.small)
            .padding(horizontal = if (large) 14.dp else 8.dp, vertical = if (large) 8.dp else 3.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        Icon(outcomeIcon(outcome), contentDescription = null, tint = color, modifier = Modifier.size(if (large) 24.dp else 16.dp))
        Spacer(Modifier.width(if (large) 8.dp else 4.dp))
        Text(
            outcome.stamp,
            color = color,
            style = if (large) Desk.type.stamp else MaterialTheme.typography.labelMedium,
            textAlign = TextAlign.Center,
        )
    }
}

/** Screen heading in Archivo, marked as a heading for TalkBack. */
@Composable
fun ScreenTitle(text: String, modifier: Modifier = Modifier) {
    Text(text, modifier = modifier.semantics { heading() }, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.onBackground)
}

@Composable
fun Gap(h: Dp) = Spacer(Modifier.height(h))

@Composable
fun CenterBox(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Box(modifier, contentAlignment = Alignment.Center) { content() }
}
