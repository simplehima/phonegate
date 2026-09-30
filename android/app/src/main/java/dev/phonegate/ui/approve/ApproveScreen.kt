package dev.phonegate.ui.approve

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.phonegate.R
import dev.phonegate.data.Outcome
import dev.phonegate.ui.components.DecisionStamp
import dev.phonegate.ui.components.FormLabel
import dev.phonegate.ui.components.Gap
import dev.phonegate.ui.components.NotMeButton
import dev.phonegate.ui.components.OutcomeStamp
import dev.phonegate.ui.components.PerforationCountdown
import dev.phonegate.ui.components.RecordSheet
import dev.phonegate.ui.components.RuledField
import dev.phonegate.ui.components.StampKind
import dev.phonegate.ui.components.VisitorSlip
import dev.phonegate.ui.theme.Desk
import kotlinx.coroutines.delay

/** What the slip shows. Deliberately carries no match number: the owner reads it off the PC. */
data class SlipModel(
    val pcName: String,
    val account: String,
    val signInKind: String,
    val time: String,
    val remote: String,
    val deadline: Long,
    val lifetimeMs: Long,
    /** For change-setting requests the account field carries the setting description. */
    val accountLabel: String? = null,
)

sealed class SlipPhase {
    data object Open : SlipPhase()
    data object Working : SlipPhase()
    data class Done(val outcome: Outcome, val message: String) : SlipPhase()
    data object Expired : SlipPhase()
    data object Superseded : SlipPhase()
    data object Gone : SlipPhase()
}

/**
 * The hero screen: one canary visitor slip owning the viewport (direction contract, FIRST
 * VIEWPORT). Deny is never harder than approve: both stamps are equal width, deny needs no
 * number and no biometric.
 */
@Composable
fun ApproveScreen(
    model: SlipModel?,
    phase: SlipPhase,
    now: () -> Long,
    matches: (Long) -> Boolean,
    onApprove: (Long) -> Unit,
    onDeny: () -> Unit,
    onNotMe: (autoAfterWrongNumbers: Boolean) -> Unit,
    onClose: () -> Unit,
    initialDigits: String = "",
    initialWrong: Int = 0,
) {
    Box(
        Modifier
            .fillMaxSize()
            .background(Desk.colors.ground)
            // safeDrawing already includes the IME inset, so no extra imePadding.
            .safeDrawingPadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        when {
            model == null || phase is SlipPhase.Gone -> Closed(
                title = stringResource(R.string.slip_gone_title),
                body = stringResource(R.string.slip_gone_body),
                outcome = null,
                onClose = onClose,
            )
            phase is SlipPhase.Expired -> Closed(
                title = stringResource(R.string.slip_expired_title),
                body = stringResource(R.string.slip_expired_body),
                outcome = Outcome.Expired,
                onClose = onClose,
            )
            phase is SlipPhase.Superseded -> Closed(
                title = stringResource(R.string.slip_superseded_title),
                body = stringResource(R.string.slip_superseded_body),
                outcome = null,
                onClose = onClose,
            )
            phase is SlipPhase.Done -> Closed(
                title = model.pcName,
                body = phase.message,
                outcome = phase.outcome,
                onClose = onClose,
            )
            else -> OpenSlip(model, phase is SlipPhase.Working, now, matches, onApprove, onDeny, onNotMe, initialDigits, initialWrong)
        }
    }
}

@Composable
private fun OpenSlip(
    m: SlipModel,
    working: Boolean,
    now: () -> Long,
    matches: (Long) -> Boolean,
    onApprove: (Long) -> Unit,
    onDeny: () -> Unit,
    onNotMe: (Boolean) -> Unit,
    initialDigits: String,
    initialWrong: Int,
) {
    val c = Desk.colors
    var clock by remember { mutableLongStateOf(now()) }
    LaunchedEffect(m.deadline) {
        while (true) {
            clock = now()
            delay(250)
        }
    }
    val remaining = (m.deadline - clock).coerceAtLeast(0)
    val fraction = if (m.lifetimeMs > 0) remaining.toFloat() / m.lifetimeMs else 0f
    val seconds = ((remaining + 999) / 1000).toInt()

    var field by remember { mutableStateOf(TextFieldValue(initialDigits, TextRange(initialDigits.length))) }
    var wrong by remember { mutableIntStateOf(initialWrong) }
    val focus = remember { FocusRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    LaunchedEffect(Unit) {
        runCatching { focus.requestFocus() }
        keyboard?.show()
    }
    val digits = field.text
    val canApprove = digits.length == 2 && !working && remaining > 0

    fun submit() {
        if (!canApprove) return
        val typed = digits.toLong()
        if (matches(typed)) {
            onApprove(typed)
        } else {
            wrong += 1
            field = TextFieldValue("")
            if (wrong >= 2) onNotMe(true)
        }
    }

    // Normally the decision area (number, stamps, not me) is pinned above the keyboard and the
    // context fields scroll; from 125% font scale the whole slip scrolls as one sheet so no
    // field ever hides under the fade edge.
    val density = LocalDensity.current
    val hugeText = density.fontScale > 1.25f
    val outer = rememberScrollState()
    val inner = rememberScrollState()
    // When the whole slip scrolls, keep the decision group (number, stamps, not me) fully in
    // view once the number field has focus and whenever the keyboard settles, so no control
    // ever rests half under the keyboard edge.
    val decision = remember { BringIntoViewRequester() }
    val imeBottom = WindowInsets.ime.getBottom(density)
    LaunchedEffect(hugeText, imeBottom) {
        if (!hugeText) return@LaunchedEffect
        delay(if (imeBottom > 0) 150 else 400) // restarts on every IME animation frame
        decision.bringIntoView()
    }
    Column(
        Modifier
            .widthIn(max = 560.dp)
            .fillMaxWidth()
            .fillMaxHeight()
            .then(if (hugeText) Modifier.verticalScroll(outer) else Modifier)
            // Guard: never less bottom padding than the IME inset (a no-op when the parent's
            // safeDrawingPadding has already consumed it).
            .imePadding()
            .padding(horizontal = 12.dp, vertical = 12.dp),
    ) {
        // "Visitor slip" is kept for TalkBack only; the PC name opens the slip visually.
        val slipLabel = stringResource(R.string.slip_header)
        VisitorSlip(
            (if (hugeText) Modifier.fillMaxWidth() else Modifier.fillMaxWidth().weight(1f, fill = false))
                .semantics { contentDescription = slipLabel },
        ) {
            val slipColor = c.slip
            Column(
                if (hugeText) Modifier else Modifier
                    .weight(1f, fill = false)
                    .drawWithContent {
                        drawContent()
                        // Fade edge: tells the reader more fields are scrolled out of view.
                        val h = 28.dp.toPx()
                        if (inner.canScrollForward) {
                            drawRect(Brush.verticalGradient(listOf(slipColor.copy(alpha = 0f), slipColor), startY = size.height - h, endY = size.height), topLeft = Offset(0f, size.height - h))
                        }
                        if (inner.canScrollBackward) {
                            drawRect(Brush.verticalGradient(listOf(slipColor, slipColor.copy(alpha = 0f)), startY = 0f, endY = h), size = androidx.compose.ui.geometry.Size(size.width, h))
                        }
                    }
                    .verticalScroll(inner),
            ) {
                Text(
                    m.pcName,
                    modifier = Modifier.semantics { heading() },
                    style = MaterialTheme.typography.headlineMedium,
                    color = c.onSlip,
                )
                Gap(10.dp)
                PerforationCountdown(fraction, seconds)
                Gap(4.dp)
                RuledField(m.accountLabel ?: stringResource(R.string.field_account), m.account.ifBlank { stringResource(R.string.field_unknown) })
                RuledField(stringResource(R.string.field_remote), m.remote)
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    RuledField(stringResource(R.string.field_kind), m.signInKind, Modifier.weight(1f))
                    RuledField(stringResource(R.string.field_time), m.time, Modifier.weight(1f), mono = true)
                }
            }
            Column(Modifier.fillMaxWidth().bringIntoViewRequester(decision)) {
                Gap(12.dp)
                val message = when {
                    wrong == 1 -> stringResource(R.string.badge_wrong)
                    working -> stringResource(R.string.slip_working)
                    else -> stringResource(R.string.badge_hint)
                }
                // Number entry: label and guidance beside the two cells to keep the stamps in view.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f).padding(end = 12.dp)) {
                        FormLabel(stringResource(R.string.badge_label))
                        Gap(4.dp)
                        Text(
                            message,
                            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (wrong == 1) c.deniedOnSlip else c.slipLabel,
                        )
                    }
                    BadgeCells(
                        value = field,
                        onValue = { v ->
                            val clean = v.text.filter { it.isDigit() }.take(2)
                            field = TextFieldValue(clean, TextRange(clean.length))
                        },
                        onDone = { submit() },
                        enabled = !working,
                        focus = focus,
                    )
                }
                Gap(12.dp)
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    DecisionStamp(stringResource(R.string.stamp_deny), StampKind.Deny, enabled = !working, onClick = onDeny, modifier = Modifier.weight(1f))
                    DecisionStamp(stringResource(R.string.stamp_approve), StampKind.Approve, enabled = canApprove, onClick = { submit() }, modifier = Modifier.weight(1f))
                }
                Gap(10.dp)
                NotMeButton(stringResource(R.string.not_me), onClick = { onNotMe(false) }, enabled = !working)
            }
        }
    }
}

@Composable
private fun BadgeCells(
    value: TextFieldValue,
    onValue: (TextFieldValue) -> Unit,
    onDone: () -> Unit,
    enabled: Boolean,
    focus: FocusRequester,
) {
    val c = Desk.colors
    val description = pluralStringResource(R.plurals.badge_a11y, value.text.length, value.text.length)
    BasicTextField(
        value = value,
        onValueChange = onValue,
        enabled = enabled,
        singleLine = true,
        cursorBrush = SolidColor(c.onSlip),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done, autoCorrectEnabled = false),
        keyboardActions = KeyboardActions(onDone = { onDone() }),
        textStyle = Desk.type.badge.copy(color = androidx.compose.ui.graphics.Color.Transparent),
        modifier = Modifier
            .focusRequester(focus)
            .semantics { contentDescription = description },
        decorationBox = { inner ->
            Box {
                // The real (transparent) field keeps IME, focus and accessibility behaviour.
                Box(Modifier.size(1.dp)) { inner() }
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    for (i in 0 until 2) {
                        val ch = value.text.getOrNull(i)?.toString() ?: ""
                        val active = i == value.text.length.coerceAtMost(1) && enabled
                        Box(
                            Modifier
                                .width(64.dp)
                                .heightIn(min = 72.dp)
                                .background(c.record, MaterialTheme.shapes.small)
                                .border(if (active) BorderStroke(3.dp, c.onSlip) else BorderStroke(2.dp, c.slipEdge), MaterialTheme.shapes.small),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(ch, style = Desk.type.badge, color = c.ink, textAlign = TextAlign.Center)
                        }
                    }
                }
            }
        },
    )
}

@Composable
private fun Closed(title: String, body: String, outcome: Outcome?, onClose: () -> Unit) {
    Column(
        Modifier
            .widthIn(max = 560.dp)
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(12.dp),
    ) {
        val slipLabel = stringResource(R.string.slip_header)
        RecordSheet(Modifier.fillMaxWidth().semantics { contentDescription = slipLabel }) {
            Text(title, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
            if (outcome != null) {
                Gap(14.dp)
                OutcomeStamp(outcome, large = true)
            }
            Gap(14.dp)
            Text(body, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            Gap(12.dp)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onClose, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.close))
                }
            }
        }
        Spacer(Modifier.width(1.dp))
    }
}
