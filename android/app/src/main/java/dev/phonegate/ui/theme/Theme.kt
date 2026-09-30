package dev.phonegate.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.phonegate.R

/**
 * The front-desk world: carbonless visitor slips (canary live slip, white records, pink copy for
 * "not me"), ballpoint ink-blue values, graphite tracked-caps labels, and bordered outcome stamps.
 *
 * Dynamic color (Material You) is deliberately OFF. The approval screen's meaning is carried by
 * fixed state colors: APPROVED green, DENIED red, the canary live slip and the pink "not me" copy.
 * Deriving them from the wallpaper could make a denial look like an approval or wash the live slip
 * into the records around it, which is exactly the misreading this app must prevent. Brand color
 * is instead expressed through the Material color roles below, in light and night-shift dark.
 */
@Immutable
data class DeskColors(
    val ground: Color,
    val slip: Color,
    val slipEdge: Color,
    val onSlip: Color,
    val slipLabel: Color,
    val ink: Color,
    val onInk: Color,
    val record: Color,
    val onRecord: Color,
    val recordLabel: Color,
    val rule: Color,
    val pinkCopy: Color,
    val onPinkCopy: Color,
    val approved: Color,
    val denied: Color,
    val deniedOnSlip: Color,
    val neutralStamp: Color,
)

private val LightDesk = DeskColors(
    ground = Color(0xFFE4E7EC),
    slip = Color(0xFFF4C430),
    slipEdge = Color(0xFFD9A915),
    onSlip = Color(0xFF1F3A93),
    slipLabel = Color(0xFF3B3A36),
    ink = Color(0xFF1F3A93),
    onInk = Color(0xFFF7F8FF),
    record = Color(0xFFFCFCFA),
    onRecord = Color(0xFF1B2130),
    recordLabel = Color(0xFF55544E),
    rule = Color(0xFF8C8A82),
    pinkCopy = Color(0xFFF7C6CF),
    onPinkCopy = Color(0xFF6B1426),
    approved = Color(0xFF0E7C4A),
    denied = Color(0xFFC4271F),
    deniedOnSlip = Color(0xFFA11E17),
    neutralStamp = Color(0xFF4A4943),
)

private val NightDesk = DeskColors(
    ground = Color(0xFF0E1523),
    slip = Color(0xFF3A3118),
    slipEdge = Color(0xFFB8922A),
    onSlip = Color(0xFFD9E2FF),
    slipLabel = Color(0xFFDCCF9F),
    ink = Color(0xFFB7C8FF),
    onInk = Color(0xFF0E1F5C),
    record = Color(0xFF182235),
    onRecord = Color(0xFFE3E7F0),
    recordLabel = Color(0xFFAEB5C4),
    rule = Color(0xFF5E6778),
    pinkCopy = Color(0xFF4B2231),
    onPinkCopy = Color(0xFFFFD0DA),
    approved = Color(0xFF5FD39A),
    denied = Color(0xFFFF8A7A),
    deniedOnSlip = Color(0xFFFF9B8C),
    neutralStamp = Color(0xFFC3C8D2),
)

private fun lightScheme(d: DeskColors): ColorScheme = lightColorScheme(
    primary = d.ink,
    onPrimary = d.onInk,
    primaryContainer = Color(0xFFD9E0FA),
    onPrimaryContainer = Color(0xFF0E1F5C),
    secondary = Color(0xFF4A4943),
    onSecondary = Color(0xFFFBFBF8),
    secondaryContainer = d.slip,
    onSecondaryContainer = Color(0xFF2A2204),
    tertiary = d.approved,
    onTertiary = Color(0xFFF4FFF8),
    error = d.denied,
    onError = Color(0xFFFFF7F6),
    errorContainer = d.pinkCopy,
    onErrorContainer = d.onPinkCopy,
    background = d.ground,
    onBackground = d.onRecord,
    surface = d.ground,
    onSurface = d.onRecord,
    surfaceVariant = Color(0xFFD9DCE2),
    onSurfaceVariant = d.recordLabel,
    surfaceContainerLowest = d.record,
    surfaceContainerLow = d.record,
    surfaceContainer = Color(0xFFF1F2F4),
    surfaceContainerHigh = Color(0xFFEBEDF0),
    surfaceContainerHighest = Color(0xFFE0E3E8),
    outline = d.rule,
    outlineVariant = Color(0xFFC3C6CC),
)

private fun darkScheme(d: DeskColors): ColorScheme = darkColorScheme(
    primary = d.ink,
    onPrimary = d.onInk,
    primaryContainer = Color(0xFF26397A),
    onPrimaryContainer = Color(0xFFDDE4FF),
    secondary = Color(0xFFC3C8D2),
    onSecondary = Color(0xFF1B2130),
    secondaryContainer = d.slip,
    onSecondaryContainer = Color(0xFFF1E4B4),
    tertiary = d.approved,
    onTertiary = Color(0xFF00391F),
    error = d.denied,
    onError = Color(0xFF4A0703),
    errorContainer = d.pinkCopy,
    onErrorContainer = d.onPinkCopy,
    background = d.ground,
    onBackground = d.onRecord,
    surface = d.ground,
    onSurface = d.onRecord,
    surfaceVariant = Color(0xFF232E44),
    onSurfaceVariant = d.recordLabel,
    surfaceContainerLowest = Color(0xFF0B111D),
    surfaceContainerLow = d.record,
    surfaceContainer = Color(0xFF1A2438),
    surfaceContainerHigh = Color(0xFF1F2A40),
    surfaceContainerHighest = Color(0xFF263249),
    outline = d.rule,
    outlineVariant = Color(0xFF354056),
)

@OptIn(ExperimentalTextApi::class)
private val Archivo = FontFamily(
    Font(R.font.archivo, FontWeight.Normal, variationSettings = FontVariation.Settings(FontVariation.weight(400))),
    Font(R.font.archivo, FontWeight.Medium, variationSettings = FontVariation.Settings(FontVariation.weight(500))),
    Font(R.font.archivo, FontWeight.SemiBold, variationSettings = FontVariation.Settings(FontVariation.weight(600))),
    Font(R.font.archivo, FontWeight.Bold, variationSettings = FontVariation.Settings(FontVariation.weight(700))),
    Font(R.font.archivo, FontWeight.ExtraBold, variationSettings = FontVariation.Settings(FontVariation.weight(800))),
)

/** Tabular monospace for every number: badge numbers, pairing codes, offline codes, times. */
@OptIn(ExperimentalTextApi::class)
val JetBrainsMono = FontFamily(
    Font(R.font.jetbrains_mono, FontWeight.Normal, variationSettings = FontVariation.Settings(FontVariation.weight(400))),
    Font(R.font.jetbrains_mono, FontWeight.Medium, variationSettings = FontVariation.Settings(FontVariation.weight(500))),
    Font(R.font.jetbrains_mono, FontWeight.Bold, variationSettings = FontVariation.Settings(FontVariation.weight(700))),
)

private val base = Typography()

private val DeskTypography = Typography(
    displayLarge = base.displayLarge.copy(fontFamily = Archivo, fontWeight = FontWeight.ExtraBold),
    displayMedium = base.displayMedium.copy(fontFamily = Archivo, fontWeight = FontWeight.ExtraBold),
    displaySmall = base.displaySmall.copy(fontFamily = Archivo, fontWeight = FontWeight.Bold),
    headlineLarge = base.headlineLarge.copy(fontFamily = Archivo, fontWeight = FontWeight.Bold),
    headlineMedium = base.headlineMedium.copy(fontFamily = Archivo, fontWeight = FontWeight.Bold),
    headlineSmall = base.headlineSmall.copy(fontFamily = Archivo, fontWeight = FontWeight.Bold),
    titleLarge = base.titleLarge.copy(fontFamily = Archivo, fontWeight = FontWeight.Bold),
    titleMedium = base.titleMedium.copy(fontFamily = Archivo, fontWeight = FontWeight.SemiBold),
    titleSmall = base.titleSmall.copy(fontFamily = Archivo, fontWeight = FontWeight.SemiBold),
    // Form labels: small tracked caps (callers uppercase the text).
    labelSmall = base.labelSmall.copy(fontWeight = FontWeight.Medium, letterSpacing = 1.1.sp),
    labelMedium = base.labelMedium.copy(fontWeight = FontWeight.Medium, letterSpacing = 0.9.sp),
    labelLarge = base.labelLarge.copy(fontFamily = Archivo, fontWeight = FontWeight.Bold, letterSpacing = 1.4.sp),
)

@Immutable
data class DeskType(
    val badge: TextStyle,
    val code: TextStyle,
    val codeSmall: TextStyle,
    val value: TextStyle,
    val stamp: TextStyle,
)

private val DefaultDeskType = DeskType(
    badge = TextStyle(fontFamily = JetBrainsMono, fontWeight = FontWeight.Bold, fontSize = 44.sp, lineHeight = 52.sp),
    code = TextStyle(fontFamily = JetBrainsMono, fontWeight = FontWeight.Bold, fontSize = 40.sp, lineHeight = 48.sp, letterSpacing = 2.sp),
    codeSmall = TextStyle(fontFamily = JetBrainsMono, fontWeight = FontWeight.Medium, fontSize = 15.sp, lineHeight = 22.sp),
    value = TextStyle(fontSize = 18.sp, lineHeight = 24.sp, fontWeight = FontWeight.Medium),
    stamp = TextStyle(fontFamily = Archivo, fontWeight = FontWeight.ExtraBold, fontSize = 20.sp, lineHeight = 24.sp, letterSpacing = 1.6.sp),
)

/**
 * One corner rule for the whole app: paper (slips, records) is almost square at 2dp, controls
 * and stamps are 4dp. Nothing is pill-shaped.
 */
private val DeskShapes = Shapes(
    extraSmall = RoundedCornerShape(2.dp),
    small = RoundedCornerShape(4.dp),
    medium = RoundedCornerShape(4.dp),
    large = RoundedCornerShape(4.dp),
    extraLarge = RoundedCornerShape(4.dp),
)

val LocalDeskColors = staticCompositionLocalOf { LightDesk }
val LocalDeskType = staticCompositionLocalOf { DefaultDeskType }

object Desk {
    val colors: DeskColors @Composable get() = LocalDeskColors.current
    val type: DeskType @Composable get() = LocalDeskType.current
}

@Composable
fun PhoneGateTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val desk = if (dark) NightDesk else LightDesk
    CompositionLocalProvider(LocalDeskColors provides desk, LocalDeskType provides DefaultDeskType) {
        MaterialTheme(
            colorScheme = if (dark) darkScheme(desk) else lightScheme(desk),
            typography = DeskTypography,
            shapes = DeskShapes,
            content = content,
        )
    }
}
