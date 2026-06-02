package tz.apt.thp.core.design

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * APT THP Compose theme — Material 3 ColorScheme derived from the brand
 * tokens. Light and dark surfaces are both honoured per the dashboard plan;
 * mode is driven by [ThemeController] so the user can override the system
 * preference.
 */

enum class ThemeMode { Auto, Light, Dark }

/** Extra brand-specific colors not captured by the standard Material slots. */
data class AptColors(
    val sevCritical: Color,
    val sevHigh: Color,
    val sevMedium: Color,
    val sevLow: Color,
    val sevInfo: Color,
    val statusOk: Color,
    val statusWarn: Color,
    val statusErr: Color,
    val statusUnknown: Color,
    val tealMuted: Color,
    val tealSoft: Color,
    val borderDark: Color,
    val borderLight: Color,
    val chartPalette: List<Color>,
    val isDark: Boolean,
)

val LocalAptColors = staticCompositionLocalOf<AptColors> {
    error("AptColors not provided — wrap your composable in AptTheme { … }")
}

private val DarkColors: ColorScheme = darkColorScheme(
    primary           = BrandTokens.TealPrimary,
    onPrimary         = Color.White,
    primaryContainer  = BrandTokens.TealMuted,
    onPrimaryContainer= Color.White,
    secondary         = BrandTokens.TealMuted,
    onSecondary       = Color.White,
    background        = BrandTokens.DarkBg0,
    onBackground      = BrandTokens.FgOnDark1,
    surface           = BrandTokens.DarkBg1,
    onSurface         = BrandTokens.FgOnDark1,
    surfaceVariant    = BrandTokens.DarkBg2,
    onSurfaceVariant  = BrandTokens.FgOnDark2,
    surfaceTint       = BrandTokens.TealPrimary,
    outline           = BrandTokens.BorderDark,
    outlineVariant    = BrandTokens.DarkBg3,
    error             = BrandTokens.SevCritical,
    onError           = Color.White,
)

private val LightColors: ColorScheme = lightColorScheme(
    primary           = BrandTokens.TealMuted,
    onPrimary         = Color.White,
    primaryContainer  = BrandTokens.TealSoft,
    onPrimaryContainer= BrandTokens.FgOnLight1,
    secondary         = BrandTokens.TealMuted,
    onSecondary       = Color.White,
    background        = BrandTokens.LightBg0,
    onBackground      = BrandTokens.FgOnLight1,
    surface           = Color.White,
    onSurface         = BrandTokens.FgOnLight1,
    surfaceVariant    = BrandTokens.LightBg1,
    onSurfaceVariant  = BrandTokens.FgOnLight2,
    surfaceTint       = BrandTokens.TealMuted,
    outline           = BrandTokens.BorderLight,
    outlineVariant    = BrandTokens.LightBg2,
    error             = BrandTokens.SevCritical,
    onError           = Color.White,
)

private val DarkAptColors = AptColors(
    sevCritical   = BrandTokens.SevCritical,
    sevHigh       = BrandTokens.SevHigh,
    sevMedium     = BrandTokens.SevMedium,
    sevLow        = BrandTokens.SevLow,
    sevInfo       = BrandTokens.SevInfo,
    statusOk      = BrandTokens.StatusOk,
    statusWarn    = BrandTokens.StatusWarn,
    statusErr     = BrandTokens.StatusErr,
    statusUnknown = BrandTokens.StatusUnknown,
    tealMuted     = BrandTokens.TealMuted,
    tealSoft      = BrandTokens.TealSoft,
    borderDark    = BrandTokens.BorderDark,
    borderLight   = BrandTokens.BorderLight,
    chartPalette  = BrandTokens.ChartPalette,
    isDark        = true,
)

private val LightAptColors = DarkAptColors.copy(isDark = false)

/**
 * Top-level theme wrapper. Resolves the active [ThemeMode] (Auto follows
 * the system) and emits both the Material 3 [ColorScheme] and the extra
 * APT-specific colours via [LocalAptColors].
 */
@Composable
fun AptTheme(
    mode: ThemeMode = ThemeMode.Auto,
    content: @Composable () -> Unit,
) {
    val systemDark = isSystemInDarkTheme()
    val useDark = when (mode) {
        ThemeMode.Auto  -> systemDark
        ThemeMode.Light -> false
        ThemeMode.Dark  -> true
    }
    val scheme = if (useDark) DarkColors else LightColors
    val aptColors = if (useDark) DarkAptColors else LightAptColors

    CompositionLocalProvider(LocalAptColors provides aptColors) {
        MaterialTheme(
            colorScheme = scheme,
            typography  = AptMaterialTypography,
            content     = content,
        )
    }
}
