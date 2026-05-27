package tz.apt.thp.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * APT THP brand theme. Mirrors the dashboard design system:
 *  - navy `#072147` chrome
 *  - teal `#1FB6A6` primary actions
 *  - sev colours: critical `#E5484D`, high `#F5A524`, medium `#F2C94C`, low `#6B7280`
 *
 * Respects `isSystemInDarkTheme()`. No follow-up toggle yet — analysts almost
 * always run their phone on the same theme system-wide.
 */

object Brand {
    val Navy900    = Color(0xFF051A36)
    val Navy800    = Color(0xFF072147)
    val Navy700    = Color(0xFF0E2B58)
    val TealPrimary= Color(0xFF1FB6A6)
    val TealMuted  = Color(0xFF0FA396)
    val SurfaceLt  = Color(0xFFF7F9FC)
    val SurfaceLt2 = Color(0xFFEEF1F6)
    val InkLt      = Color(0xFF0B1220)
    val InkDk      = Color(0xFFE6EAF2)
    val InkMuted   = Color(0xFF8A93A6)

    val SevCritical = Color(0xFFE5484D)
    val SevHigh     = Color(0xFFF5A524)
    val SevMedium   = Color(0xFFF2C94C)
    val SevLow      = Color(0xFF6B7280)
}

private val DarkColors = darkColorScheme(
    primary           = Brand.TealPrimary,
    onPrimary         = Color.White,
    primaryContainer  = Brand.TealMuted,
    onPrimaryContainer= Color.White,
    background        = Brand.Navy900,
    onBackground      = Brand.InkDk,
    surface           = Brand.Navy800,
    onSurface         = Brand.InkDk,
    surfaceVariant    = Brand.Navy700,
    onSurfaceVariant  = Brand.InkMuted,
    error             = Brand.SevCritical,
)

private val LightColors = lightColorScheme(
    primary           = Brand.TealMuted,
    onPrimary         = Color.White,
    primaryContainer  = Brand.TealPrimary,
    onPrimaryContainer= Color.White,
    background        = Brand.SurfaceLt,
    onBackground      = Brand.InkLt,
    surface           = Color.White,
    onSurface         = Brand.InkLt,
    surfaceVariant    = Brand.SurfaceLt2,
    onSurfaceVariant  = Brand.InkMuted,
    error             = Brand.SevCritical,
)

fun severityColor(sev: String): Color = when (sev.lowercase()) {
    "critical" -> Brand.SevCritical
    "high"     -> Brand.SevHigh
    "medium"   -> Brand.SevMedium
    else       -> Brand.SevLow
}

@Composable
fun AptThpTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) DarkColors else LightColors
    MaterialTheme(colorScheme = colors, content = content)
}
