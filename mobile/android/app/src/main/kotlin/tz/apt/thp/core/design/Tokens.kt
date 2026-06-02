package tz.apt.thp.core.design

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Brand tokens ported from the dashboard design system
 * (api/static/colors_and_type.css + styles.css). Single source of truth for
 * every colour, radius, spacing, and elevation value in the app — features
 * MUST consume from here, never inline a hex string.
 *
 * The token names mirror the CSS custom properties so a designer can trace
 * any value across web and mobile with grep.
 */
object BrandTokens {

    // ─── Dark surfaces (--bg-0..4) ────────────────────────────────────────
    val DarkBg0 = Color(0xFF051A36)
    val DarkBg1 = Color(0xFF072147)
    val DarkBg2 = Color(0xFF0E2B58)
    val DarkBg3 = Color(0xFF14346B)
    val DarkBg4 = Color(0xFF1B3F80)

    // ─── Light surfaces (--light-bg-0..2) ─────────────────────────────────
    val LightBg0 = Color(0xFFF7F8FA)
    val LightBg1 = Color(0xFFEFF2F7)
    val LightBg2 = Color(0xFFE2E7F0)

    // ─── Brand teal (primary accents, CTAs) ───────────────────────────────
    val TealPrimary = Color(0xFF1FB6A6)
    val TealMuted   = Color(0xFF0FA396)
    val TealSoft    = Color(0x331FB6A6)   // 20% — chip backgrounds on dark

    // ─── Foreground on dark surfaces (--fg-1..3) ──────────────────────────
    val FgOnDark1 = Color(0xFFE6EAF2)
    val FgOnDark2 = Color(0xFFB6BDCC)
    val FgOnDark3 = Color(0xFF8A93A6)

    // ─── Foreground on light surfaces (--fg-on-light-*) ───────────────────
    val FgOnLight1 = Color(0xFF0B1220)
    val FgOnLight2 = Color(0xFF2B3346)
    val FgOnLight3 = Color(0xFF5B6477)

    // ─── Severity (uppercase badges per brand brief) ──────────────────────
    val SevCritical = Color(0xFFE5484D)
    val SevHigh     = Color(0xFFF5A524)
    val SevMedium   = Color(0xFFF2C94C)
    val SevLow      = Color(0xFF6B7280)
    val SevInfo     = Color(0xFF1FB6A6)

    // ─── Status pills (fleet / service health) ────────────────────────────
    val StatusOk      = Color(0xFF22C55E)
    val StatusWarn    = Color(0xFFF59E0B)
    val StatusErr     = Color(0xFFEF4444)
    val StatusUnknown = Color(0xFF6B7280)

    // ─── Borders ──────────────────────────────────────────────────────────
    val BorderDark  = Color(0xFF1F2A45)
    val BorderLight = Color(0xFFD8DEEA)

    // ─── Chart palette (--chart-1..7) — token order is significant ────────
    val Chart1 = Color(0xFF1FB6A6)
    val Chart2 = Color(0xFFE5484D)
    val Chart3 = Color(0xFFF5A524)
    val Chart4 = Color(0xFFF2C94C)
    val Chart5 = Color(0xFF6B7280)
    val Chart6 = Color(0xFF60A5FA)
    val Chart7 = Color(0xFFA78BFA)
    val ChartPalette = listOf(Chart1, Chart2, Chart3, Chart4, Chart5, Chart6, Chart7)
}

/** Spacing scale — 4px grid. */
object Spacing {
    val xxs: Dp = 2.dp
    val xs:  Dp = 4.dp
    val sm:  Dp = 8.dp
    val md:  Dp = 12.dp
    val lg:  Dp = 16.dp
    val xl:  Dp = 24.dp
    val xxl: Dp = 32.dp
    val xxxl: Dp = 48.dp
}

/** Corner radii. */
object Radii {
    val pill: Dp = 999.dp
    val card: Dp = 14.dp
    val chip: Dp = 10.dp
    val input: Dp = 12.dp
    val sheet: Dp = 20.dp
}

/** Elevation scale. */
object Elev {
    val card: Dp = 1.dp
    val sheet: Dp = 8.dp
    val sticky: Dp = 4.dp
}

/** Severity → color helper. Lowercase-insensitive. */
fun severityColor(severity: String?): Color = when (severity?.lowercase()) {
    "critical" -> BrandTokens.SevCritical
    "high"     -> BrandTokens.SevHigh
    "medium", "med" -> BrandTokens.SevMedium
    "low"      -> BrandTokens.SevLow
    "info"     -> BrandTokens.SevInfo
    else       -> BrandTokens.SevLow
}

/** Status pill → color. */
fun statusColor(status: String?): Color = when (status?.lowercase()) {
    "ok", "active", "listening", "healthy" -> BrandTokens.StatusOk
    "warn", "stale", "degraded"            -> BrandTokens.StatusWarn
    "err", "error", "offline", "down"      -> BrandTokens.StatusErr
    else -> BrandTokens.StatusUnknown
}
