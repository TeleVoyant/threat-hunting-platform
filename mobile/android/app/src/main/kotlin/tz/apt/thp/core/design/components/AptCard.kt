package tz.apt.thp.core.design.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import tz.apt.thp.core.design.LocalAptColors
import tz.apt.thp.core.design.Radii
import tz.apt.thp.core.design.Spacing

/**
 * Card primitive matching the dashboard's `.card` class — rounded corners,
 * outlined border, surface background, optional click target.
 */
@Composable
fun AptCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    padding: Dp = Spacing.lg,
    cornerRadius: Dp = Radii.card,
    // Override the card's surface background. Default = MaterialTheme.surface
    // matches the rest of the page; pass MaterialTheme.colorScheme.errorContainer
    // for warning / failed states (e.g. the UPDATE FAILED card on Agent detail).
    containerColor: androidx.compose.ui.graphics.Color? = null,
    content: @Composable () -> Unit,
) {
    val aptColors = LocalAptColors.current
    val borderColor =
        if (aptColors.isDark) aptColors.borderDark else aptColors.borderLight
    val bg = containerColor ?: MaterialTheme.colorScheme.surface
    val fg = if (containerColor != null) {
        // Best-effort: when caller supplies a custom background, prefer the
        // matching on* color. For error-container the inverse of "onSurface"
        // is unreadable, so route through onErrorContainer explicitly.
        if (bg == MaterialTheme.colorScheme.errorContainer)
            MaterialTheme.colorScheme.onErrorContainer
        else
            MaterialTheme.colorScheme.onSurface
    } else MaterialTheme.colorScheme.onSurface

    val baseMod = modifier
        .fillMaxWidth()
        .clip(RoundedCornerShape(cornerRadius))
        .background(bg)
        .border(width = 1.dp, color = borderColor, shape = RoundedCornerShape(cornerRadius))

    val finalMod = if (onClick != null) baseMod.clickable(onClick = onClick) else baseMod

    Box(modifier = finalMod.padding(padding)) {
        CompositionLocalProvider(
            LocalContentColor provides fg,
            content = content,
        )
    }
}
