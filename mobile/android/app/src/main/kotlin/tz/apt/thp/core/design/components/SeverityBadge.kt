package tz.apt.thp.core.design.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Radii
import tz.apt.thp.core.design.severityColor

/**
 * Severity badge — uppercase label on a tinted background. Mirrors the
 * dashboard's `.sev-pill` class. Default is "filled" style.
 */
@Composable
fun SeverityBadge(
    severity: String,
    modifier: Modifier = Modifier,
    filled: Boolean = true,
) {
    val color = severityColor(severity)
    val (bg, fg, borderColor) = if (filled) {
        Triple(color, Color.White, color)
    } else {
        Triple(Color.Transparent, color, color)
    }
    Box(
        modifier = modifier
            .background(bg, shape = RoundedCornerShape(Radii.pill))
            .border(1.dp, borderColor, shape = RoundedCornerShape(Radii.pill))
            .padding(horizontal = 8.dp, vertical = 3.dp),
    ) {
        Text(
            text = severity.uppercase(),
            style = AptType.severityBadge,
            color = fg,
        )
    }
}
