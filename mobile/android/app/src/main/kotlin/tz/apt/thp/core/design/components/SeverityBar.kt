package tz.apt.thp.core.design.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.BrandTokens

/**
 * Horizontal stacked-bar showing severity mix. Replaces the dashboard's
 * donut for mobile (too small to be legible). Renders proportional segments
 * for CRITICAL / HIGH / MEDIUM / LOW counts.
 */
@Composable
fun SeverityBar(
    critical: Int,
    high: Int,
    medium: Int,
    low: Int,
    modifier: Modifier = Modifier,
) {
    val total = (critical + high + medium + low).coerceAtLeast(1)
    val segments = listOf(
        critical to BrandTokens.SevCritical,
        high     to BrandTokens.SevHigh,
        medium   to BrandTokens.SevMedium,
        low      to BrandTokens.SevLow,
    )

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(12.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            segments.forEach { (count, color) ->
                if (count > 0) {
                    val weight = count.toFloat() / total
                    Box(
                        modifier = Modifier
                            .weight(weight)
                            .height(12.dp)
                            .background(color),
                    )
                }
            }
        }
    }
}

/** Legend row to accompany [SeverityBar]. */
@Composable
fun SeverityLegend(
    critical: Int,
    high: Int,
    medium: Int,
    low: Int,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        LegendDot("Critical", critical, BrandTokens.SevCritical)
        LegendDot("High",     high,     BrandTokens.SevHigh)
        LegendDot("Medium",   medium,   BrandTokens.SevMedium)
        LegendDot("Low",      low,      BrandTokens.SevLow)
    }
}

@Composable
private fun LegendDot(label: String, count: Int, color: androidx.compose.ui.graphics.Color) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        Box(
            modifier = Modifier
                .width(8.dp)
                .height(8.dp)
                .background(color, RoundedCornerShape(2.dp)),
        )
        Text("$label $count", style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
