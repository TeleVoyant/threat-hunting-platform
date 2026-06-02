package tz.apt.thp.core.design.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing

/**
 * KPI tile — a single hero number on a labeled card. Matches the dashboard's
 * `.kpi-card` layout. Optional accent color paints the number (used for
 * critical-count / high-count tiles).
 */
@Composable
fun KpiTile(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    accent: Color? = null,
    onClick: (() -> Unit)? = null,
) {
    AptCard(
        modifier = modifier,
        padding = Spacing.md,
        onClick = onClick,
    ) {
        Column {
            Text(
                text = label.uppercase(),
                style = AptType.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = value,
                style = AptType.kpiNumber,
                color = accent ?: MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
