package tz.apt.thp.core.design.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Radii
import tz.apt.thp.core.design.heartbeat
import tz.apt.thp.core.design.statusColor

/**
 * Status pill — dot + label on a tinted background. The dot can heartbeat
 * (used for "listening" upstream indicators) so the user can spot a live
 * connection at a glance.
 */
@Composable
fun StatusPill(
    label: String,
    status: String,
    modifier: Modifier = Modifier,
    pulse: Boolean = false,
) {
    val color = statusColor(status)
    Row(
        modifier = modifier
            .background(color.copy(alpha = 0.12f), shape = RoundedCornerShape(Radii.pill))
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .background(color, shape = CircleShape)
                .heartbeat(enabled = pulse),
        )
        Text(label, style = AptType.labelMedium, color = color)
    }
}
