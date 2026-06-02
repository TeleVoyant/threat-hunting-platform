package tz.apt.thp.core.design.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import tz.apt.thp.core.design.LocalAptColors

/**
 * Tiny pure-Compose line chart. No external dep. Renders a smooth single-
 * series line over a fill area. Used by KPI strip 24h volume + Models tab
 * drift sparkline + Audit trend.
 *
 * Empty / single-point series render as an invisible no-op so callers can
 * treat the lack of data as a layout-only concern.
 */
@Composable
fun Sparkline(
    points: List<Float>,
    modifier: Modifier = Modifier,
    height: Dp = 48.dp,
    color: Color? = null,
    strokeWidth: Dp = 1.5.dp,
    fillAlpha: Float = 0.18f,
) {
    if (points.size < 2) {
        // Degenerate — still occupy the layout slot to avoid jumps.
        Canvas(modifier = modifier.fillMaxWidth().height(height)) {}
        return
    }
    val effectiveColor = color ?: LocalAptColors.current.chartPalette.first()

    Canvas(modifier = modifier.fillMaxWidth().height(height)) {
        val w = size.width
        val h = size.height
        val maxV = points.max()
        val minV = points.min()
        val range = (maxV - minV).coerceAtLeast(1e-3f)
        val stepX = w / (points.size - 1).toFloat()

        val linePath = Path()
        val fillPath = Path()
        points.forEachIndexed { i, v ->
            val x = i * stepX
            // y inverts because Canvas origin is top-left.
            val y = h - ((v - minV) / range) * h * 0.9f - h * 0.05f
            if (i == 0) {
                linePath.moveTo(x, y)
                fillPath.moveTo(x, h)
                fillPath.lineTo(x, y)
            } else {
                linePath.lineTo(x, y)
                fillPath.lineTo(x, y)
            }
        }
        fillPath.lineTo(w, h)
        fillPath.close()

        drawPath(fillPath, color = effectiveColor.copy(alpha = fillAlpha))
        drawPath(
            path = linePath,
            color = effectiveColor,
            style = Stroke(width = strokeWidth.toPx()),
        )
        // Last-point dot.
        val lastX = (points.size - 1) * stepX
        val lastY = h - ((points.last() - minV) / range) * h * 0.9f - h * 0.05f
        drawCircle(color = effectiveColor, radius = strokeWidth.toPx() * 1.6f, center = Offset(lastX, lastY))
    }
}
