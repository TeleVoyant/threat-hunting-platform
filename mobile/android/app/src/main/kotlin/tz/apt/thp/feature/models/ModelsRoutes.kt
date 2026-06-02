package tz.apt.thp.feature.models

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.design.components.Sparkline
import tz.apt.thp.core.design.components.StatusPill

/**
 * Read-only Telemetry Pack — Models tab. Per-detector cards with the
 * currently-loaded version, a drift sparkline, and the count of saved
 * versions. NO retrain / tune / threshold-edit on mobile.
 */
@Composable
fun ModelsRoute(onOpenDetector: (String) -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: ModelsViewModel = viewModel(factory = ModelsViewModel.Factory(appGraph))
    val state by vm.state.collectAsState()

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Models", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            IconButton(onClick = { vm.refresh() }) {
                Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
            }
        }

        Spacer(Modifier.height(Spacing.sm))

        if (state.cards.isEmpty()) {
            AptCard {
                Text(
                    text = state.error ?: "No detectors registered yet.",
                    style = AptType.bodyMedium,
                    color = if (state.error != null) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                items(state.cards, key = { it.summary.name }) { card ->
                    DetectorCard(card, onClick = { onOpenDetector(card.summary.name) })
                }
            }
        }
    }
}

@Composable
private fun DetectorCard(
    card: ModelsViewModel.DetectorCard,
    onClick: () -> Unit,
) {
    val points = card.drift?.points
        ?.map { it.mean.toFloat() }
        ?: emptyList()
    val status = when {
        card.summary.current_version.isNullOrBlank() -> "warn"
        card.drift?.current_count == 0               -> "warn"
        else                                         -> "ok"
    }

    AptCard(onClick = onClick) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(
                        text = card.summary.name,
                        style = AptType.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "v${card.summary.current_version ?: "—"} · ${card.summary.version_count} saved",
                        style = AptType.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                StatusPill(
                    label = if (status == "ok") "ACTIVE" else "IDLE",
                    status = status,
                )
            }
            Text("Drift (mean confidence)", style = AptType.labelSmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
            Sparkline(points = points)
            card.drift?.let {
                Text(
                    text = "${it.current_count} recent predictions",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * Detail sheet — currently shows the full drift trace + a "View on
 * dashboard" stub. Future iteration adds version history + NFR-02 grades.
 */
@Composable
fun ModelDetailRoute(detectorName: String, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: ModelsViewModel = viewModel(factory = ModelsViewModel.Factory(appGraph))
    val state by vm.state.collectAsState()
    val card = state.cards.firstOrNull { it.summary.name == detectorName }
    val driftPoints = card?.drift?.points?.map { it.mean.toFloat() } ?: emptyList()
    val p95Points = card?.drift?.points?.map { it.p95.toFloat() } ?: emptyList()

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) {
                Icon(Icons.Outlined.ArrowBack, contentDescription = "Back")
            }
            Text(detectorName, style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
        }
        Spacer(Modifier.height(Spacing.md))

        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Current version", style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(card?.summary?.current_version ?: "—", style = AptType.mono, color = MaterialTheme.colorScheme.onSurface)
                Text("Versions saved", style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text((card?.summary?.version_count ?: 0).toString(), style = AptType.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
            }
        }

        Spacer(Modifier.height(Spacing.md))

        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Drift — mean", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Sparkline(points = driftPoints)
                Text("Drift — p95", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Sparkline(points = p95Points)
                Text(
                    text = "Retrain / tune / threshold edits stay on the dashboard.",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
