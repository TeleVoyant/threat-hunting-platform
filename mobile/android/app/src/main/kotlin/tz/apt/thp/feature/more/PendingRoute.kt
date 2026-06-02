package tz.apt.thp.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.sync.OutboxEntity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Outbox inspector — surfaces queued + failed actions so the operator can
 * retry or delete by hand. Pending rows are shown first, then terminal
 * failures. Everything links to the underlying alert when the row's URL
 * carries an alert id.
 */
@Composable
fun PendingRoute(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val repo = remember { AppGraph.from(ctx).outbox }
    val rows by repo.all.collectAsState(initial = emptyList())
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier.fillMaxSize().padding(Spacing.lg),
        verticalArrangement = Arrangement.spacedBy(Spacing.md),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Pending actions", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            if (rows.any { it.terminal }) {
                TextButton(onClick = { scope.launch { repo.clearTerminal() } }) {
                    Text("Clear failed")
                }
            }
        }

        if (rows.isEmpty()) {
            AptCard {
                Text(
                    "Nothing pending. Acks and notes you take offline land here until they sync.",
                    style = AptType.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                items(rows, key = { it.id }) { row ->
                    PendingRowCard(row, onRetry = { scope.launch { repo.retry(row.id) } })
                }
            }
        }
    }
}

@Composable
private fun PendingRowCard(row: OutboxEntity, onRetry: () -> Unit) {
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }
    AptCard {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = row.kind.uppercase(),
                    style = AptType.labelMedium,
                    color = if (row.terminal) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                )
                Text(
                    text = if (row.terminal) "FAILED" else "QUEUED (attempt ${row.attempts + 1})",
                    style = AptType.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(row.targetUrlSuffix, style = AptType.mono, color = MaterialTheme.colorScheme.onSurface)
            Text(fmt.format(Date(row.createdAt)), style = AptType.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            row.lastError?.let {
                Text(it, style = AptType.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            if (row.terminal) {
                Row {
                    TextButton(onClick = onRetry) { Text("Retry") }
                }
            }
        }
    }
}
