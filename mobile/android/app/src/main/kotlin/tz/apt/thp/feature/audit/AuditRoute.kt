package tz.apt.thp.feature.audit

import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.FilterChip
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
import tz.apt.thp.core.design.components.StatusPill
import tz.apt.thp.data.AuditEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Audit log inspector. Top-of-screen integrity badge calls /audit/verify;
 * the row list is the most-recent 50 entries, client-side filtered by
 * category chips.
 */
@Composable
fun AuditRoute() {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: AuditViewModel = viewModel(factory = AuditViewModel.Factory(appGraph))
    val state by vm.state.collectAsState()
    val visible = remember(state.entries, state.category) { vm.filtered() }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Audit", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            IconButton(onClick = { vm.refresh() }) {
                Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
            }
        }

        Spacer(Modifier.height(Spacing.sm))

        // Integrity badge
        state.integrity?.let { check ->
            AptCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column {
                        Text("Hash chain", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                        Text(
                            "${check.entries} entries verified",
                            style = AptType.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    StatusPill(
                        label = if (check.integrity_ok) "INTACT" else "BROKEN",
                        status = if (check.integrity_ok) "ok" else "error",
                    )
                }
            }
        }

        Spacer(Modifier.height(Spacing.sm))

        // Category chips — horizontally scrollable.
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            AuditViewModel.Category.entries.forEach { cat ->
                FilterChip(
                    selected = state.category == cat,
                    onClick = { vm.setCategory(cat) },
                    label = { Text(cat.label, style = AptType.labelMedium) },
                )
            }
        }

        Spacer(Modifier.height(Spacing.sm))

        if (visible.isEmpty()) {
            AptCard {
                Text(
                    state.error ?: "No audit entries in this category.",
                    style = AptType.bodyMedium,
                    color = if (state.error != null) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                items(visible, key = { it.id ?: it.timestamp ?: it.hashCode() }) { entry ->
                    AuditRow(entry)
                }
            }
        }
    }
}

@Composable
private fun AuditRow(entry: AuditEntry) {
    val fmt = remember { SimpleDateFormat("MMM d HH:mm:ss", Locale.US) }
    val ts = entry.timestamp?.let { Date((it * 1000).toLong()) }
    AptCard {
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = entry.action ?: "—",
                    style = AptType.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                ts?.let {
                    Text(
                        text = fmt.format(it),
                        style = AptType.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Text(
                text = "by ${entry.actor ?: "—"}" + (entry.target?.let { " → $it" } ?: ""),
                style = AptType.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}
