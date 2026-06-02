package tz.apt.thp.feature.inbox

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import kotlinx.coroutines.delay
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.LocalAptColors
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.design.components.KpiTile
import tz.apt.thp.core.design.components.SeverityBadge
import tz.apt.thp.core.design.components.SeverityBar
import tz.apt.thp.core.design.components.SeverityLegend
import tz.apt.thp.core.design.components.Sparkline
import tz.apt.thp.core.design.components.StatusPill
import tz.apt.thp.data.Notification
import tz.apt.thp.feature.inbox.InboxViewModel.SevFilter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Inbox — the screen the analyst lives in. Layout:
 *   ┌─────────────────────────────────────────┐
 *   │ "Inbox"             [● LIVE]    [↻]     │  topbar
 *   ├─────────────────────────────────────────┤
 *   │ ⌗⌗ ⌗⌗ ⌗⌗ ⌗⌗  ← KPI tiles                 │
 *   │ ━━━━━━━━━━━━  ← severity stacked bar    │
 *   │ ╱╲╱╲╱╲       ← 24h volume sparkline     │
 *   │ [All] [Crit] [High] [Other]             │  filter chips
 *   ├─────────────────────────────────────────┤
 *   │ ▸ CRIT ▸ T1110 brute-force on srv-01    │  notification rows
 *   │ ▸ HIGH ▸ DNS exfil candidate to …       │
 *   └─────────────────────────────────────────┘
 */
@Composable
fun InboxRoute(onOpenAlert: (String) -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: InboxViewModel = viewModel(factory = InboxViewModel.Factory(appGraph))
    val state by vm.state.collectAsState()
    val aptColors = LocalAptColors.current

    val visibleNotifs = remember(state.notifications, state.filter) {
        when (state.filter) {
            SevFilter.ALL      -> state.notifications
            SevFilter.CRITICAL -> state.notifications.filter { it.severity.equals("critical", true) }
            SevFilter.HIGH     -> state.notifications.filter { it.severity.equals("high", true) }
            SevFilter.OTHER    -> state.notifications.filter {
                !it.severity.equals("critical", true) && !it.severity.equals("high", true)
            }
        }
    }

    // Auto-poll while the Inbox is on screen so the LIVE / OFFLINE pill
    // reflects current backend reachability without the user having to tap
    // refresh. Cancelled automatically when the Composable leaves
    // composition (tab switch, app background, navigation away) — no
    // wasted battery while the user is elsewhere.
    LaunchedEffect(Unit) {
        while (true) {
            delay(10_000L)   // 30 s cadence — cheap calls, meaningful pill
            vm.refresh()
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        // ─── Topbar ────────────────────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Inbox", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatusPill(
                    label = if (state.live) "LIVE" else "OFFLINE",
                    status = if (state.live) "ok" else "warn",
                    pulse = state.live,
                )
                IconButton(onClick = { vm.refresh() }) {
                    Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
                }
            }
        }

        Spacer(Modifier.height(Spacing.md))

        // ─── KPI tiles ─────────────────────────────────────────────────
        Row(horizontalArrangement = Arrangement.spacedBy(Spacing.sm)) {
            KpiTile(label = "Hunts",    value = state.stats.active_hunts.toString(), modifier = Modifier.weight(1f))
            KpiTile(label = "Open",     value = state.stats.open.toString(),         modifier = Modifier.weight(1f))
            KpiTile(label = "Critical", value = state.stats.critical.toString(),     modifier = Modifier.weight(1f), accent = aptColors.sevCritical)
            KpiTile(label = "High",     value = state.stats.high.toString(),         modifier = Modifier.weight(1f), accent = aptColors.sevHigh)
        }

        Spacer(Modifier.height(Spacing.md))

        // ─── Severity bar + sparkline ──────────────────────────────────
        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                Text("24h volume", style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Sparkline(points = state.volumeBuckets)
                SeverityBar(
                    critical = state.stats.critical,
                    high     = state.stats.high,
                    medium   = state.stats.medium,
                    low      = state.stats.low,
                )
                SeverityLegend(
                    critical = state.stats.critical,
                    high     = state.stats.high,
                    medium   = state.stats.medium,
                    low      = state.stats.low,
                )
            }
        }

        Spacer(Modifier.height(Spacing.md))

        // ─── Filter chips ──────────────────────────────────────────────
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SevFilter.entries.forEach { f ->
                FilterChip(
                    selected = state.filter == f,
                    onClick = { vm.setFilter(f) },
                    label = { Text(f.label, style = AptType.labelMedium) },
                )
            }
        }

        Spacer(Modifier.height(Spacing.md))

        // ─── List ──────────────────────────────────────────────────────
        if (visibleNotifs.isEmpty()) {
            AptCard {
                Text(
                    text = state.error ?: "Nothing to triage. New detections will appear here as they fire.",
                    style = AptType.bodyMedium,
                    color = if (state.error != null) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                items(visibleNotifs, key = { it.id }) { n ->
                    NotificationRow(
                        notif = n,
                        isRead = appGraph.prefs.isRead(n.id),
                        onClick = {
                            vm.markRead(n.id)
                            onOpenAlert(n.alert_id)
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun NotificationRow(
    notif: Notification,
    isRead: Boolean,
    onClick: () -> Unit,
) {
    val fmt = remember { SimpleDateFormat("HH:mm", Locale.US) }
    AptCard(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // Unread dot
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(
                        if (isRead) MaterialTheme.colorScheme.surfaceVariant
                        else MaterialTheme.colorScheme.primary,
                    ),
            )
            Spacer(Modifier.size(8.dp))
            SeverityBadge(severity = notif.severity)
            Spacer(Modifier.size(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = notif.title.orEmpty().ifBlank { "Detection ${notif.alert_id}" },
                    style = AptType.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (!notif.body.isNullOrBlank()) {
                    Text(
                        text = notif.body!!,
                        style = AptType.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Spacer(Modifier.size(10.dp))
            val ts = notif.created_at
            if (ts != null) {
                Text(
                    text = fmt.format(Date((ts * 1000).toLong())),
                    style = AptType.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
