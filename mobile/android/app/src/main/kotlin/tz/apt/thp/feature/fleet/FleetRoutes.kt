package tz.apt.thp.feature.fleet

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.design.components.StatusPill
import tz.apt.thp.data.Agent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Field Ops Pack — Fleet list. Searchable agent inventory; tap an agent to
 * drill into the per-agent action sheet. No bulk multi-select on mobile (by
 * design — dashboards do bulk, phones do single-target actions).
 */
@Composable
fun FleetRoute(onOpenAgent: (String) -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: FleetViewModel = viewModel(factory = FleetViewModel.Factory(appGraph))
    val state by vm.state.collectAsState()
    val snackbarHost = remember { SnackbarHostState() }

    LaunchedEffect(state.lastCommandResult) {
        state.lastCommandResult?.let {
            snackbarHost.showSnackbar(it)
            vm.clearLastResult()
        }
    }

    val filteredAgents = remember(state.agents, state.query) {
        if (state.query.isBlank()) state.agents
        else state.agents.filter { a -> a.agent_id.contains(state.query, ignoreCase = true) }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Fleet", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
                IconButton(onClick = { vm.refresh() }) {
                    Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
                }
            }

            Spacer(Modifier.height(Spacing.sm))

            OutlinedTextField(
                value = state.query,
                onValueChange = { vm.setQuery(it) },
                placeholder = { Text("Filter by agent id…") },
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(Spacing.sm))

            if (filteredAgents.isEmpty()) {
                AptCard {
                    Text(
                        text = state.error ?: "No agents enrolled yet. Mint a token in More → Enrollment.",
                        style = AptType.bodyMedium,
                        color = if (state.error != null) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                    items(filteredAgents, key = { it.agent_id }) { agent ->
                        AgentRow(
                            agent = agent,
                            liveHandlerVersion = state.liveHandlerVersion,
                            onOpen = { onOpenAgent(agent.agent_id) },
                        )
                    }
                }
            }
        }
        SnackbarHost(
            snackbarHost,
            modifier = Modifier.align(Alignment.BottomCenter).padding(Spacing.md),
        )
    }
}

@Composable
private fun AgentRow(
    agent: Agent,
    liveHandlerVersion: String?,
    onOpen: () -> Unit,
) {
    val fmt = remember { SimpleDateFormat("MMM d HH:mm", Locale.US) }
    val lastSeenLabel = agent.last_seen_at?.let {
        fmt.format(Date((it * 1000).toLong()))
    } ?: "never"
    val display = agentDisplay(agent)
    val handler = handlerPillState(agent.handler_version, liveHandlerVersion)

    AptCard(onClick = onOpen) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    agent.agent_id,
                    style = AptType.mono,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "${agent.profile ?: "—"} · last seen $lastSeenLabel",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // Handler-version line — only when we have any signal at
                // all. Server-reported "—" still renders as muted text
                // because a brand-new install before its first heartbeat
                // shouldn't look broken.
                handler?.subtitleLine?.let { sub ->
                    Text(
                        sub,
                        style = AptType.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(4.dp)) {
                StatusPill(label = display.label, status = display.statusKeyword)
                handler?.let {
                    StatusPill(label = it.pillLabel, status = it.pillStatus)
                }
            }
        }
    }
}

/**
 * Pill display for an agent — label + a coarse status keyword that the
 * StatusPill component maps to the brand colour palette.
 *
 *   last_seen ages out (5 min stale, 30 min offline) — those take priority.
 *   Otherwise the agent's server-reported `last_status` wins, including the
 *   `isolated:<level>` and `panic-unisolated:<level>:<reason>` forms emitted
 *   by the isolation handler's heartbeat.
 */
internal data class AgentDisplay(val label: String, val statusKeyword: String)

internal fun agentDisplay(agent: Agent): AgentDisplay {
    val lastSeen = agent.last_seen_at
    if (lastSeen == null) return AgentDisplay("OFFLINE", "offline")
    val ageSec = (System.currentTimeMillis() / 1000.0) - lastSeen
    if (ageSec >= 30 * 60) return AgentDisplay("OFFLINE", "offline")
    if (ageSec >= 5  * 60) return AgentDisplay("STALE", "stale")

    val raw = agent.last_status?.lowercase().orEmpty()
    return when {
        raw.startsWith("isolated:") -> {
            val level = raw.removePrefix("isolated:").substringBefore(":").uppercase()
            // Light is intentionally lighter-touch — amber instead of red.
            val keyword = if (level == "LIGHT") "warn" else "error"
            AgentDisplay("ISOLATED · $level", keyword)
        }
        raw.startsWith("panic-unisolated:") -> {
            val level = raw.removePrefix("panic-unisolated:").substringBefore(":").uppercase()
            AgentDisplay("PANIC RECOVERED · $level", "warn")
        }
        raw.isBlank() || raw == "ok" -> AgentDisplay("OK", "ok")
        else -> AgentDisplay(raw.uppercase(), "warn")
    }
}

/** Legacy single-string status. Kept for back-compat with any direct callers. */
private fun agentStatus(agent: Agent): String = agentDisplay(agent).statusKeyword

/**
 * Pill state for the handler-version column.
 *
 *   green "LATEST"      — agent's installed version == server live version
 *   amber "<version>"   — agent on a non-live version (out of date or staged)
 *   grey  "NO VER"      — agent hasn't reported a version yet (fresh install)
 *
 * Returns null when both the server has no live version AND the agent has
 * no reported version — nothing useful to show, hide the pill entirely.
 */
internal data class HandlerPillState(
    val pillLabel: String,
    val pillStatus: String,
    val subtitleLine: String?,
    val isOutOfDate: Boolean,
)

internal fun handlerPillState(
    agentVersion: String?,
    liveVersion: String?,
): HandlerPillState? {
    if (liveVersion.isNullOrBlank() && agentVersion.isNullOrBlank()) return null
    return when {
        agentVersion.isNullOrBlank() -> HandlerPillState(
            pillLabel    = "NO VER",
            pillStatus   = "unknown",
            subtitleLine = "handler: not reported",
            isOutOfDate  = liveVersion != null,
        )
        liveVersion.isNullOrBlank() -> HandlerPillState(
            pillLabel    = "v${agentVersion.removePrefix("v")}",
            pillStatus   = "warn",
            subtitleLine = "handler: $agentVersion (no live version on server)",
            isOutOfDate  = false,
        )
        agentVersion == liveVersion -> HandlerPillState(
            pillLabel    = "LATEST",
            pillStatus   = "ok",
            subtitleLine = "handler: $agentVersion",
            isOutOfDate  = false,
        )
        else -> HandlerPillState(
            pillLabel    = "OUT OF DATE",
            pillStatus   = "warn",
            subtitleLine = "handler: $agentVersion → live $liveVersion",
            isOutOfDate  = true,
        )
    }
}
