package tz.apt.thp.feature.fleet

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Upgrade
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import kotlinx.coroutines.launch
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import tz.apt.thp.AppGraph
import tz.apt.thp.core.auth.rememberBiometricStepUp
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.design.components.StatusPill
import tz.apt.thp.data.Agent

/**
 * Per-agent action sheet. Non-destructive actions (get_status) fire
 * directly; destructive actions (isolate / unisolate / rotate-secret) go
 * through the offline outbox so they survive a tunnel drop and surface
 * coherently in the Pending sheet.
 *
 * Isolate opens a bottom-sheet picker so the operator chooses level + TTL +
 * reason before the command is queued.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AgentDetailRoute(agentId: String, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: FleetViewModel = viewModel(factory = FleetViewModel.Factory(appGraph))
    val state by vm.state.collectAsState()

    val agent = state.agents.firstOrNull { it.agent_id == agentId }

    var showIsolateSheet by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        // Topbar
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) {
                Icon(Icons.Outlined.ArrowBack, contentDescription = "Back")
            }
            Text("Agent", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
        }

        Spacer(Modifier.height(Spacing.md))

        // Identity card — three fields on ONE ROW (agent id | profile | last
        // status) so the operator gets the at-a-glance summary without
        // scrolling. Each column has its own label-over-value stack and
        // shares horizontal space via weight(1f). Long agent_ids ellipsise
        // rather than wrap so the row height stays predictable.
        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(Spacing.md),
                    verticalAlignment = Alignment.Top,
                ) {
                    InfoColumn(
                        label = "Agent id",
                        value = agentId,
                        mono  = true,
                        modifier = Modifier.weight(1.4f),
                    )
                    InfoColumn(
                        label = "Profile",
                        value = agent?.profile ?: "—",
                        modifier = Modifier.weight(0.8f),
                    )
                    InfoColumn(
                        label = "Last status",
                        value = agent?.last_status ?: "—",
                        modifier = Modifier.weight(1f),
                    )
                }
                if (agent != null && agent.pending_commands > 0) {
                    StatusPill(
                        label = "${agent.pending_commands} pending",
                        status = "warn",
                    )
                }
            }
        }

        Spacer(Modifier.height(Spacing.md))

        // Handler-version card — visible whenever we have any signal
        // (either the agent reported a version, or the server has a live
        // version, or both). Surfaces the same LATEST / out-of-date logic
        // as the fleet list row but with a paragraph-length explanation.
        val handler = handlerPillState(agent?.handler_version, state.liveHandlerVersion)
        if (handler != null) {
            AptCard {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "Handler script",
                            style = AptType.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        StatusPill(label = handler.pillLabel, status = handler.pillStatus)
                    }
                    Text(
                        agent?.handler_version ?: "not reported",
                        style = AptType.mono,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    state.liveHandlerVersion?.let { live ->
                        Text(
                            "live: $live",
                            style = AptType.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            Spacer(Modifier.height(Spacing.md))
        }

        // UPDATE FAILED card — only when the agent's last OTA self-verify
        // failed. The agent has auto-rolled back to .bak so it's still
        // running a working version, but the LATEST push didn't take.
        // Operator can tap "Retry push" to re-fire the same live version
        // (idempotent on the agent side).
        val updStatus = agent?.handler_update_status
        if (updStatus != null && updStatus != "ok") {
            AptCard(
                containerColor = MaterialTheme.colorScheme.errorContainer,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "OTA UPDATE FAILED",
                            style = AptType.titleSmall,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                        StatusPill(label = updStatus, status = "crit")
                    }
                    agent.handler_update_bad_version?.let { bad ->
                        Text(
                            "Failed version: $bad",
                            style = AptType.mono,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                    }
                    Text(
                        "Now running: ${agent.handler_version ?: "—"}",
                        style = AptType.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    agent.handler_update_detail?.let { detail ->
                        Text(
                            detail,
                            style = AptType.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Button(
                        onClick = rememberBiometricStepUp(
                            "Retry OTA for $agentId", alwaysPrompt = true,
                        ) { vm.retryHandlerUpdate(agentId) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                            contentColor   = MaterialTheme.colorScheme.onError,
                        ),
                    ) {
                        Icon(Icons.Outlined.Refresh, contentDescription = null)
                        Spacer(Modifier.size(8.dp))
                        Text("Retry push")
                    }
                }
            }
            Spacer(Modifier.height(Spacing.md))
        }

        Text("Actions", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)

        Spacer(Modifier.height(Spacing.sm))

        // Non-destructive
        ActionButton(
            label = "Get status",
            icon = Icons.Outlined.Info,
            onClick = { vm.sendCommand(agentId, "get_status") },
        )

        Spacer(Modifier.height(Spacing.sm))

        // Destructive — funnelled through the outbox AND gated behind a
        // biometric step-up so a stolen unlocked phone can't fire any of
        // these. The 5-min grace inside BiometricGate keeps the prompt
        // chain ergonomic when the operator runs several actions in a row.
        //
        // Isolate + Unisolate share a row: they're conceptually paired
        // (apply / lift containment) and putting them side-by-side mirrors
        // the dashboard's per-row action layout — saves vertical scrolling
        // on small phones and makes the "wrong button" mistake harder.
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(Spacing.sm),
        ) {
            ActionButton(
                label = "Isolate",
                icon = Icons.Outlined.Block,
                destructive = true,
                // Sheet open is unauthenticated — operator may want to inspect
                // the level descriptions / TTL slider before committing. The
                // biometric gates the sheet's final Confirm below.
                onClick = { showIsolateSheet = true },
                modifier = Modifier.weight(1f),
            )
            ActionButton(
                label = "Unisolate",
                icon = Icons.Outlined.LockOpen,
                // alwaysPrompt: lifting containment on a possibly-compromised
                // host is higher-stakes than applying it — never honour a grace
                // from an unrelated recent action.
                onClick = rememberBiometricStepUp(
                    "Unisolate $agentId", alwaysPrompt = true,
                ) {
                    vm.queueDestructive(agentId, "unisolate")
                },
                modifier = Modifier.weight(1f),
            )
        }

        Spacer(Modifier.height(Spacing.sm))

        ActionButton(
            label = "Rotate secret",
            icon = Icons.Outlined.VpnKey,
            destructive = true,
            // alwaysPrompt: agent goes silent until re-enrolled; disruptive
            // to fleet visibility and not what a passer-by should be able to
            // trigger by piggybacking on a 4-min-old unlock.
            onClick = rememberBiometricStepUp(
                "Rotate secret for $agentId", alwaysPrompt = true,
            ) {
                vm.queueRotateSecret(agentId)
            },
        )

        // Handler OTA actions — only meaningful when there's a server-side
        // live version to push and the agent isn't already on it. Hide the
        // push button entirely on a matching version (no clutter); always
        // show the rollback so the operator can swap to .bak even when on
        // latest (e.g. if a brand-new live version starts misbehaving and
        // .bak is the previous known-good).
        if (handler != null && handler.isOutOfDate) {
            Spacer(Modifier.height(Spacing.sm))
            ActionButton(
                label = "Push latest handler"
                       + (state.liveHandlerVersion?.let { " ($it)" } ?: ""),
                icon = Icons.Outlined.Upgrade,
                destructive = true,   // rewrites endpoint code → red treatment
                // alwaysPrompt: replaces the endpoint's executing code; the
                // single most destructive thing the operator can do from
                // mobile. Never piggyback on a stale unlock.
                onClick = rememberBiometricStepUp(
                    "Push latest handler to $agentId", alwaysPrompt = true,
                ) {
                    vm.queuePushHandler(agentId)
                },
            )
        }

        Spacer(Modifier.height(Spacing.sm))

        ActionButton(
            label = "Rollback handler",
            icon = Icons.Outlined.History,
            destructive = true,
            // alwaysPrompt: rollback restores the .bak from disk; on an
            // already-rolled-back endpoint the server returns 'rejected'
            // via the command-result path, surfaced in lastCommandResult.
            onClick = rememberBiometricStepUp(
                "Rollback handler for $agentId", alwaysPrompt = true,
            ) {
                vm.queueRollbackHandler(agentId)
            },
        )

        Spacer(Modifier.height(Spacing.lg))

        state.lastCommandResult?.let { msg ->
            AptCard {
                Text(msg, style = AptType.bodyMedium, color = MaterialTheme.colorScheme.primary)
            }
        }
    }

    if (showIsolateSheet) {
        val ctx = LocalContext.current
        val activity = ctx as? androidx.fragment.app.FragmentActivity
        IsolateLevelSheet(
            agentId = agentId,
            onDismiss = { showIsolateSheet = false },
            onConfirm = { level, ttlMin, reason ->
                val fire: () -> Unit = {
                    vm.queueIsolate(agentId, level, ttlMin, reason)
                    showIsolateSheet = false
                }
                if (activity != null) {
                    // alwaysPrompt: isolation is a high-blast-radius action
                    // (denies the endpoint user network access). reset()
                    // before gateSensitive forces a fresh biometric every
                    // time, regardless of any recent unlock from another
                    // action.
                    tz.apt.thp.security.BiometricGate.reset()
                    tz.apt.thp.security.BiometricGate.gateSensitive(
                        activity,
                        action = "Isolate $agentId at $level",
                        onPass = fire,
                        onFail = { /* user cancelled; leave sheet open */ },
                    )
                } else {
                    fire()
                }
            },
        )
    }
}

private val TTL_STOPS = listOf(15, 30, 60, 120, 240, 480, 960, 1440) // minutes

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun IsolateLevelSheet(
    agentId: String,
    onDismiss: () -> Unit,
    onConfirm: (level: String, ttlMinutes: Int, reason: String) -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var selectedLevel by remember { mutableStateOf("standard") }
    var ttlIndex by remember { mutableFloatStateOf(4f) } // default index → 240 min
    var reason by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    val ttlMinutes = TTL_STOPS[ttlIndex.toInt().coerceIn(0, TTL_STOPS.size - 1)]
    val ttlLabel = when {
        ttlMinutes < 60   -> "$ttlMinutes min"
        ttlMinutes < 1440 -> "${ttlMinutes / 60} h"
        else              -> "${ttlMinutes / 60} h (24 h cap)"
    }

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(modifier = Modifier.padding(Spacing.lg)) {
            Text("Isolate ", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            Text(
                agentId,
                style = AptType.mono,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )

            Spacer(Modifier.height(Spacing.md))

            // Level picker
            Text("Level", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
            LevelOption(
                label = "Light",
                description = "Block lateral movement (SMB, RDP, WinRM) + non-corp DNS. User keeps browsing.",
                selected = selectedLevel == "light",
                onSelect = { selectedLevel = "light" },
            )
            LevelOption(
                label = "Standard",
                description = "Cut public internet, keep LAN. User sees a notification.",
                selected = selectedLevel == "standard",
                onSelect = { selectedLevel = "standard" },
            )
            LevelOption(
                label = "Full",
                description = "Block all except platform lifeline; disable VPN/virtual adapters; toast.",
                selected = selectedLevel == "full",
                onSelect = { selectedLevel = "full" },
            )

            Spacer(Modifier.height(Spacing.md))

            // TTL slider
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Auto-unisolate in", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(ttlLabel, style = AptType.mono, color = MaterialTheme.colorScheme.primary)
            }
            Slider(
                value = ttlIndex,
                onValueChange = { ttlIndex = it },
                valueRange = 0f..(TTL_STOPS.size - 1).toFloat(),
                steps = TTL_STOPS.size - 2,
            )

            Spacer(Modifier.height(Spacing.md))

            OutlinedTextField(
                value = reason,
                onValueChange = { if (it.length <= 200) reason = it },
                label = { Text("Reason (optional, audit-logged)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = false,
                minLines = 2,
            )

            Spacer(Modifier.height(Spacing.lg))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(Spacing.sm),
            ) {
                TextButton(
                    onClick = { scope.launch { sheetState.hide(); onDismiss() } },
                    modifier = Modifier.weight(1f),
                ) { Text("Cancel") }
                Button(
                    onClick = { onConfirm(selectedLevel, ttlMinutes, reason) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor   = MaterialTheme.colorScheme.onErrorContainer,
                    ),
                ) { Text("Isolate") }
            }
        }
    }
}

@Composable
private fun LevelOption(
    label: String,
    description: String,
    selected: Boolean,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onSelect)
        Column(modifier = Modifier.weight(1f).padding(start = 8.dp)) {
            Text(label, style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
            Text(description, style = AptType.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ActionButton(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit,
    destructive: Boolean = false,
    modifier: Modifier = Modifier.fillMaxWidth(),
) {
    Button(
        onClick = onClick,
        modifier = modifier,
        colors = if (destructive) {
            ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor   = MaterialTheme.colorScheme.onErrorContainer,
            )
        } else {
            ButtonDefaults.buttonColors()
        },
    ) {
        Icon(icon, contentDescription = null)
        Spacer(Modifier.size(8.dp))
        Text(label)
    }
}

/** Label-over-value pair used inside the agent identity card's one-row
 * layout. `mono` flips the value to monospace for agent_ids / SHAs etc. */
@Composable
private fun InfoColumn(
    label: String,
    value: String,
    mono: Boolean = false,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        Text(
            label,
            style = AptType.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = if (mono) AptType.mono else AptType.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
