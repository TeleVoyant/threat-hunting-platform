package tz.apt.thp.feature.inbox

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.OpenInBrowser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import tz.apt.thp.AppGraph
import tz.apt.thp.core.auth.rememberBiometricStepUp
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.design.components.SeverityBadge
import tz.apt.thp.core.rbac.LocalSession
import tz.apt.thp.core.rbac.Perm
import tz.apt.thp.core.rbac.RequirePermission
import tz.apt.thp.data.AlertNote
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Investigation panel — sliding-in detail view for one alert. Hosts:
 *   - severity badge, source entity, alert id (mono)
 *   - MITRE technique chips
 *   - "Model card" stub (placeholder for v0.3 — needs server endpoint)
 *   - SHAP fallback ("View on dashboard" link — iframe doesn't reflow)
 *   - notes timeline
 *   - new-note composer
 *   - Acknowledge CTA
 */
@Composable
fun InvestigationRoute(alertId: String, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: InvestigationViewModel = viewModel(
        key = alertId,
        factory = InvestigationViewModel.Factory(appGraph, alertId),
    )
    val state by vm.state.collectAsState()
    val session = LocalSession.current

    var noteText by rememberSaveable { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        // Topbar
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onClose) {
                    Icon(Icons.Outlined.ArrowBack, contentDescription = "Back")
                }
                Text("Investigation", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            }
            session?.serverUrl?.let { url ->
                TextButton(onClick = {
                    val dashUrl = "$url/dashboard/alerts/$alertId"
                    ctx.openExternal(dashUrl)
                }) {
                    Icon(Icons.Outlined.OpenInBrowser, contentDescription = null)
                    Spacer(Modifier.size(4.dp))
                    Text("Dashboard")
                }
            }
        }

        Spacer(Modifier.height(Spacing.md))

        Column(
            modifier = Modifier.weight(1f).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(Spacing.md),
        ) {

            // ── Summary card ────────────────────────────────────────────
            AptCard {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        state.summary?.overall_severity?.let { sev ->
                            SeverityBadge(severity = sev)
                            Spacer(Modifier.size(8.dp))
                        }
                        Text(
                            text = state.summary?.source_entity ?: "Detection",
                            style = AptType.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    Text("Alert id", style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(alertId, style = AptType.mono, color = MaterialTheme.colorScheme.onSurface)

                    state.summary?.timestamp?.let { ts ->
                        Text("Detected", style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(
                            text = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                                .format(Date((ts * 1000).toLong())),
                            style = AptType.mono,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }

                    state.summary?.status?.let { st ->
                        Text("Status", style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(st, style = AptType.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
                    }
                }
            }

            // ── MITRE techniques ────────────────────────────────────────
            val techs = state.summary?.mitre_techniques.orEmpty()
            if (techs.isNotEmpty()) {
                AptCard {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("MITRE ATT&CK", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                        techs.forEach { t ->
                            Text("• $t", style = AptType.mono, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }

            // ── Notes timeline ──────────────────────────────────────────
            AptCard {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Investigation notes", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                    if (state.notes.isEmpty()) {
                        Text(
                            "No notes yet. Add the first observation below.",
                            style = AptType.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        state.notes.forEach { note -> NoteRow(note) }
                    }
                }
            }
        }

        // ─── Composer + actions ────────────────────────────────────────
        RequirePermission(Perm.ADD_NOTES) {
            OutlinedTextField(
                value = noteText,
                onValueChange = { noteText = it },
                placeholder = { Text("Add a note (queued offline-safe)") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
            )
            Spacer(Modifier.height(8.dp))
            // Capture the current note text for the biometric closure so the
            // gated handler reads the value at confirmation time, not at
            // setup time. alwaysPrompt = true per operator policy: notes go
            // into the audit trail with the operator's identity, and that
            // attribution must never piggyback on a stale unlock.
            val capturedNote = noteText.trim()
            val onPostNote = rememberBiometricStepUp(
                actionLabel = "Post note on $alertId",
                alwaysPrompt = true,
            ) {
                if (capturedNote.isNotBlank()) {
                    vm.postNote(capturedNote)
                    noteText = ""
                }
            }
            // Per operator policy: ack is always a fresh prompt (no grace),
            // even if the user just typed a note 30 s ago. Ack is the
            // accountability anchor for an alert — it should never piggyback
            // on a stale unlock from a less-destructive action.
            val onAck = rememberBiometricStepUp(
                actionLabel = "Acknowledge $alertId",
                alwaysPrompt = true,
            ) { vm.acknowledge() }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onPostNote, enabled = noteText.isNotBlank()) {
                    Text("Post note")
                }
                RequirePermission(Perm.ACKNOWLEDGE_ALERTS) {
                    Button(
                        onClick = onAck,
                        enabled = !state.acked,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary,
                        ),
                    ) {
                        Icon(Icons.Outlined.CheckCircle, contentDescription = null)
                        Spacer(Modifier.size(6.dp))
                        Text(if (state.acked) "Acknowledged" else "Acknowledge")
                    }
                }
            }
        }
    }
}

@Composable
private fun NoteRow(note: AlertNote) {
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(note.actor, style = AptType.labelMedium, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.size(8.dp))
            Text(
                fmt.format(Date((note.at * 1000).toLong())),
                style = AptType.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(note.text, style = AptType.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}

private fun android.content.Context.openExternal(url: String) {
    val intent = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))
    intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { startActivity(intent) }
}
