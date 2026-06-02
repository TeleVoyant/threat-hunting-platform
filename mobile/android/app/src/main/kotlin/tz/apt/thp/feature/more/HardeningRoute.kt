package tz.apt.thp.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.design.components.StatusPill
import tz.apt.thp.data.ApiResult
import tz.apt.thp.data.HardeningReport

/**
 * Read-only hardening checklist. The server runs
 * `scripts/audit_compose_hardening.py` and returns stdout. Mobile inspects;
 * fixing happens on the dashboard / shell.
 */
@Composable
fun HardeningRoute(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val scope = rememberCoroutineScope()
    var report by remember { mutableStateOf<HardeningReport?>(null) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun refresh() {
        scope.launch {
            loading = true; error = null
            val api = appGraph.apiClient() ?: run { error = "Not enrolled"; loading = false; return@launch }
            val res = withContext(Dispatchers.IO) { api.hardening() }
            loading = false
            when (res) {
                is ApiResult.Ok      -> report = res.value
                is ApiResult.Http    -> error = "${res.code} ${res.message}"
                is ApiResult.Network -> error = res.cause
            }
        }
    }
    LaunchedEffect(Unit) { refresh() }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.Outlined.ArrowBack, contentDescription = "Back")
            }
            Text("Hardening", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { refresh() }) {
                Icon(Icons.Outlined.Refresh, contentDescription = "Re-run audit")
            }
        }
        Spacer(Modifier.height(Spacing.sm))

        if (loading && report == null) {
            AptCard { Text("Running audit…", style = AptType.bodyMedium, color = MaterialTheme.colorScheme.onSurface) }
        } else {
            report?.let { r ->
                AptCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column {
                            Text("Compose hardening", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                            Text("Exit code ${r.exit_code}", style = AptType.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        StatusPill(
                            label = if (r.passed) "PASSED" else "FAILED",
                            status = if (r.passed) "ok" else "error",
                        )
                    }
                }
                Spacer(Modifier.height(Spacing.sm))
                AptCard {
                    Column(
                        modifier = Modifier.verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        if (r.stdout.isNotBlank()) {
                            Text(r.stdout, style = AptType.mono, color = MaterialTheme.colorScheme.onSurface)
                        }
                        if (r.stderr.isNotBlank()) {
                            Text(r.stderr, style = AptType.mono, color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            } ?: AptCard {
                Text(
                    error ?: "No report yet.",
                    style = AptType.bodyMedium,
                    color = if (error != null) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
