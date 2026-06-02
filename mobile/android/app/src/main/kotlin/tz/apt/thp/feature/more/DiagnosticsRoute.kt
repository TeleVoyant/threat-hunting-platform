package tz.apt.thp.feature.more

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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
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
import tz.apt.thp.data.ServiceHealth

/**
 * Service health snapshot. Pull-to-refresh only — no live tail (battery +
 * bandwidth). The status pill maps the server's free-text status onto the
 * brand's ok / warn / err / unknown palette.
 */
@Composable
fun DiagnosticsRoute(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val scope = rememberCoroutineScope()
    var services by remember { mutableStateOf<List<ServiceHealth>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }

    fun refresh() {
        scope.launch {
            error = null
            val api = appGraph.apiClient() ?: run { error = "Not enrolled"; return@launch }
            val res = withContext(Dispatchers.IO) { api.diagServices() }
            when (res) {
                is ApiResult.Ok      -> services = res.value
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
            Text("Diagnostics", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { refresh() }) {
                Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
            }
        }
        Spacer(Modifier.height(Spacing.sm))

        if (services.isEmpty()) {
            AptCard {
                Text(
                    text = error ?: "Loading service health…",
                    style = AptType.bodyMedium,
                    color = if (error != null) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                items(services, key = { it.name }) { svc -> ServiceCard(svc) }
            }
        }
    }
}

@Composable
private fun ServiceCard(svc: ServiceHealth) {
    AptCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(svc.name, style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                svc.detail?.let {
                    Text(
                        it,
                        style = AptType.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            StatusPill(label = svc.status.uppercase(), status = svc.status)
        }
    }
}
