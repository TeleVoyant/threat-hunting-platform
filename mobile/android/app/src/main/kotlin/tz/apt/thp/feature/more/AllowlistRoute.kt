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
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
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
import tz.apt.thp.data.AllowlistDomain
import tz.apt.thp.data.ApiResult

/**
 * DNS allowlist editor. Inline add + delete. Audit-logged on the server.
 * No CSV import / export on mobile — dashboard only.
 */
@Composable
fun AllowlistRoute(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val scope = rememberCoroutineScope()
    var domains by remember { mutableStateOf<List<AllowlistDomain>>(emptyList()) }
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    fun refresh() {
        scope.launch {
            error = null
            val api = appGraph.apiClient() ?: run { error = "Not enrolled"; return@launch }
            val res = withContext(Dispatchers.IO) { api.listAllowlist() }
            when (res) {
                is ApiResult.Ok      -> domains = res.value.domains
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
            Text("DNS allowlist", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
        }
        Spacer(Modifier.height(Spacing.sm))

        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Entries here are excluded from DNS-exfil detection. Keep the list tight — every entry is an exfil blind spot.",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = input,
                        onValueChange = { input = it },
                        label = { Text("domain.example") },
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.height(8.dp))
                    IconButton(onClick = {
                        if (input.isBlank()) return@IconButton
                        scope.launch {
                            val api = appGraph.apiClient() ?: return@launch
                            val res = withContext(Dispatchers.IO) { api.addAllowlist(input.trim()) }
                            when (res) {
                                is ApiResult.Ok      -> { input = ""; refresh() }
                                is ApiResult.Http    -> error = "${res.code} ${res.message}"
                                is ApiResult.Network -> error = res.cause
                            }
                        }
                    }) {
                        Icon(Icons.Outlined.Add, contentDescription = "Add")
                    }
                }
            }
        }

        Spacer(Modifier.height(Spacing.sm))

        if (domains.isEmpty()) {
            AptCard {
                Text(
                    error ?: "No domains allowlisted.",
                    style = AptType.bodyMedium,
                    color = if (error != null) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                items(domains, key = { it.domain }) { entry ->
                    AptCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(entry.domain, style = AptType.mono, color = MaterialTheme.colorScheme.onSurface)
                                Text(
                                    "added by ${entry.added_by ?: "—"}" +
                                        (entry.note?.let { " · $it" } ?: ""),
                                    style = AptType.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            TextButton(onClick = {
                                scope.launch {
                                    val api = appGraph.apiClient() ?: return@launch
                                    val res = withContext(Dispatchers.IO) { api.removeAllowlist(entry.domain) }
                                    when (res) {
                                        is ApiResult.Ok      -> refresh()
                                        is ApiResult.Http    -> error = "${res.code} ${res.message}"
                                        is ApiResult.Network -> error = res.cause
                                    }
                                }
                            }) {
                                Icon(Icons.Outlined.Delete, contentDescription = "Remove")
                            }
                        }
                    }
                }
            }
        }
    }
}
