package tz.apt.thp.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tz.apt.thp.BuildConfig
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.rbac.SessionStore

@Composable
fun AboutRoute(onBack: () -> Unit) {
    val session by SessionStore.current.collectAsState()
    Column(
        modifier = Modifier.fillMaxSize().padding(Spacing.lg),
        verticalArrangement = Arrangement.spacedBy(Spacing.md),
    ) {
        Text("About", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row2("App name",   "APT THP Companion")
                Row2("Version",    "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                Row2("Server",     session?.serverUrl ?: "—")
                Row2("Signed in",  session?.username ?: "—")
                Row2("Role",       session?.role?.name?.lowercase() ?: "—")
            }
        }
    }
}

@Composable
private fun Row2(label: String, value: String) {
    Column {
        Text(label.uppercase(), style = AptType.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = AptType.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}
