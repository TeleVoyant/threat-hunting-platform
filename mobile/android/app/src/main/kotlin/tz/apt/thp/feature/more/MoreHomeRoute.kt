package tz.apt.thp.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AdminPanelSettings
import androidx.compose.material.icons.outlined.BugReport
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.PendingActions
import androidx.compose.material.icons.outlined.QrCode2
import androidx.compose.material.icons.outlined.Rule
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.rbac.Perm
import tz.apt.thp.core.rbac.PermissionMap
import tz.apt.thp.core.rbac.Role
import tz.apt.thp.core.rbac.SessionStore
import tz.apt.thp.navigation.MoreRoutes

/**
 * Role-aware tile grid surfacing the long tail of features that don't
 * deserve a top-level tab. Tiles are filtered by the permission the
 * underlying route needs. Layout is identical for every role; the grid
 * just renders fewer cells for lower-role users.
 */
@Composable
fun MoreHomeRoute(onOpen: (String) -> Unit) {
    val session by SessionStore.current.collectAsState()
    val role = session?.role ?: Role.UNKNOWN

    val tiles = listOf(
        MoreTile("Settings",    Icons.Outlined.Settings,             MoreRoutes.SETTINGS,    null),
        MoreTile("Pending",     Icons.Outlined.PendingActions,       MoreRoutes.PENDING,     null),
        MoreTile("About",       Icons.Outlined.Info,                 MoreRoutes.ABOUT,       null),
        MoreTile("Enrollment",  Icons.Outlined.QrCode2,              MoreRoutes.ENROLLMENT,  Perm.ENROLL_AGENTS),
        MoreTile("Diagnostics", Icons.Outlined.BugReport,            MoreRoutes.DIAGNOSTICS, Perm.MANAGE_DETECTORS),
        MoreTile("Allowlist",   Icons.Outlined.Rule,                 MoreRoutes.ALLOWLIST,   Perm.MANAGE_DETECTORS),
        MoreTile("Hardening",   Icons.Outlined.Shield,               MoreRoutes.HARDENING,   Perm.VIEW_AUDIT_LOG),
        MoreTile("Secrets",     Icons.Outlined.Key,                  MoreRoutes.SECRETS,     Perm.MANAGE_USERS),
    ).filter { it.perm == null || PermissionMap.has(role, it.perm) }

    LazyVerticalGrid(
        columns = GridCells.Fixed(2),
        modifier = Modifier.fillMaxSize().padding(Spacing.lg),
        horizontalArrangement = Arrangement.spacedBy(Spacing.md),
        verticalArrangement = Arrangement.spacedBy(Spacing.md),
    ) {
        items(tiles, key = { it.route }) { tile ->
            AptCard(onClick = { onOpen(tile.route) }, padding = Spacing.lg) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(tile.icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(tile.label, style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                }
            }
        }
    }
}

private data class MoreTile(
    val label: String,
    val icon: ImageVector,
    val route: String,
    val perm: String?,
)
