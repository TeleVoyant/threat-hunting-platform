package tz.apt.thp.navigation

import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.currentBackStackEntryAsState
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.rbac.Role

/**
 * Five-tab bottom bar with role-aware visibility. Per the plan, unauthorized
 * tabs are HIDDEN entirely (not greyed). Material 3's NavigationBar accepts
 * 3-5 items, so viewer-role users (3 visible tabs) get a coherent layout.
 *
 * Tab re-selection pops back to the tab's start destination, matching the
 * behaviour every other Material 3 app uses.
 */
@Composable
fun AptBottomBar(navController: NavController, role: Role, modifier: Modifier = Modifier) {
    val tabs = TabRoute.visibleFor(role)
    if (tabs.isEmpty()) return

    val backStack by navController.currentBackStackEntryAsState()
    val currentRoute = backStack?.destination?.route.orEmpty()

    NavigationBar(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor   = MaterialTheme.colorScheme.onSurface,
        tonalElevation = 2.dp,
    ) {
        tabs.forEach { tab ->
            val selected = currentRoute.startsWith(tab.path)
            NavigationBarItem(
                selected = selected,
                onClick = {
                    if (selected) return@NavigationBarItem
                    navController.navigate(tab.path) {
                        popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                        launchSingleTop = true
                        restoreState = true
                    }
                },
                icon  = { Icon(tab.icon, contentDescription = tab.label) },
                label = { Text(tab.label, style = AptType.labelSmall) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor   = MaterialTheme.colorScheme.primary,
                    selectedTextColor   = MaterialTheme.colorScheme.primary,
                    indicatorColor      = MaterialTheme.colorScheme.primaryContainer,
                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )
        }
    }
}

