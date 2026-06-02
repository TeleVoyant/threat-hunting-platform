package tz.apt.thp.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.navigation
import androidx.navigation.navArgument
import tz.apt.thp.core.design.panelRightEnter
import tz.apt.thp.core.design.panelRightExit
import tz.apt.thp.core.design.sharedAxisHorizontalEnter
import tz.apt.thp.core.design.sharedAxisHorizontalExit
import tz.apt.thp.feature.audit.AuditRoute
import tz.apt.thp.feature.fleet.AgentDetailRoute
import tz.apt.thp.feature.fleet.FleetRoute
import tz.apt.thp.feature.inbox.InboxRoute
import tz.apt.thp.feature.inbox.InvestigationRoute
import tz.apt.thp.feature.models.ModelDetailRoute
import tz.apt.thp.feature.models.ModelsRoute
import tz.apt.thp.feature.more.AboutRoute
import tz.apt.thp.feature.more.AllowlistRoute
import tz.apt.thp.feature.more.DiagnosticsRoute
import tz.apt.thp.feature.more.EnrollmentRoute
import tz.apt.thp.feature.more.HardeningRoute
import tz.apt.thp.feature.more.MoreHomeRoute
import tz.apt.thp.feature.more.PendingRoute
import tz.apt.thp.feature.more.SecretsRoute
import tz.apt.thp.feature.more.SettingsRoute

/**
 * Root NavHost for the enrolled-and-unlocked half of the app. Each top-level
 * tab is its own nested navigation graph so the back stack of one tab is
 * isolated from another (Material's "tab persistence" pattern).
 */
@Composable
fun AptNavHost(
    navController: NavHostController,
    modifier: Modifier = Modifier,
) {
    NavHost(
        navController = navController,
        startDestination = TabRoute.Inbox.path,
        modifier = modifier,
        enterTransition = { sharedAxisHorizontalEnter(this, forward = true) },
        exitTransition  = { sharedAxisHorizontalExit(this, forward = true) },
        popEnterTransition = { sharedAxisHorizontalEnter(this, forward = false) },
        popExitTransition  = { sharedAxisHorizontalExit(this, forward = false) },
    ) {
        // ─── Inbox tab ─────────────────────────────────────────────────
        navigation(startDestination = InboxRoutes.LIST, route = TabRoute.Inbox.path) {
            composable(InboxRoutes.LIST) {
                InboxRoute(
                    onOpenAlert = { id -> navController.navigate(InboxRoutes.detail(id)) },
                )
            }
            composable(
                InboxRoutes.DETAIL,
                arguments = listOf(navArgument("alertId") { type = NavType.StringType }),
                enterTransition = { panelRightEnter() },
                exitTransition  = { panelRightExit() },
            ) { backStackEntry ->
                val id = backStackEntry.arguments?.getString("alertId").orEmpty()
                InvestigationRoute(
                    alertId = id,
                    onClose = { navController.popBackStack() },
                )
            }
        }

        // ─── Fleet tab ─────────────────────────────────────────────────
        navigation(startDestination = FleetRoutes.LIST, route = TabRoute.Fleet.path) {
            composable(FleetRoutes.LIST) {
                FleetRoute(
                    onOpenAgent = { id -> navController.navigate(FleetRoutes.agent(id)) },
                )
            }
            composable(
                FleetRoutes.AGENT,
                arguments = listOf(navArgument("agentId") { type = NavType.StringType }),
            ) { backStackEntry ->
                val id = backStackEntry.arguments?.getString("agentId").orEmpty()
                AgentDetailRoute(agentId = id, onClose = { navController.popBackStack() })
            }
        }

        // ─── Models tab ────────────────────────────────────────────────
        navigation(startDestination = ModelsRoutes.LIST, route = TabRoute.Models.path) {
            composable(ModelsRoutes.LIST) {
                ModelsRoute(
                    onOpenDetector = { name -> navController.navigate(ModelsRoutes.detail(name)) },
                )
            }
            composable(
                ModelsRoutes.DETAIL,
                arguments = listOf(navArgument("name") { type = NavType.StringType }),
            ) { backStackEntry ->
                val name = backStackEntry.arguments?.getString("name").orEmpty()
                ModelDetailRoute(detectorName = name, onClose = { navController.popBackStack() })
            }
        }

        // ─── Audit tab ─────────────────────────────────────────────────
        navigation(startDestination = AuditRoutes.LIST, route = TabRoute.Audit.path) {
            composable(AuditRoutes.LIST) { AuditRoute() }
        }

        // ─── More tab ──────────────────────────────────────────────────
        navigation(startDestination = MoreRoutes.HOME, route = TabRoute.More.path) {
            composable(MoreRoutes.HOME) {
                MoreHomeRoute(
                    onOpen = { route -> navController.navigate(route) },
                )
            }
            composable(MoreRoutes.SETTINGS)    { SettingsRoute(onBack = { navController.popBackStack() }) }
            composable(MoreRoutes.ENROLLMENT)  { EnrollmentRoute(onBack = { navController.popBackStack() }) }
            composable(MoreRoutes.DIAGNOSTICS) { DiagnosticsRoute(onBack = { navController.popBackStack() }) }
            composable(MoreRoutes.ALLOWLIST)   { AllowlistRoute(onBack = { navController.popBackStack() }) }
            composable(MoreRoutes.HARDENING)   { HardeningRoute(onBack = { navController.popBackStack() }) }
            composable(MoreRoutes.SECRETS)     { SecretsRoute(onBack = { navController.popBackStack() }) }
            composable(MoreRoutes.ABOUT)       { AboutRoute(onBack = { navController.popBackStack() }) }
            composable(MoreRoutes.PENDING)     { PendingRoute(onBack = { navController.popBackStack() }) }
        }
    }
}
