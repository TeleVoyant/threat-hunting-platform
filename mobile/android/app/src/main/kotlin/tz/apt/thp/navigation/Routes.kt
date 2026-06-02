package tz.apt.thp.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Inbox
import androidx.compose.material.icons.outlined.Menu
import androidx.compose.material.icons.outlined.ShowChart
import androidx.compose.ui.graphics.vector.ImageVector
import tz.apt.thp.core.rbac.Perm
import tz.apt.thp.core.rbac.PermissionMap
import tz.apt.thp.core.rbac.Role

/**
 * Type-safe route catalog. Every navigable destination lives here so the
 * NavHost wiring and the bottom-bar tab list cannot drift out of sync.
 *
 * Top-level (TabRoute) destinations are surfaced as bottom-bar tabs. Nested
 * destinations (e.g. detail screens, sheets) are reachable from inside a
 * tab's nav graph and do not appear in the bar.
 */
sealed interface AptRoute {
    val path: String
}

/** Top-level tabs. Visibility is gated by `requiredPerm`. */
enum class TabRoute(
    override val path: String,
    val label: String,
    val icon: ImageVector,
    val requiredPerm: String? = null,
) : AptRoute {
    Inbox(   path = "inbox",   label = "Inbox",   icon = Icons.Outlined.Inbox,         requiredPerm = Perm.READ_ALERTS),
    Fleet(   path = "fleet",   label = "Fleet",   icon = Icons.Outlined.Dns,           requiredPerm = Perm.MANAGE_FLEET),
    Models(  path = "models",  label = "Models",  icon = Icons.Outlined.ShowChart,     requiredPerm = Perm.READ_DETECTIONS),
    Audit(   path = "audit",   label = "Audit",   icon = Icons.Outlined.History,       requiredPerm = Perm.VIEW_AUDIT_LOG),
    More(    path = "more",    label = "More",    icon = Icons.Outlined.Menu,          requiredPerm = null);

    companion object {
        /** Filter to tabs the given role may actually use. */
        fun visibleFor(role: Role): List<TabRoute> = entries.filter { tab ->
            val perm = tab.requiredPerm
            perm == null || PermissionMap.has(role, perm)
        }
    }
}

/** Nested routes inside the Inbox tab. */
object InboxRoutes {
    const val LIST   = "inbox/list"
    const val DETAIL = "inbox/detail/{alertId}"
    fun detail(alertId: String) = "inbox/detail/$alertId"
}

/** Nested routes inside the Fleet tab. */
object FleetRoutes {
    const val LIST   = "fleet/list"
    const val AGENT  = "fleet/agent/{agentId}"
    fun agent(agentId: String) = "fleet/agent/$agentId"
}

/** Nested routes inside the Models tab. */
object ModelsRoutes {
    const val LIST    = "models/list"
    const val DETAIL  = "models/detail/{name}"
    fun detail(name: String) = "models/detail/$name"
}

/** Nested routes inside the Audit tab. */
object AuditRoutes {
    const val LIST = "audit/list"
}

/** Nested routes inside the More tab. */
object MoreRoutes {
    const val HOME        = "more/home"
    const val SETTINGS    = "more/settings"
    const val ENROLLMENT  = "more/enrollment"      // operator-mode mint-token UI
    const val DIAGNOSTICS = "more/diagnostics"
    const val ALLOWLIST   = "more/allowlist"
    const val HARDENING   = "more/hardening"
    const val SECRETS     = "more/secrets"
    const val ABOUT       = "more/about"
    const val PENDING     = "more/pending"         // outbox failures inspector
}

/** Top-level (outside-tab) destinations. */
object RootRoutes {
    const val ENROLL = "enroll"
    const val LOCK   = "lock"
    const val TABS   = "tabs"
}
