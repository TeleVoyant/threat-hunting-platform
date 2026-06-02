package tz.apt.thp.core.rbac

/**
 * Mobile mirror of `shared/security.py:PERMISSIONS`. Keep in lockstep with
 * the server's table whenever permissions change. Unknown role → no perms.
 *
 * Convention: permission names match the server strings exactly (snake_case)
 * so audit-log diagnostics across web + mobile align.
 */
object PermissionMap {

    private val viewer = setOf(
        Perm.READ_ALERTS,
        Perm.READ_DETECTIONS,
        Perm.VIEW_GRAPHS,
    )

    private val analyst = viewer + setOf(
        Perm.ACKNOWLEDGE_ALERTS,
        Perm.ADD_NOTES,
        Perm.EXPORT_DATA,
    )

    private val operator = analyst + setOf(
        Perm.UPDATE_THRESHOLDS,
        Perm.MANAGE_DETECTORS,
        Perm.MANAGE_FLEET,
    )

    private val admin = operator + setOf(
        Perm.ENROLL_AGENTS,
        Perm.RETRAIN_MODELS,
        Perm.MANAGE_USERS,
        Perm.VIEW_AUDIT_LOG,
        Perm.MANAGE_FL_LOCAL,
    )

    private val table = mapOf(
        Role.VIEWER   to viewer,
        Role.ANALYST  to analyst,
        Role.OPERATOR to operator,
        Role.ADMIN    to admin,
        Role.UNKNOWN  to emptySet(),
    )

    fun has(role: Role, perm: String): Boolean =
        perm in (table[role] ?: emptySet())

    fun permissionsOf(role: Role): Set<String> = table[role].orEmpty()
}

/** Permission constants — string values MUST match `shared/security.py`. */
object Perm {
    const val READ_ALERTS        = "read_alerts"
    const val READ_DETECTIONS    = "read_detections"
    const val VIEW_GRAPHS        = "view_graphs"
    const val ACKNOWLEDGE_ALERTS = "acknowledge_alerts"
    const val ADD_NOTES          = "add_notes"
    const val EXPORT_DATA        = "export_data"
    const val UPDATE_THRESHOLDS  = "update_thresholds"
    const val MANAGE_DETECTORS   = "manage_detectors"
    const val MANAGE_FLEET       = "manage_fleet"
    const val ENROLL_AGENTS      = "enroll_agents"
    const val RETRAIN_MODELS     = "retrain_models"
    const val MANAGE_USERS       = "manage_users"
    const val VIEW_AUDIT_LOG     = "view_audit_log"
    const val MANAGE_FL_LOCAL    = "manage_fl_local"
}
