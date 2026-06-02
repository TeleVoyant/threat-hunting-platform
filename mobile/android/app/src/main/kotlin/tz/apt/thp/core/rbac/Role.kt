package tz.apt.thp.core.rbac

/**
 * Mobile mirror of `shared/security.py:Role`. Kept in lockstep manually —
 * any server-side role addition MUST be reflected here for the role-aware
 * tab bar + RequirePermission gates to work.
 *
 * The server is authoritative — the local enum is purely for hiding UI a
 * user can't action. The HTTP 403 returned by the API is the actual safety
 * net.
 */
enum class Role {
    VIEWER,    // IT admins — read alerts + dashboards
    ANALYST,   // SOC — investigate, ack, take notes
    OPERATOR,  // Senior SOC — adjust thresholds, manage fleet
    ADMIN,     // Platform — retrain, audit, users, FL opt-in
    UNKNOWN;   // Server returned something we don't recognise — show least-privileged UI

    companion object {
        fun from(raw: String?): Role = when (raw?.lowercase()?.trim()) {
            "viewer"   -> VIEWER
            "analyst"  -> ANALYST
            "operator" -> OPERATOR
            "admin"    -> ADMIN
            else       -> UNKNOWN
        }
    }
}
