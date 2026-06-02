package tz.apt.thp.core.rbac

import androidx.compose.runtime.staticCompositionLocalOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Authenticated session as known to the mobile UI. Mirrors what the server
 * tells us via `/auth/exchange-enroll` + `/auth/me`. Held as a process-wide
 * MutableStateFlow so role-aware UI re-composes on cold-start refresh.
 */
data class Session(
    val username: String,
    val role: Role,
    val serverUrl: String,
)

object SessionStore {
    private val _current = MutableStateFlow<Session?>(null)
    val current: StateFlow<Session?> = _current

    fun set(session: Session?) { _current.value = session }
    fun clear() { _current.value = null }
    fun role(): Role = _current.value?.role ?: Role.UNKNOWN
    fun hasPermission(perm: String): Boolean = PermissionMap.has(role(), perm)
}

/**
 * CompositionLocal that carries the active session into the tree. NOT a
 * source of truth — the SessionStore flow is. This is just a thin reader so
 * RequirePermission { … } and tab-visibility helpers don't have to plumb
 * the flow down through every composable.
 */
val LocalSession = staticCompositionLocalOf<Session?> { null }
