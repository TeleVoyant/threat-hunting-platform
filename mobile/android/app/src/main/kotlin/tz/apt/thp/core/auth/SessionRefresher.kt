package tz.apt.thp.core.auth

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import tz.apt.thp.AppGraph
import tz.apt.thp.core.rbac.Role
import tz.apt.thp.core.rbac.Session
import tz.apt.thp.core.rbac.SessionStore
import tz.apt.thp.data.ApiResult

/**
 * On app open / role-revalidation, calls GET /auth/me and updates the
 * SessionStore + persisted role so the bottom-bar tab visibility reflects
 * any server-side promotion / demotion (e.g. an admin changing the user's
 * role via the dashboard while the phone was offline).
 *
 * Silent on failure — keeps the persisted role on a network error or 5xx;
 * a 401 surfaces via the existing AuthEvents.signalUnauthorized hook.
 */
@Composable
fun SessionRefresher() {
    val ctx = LocalContext.current
    LaunchedEffect(Unit) {
        val appGraph = AppGraph.from(ctx)
        val api = appGraph.apiClient() ?: return@LaunchedEffect
        val res = withContext(Dispatchers.IO) { api.me() }
        if (res is ApiResult.Ok) {
            val role = Role.from(res.value.role)
            appGraph.prefs.setRole(res.value.role)
            val current = SessionStore.current.value
            if (current != null && current.role != role) {
                SessionStore.set(current.copy(role = role))
            }
        }
    }
}
