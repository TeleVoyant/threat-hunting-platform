package tz.apt.thp

import android.app.Application
import androidx.work.Configuration
import tz.apt.thp.core.design.ThemeController
import tz.apt.thp.core.rbac.Role
import tz.apt.thp.core.rbac.Session
import tz.apt.thp.core.rbac.SessionStore
import tz.apt.thp.notif.NotifChannels

/**
 * Process entry. Boots:
 *   - the theme preference (synchronous read; no white-flash on first paint)
 *   - the SessionStore (so the bottom tab bar knows the user's role at the
 *     first composition, with the role re-validated against /auth/me on the
 *     first network call)
 *   - the AppGraph (lazy — services materialise on first use)
 *   - notification channels (idempotent)
 *
 * WorkManager is configured via [Configuration.Provider] so the OutboxFlush
 * worker can be constructed without an explicit Hilt graph.
 */
class AptApplication : Application(), Configuration.Provider {

    override fun onCreate() {
        super.onCreate()

        // 1. Theme — synchronous so MainActivity.onCreate sees the value.
        ThemeController.boot(this)

        // 2. Session — restore from encrypted prefs if the user is already
        //    enrolled. Role is re-validated against /auth/me on the first
        //    successful network call (see SessionRefresher).
        val graph = AppGraph.from(this)
        val prefs = graph.prefs
        if (prefs.isEnrolled()) {
            val username = prefs.username() ?: return
            val server = prefs.serverUrl() ?: return
            val role = Role.from(prefs.role())
            SessionStore.set(Session(username = username, role = role, serverUrl = server))
        }

        // 3. Notification channels.
        NotifChannels.ensure(this)
    }

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setMinimumLoggingLevel(android.util.Log.INFO)
            .build()
}
