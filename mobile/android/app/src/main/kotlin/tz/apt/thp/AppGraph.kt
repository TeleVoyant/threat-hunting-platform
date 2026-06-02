package tz.apt.thp

import android.content.Context
import tz.apt.thp.core.sync.OutboxRepository
import tz.apt.thp.data.ApiClient
import tz.apt.thp.data.Prefs

/**
 * Application-level service locator. Manages singletons that depend on a
 * Context but should not be constructed per-screen — ApiClient, Prefs,
 * Outbox, etc.
 *
 * Why a service locator instead of Hilt? Hilt's KSP/KAPT setup roughly
 * doubles cold-build time on this small project and adds non-trivial
 * complexity (per-module modules, ViewModel binding boilerplate). For ~20
 * features sharing a stable dependency graph, manual wiring is faster to
 * read and to reason about. Each feature pulls what it needs through
 * [AppGraph.from(context)] inside its ViewModel factory.
 */
class AppGraph private constructor(private val appContext: Context) {

    val prefs: Prefs by lazy { Prefs.get(appContext) }
    val outbox: OutboxRepository by lazy { OutboxRepository.get(appContext) }

    /**
     * Returns an ApiClient configured for the current session. Returns null
     * if the user has not yet enrolled — callers should redirect to enrol.
     */
    fun apiClient(): ApiClient? {
        val server = prefs.serverUrl() ?: return null
        val key = prefs.apiKey() ?: return null
        return ApiClient(server, key)
    }

    companion object {
        @Volatile private var instance: AppGraph? = null

        fun from(context: Context): AppGraph = instance ?: synchronized(this) {
            instance ?: AppGraph(context.applicationContext).also { instance = it }
        }
    }
}
