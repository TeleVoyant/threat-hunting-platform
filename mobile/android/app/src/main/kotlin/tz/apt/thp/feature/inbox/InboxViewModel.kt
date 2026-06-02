package tz.apt.thp.feature.inbox

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tz.apt.thp.AppGraph
import tz.apt.thp.data.AlertStats
import tz.apt.thp.data.ApiResult
import tz.apt.thp.data.Notification

/**
 * State holder for the Inbox screen. Single source of truth for:
 *   - notification list (loaded via /notifications/poll then merged with
 *     anything the foreground SSE service has pushed since)
 *   - severity filter chip
 *   - KPI stats (active hunts / open / critical / high)
 *   - 24h volume buckets (for the sparkline)
 *   - listener "LIVE" indicator (the foreground service writes here)
 *
 * Deliberately framework-light — no Hilt; pulls its dependency graph from
 * [AppGraph]. A simple [Factory] constructs it for `viewModel(...)`.
 */
class InboxViewModel(
    private val appGraph: AppGraph,
) : ViewModel() {

    enum class SevFilter(val label: String) {
        ALL("All"), CRITICAL("Critical"), HIGH("High"), OTHER("Other")
    }

    data class State(
        val notifications: List<Notification> = emptyList(),
        val stats: AlertStats = AlertStats(),
        val volumeBuckets: List<Float> = emptyList(),
        val refreshing: Boolean = false,
        val error: String? = null,
        val filter: SevFilter = SevFilter.ALL,
        val live: Boolean = false,
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    init { refresh() }

    fun setFilter(f: SevFilter) { _state.value = _state.value.copy(filter = f) }

    fun setLive(live: Boolean) { _state.value = _state.value.copy(live = live) }

    fun refresh() {
        viewModelScope.launch {
            _state.value = _state.value.copy(refreshing = true, error = null)
            val api = appGraph.apiClient()
            if (api == null) {
                _state.value = _state.value.copy(
                    refreshing = false,
                    error = "Not enrolled",
                    live = false,
                )
                return@launch
            }

            // Parallel fetch — list + stats + sparkline.
            val notifsResult: ApiResult<List<Notification>>
            val statsResult: ApiResult<AlertStats>
            val tsResult = withContext(Dispatchers.IO) {
                api.alertTimeseries(hours = 24, bucketMinutes = 60)
            }
            notifsResult = withContext(Dispatchers.IO) { api.poll(0.0) }
            statsResult  = withContext(Dispatchers.IO) { api.alertStats() }

            val notifs = (notifsResult as? ApiResult.Ok)?.value
                ?.sortedByDescending { it.created_at ?: 0.0 }
                ?: _state.value.notifications
            val stats = (statsResult as? ApiResult.Ok)?.value ?: _state.value.stats
            val buckets = (tsResult as? ApiResult.Ok)?.value
                ?.buckets?.map { it.total.toFloat() }
                ?: _state.value.volumeBuckets

            val err = when {
                notifsResult is ApiResult.Network -> notifsResult.cause
                notifsResult is ApiResult.Http    -> notifsResult.message
                else                              -> null
            }
            // Live pill = "we reached the backend on this refresh".
            // Any success on the primary notifications poll flips us LIVE;
            // a Network error (DNS / TCP) flips us OFFLINE; a 4xx/5xx
            // (server reachable but said no) keeps us LIVE with an error
            // surfaced separately. Server reachability and authentication
            // state are different signals — auth failures route through
            // AuthEvents.signalUnauthorized which the AppRoot handles.
            val nowLive = when (notifsResult) {
                is ApiResult.Ok      -> true
                is ApiResult.Http    -> true
                is ApiResult.Network -> false
            }

            _state.value = _state.value.copy(
                notifications = notifs,
                stats = stats,
                volumeBuckets = buckets,
                refreshing = false,
                error = err,
                live = nowLive,
            )
        }
    }

    /** Optimistically mark a notification read. */
    fun markRead(id: String) {
        appGraph.prefs.markRead(id)
        viewModelScope.launch(Dispatchers.IO) {
            appGraph.apiClient()?.markRead(id)
        }
    }

    class Factory(private val appGraph: AppGraph) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass == InboxViewModel::class.java)
            return InboxViewModel(appGraph) as T
        }
    }
}
