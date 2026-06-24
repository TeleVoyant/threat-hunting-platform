package tz.apt.thp.feature.models

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tz.apt.thp.AppGraph
import tz.apt.thp.data.ApiResult
import tz.apt.thp.data.DriftHistory
import tz.apt.thp.data.ModelSummary
import tz.apt.thp.data.ModelVersionMeta

/**
 * Loads the detector inventory then, for each detector, fetches the drift
 * history (sparkline) and the latest version's manifest metadata (eval AUC,
 * feature count, degenerate-model guard flag). Read-only — no retrain /
 * threshold edit from mobile.
 */
class ModelsViewModel(
    private val appGraph: AppGraph,
) : ViewModel() {

    data class DetectorCard(
        val summary: ModelSummary,
        val drift: DriftHistory? = null,
        val latestMeta: ModelVersionMeta? = null,
    )

    data class State(
        val cards: List<DetectorCard> = emptyList(),
        val refreshing: Boolean = false,
        val error: String? = null,
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    init { refresh() }

    fun refresh() {
        viewModelScope.launch {
            _state.value = _state.value.copy(refreshing = true, error = null)
            val api = appGraph.apiClient()
            if (api == null) {
                _state.value = _state.value.copy(refreshing = false, error = "Not enrolled")
                return@launch
            }
            val listRes = withContext(Dispatchers.IO) { api.listModels() }
            val list = (listRes as? ApiResult.Ok)?.value.orEmpty()
            if (listRes !is ApiResult.Ok) {
                _state.value = _state.value.copy(
                    refreshing = false,
                    error = (listRes as? ApiResult.Http)?.message
                        ?: (listRes as? ApiResult.Network)?.cause,
                )
                return@launch
            }

            // Fetch drift + latest-version metadata — tolerate per-detector failure.
            val cards = list.map { summary ->
                val driftRes = withContext(Dispatchers.IO) {
                    api.driftHistory(summary.name)
                }
                val versRes = withContext(Dispatchers.IO) {
                    api.listVersions(summary.name)
                }
                val versions = (versRes as? ApiResult.Ok)?.value?.versions.orEmpty()
                // Prefer the active version; else the newest by created_at.
                val latest = versions.firstOrNull { it.status == "active" }
                    ?: versions.maxByOrNull { it.created_at ?: 0.0 }
                DetectorCard(
                    summary = summary,
                    drift = (driftRes as? ApiResult.Ok)?.value,
                    latestMeta = latest?.metadata,
                )
            }
            _state.value = _state.value.copy(cards = cards, refreshing = false)
        }
    }

    class Factory(private val appGraph: AppGraph) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass == ModelsViewModel::class.java)
            return ModelsViewModel(appGraph) as T
        }
    }
}
