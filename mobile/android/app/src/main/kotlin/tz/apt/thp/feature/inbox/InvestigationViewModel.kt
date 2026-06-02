package tz.apt.thp.feature.inbox

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tz.apt.thp.AppGraph
import tz.apt.thp.core.sync.OutboxKind
import tz.apt.thp.data.AlertNote
import tz.apt.thp.data.AlertSummary
import tz.apt.thp.data.ApiResult

class InvestigationViewModel(
    private val appGraph: AppGraph,
    private val alertId: String,
) : ViewModel() {

    data class State(
        val alertId: String,
        val summary: AlertSummary? = null,
        val notes: List<AlertNote> = emptyList(),
        val loading: Boolean = true,
        val error: String? = null,
        val acked: Boolean = false,
        val pendingAction: String? = null,
    )

    private val _state = MutableStateFlow(State(alertId = alertId))
    val state: StateFlow<State> = _state

    init { load() }

    fun load() {
        viewModelScope.launch {
            _state.value = _state.value.copy(loading = true, error = null)
            val api = appGraph.apiClient()
            if (api == null) {
                _state.value = _state.value.copy(loading = false, error = "Not enrolled")
                return@launch
            }
            val sumR = withContext(Dispatchers.IO) { api.getAlert(alertId) }
            val notesR = withContext(Dispatchers.IO) { api.listNotes(alertId) }
            val sum = (sumR as? ApiResult.Ok)?.value
            val notes = (notesR as? ApiResult.Ok)?.value.orEmpty()
            val err = (sumR as? ApiResult.Network)?.cause
                ?: (sumR as? ApiResult.Http)?.message
            _state.value = _state.value.copy(
                summary = sum,
                notes = notes,
                loading = false,
                error = err,
                acked = sum?.status?.equals("acknowledged", true) == true,
            )
        }
    }

    /** Queues the ack via the outbox so it survives offline. */
    fun acknowledge() {
        viewModelScope.launch {
            _state.value = _state.value.copy(pendingAction = "Acknowledging…")
            appGraph.outbox.enqueue(
                kind = OutboxKind.ACK,
                urlSuffix = "/alerts/$alertId/acknowledge",
                method = "POST",
                body = "",
            )
            appGraph.prefs.bumpAckCount()
            _state.value = _state.value.copy(
                acked = true,
                pendingAction = null,
            )
        }
    }

    /** Queues a note via the outbox. */
    fun postNote(text: String) {
        if (text.isBlank()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(pendingAction = "Sending note…")
            val payload = """{"text": ${'"'}${text.replace("\\", "\\\\").replace("\"", "\\\"")}${'"'}}"""
            appGraph.outbox.enqueue(
                kind = OutboxKind.NOTE,
                urlSuffix = "/alerts/$alertId/notes",
                method = "POST",
                body = payload,
            )
            // Optimistic — show locally; real list refreshes on next load.
            val localNote = AlertNote(
                actor = appGraph.prefs.username() ?: "me",
                at = System.currentTimeMillis() / 1000.0,
                text = text,
            )
            _state.value = _state.value.copy(
                notes = listOf(localNote) + _state.value.notes,
                pendingAction = null,
            )
        }
    }

    class Factory(
        private val appGraph: AppGraph,
        private val alertId: String,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass == InvestigationViewModel::class.java)
            return InvestigationViewModel(appGraph, alertId) as T
        }
    }
}
