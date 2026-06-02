package tz.apt.thp.feature.audit

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
import tz.apt.thp.data.AuditEntry
import tz.apt.thp.data.AuditIntegrity

class AuditViewModel(
    private val appGraph: AppGraph,
) : ViewModel() {

    enum class Category(val label: String, val prefix: String?) {
        ALL("All", null),
        ALERT("Alerts", "alert."),
        AUTH("Auth", "auth."),
        FLEET("Fleet", "fleet."),
        MODEL("Models", "model."),
        ADMIN("Admin", "admin."),
    }

    data class State(
        val entries: List<AuditEntry> = emptyList(),
        val integrity: AuditIntegrity? = null,
        val refreshing: Boolean = false,
        val error: String? = null,
        val category: Category = Category.ALL,
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    init { refresh() }

    fun setCategory(c: Category) {
        _state.value = _state.value.copy(category = c)
        // No need to re-fetch — server returns the union; the chip filter is
        // client-side so chip toggling stays instant.
    }

    fun refresh() {
        viewModelScope.launch {
            _state.value = _state.value.copy(refreshing = true, error = null)
            val api = appGraph.apiClient()
            if (api == null) {
                _state.value = _state.value.copy(refreshing = false, error = "Not enrolled")
                return@launch
            }
            val rowsRes = withContext(Dispatchers.IO) { api.audit(limit = 50) }
            val checkRes = withContext(Dispatchers.IO) { api.auditVerify() }
            val rows = (rowsRes as? ApiResult.Ok)?.value?.entries.orEmpty()
            val check = (checkRes as? ApiResult.Ok)?.value
            val err = when (rowsRes) {
                is ApiResult.Http    -> "${rowsRes.code} ${rowsRes.message}"
                is ApiResult.Network -> rowsRes.cause
                else                 -> null
            }
            _state.value = _state.value.copy(
                entries = rows,
                integrity = check,
                refreshing = false,
                error = err,
            )
        }
    }

    fun filtered(): List<AuditEntry> {
        val prefix = state.value.category.prefix ?: return state.value.entries
        return state.value.entries.filter { (it.action ?: "").startsWith(prefix) }
    }

    class Factory(private val appGraph: AppGraph) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass == AuditViewModel::class.java)
            return AuditViewModel(appGraph) as T
        }
    }
}
