package tz.apt.thp.feature.more

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
import tz.apt.thp.data.CreateTokenRequest
import tz.apt.thp.data.InstallToken

/**
 * Operator-mode enrollment helper. Mint / list / revoke single- or
 * multi-use install tokens. The plaintext token is rendered ONCE in the
 * `lastMinted` slot and is dropped on the next refresh — never persisted.
 */
class EnrollmentViewModel(
    private val appGraph: AppGraph,
) : ViewModel() {

    data class State(
        val active: List<InstallToken> = emptyList(),
        val lastMinted: InstallToken? = null,
        val creating: Boolean = false,
        val refreshing: Boolean = false,
        val error: String? = null,
        val message: String? = null,
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
            val res = withContext(Dispatchers.IO) { api.listInstallTokens() }
            _state.value = when (res) {
                is ApiResult.Ok      -> _state.value.copy(refreshing = false, active = res.value.active)
                is ApiResult.Http    -> _state.value.copy(refreshing = false, error = "${res.code} ${res.message}")
                is ApiResult.Network -> _state.value.copy(refreshing = false, error = res.cause)
            }
        }
    }

    fun create(profile: String, maxUses: Int, ttlMinutes: Int) {
        viewModelScope.launch {
            _state.value = _state.value.copy(creating = true)
            val api = appGraph.apiClient() ?: run {
                _state.value = _state.value.copy(creating = false, error = "Not enrolled")
                return@launch
            }
            val body = CreateTokenRequest(
                profile = profile,
                expires_in_minutes = ttlMinutes,
                max_uses = maxUses,
            )
            val res = withContext(Dispatchers.IO) { api.createInstallToken(body) }
            when (res) {
                is ApiResult.Ok -> {
                    _state.value = _state.value.copy(
                        creating = false,
                        lastMinted = res.value,
                        message = "Token #${res.value.id} minted",
                    )
                    refresh()
                }
                is ApiResult.Http    -> _state.value = _state.value.copy(creating = false, error = "${res.code} ${res.message}")
                is ApiResult.Network -> _state.value = _state.value.copy(creating = false, error = res.cause)
            }
        }
    }

    fun revoke(id: Long) {
        viewModelScope.launch {
            val api = appGraph.apiClient() ?: return@launch
            val res = withContext(Dispatchers.IO) { api.revokeInstallToken(id) }
            _state.value = when (res) {
                is ApiResult.Ok      -> _state.value.copy(message = "Token #$id revoked")
                is ApiResult.Http    -> _state.value.copy(error = "${res.code} ${res.message}")
                is ApiResult.Network -> _state.value.copy(error = res.cause)
            }
            refresh()
        }
    }

    fun clearMessage() { _state.value = _state.value.copy(message = null) }

    class Factory(private val appGraph: AppGraph) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass == EnrollmentViewModel::class.java)
            return EnrollmentViewModel(appGraph) as T
        }
    }
}
