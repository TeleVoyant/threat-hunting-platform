package tz.apt.thp.feature.fleet

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
import tz.apt.thp.data.Agent
import tz.apt.thp.data.ApiResult

class FleetViewModel(
    private val appGraph: AppGraph,
) : ViewModel() {

    data class State(
        val agents: List<Agent> = emptyList(),
        val query: String = "",
        val refreshing: Boolean = false,
        val error: String? = null,
        val lastCommandResult: String? = null,
        // Server-side current LIVE handler version. Used by the fleet row
        // + agent-detail view to render LATEST vs out-of-date pills and to
        // pre-fill the "Push latest handler" action with the right label.
        val liveHandlerVersion: String? = null,
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    init { refresh() }

    fun setQuery(q: String) { _state.value = _state.value.copy(query = q) }

    fun refresh() {
        viewModelScope.launch {
            _state.value = _state.value.copy(refreshing = true, error = null)
            val api = appGraph.apiClient()
            if (api == null) {
                _state.value = _state.value.copy(refreshing = false, error = "Not enrolled")
                return@launch
            }
            val res = withContext(Dispatchers.IO) { api.listAgents() }
            _state.value = when (res) {
                is ApiResult.Ok -> _state.value.copy(
                    agents = res.value.agents,
                    liveHandlerVersion = res.value.live_handler_version,
                    refreshing = false,
                )
                is ApiResult.Http -> _state.value.copy(refreshing = false, error = "${res.code} ${res.message}")
                is ApiResult.Network -> _state.value.copy(refreshing = false, error = res.cause)
            }
        }
    }

    /**
     * Push the current live handler version to a specific agent. Outbox-
     * queued so it survives a network drop. The actual params payload is
     * `{version: <live>}` — the server-side validator rejects with 422 if
     * the named version doesn't exist, so the operator sees the failure
     * via the existing command-result path. No-op when `liveHandlerVersion`
     * is null (fleet has nothing to push yet).
     */
    fun queuePushHandler(agentId: String) {
        val live = _state.value.liveHandlerVersion
        if (live.isNullOrBlank()) {
            _state.value = _state.value.copy(
                lastCommandResult = "No live handler version on server — upload + promote one first",
            )
            return
        }
        queueDestructive(
            agentId = agentId,
            commandType = "update_handler",
            params = mapOf("version" to live),
        )
        _state.value = _state.value.copy(
            lastCommandResult = "Push of handler $live queued for $agentId",
        )
    }

    /**
     * Re-issue the LIVE handler version to a single agent whose last OTA
     * verify failed. Online-only (not outboxed) — this is a retry/diagnostic
     * action the operator triggers from the UPDATE FAILED card. Surfaces
     * the server response in lastCommandResult so the operator sees it
     * succeeded immediately.
     */
    fun retryHandlerUpdate(agentId: String) {
        viewModelScope.launch {
            val api = appGraph.apiClient() ?: return@launch
            val res = withContext(Dispatchers.IO) {
                api.retryHandlerUpdate(agentId)
            }
            _state.value = _state.value.copy(
                lastCommandResult = when (res) {
                    is ApiResult.Ok      -> "OTA retry queued for $agentId — applies on next poll"
                    is ApiResult.Http    -> "Retry failed: ${res.code} ${res.message}"
                    is ApiResult.Network -> "Retry offline: ${res.cause}"
                },
            )
        }
    }

    /**
     * Roll the agent's handler back to its on-disk .bak (the immediately-
     * previous version). Idempotent on the agent side — if no .bak exists,
     * the handler returns 'rejected' which surfaces in the command result.
     */
    fun queueRollbackHandler(agentId: String, reason: String = "") {
        queueDestructive(
            agentId = agentId,
            commandType = "rollback_handler",
            params = if (reason.isNotBlank()) mapOf("reason" to reason) else emptyMap(),
        )
        _state.value = _state.value.copy(
            lastCommandResult = "Rollback queued for $agentId",
        )
    }

    /** Sends a non-destructive command synchronously. Returns the queued id. */
    fun sendCommand(agentId: String, commandType: String) {
        viewModelScope.launch {
            val api = appGraph.apiClient() ?: return@launch
            val res = withContext(Dispatchers.IO) {
                api.sendCommand(agentId = agentId, commandType = commandType)
            }
            _state.value = _state.value.copy(
                lastCommandResult = when (res) {
                    is ApiResult.Ok      -> "$commandType queued (cmd ${res.value.command_id.takeLast(6)})"
                    is ApiResult.Http    -> "Server: ${res.code} ${res.message}"
                    is ApiResult.Network -> "Offline: ${res.cause}"
                },
            )
        }
    }

    /**
     * Destructive commands (isolate / rotate-secret / unisolate) go through
     * the offline outbox so they survive an in-flight network drop. The
     * actual call is deferred to OutboxFlushWorker; the UI just shows queued.
     *
     * `params` carries the command-specific payload — empty for unisolate,
     * full {level,ttl_minutes,reason} for isolate (set via [queueIsolate]).
     */
    fun queueDestructive(
        agentId: String,
        commandType: String,
        params: Map<String, Any> = emptyMap(),
    ) {
        viewModelScope.launch {
            val paramsJson = paramsToJson(params)
            val body = """{"command_type": "$commandType", "params": $paramsJson}"""
            appGraph.outbox.enqueue(
                kind = OutboxKind.FLEET_CMD,
                urlSuffix = "/fleet/agents/$agentId/commands",
                method = "POST",
                body = body,
            )
            _state.value = _state.value.copy(
                lastCommandResult = "$commandType queued for $agentId — will sync when online",
            )
        }
    }

    /**
     * Convenience for ISOLATE — enforces server-side bounds on the client too
     * so the outbox doesn't carry obviously-invalid params that the server
     * will 422-reject.
     */
    fun queueIsolate(
        agentId: String,
        level: String,
        ttlMinutes: Int,
        reason: String,
    ) {
        val clampedTtl = ttlMinutes.coerceIn(5, 1440)
        val safeLevel  = level.lowercase().takeIf { it in setOf("light","standard","full") } ?: "standard"
        queueDestructive(
            agentId = agentId,
            commandType = "isolate",
            params = mapOf(
                "level"        to safeLevel,
                "ttl_minutes"  to clampedTtl,
                "reason"       to reason,
            ),
        )
    }

    /** Minimal JSON serialiser for our shallow params map — int + string only. */
    private fun paramsToJson(params: Map<String, Any>): String {
        if (params.isEmpty()) return "{}"
        val parts = params.entries.joinToString(",") { (k, v) ->
            val key = "\"" + k.replace("\"", "\\\"") + "\""
            val value = when (v) {
                is Number  -> v.toString()
                is Boolean -> v.toString()
                else       -> "\"" + v.toString()
                                  .replace("\\", "\\\\")
                                  .replace("\"", "\\\"") + "\""
            }
            "$key:$value"
        }
        return "{$parts}"
    }

    fun queueRotateSecret(agentId: String) {
        viewModelScope.launch {
            appGraph.outbox.enqueue(
                kind = OutboxKind.FLEET_CMD,
                urlSuffix = "/fleet/agents/$agentId/rotate-secret",
                method = "POST",
                body = "",
            )
            _state.value = _state.value.copy(
                lastCommandResult = "Rotate-secret queued for $agentId",
            )
        }
    }

    fun clearLastResult() { _state.value = _state.value.copy(lastCommandResult = null) }

    class Factory(private val appGraph: AppGraph) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass == FleetViewModel::class.java)
            return FleetViewModel(appGraph) as T
        }
    }
}
