package tz.apt.thp.core.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.flow.Flow
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Façade over the Room-backed outbox + WorkManager flush worker. Callers
 * enqueue an action with the URL suffix + JSON body; the worker handles the
 * rest (retry, backoff, terminal failure).
 *
 * IMPORTANT: this is the ONLY safe enqueue path. Bypassing it (e.g. an
 * inline OkHttp call) loses the offline-survives-process-death guarantee
 * the Inbox now promises.
 */
class OutboxRepository private constructor(
    private val ctx: Context,
    private val dao: OutboxDao,
) {

    val pendingCount: Flow<Int> get() = dao.pendingCount()
    val all: Flow<List<OutboxEntity>> get() = dao.all()

    suspend fun enqueue(
        kind: String,
        urlSuffix: String,
        method: String = "POST",
        body: String = "",
    ): String {
        val entity = OutboxEntity(
            id = UUID.randomUUID().toString(),
            kind = kind,
            targetUrlSuffix = urlSuffix,
            method = method,
            payloadJson = body,
            createdAt = System.currentTimeMillis(),
            nextAttemptAt = 0L,
        )
        dao.upsert(entity)
        kick()
        return entity.id
    }

    suspend fun nextDue(nowMs: Long = System.currentTimeMillis()): OutboxEntity? =
        dao.nextDue(nowMs)

    suspend fun markSuccess(id: String) { dao.delete(id) }

    suspend fun markFailure(entity: OutboxEntity, reason: String, terminal: Boolean) {
        val next = if (terminal) {
            entity.copy(terminal = true, lastError = reason)
        } else {
            val backoffSec = nextBackoffSeconds(entity.attempts + 1)
            entity.copy(
                attempts = entity.attempts + 1,
                nextAttemptAt = System.currentTimeMillis() + backoffSec * 1000L,
                lastError = reason,
            )
        }
        dao.update(next)
    }

    suspend fun clearTerminal() { dao.clearTerminal() }

    /** Drop every pending + terminal row. Used during unpair. */
    suspend fun clearAll() { dao.clearAll() }

    suspend fun retry(id: String) {
        val pending = dao.allPending().firstOrNull { it.id == id } ?: return
        dao.upsert(pending.copy(terminal = false, attempts = 0, nextAttemptAt = 0L, lastError = null))
        kick()
    }

    fun kick() {
        val req = OneTimeWorkRequestBuilder<OutboxFlushWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(ctx).enqueueUniqueWork(
            "outbox-flush", ExistingWorkPolicy.KEEP, req,
        )
    }

    private fun nextBackoffSeconds(attempt: Int): Long = when (attempt) {
        1 -> 60L           // 1 min
        2 -> 5L * 60       // 5 min
        3 -> 15L * 60      // 15 min
        4 -> 60L * 60      // 1 h
        else -> 6L * 60 * 60  // 6h cap
    }

    companion object {
        @Volatile private var instance: OutboxRepository? = null
        fun get(ctx: Context): OutboxRepository = instance ?: synchronized(this) {
            instance ?: OutboxRepository(
                ctx.applicationContext,
                OutboxDb.get(ctx).outboxDao(),
            ).also { instance = it }
        }
    }
}
