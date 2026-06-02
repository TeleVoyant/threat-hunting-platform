package tz.apt.thp.core.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import tz.apt.thp.data.AuthEvents
import tz.apt.thp.data.Prefs
import java.util.concurrent.TimeUnit

/**
 * Flushes the outbox in FIFO order. For each due row:
 *   - 2xx                 → delete
 *   - 401                 → mark terminal, signal AuthEvents, stop the chain
 *   - 4xx (other)         → mark terminal with the error message
 *   - 408 / 429 / 5xx     → bump attempts + schedule next backoff
 *   - I/O failure         → bump attempts + schedule next backoff
 *
 * The worker yields with [Result.success] after one pass; WorkManager re-runs
 * it when [OutboxRepository.kick] is called or when network availability
 * changes (constraint-driven).
 *
 * IMPORTANT: read the session synchronously each iteration — a mid-flight
 * unpair or server-URL change means subsequent retries pick up the new
 * config without re-enqueueing every row.
 */
class OutboxFlushWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    override suspend fun doWork(): Result {
        val ctx = applicationContext
        val repo = OutboxRepository.get(ctx)
        val prefs = Prefs.get(ctx)
        val baseUrl = prefs.serverUrl() ?: return Result.success()
        val apiKey  = prefs.apiKey()    ?: return Result.success()

        var processed = 0
        // Drain up to 20 rows per pass to bound execution time.
        while (processed < 20) {
            val due = repo.nextDue() ?: break
            processed += 1
            val req = Request.Builder()
                .url(baseUrl.trimEnd('/') + due.targetUrlSuffix)
                .header("X-API-Key", apiKey)
                .also { b ->
                    if (due.method.equals("POST", ignoreCase = true)) {
                        val body = due.payloadJson.toRequestBody("application/json".toMediaType())
                        b.post(body)
                    } else if (due.method.equals("DELETE", ignoreCase = true)) {
                        b.delete()
                    }
                }
                .build()

            try {
                client.newCall(req).execute().use { r ->
                    when {
                        r.isSuccessful -> {
                            runBlocking { repo.markSuccess(due.id) }
                        }
                        r.code == 401 -> {
                            // Auth invalidated. Signal up; user will re-pair.
                            AuthEvents.signalUnauthorized()
                            runBlocking { repo.markFailure(due, "Unauthorized — re-pair to retry", terminal = true) }
                            return Result.success()
                        }
                        r.code in setOf(408, 429) || r.code in 500..599 -> {
                            runBlocking { repo.markFailure(due, "HTTP ${r.code}", terminal = false) }
                            return Result.retry()
                        }
                        else -> {
                            runBlocking { repo.markFailure(due, "HTTP ${r.code}", terminal = true) }
                        }
                    }
                }
            } catch (e: Exception) {
                runBlocking {
                    repo.markFailure(due, e.message ?: e.javaClass.simpleName, terminal = false)
                }
                return Result.retry()
            }
        }
        return Result.success()
    }
}
