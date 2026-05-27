package tz.apt.thp.service

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.ExistingWorkPolicy
import androidx.work.Constraints
import androidx.work.NetworkType
import tz.apt.thp.data.ApiClient
import tz.apt.thp.data.ApiResult
import tz.apt.thp.data.Prefs
import tz.apt.thp.notif.NotifBuilder
import java.util.concurrent.TimeUnit

/** Wakes ~every 5 minutes when the SSE socket is down. */
class PollWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {

    override fun doWork(): Result {
        val prefs = Prefs.get(applicationContext)
        if (!prefs.isEnrolled()) return Result.success()
        val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
        val sp = applicationContext.getSharedPreferences("apt-thp-poll", Context.MODE_PRIVATE)
        val since = sp.getLong("since_ms", 0L).toDouble() / 1000.0

        return when (val res = client.poll(since)) {
            is ApiResult.Ok -> {
                for (n in res.value) NotifBuilder.post(applicationContext, n)
                sp.edit().putLong("since_ms", System.currentTimeMillis()).apply()
                reschedule()
                Result.success()
            }
            is ApiResult.Network -> {
                reschedule() // try again on next tick
                Result.retry()
            }
            is ApiResult.Http -> {
                // 401/403: stop polling, the api_key is dead. Other 4xx/5xx:
                // back off via WorkManager retry policy.
                if (res.code == 401 || res.code == 403) Result.failure() else Result.retry()
            }
        }
    }

    private fun reschedule() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        val next = OneTimeWorkRequestBuilder<PollWorker>()
            .setConstraints(constraints)
            .setInitialDelay(5, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(applicationContext).enqueueUniqueWork(
            "apt-thp-poll", ExistingWorkPolicy.REPLACE, next,
        )
    }
}
