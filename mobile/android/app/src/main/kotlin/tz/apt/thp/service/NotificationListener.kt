package tz.apt.thp.service

import android.app.Notification
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.serialization.json.Json
import okhttp3.Response
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import tz.apt.thp.R
import tz.apt.thp.data.ApiClient
import tz.apt.thp.data.AuthEvents
import tz.apt.thp.data.Notification as NotificationModel
import tz.apt.thp.data.Prefs
import tz.apt.thp.notif.NotifBuilder
import tz.apt.thp.notif.NotifChannels

/**
 * Foreground service that holds the SSE long-poll to /notifications/stream.
 *
 *   LISTENING  — socket up; new detections arrive immediately.
 *   STALE      — socket down; PollWorker scheduled every 5 min.
 */
class NotificationListener : Service() {

    private var source: EventSource? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val json = Json { ignoreUnknownKeys = true }
    private var state: State = State.LISTENING

    enum class State { LISTENING, STALE }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        NotifChannels.ensure(this)
        startForeground(STICKY_ID, buildSticky(State.LISTENING))
        connect()
        return START_STICKY
    }

    override fun onDestroy() {
        source?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    private fun connect() {
        val prefs = Prefs.get(this)
        if (!prefs.isEnrolled()) {
            updateSticky(State.STALE, "Not enrolled")
            stopSelf()
            return
        }
        val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
        source = client.openStream(object : EventSourceListener() {
            override fun onOpen(eventSource: EventSource, response: Response) {
                updateSticky(State.LISTENING, "Connected")
            }
            override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                if (type != "notification") return
                val n = runCatching {
                    json.decodeFromString(NotificationModel.serializer(), data)
                }.getOrNull() ?: return
                NotifBuilder.post(this@NotificationListener, n)
            }
            override fun onFailure(eventSource: EventSource, t: Throwable?, response: Response?) {
                // If the server is telling us our api_key is no good (most
                // commonly because an admin unpaired us), route the user
                // back to the enrol screen instead of looping polls forever.
                if (response?.code == 401) {
                    AuthEvents.signalUnauthorized()
                    return
                }
                updateSticky(State.STALE, t?.message ?: "Disconnected")
                schedulePoll()
            }
            override fun onClosed(eventSource: EventSource) {
                updateSticky(State.STALE, "Closed by server")
                schedulePoll()
            }
        })
    }

    private fun schedulePoll() {
        val req = OneTimeWorkRequestBuilder<PollWorker>().build()
        WorkManager.getInstance(this).enqueueUniqueWork(
            "apt-thp-poll", androidx.work.ExistingWorkPolicy.REPLACE, req,
        )
    }

    private fun buildSticky(s: State, detail: String? = null): Notification {
        val title = when (s) {
            State.LISTENING -> "APT THP — listening for detections"
            State.STALE     -> "APT THP — reconnecting…"
        }
        return NotificationCompat.Builder(this, NotifChannels.CHANNEL_LISTENER)
            .setSmallIcon(R.drawable.ic_listener)
            .setContentTitle(title)
            .setContentText(detail ?: "")
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
    }

    private fun updateSticky(s: State, detail: String? = null) {
        this.state = s
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(STICKY_ID, buildSticky(s, detail))
    }

    companion object {
        private const val STICKY_ID = 9001

        fun start(ctx: Context) {
            val i = Intent(ctx, NotificationListener::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                ctx.startForegroundService(i) else ctx.startService(i)
        }
        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, NotificationListener::class.java))
        }
    }
}
