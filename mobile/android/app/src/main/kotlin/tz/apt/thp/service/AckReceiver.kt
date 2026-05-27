package tz.apt.thp.service

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import tz.apt.thp.data.ApiClient
import tz.apt.thp.data.Prefs

/**
 * Receives "Acknowledge" taps from the native notification.
 *
 * `goAsync()` holds the broadcast PendingResult open so the OS does not kill
 * the process before the HTTP round-trip completes. Without it, tapping Ack
 * from the lock screen on a battery-saver phone is a coin flip.
 */
class AckReceiver : BroadcastReceiver() {

    override fun onReceive(ctx: Context, intent: Intent) {
        val alertId = intent.getStringExtra(EXTRA_ALERT_ID) ?: return
        val notifId = intent.getStringExtra(EXTRA_NOTIF_ID)

        val prefs = Prefs.get(ctx)
        if (!prefs.isEnrolled()) return

        // Dismiss immediately — gives the analyst instant feedback even if the
        // network call takes a couple of seconds.
        notifId?.let {
            val mgr = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            mgr.cancel(it.hashCode())
        }

        val pending = goAsync()
        val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val res = client.acknowledge(alertId)
                if (res is tz.apt.thp.data.ApiResult.Ok) prefs.bumpAckCount()
                notifId?.let {
                    prefs.markRead(it)
                    client.markRead(it)
                }
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val EXTRA_ALERT_ID = "alert_id"
        const val EXTRA_NOTIF_ID = "notif_id"
        fun intent(ctx: Context, alertId: String, notifId: String): Intent =
            Intent(ctx, AckReceiver::class.java).apply {
                putExtra(EXTRA_ALERT_ID, alertId)
                putExtra(EXTRA_NOTIF_ID, notifId)
            }
    }
}
