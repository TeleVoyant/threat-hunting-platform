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
 * Posts a canned investigation note + acknowledges in one round-trip.
 * Triggered by the chip buttons under each native notification:
 *   - "Investigating"
 *   - "False positive"
 *   - "Escalated"
 *
 * Acks via the same code path as AckReceiver so the audit-trail records both
 * the note and the acknowledgement under the analyst's user.
 */
class QuickReplyReceiver : BroadcastReceiver() {

    override fun onReceive(ctx: Context, intent: Intent) {
        val alertId = intent.getStringExtra(EXTRA_ALERT_ID) ?: return
        val notifId = intent.getStringExtra(EXTRA_NOTIF_ID)
        val text    = intent.getStringExtra(EXTRA_TEXT) ?: return

        val prefs = Prefs.get(ctx)
        if (!prefs.isEnrolled()) return

        notifId?.let {
            val mgr = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            mgr.cancel(it.hashCode())
        }

        val pending = goAsync()
        val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                client.postNote(alertId, text)
                client.acknowledge(alertId)
                notifId?.let { client.markRead(it) }
                prefs.bumpAckCount()
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val EXTRA_ALERT_ID = "alert_id"
        const val EXTRA_NOTIF_ID = "notif_id"
        const val EXTRA_TEXT     = "text"

        fun intent(ctx: Context, alertId: String, notifId: String, text: String): Intent =
            Intent(ctx, QuickReplyReceiver::class.java).apply {
                putExtra(EXTRA_ALERT_ID, alertId)
                putExtra(EXTRA_NOTIF_ID, notifId)
                putExtra(EXTRA_TEXT, text)
            }

        /** Canned reply texts surfaced both in the notification and DetailPane. */
        val PRESETS = listOf(
            "Investigating",
            "False positive",
            "Escalated",
        )
    }
}
