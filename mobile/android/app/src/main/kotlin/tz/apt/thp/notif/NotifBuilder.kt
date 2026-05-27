package tz.apt.thp.notif

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationCompat
import tz.apt.thp.R
import tz.apt.thp.data.Notification as NotificationModel
import tz.apt.thp.service.AckReceiver
import tz.apt.thp.service.QuickReplyReceiver

object NotifBuilder {

    /** Group key so individual rows collapse into one stack in the shade. */
    private const val GROUP_KEY = "apt-thp-detections"
    private const val GROUP_SUMMARY_ID = 9000

    fun post(ctx: Context, n: NotificationModel) {
        NotifChannels.ensure(ctx)
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Deep link into the app at apt-thp://alert/<alert_id>
        val openIntent = Intent(Intent.ACTION_VIEW,
            Uri.parse("apt-thp://alert/${n.alert_id}")).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val openPi = PendingIntent.getActivity(
            ctx, n.id.hashCode(), openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val ackPi = PendingIntent.getBroadcast(
            ctx, ("ack:" + n.id).hashCode(),
            AckReceiver.intent(ctx, n.alert_id, n.id),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        // Quick-reply chip ("Investigating" by default — fastest single-tap
        // that conveys "saw it, working it"). The full preset list is
        // available inside the app's DetailPane.
        val quickText = QuickReplyReceiver.PRESETS.first()
        val quickPi = PendingIntent.getBroadcast(
            ctx, ("quick:" + n.id).hashCode(),
            QuickReplyReceiver.intent(ctx, n.alert_id, n.id, quickText),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val title = n.title ?: "APT THP detection"
        val body  = n.body ?: ("New ${n.severity.uppercase()} detection. Open dashboard.")

        val nb = NotificationCompat.Builder(ctx, NotifChannels.channelFor(n.severity))
            .setSmallIcon(R.drawable.ic_baseline_notifications)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(openPi)
            .setAutoCancel(true)
            .setGroup(GROUP_KEY)
            .addAction(R.drawable.ic_check, "Acknowledge", ackPi)
            .addAction(R.drawable.ic_open, "Open", openPi)
            .addAction(R.drawable.ic_check, quickText, quickPi)
            .setPriority(if (n.severity.equals("critical", true))
                NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)

        nm.notify(n.id.hashCode(), nb.build())
        nm.notify(GROUP_SUMMARY_ID, buildSummary(ctx))
    }

    /** Stack header — Android shows it when multiple per-row entries collapse. */
    private fun buildSummary(ctx: Context): android.app.Notification =
        NotificationCompat.Builder(ctx, NotifChannels.CHANNEL_HIGH)
            .setSmallIcon(R.drawable.ic_baseline_notifications)
            .setContentTitle("APT THP — new detections")
            .setStyle(NotificationCompat.InboxStyle().setSummaryText("Multiple new detections"))
            .setGroup(GROUP_KEY)
            .setGroupSummary(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setAutoCancel(true)
            .build()
}
