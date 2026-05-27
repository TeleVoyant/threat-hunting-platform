package tz.apt.thp.notif

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build

object NotifChannels {
    const val CHANNEL_CRITICAL = "apt_critical"
    const val CHANNEL_HIGH     = "apt_high"
    const val CHANNEL_DEFAULT  = "apt_default"
    const val CHANNEL_LISTENER = "apt_listener_status"

    // CRITICAL haptic — sharp double-buzz on a 1.2s loop. Deliberately
    // distinct from a regular text-message buzz so analysts can identify it
    // from across the room without looking at the phone.
    private val CRITICAL_VIBRATION = longArrayOf(0L, 220L, 110L, 220L, 600L, 220L, 110L, 220L)

    fun ensure(ctx: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        mgr.createNotificationChannel(NotificationChannel(
            CHANNEL_CRITICAL, "Critical detections", NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Full kill-chain / CRITICAL alerts."
            // Body redacted on the lock screen. Title (e.g. "CRITICAL detection")
            // still shows; analyst must unlock to see hostname / IOCs.
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            enableVibration(true)
            vibrationPattern = CRITICAL_VIBRATION
            setBypassDnd(true)
            val audio = AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT)
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build()
            setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION), audio)
            setShowBadge(true)
        })

        mgr.createNotificationChannel(NotificationChannel(
            CHANNEL_HIGH, "High detections", NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "HIGH severity detections."
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            enableVibration(true)
        })

        mgr.createNotificationChannel(NotificationChannel(
            CHANNEL_DEFAULT, "Other detections", NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "MEDIUM / LOW detections (if enabled in prefs)."
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        })

        mgr.createNotificationChannel(NotificationChannel(
            CHANNEL_LISTENER, "Listener status", NotificationManager.IMPORTANCE_MIN,
        ).apply {
            description = "Background service status (LISTENING / STALE)."
            setShowBadge(false)
            // Sticky service status carries no detection content — safe to show.
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        })
    }

    fun channelFor(severity: String): String = when (severity.lowercase()) {
        "critical" -> CHANNEL_CRITICAL
        "high"     -> CHANNEL_HIGH
        else       -> CHANNEL_DEFAULT
    }
}
