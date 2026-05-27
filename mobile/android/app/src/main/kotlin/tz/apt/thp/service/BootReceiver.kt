package tz.apt.thp.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import tz.apt.thp.data.Prefs

/** Re-start the listener after a reboot so weekend pages don't go silent. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (Prefs.get(context).isEnrolled()) {
            NotificationListener.start(context)
        }
    }
}
