package tz.apt.thp.security

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor

/**
 * Biometric gate. Two modes:
 *   - openApp(): prompted on app launch / resume-from-background after
 *     APP_OPEN_GRACE_MS. Confirms the person holding the phone is the analyst.
 *   - sensitive(): re-prompted for Ack / Post-Note when the last-auth time is
 *     older than SENSITIVE_GRACE_MS. Stops a forgotten-unlocked phone from
 *     being weaponised by a passer-by.
 *
 * Falls back to the device PIN/pattern/password (`DEVICE_CREDENTIAL`) on
 * phones with no enrolled biometric — the user gets ONE coherent unlock UI
 * either way.
 */
object BiometricGate {

    const val APP_OPEN_GRACE_MS  = 30_000L          // 30s — quick app-switch
    const val SENSITIVE_GRACE_MS = 5L * 60 * 1000   // 5 min between sensitive actions

    @Volatile private var lastAuthMs: Long = 0L

    enum class Availability { AVAILABLE, NONE_ENROLLED, UNSUPPORTED }

    fun availability(ctx: Context): Availability {
        val bm = BiometricManager.from(ctx)
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return when (bm.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS                 -> Availability.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED     -> Availability.NONE_ENROLLED
            else                                               -> Availability.UNSUPPORTED
        }
    }

    /** True if the last successful auth is still within `windowMs`. */
    fun fresh(windowMs: Long): Boolean =
        lastAuthMs != 0L && (System.currentTimeMillis() - lastAuthMs) < windowMs

    fun reset() { lastAuthMs = 0L }

    /** Prompt for app-open. Bypasses if a recent unlock is still fresh. */
    fun gateAppOpen(activity: FragmentActivity, onPass: () -> Unit, onFail: () -> Unit) {
        if (fresh(APP_OPEN_GRACE_MS)) { onPass(); return }
        prompt(
            activity,
            title = "Unlock APT THP",
            subtitle = "Confirm it's you before opening the inbox",
            onPass = { lastAuthMs = System.currentTimeMillis(); onPass() },
            onFail = onFail,
        )
    }

    /** Prompt for a sensitive action (Ack, Post-Note). Skips if still fresh. */
    fun gateSensitive(
        activity: FragmentActivity,
        action: String,
        onPass: () -> Unit,
        onFail: () -> Unit = {},
    ) {
        if (fresh(SENSITIVE_GRACE_MS)) { onPass(); return }
        prompt(
            activity,
            title = "Confirm $action",
            subtitle = "Re-authenticate to act on this alert",
            onPass = { lastAuthMs = System.currentTimeMillis(); onPass() },
            onFail = onFail,
        )
    }

    private fun prompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onPass: () -> Unit,
        onFail: () -> Unit,
    ) {
        // Use the activity's main executor so callbacks run on the UI thread.
        val executor: Executor = androidx.core.content.ContextCompat.getMainExecutor(activity)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()
        val prompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onPass()
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFail()
                }
                override fun onAuthenticationFailed() {
                    /* user can retry; do nothing */
                }
            })
        prompt.authenticate(info)
    }
}
