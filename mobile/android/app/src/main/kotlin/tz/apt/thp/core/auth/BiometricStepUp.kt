package tz.apt.thp.core.auth

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.fragment.app.FragmentActivity
import tz.apt.thp.security.BiometricGate

/**
 * Wrap a sensitive action with biometric step-up. Returns a `() -> Unit` you
 * can bind to a button's onClick — when the user taps, [BiometricGate.gateSensitive]
 * prompts (or skips if the 5-min grace is still fresh) and then runs [onConfirmed].
 *
 * Defence-in-depth: even if the UI ever forgets to wrap an action, the
 * destructive paths still go through the offline outbox → server → server-side
 * audit. The biometric is the on-device confirmation that the operator
 * physically present is the one issuing the command, not a stolen unlocked phone.
 *
 * If the host isn't a FragmentActivity (e.g. a Compose preview), the gate
 * degrades to a direct call so previews still render.
 *
 * @param actionLabel  Human-readable label shown in the BiometricPrompt subtitle.
 * @param alwaysPrompt If true, [BiometricGate.reset] runs immediately before
 *                     [BiometricGate.gateSensitive] so the 5-min grace is
 *                     bypassed and the prompt fires EVERY time. Use for the
 *                     highest-blast-radius actions where piggybacking on a
 *                     recent unlock from a less-destructive action is unsafe.
 *
 * Usage:
 * ```
 * Button(onClick = rememberBiometricStepUp("Isolate") { vm.queueIsolate(...) }) { ... }
 * Button(onClick = rememberBiometricStepUp("Unisolate", alwaysPrompt = true) { ... }) { ... }
 * ```
 */
@Composable
fun rememberBiometricStepUp(
    actionLabel: String,
    alwaysPrompt: Boolean = false,
    onConfirmed: () -> Unit,
): () -> Unit {
    val ctx = LocalContext.current
    val activity = ctx as? FragmentActivity
    return remember(activity, actionLabel, alwaysPrompt, onConfirmed) {
        {
            if (activity == null) {
                onConfirmed()
            } else {
                if (alwaysPrompt) BiometricGate.reset()
                BiometricGate.gateSensitive(
                    activity,
                    action = actionLabel,
                    onPass = onConfirmed,
                    onFail = { /* user cancelled / no biometric — no-op */ },
                )
            }
        }
    }
}
