package tz.apt.thp.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import android.app.Activity
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.ThemeController
import tz.apt.thp.core.design.ThemeMode
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.rbac.SessionStore
import tz.apt.thp.security.BiometricGate
import tz.apt.thp.service.NotificationListener

/**
 * In-app settings — theme cycler, on-call toggle, unpair. Unpair is wired
 * here as a soft "logout" — clears local creds; the dashboard remains the
 * source of truth on the server-side mobile_api_key_hash slot.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsRoute(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val themeMode by ThemeController.mode.collectAsState()
    val prefs = remember { AppGraph.from(ctx).prefs }
    var onCallNow by remember { mutableStateOf(prefs.isOnCallNow()) }
    var showUnpairDialog by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    // Tear down server-side first (best-effort), then wipe local creds,
    // then exit the process. The activity's onCreate re-reads prefs on
    // next launch, finds an unenrolled state, and routes straight to
    // EnrollRoute (QR scan).
    //
    // Server call is wrapped in a 5 s timeout AND a runCatching block so
    // an unreachable / dead platform doesn't trap the user on the Unpair
    // dialog forever. Worst case: the dashboard's Paired Devices view
    // shows a stale row until an admin manually cleans it up. The phone
    // is fully unpaired locally either way.
    val performUnpair = {
        scope.launch {
            // 1. Server-side unpair — clears mobile_api_key_hash + marks
            //    paired_devices row inactive so the dashboard view stays
            //    in sync. Symmetric counterpart to admin's DELETE
            //    /admin/paired-devices/{id}.
            runCatching {
                withTimeoutOrNull(5_000L) {
                    withContext(Dispatchers.IO) {
                        AppGraph.from(ctx).apiClient()?.unpair()
                    }
                }
            }

            // 2. Local teardown — always runs, even if step 1 timed out.
            runCatching { NotificationListener.stop(ctx) }
            // Wipe the outbox so a pending ack / note / fleet-command
            // from this identity can't be replayed against the credentials
            // of the NEXT pairing (otherwise the audit trail would
            // mis-attribute the old user's action to the new one).
            runCatching { AppGraph.from(ctx).outbox.clearAll() }
            prefs.clear()
            SessionStore.clear()
            BiometricGate.reset()

            // 3. Hard exit. The user re-enters via the launcher → AppRoot
            //    sees !enrolled → EnrollRoute renders.
            (ctx as? Activity)?.finishAndRemoveTask()
            android.os.Process.killProcess(android.os.Process.myPid())
        }
        Unit
    }
    // Unpair-specific biometric gate: ALWAYS prompts (no grace window).
    // The 5-min grace inside BiometricGate.gateSensitive is great for
    // chained actions like ack-then-ack, but unpair is the most destructive
    // operation in the app and should never piggyback on a stale unlock —
    // BiometricGate.reset() clears the grace immediately before the prompt
    // so a recently-authenticated user STILL sees the biometric sheet.
    val activity = ctx as? FragmentActivity
    val onUnpairConfirmed = {
        showUnpairDialog = false
        if (activity != null) {
            BiometricGate.reset()
            BiometricGate.gateSensitive(
                activity,
                action = "Unpair this device",
                onPass = performUnpair,
                onFail = { /* user cancelled biometric — abort unpair, stay in app */ },
            )
        } else {
            // Preview / non-FragmentActivity host — just run the action.
            performUnpair()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(Spacing.lg),
        verticalArrangement = Arrangement.spacedBy(Spacing.md),
    ) {
        Text("Settings", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)

        // Theme
        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Theme", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "Auto follows the system; Light and Dark override it.",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    listOf(ThemeMode.Auto, ThemeMode.Light, ThemeMode.Dark).forEachIndexed { i, mode ->
                        SegmentedButton(
                            selected = themeMode == mode,
                            onClick = { ThemeController.set(ctx, mode) },
                            shape = SegmentedButtonDefaults.itemShape(index = i, count = 3),
                        ) { Text(mode.name) }
                    }
                }
            }
        }

        // On-call
        AptCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("On call", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                    Text(
                        if (onCallNow) "You are receiving critical alerts." else "Alerts are queued silently.",
                        style = AptType.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = onCallNow,
                    onCheckedChange = { checked ->
                        onCallNow = checked
                        // 8h window when toggled on; clear when toggled off.
                        val until = if (checked) System.currentTimeMillis() + 8L * 60 * 60 * 1000 else 0L
                        prefs.setOnCallUntil(until)
                    },
                )
            }
        }

        // Unpair
        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Unpair this device", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "Clears stored credentials and closes the app. Next launch returns to the pairing QR scan.",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(
                    onClick = { showUnpairDialog = true },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) { Text("Unpair") }
            }
        }
    }

    if (showUnpairDialog) {
        AlertDialog(
            onDismissRequest = { showUnpairDialog = false },
            title = { Text("Unpair this device?") },
            text = {
                Text(
                    "The stored api_key, role, server URL, on-call window and unread cache " +
                    "will be erased and the app will close. The next launch will land on the " +
                    "QR scan screen. You'll need a fresh QR from the dashboard to enrol again."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = onUnpairConfirmed,
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) { Text("Unpair & close") }
            },
            dismissButton = {
                TextButton(onClick = { showUnpairDialog = false }) {
                    Text("Cancel")
                }
            },
        )
    }
}
