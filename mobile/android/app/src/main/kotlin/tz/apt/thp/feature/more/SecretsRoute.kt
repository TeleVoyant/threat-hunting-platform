package tz.apt.thp.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.data.ApiResult
import tz.apt.thp.data.RotateResponse
import tz.apt.thp.data.plaintext
import tz.apt.thp.security.BiometricGate

/**
 * Server-secret rotation. Two flavours: JWT signing key and bootstrap
 * enrolment token. Each action is gated behind a biometric re-prompt every
 * single time — there is no grace window for these.
 *
 * The plaintext value comes back in [RotateResponse.new_value] for the JWT
 * rotation case (server-defined behaviour); we surface it once behind a
 * Reveal toggle so it can be copied — never persisted to prefs.
 */
@Composable
fun SecretsRoute(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val activity = ctx as? FragmentActivity
    val appGraph = remember { AppGraph.from(ctx) }
    val scope = rememberCoroutineScope()
    var result by remember { mutableStateOf<RotateResponse?>(null) }
    var lastAction by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var reveal by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

    fun rotate(action: String, call: suspend () -> ApiResult<RotateResponse>) {
        if (activity == null) return
        BiometricGate.reset()
        BiometricGate.gateSensitive(
            activity,
            action = "Rotate $action",
            onPass = {
                scope.launch {
                    busy = true
                    reveal = false
                    error = null
                    val res = withContext(Dispatchers.IO) { call() }
                    busy = false
                    when (res) {
                        is ApiResult.Ok -> {
                            result = res.value
                            lastAction = action
                        }
                        is ApiResult.Http    -> error = "${res.code} ${res.message}"
                        is ApiResult.Network -> error = res.cause
                    }
                }
            },
            onFail = { error = "Biometric cancelled" },
        )
    }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.lg)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.Outlined.ArrowBack, contentDescription = "Back")
            }
            Text("Secret rotation", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
        }
        Spacer(Modifier.height(Spacing.sm))

        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Rotate JWT secret", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "Invalidates every existing dashboard session and forces re-login. Use only when a JWT compromise is suspected.",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(
                    enabled = !busy,
                    onClick = { rotate("JWT") { appGraph.apiClient()!!.rotateJwt() } },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer),
                ) { Text(if (busy && lastAction == "JWT") "Rotating…" else "Rotate JWT secret") }
            }
        }
        Spacer(Modifier.height(Spacing.sm))

        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Rotate bootstrap token", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "Used by legacy long-lived endpoint deploys. Rotating here breaks any deploy script that still embeds the old value.",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(
                    enabled = !busy,
                    onClick = { rotate("bootstrap") { appGraph.apiClient()!!.rotateBootstrap() } },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer),
                ) { Text(if (busy && lastAction == "bootstrap") "Rotating…" else "Rotate bootstrap token") }
            }
        }

        Spacer(Modifier.height(Spacing.sm))

        // ─── Result / reveal slot ──────────────────────────────────────
        result?.let { r ->
            AptCard {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Rotated: $lastAction", style = AptType.titleSmall, color = MaterialTheme.colorScheme.primary)
                    r.instructions?.let { Text(it, style = AptType.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    val plaintext = r.plaintext()
                    if (!plaintext.isNullOrBlank()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = if (reveal) plaintext else "•".repeat(24),
                                style = AptType.mono,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                            )
                            IconButton(onClick = { reveal = !reveal }) {
                                Icon(
                                    if (reveal) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                    contentDescription = if (reveal) "Hide" else "Reveal",
                                )
                            }
                        }
                        Text(
                            "Copy this now — it cannot be retrieved again.",
                            style = AptType.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }
        error?.let {
            Spacer(Modifier.height(Spacing.sm))
            AptCard { Text(it, style = AptType.bodyMedium, color = MaterialTheme.colorScheme.error) }
        }
    }
}
