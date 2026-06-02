package tz.apt.thp.feature.auth

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.ExperimentalGetImage
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tz.apt.thp.AppGraph
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.rbac.Role
import tz.apt.thp.core.rbac.Session
import tz.apt.thp.core.rbac.SessionStore
import tz.apt.thp.data.ApiResult
import tz.apt.thp.data.DeviceContext
import tz.apt.thp.data.Enrol
import tz.apt.thp.ui.QrScanner

/**
 * Enrolment screen. Same pairing protocol as before:
 *   1. Scan QR (or paste payload) → POST /auth/exchange-enroll
 *   2. Server returns api_key + (optionally) the user's role
 *   3. We persist creds, set the SessionStore, hand off to onEnrolled()
 *
 * Lifted out of MainActivity so the new NavHost-driven shell can route to
 * it from a clean slate. Behaviour is unchanged.
 */
@ExperimentalGetImage
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EnrollRoute(
    onEnrolled: () -> Unit,
    initialMessage: String? = null,
    onInitialMessageShown: () -> Unit = {},
) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val scope = rememberCoroutineScope()
    val snackbarHost = remember { SnackbarHostState() }
    var qrText by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(false) }

    LaunchedEffect(initialMessage) {
        val msg = initialMessage
        if (!msg.isNullOrBlank()) {
            snackbarHost.showSnackbar(msg, duration = SnackbarDuration.Long)
            onInitialMessageShown()
        }
    }

    var locationAsked by remember { mutableStateOf(false) }
    val askLocation = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* ignored */ }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Pair this device") }) },
        snackbarHost = { SnackbarHost(snackbarHost) },
    ) { pad ->
        if (scanning) {
            Box(Modifier.padding(pad).fillMaxSize()) {
                QrScanner(
                    onDetected = { text ->
                        qrText = text
                        scanning = false
                        scope.launch { snackbarHost.showSnackbar("QR detected.") }
                    },
                    onPermissionDenied = {
                        scanning = false
                        scope.launch { snackbarHost.showSnackbar("Camera permission denied.") }
                    },
                )
                FloatingActionButton(
                    onClick = { scanning = false },
                    modifier = Modifier.align(Alignment.BottomEnd).padding(20.dp),
                ) { Text("Cancel") }
            }
            return@Scaffold
        }
        Column(
            modifier = Modifier
                .padding(pad).padding(Spacing.xl)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(Spacing.md),
        ) {
            Text(
                "Scan the QR from the dashboard's Companion app page, or paste " +
                    "the JSON payload below.",
                style = AptType.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            OutlinedButton(
                onClick = { scanning = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Outlined.QrCodeScanner, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Scan QR")
            }
            LaunchedEffect(Unit) {
                if (!locationAsked) {
                    locationAsked = true
                    askLocation.launch(Manifest.permission.ACCESS_COARSE_LOCATION)
                }
            }
            HorizontalDivider()
            OutlinedTextField(
                value = qrText, onValueChange = { qrText = it },
                label = { Text("QR payload (JSON)") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                enabled = qrText.isNotBlank() && !loading,
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    loading = true
                    scope.launch {
                        val parsed = Enrol.parseQr(qrText)
                        if (parsed == null) {
                            loading = false
                            snackbarHost.showSnackbar("Could not parse QR payload.")
                            return@launch
                        }
                        val deviceName = DeviceContext.deviceName(ctx)
                        val loc = DeviceContext.coarseLocation(ctx)
                        val res = withContext(Dispatchers.IO) {
                            Enrol.exchange(
                                serverUrl = parsed.server_url,
                                token = parsed.token,
                                deviceName = deviceName,
                                lat = loc?.first,
                                lon = loc?.second,
                            )
                        }
                        loading = false
                        when (res) {
                            is ApiResult.Ok -> {
                                val v = res.value
                                appGraph.prefs.save(
                                    serverUrl = v.server_url,
                                    apiKey = v.api_key,
                                    username = v.username,
                                    role = v.role,
                                )
                                SessionStore.set(
                                    Session(
                                        username = v.username,
                                        role = Role.from(v.role),
                                        serverUrl = v.server_url,
                                    ),
                                )
                                onEnrolled()
                            }
                            is ApiResult.Http -> {
                                val msg = when (res.code) {
                                    409 -> "This QR was already used. Open the " +
                                            "dashboard → Settings → Pair phone, tap " +
                                            "Regenerate QR, then scan the new code."
                                    401 -> "This QR has expired (10-min limit). " +
                                            "Generate a fresh one."
                                    else -> "Exchange failed (${res.code}): ${res.message}"
                                }
                                snackbarHost.showSnackbar(msg, duration = SnackbarDuration.Long)
                            }
                            is ApiResult.Network -> snackbarHost.showSnackbar(
                                "Network error: ${res.cause}",
                            )
                        }
                    }
                },
            ) { Text(if (loading) "Pairing…" else "Pair") }

            HorizontalDivider()
            Text(
                "Tip: open the dashboard at Settings → Companion app for a QR.",
                style = AptType.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

