package tz.apt.thp.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.ExperimentalGetImage
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccessTime
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Logout
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.WifiTetheringErrorRounded
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tz.apt.thp.data.AlertNote
import tz.apt.thp.data.AlertSummary
import tz.apt.thp.data.ApiClient
import tz.apt.thp.data.ApiResult
import tz.apt.thp.data.AuthEvents
import tz.apt.thp.data.DeviceContext
import tz.apt.thp.data.Enrol
import tz.apt.thp.data.Notification as NotificationModel
import tz.apt.thp.data.Prefs
import tz.apt.thp.notif.NotifChannels
import tz.apt.thp.security.BiometricGate
import tz.apt.thp.service.NotificationListener
import tz.apt.thp.service.QuickReplyReceiver
import tz.apt.thp.ui.theme.AptThpTheme
import tz.apt.thp.ui.theme.Brand
import tz.apt.thp.ui.theme.severityColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// Single source of truth for the deep-linked alert id between MainActivity
// and its composables — set when an `apt-thp://alert/<id>` intent fires.
private var pendingDeepLinkAlertId by mutableStateOf<String?>(null)
// Reactive auth state — flips true once BiometricGate.gateAppOpen passes.
private var authPassed by mutableStateOf(false)
// Splash dismissal hint — flips true once the first composition is ready.
private var splashReady by mutableStateOf(false)
// Set non-null by AuthEvents when the server returns 401. AppRoot watches
// this and routes back to EnrollScreen with the reason as a snackbar.
private var unauthorizedReason by mutableStateOf<String?>(null)

class MainActivity : FragmentActivity() {

    private val askNotifPerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* ignore */ }

    @ExperimentalGetImage
    override fun onCreate(savedInstanceState: Bundle?) {
        // Branded splash. Hold it on screen until we know whether the user
        // is enrolled — avoids a flash of the InboxScreen before the lock.
        val splash = installSplashScreen()
        super.onCreate(savedInstanceState)
        splash.setKeepOnScreenCondition {
            // Hide once Compose has had a chance to render the lock or enrol UI.
            !splashReady
        }

        // Keep the inbox / detail out of the recents thumbnail and screenshots.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE)

        NotifChannels.ensure(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            askNotifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        handleIntent(intent)

        // 401 hook — fires from ApiClient or NotificationListener when the
        // server rejects our api_key (typically because an admin unpaired
        // this phone via the dashboard). Sets the global state; the AppRoot
        // composable does the actual cleanup on the next recomposition.
        AuthEvents.onUnauthorized = { reason ->
            runOnUiThread { unauthorizedReason = reason }
        }

        setContent { AptThpTheme { AppRoot(this) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private val processObserver = object : DefaultLifecycleObserver {
        override fun onStart(owner: LifecycleOwner) {
            // App came to foreground (cold start or returning from another app).
            // Require biometric on every such transition. This does NOT fire
            // when individual activities pause/resume — only when the *process*
            // moves between background and foreground — so we never self-loop
            // with the BiometricPrompt itself.
            if (Prefs.get(this@MainActivity).isEnrolled()) {
                authPassed = false
                BiometricGate.reset()
                promptAppOpen()
            } else {
                authPassed = true
            }
            splashReady = true
        }
    }

    override fun onResume() {
        super.onResume()
        // Lifecycle observer fires onStart at process foreground, but if this
        // is the very first onResume of a hot-from-background re-entry we
        // still want to make sure the user lands on the lock screen rather
        // than a stale InboxScreen.
        if (Prefs.get(this).isEnrolled() && !authPassed) {
            promptAppOpen()
        }
    }

    override fun onStart() {
        super.onStart()
        ProcessLifecycleOwner.get().lifecycle.addObserver(processObserver)
    }

    override fun onStop() {
        ProcessLifecycleOwner.get().lifecycle.removeObserver(processObserver)
        super.onStop()
    }

    internal fun promptAppOpen() {
        BiometricGate.gateAppOpen(this,
            onPass = { authPassed = true },
            onFail = {
                // User cancelled / no biometric. Stay on the lock screen with
                // a Try-again button rather than killing the task — killing
                // makes the next launch confusing.
                authPassed = false
            })
    }

    private fun handleIntent(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "apt-thp" && data.host == "alert") {
            // Path is /<alert_id>; take the last segment.
            val id = data.lastPathSegment
            if (!id.isNullOrBlank()) pendingDeepLinkAlertId = id
        }
    }
}

@ExperimentalGetImage
@Composable
fun AppRoot(activity: FragmentActivity) {
    val ctx = LocalContext.current
    val prefs = remember { Prefs.get(ctx) }
    var enrolled by remember { mutableStateOf(prefs.isEnrolled()) }

    // 401 from the server → drop creds + go back to enrolment. Effect runs
    // once per non-null change of unauthorizedReason.
    LaunchedEffect(unauthorizedReason) {
        if (unauthorizedReason != null && enrolled) {
            NotificationListener.stop(ctx)
            prefs.clear()
            BiometricGate.reset()
            authPassed = false
            enrolled = false
        }
    }

    if (!enrolled) {
        // Pre-enrolment: no auth gate (nothing to protect yet).
        // Pass through any pending unauth reason so the EnrollScreen can
        // surface it as the first snackbar — explains *why* the user is
        // suddenly seeing this screen again.
        EnrollScreen(
            initialMessage = unauthorizedReason,
            onEnrolled = {
                enrolled = true
                authPassed = true
                unauthorizedReason = null
                BiometricGate.reset()
                NotificationListener.start(ctx)
            },
            onInitialMessageShown = { unauthorizedReason = null },
        )
        return
    }

    if (!authPassed) {
        LockScreen(onUnlock = { (activity as MainActivity).promptAppOpen() })
        return
    }

    InboxScreen(
        activity = activity,
        onReset = {
            NotificationListener.stop(ctx)
            prefs.clear()
            BiometricGate.reset()
            authPassed = false
            enrolled = false
        },
    )
}

// ── Lock screen ─────────────────────────────────────────────────────────────

@Composable
private fun LockScreen(onUnlock: () -> Unit) {
    Surface(modifier = Modifier.fillMaxSize(), color = Brand.Navy900) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(
                Icons.Outlined.Fingerprint,
                contentDescription = null,
                tint = Brand.TealPrimary,
                modifier = Modifier.size(72.dp),
            )
            Spacer(Modifier.height(16.dp))
            Text("APT THP", color = Color.White, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text("Locked", color = Brand.InkMuted, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(32.dp))
            Button(onClick = onUnlock) {
                Icon(Icons.Outlined.Fingerprint, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Unlock")
            }
        }
    }
}

// ── Reusable confirmation dialog ────────────────────────────────────────────

@Composable
private fun ConfirmDialog(
    title: String,
    body: String,
    confirmLabel: String = "Confirm",
    danger: Boolean = false,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text  = { Text(body) },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                colors = if (danger)
                    ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                else ButtonDefaults.textButtonColors(),
            ) { Text(confirmLabel) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

// ── Enrol ────────────────────────────────────────────────────────────────────

@ExperimentalGetImage
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EnrollScreen(
    onEnrolled: () -> Unit,
    initialMessage: String? = null,
    onInitialMessageShown: () -> Unit = {},
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHost = remember { SnackbarHostState() }
    var qrText by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(false) }

    // Surface the reason we landed back here (e.g. "device was unpaired").
    LaunchedEffect(initialMessage) {
        val msg = initialMessage
        if (!msg.isNullOrBlank()) {
            snackbarHost.showSnackbar(msg, duration = SnackbarDuration.Long)
            onInitialMessageShown()
        }
    }

    // Best-effort location permission — declined is fine, enrolment proceeds.
    var locationAsked by remember { mutableStateOf(false) }
    val askLocation = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission(),
    ) { /* result ignored; we read the resolved value at exchange time */ }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Enrol — APT THP") }) },
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
                .padding(pad).padding(20.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Scan the QR from the dashboard's Companion app page, or paste " +
                 "the JSON payload below.")
            OutlinedButton(
                onClick = { scanning = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Outlined.QrCodeScanner, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Scan QR")
            }
            // One-shot permission ask the first time the screen renders. The
            // server stores the location only at enrolment — no continuous
            // tracking. Declining proceeds without coordinates.
            LaunchedEffect(Unit) {
                if (!locationAsked) {
                    locationAsked = true
                    askLocation.launch(android.Manifest.permission.ACCESS_COARSE_LOCATION)
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
                                Prefs.get(ctx).save(res.value.server_url, res.value.api_key, res.value.username)
                                onEnrolled()
                            }
                            is ApiResult.Http -> {
                                val msg = when (res.code) {
                                    409 -> "This QR was already used. Open " +
                                            "the dashboard " + "→ Settings → " +
                                            "Pair phone, tap Regenerate QR, " +
                                            "then scan the new code."
                                    401 -> "This QR has expired (10-min limit). Generate a fresh one."
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
            ) { Text(if (loading) "Enrolling…" else "Enrol") }

            HorizontalDivider()
            Text("Tip: open the dashboard at Settings → Companion app for a QR.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

// ── Inbox ────────────────────────────────────────────────────────────────────

private enum class SevFilter(val label: String, val match: (String) -> Boolean) {
    ALL("All", { true }),
    CRIT("Critical", { it.equals("critical", true) }),
    HIGH("High", { it.equals("high", true) }),
    OTHER("Other", { !it.equals("critical", true) && !it.equals("high", true) }),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InboxScreen(activity: FragmentActivity, onReset: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { Prefs.get(ctx) }
    val snackbarHost = remember { SnackbarHostState() }

    var rows by remember { mutableStateOf(emptyList<NotificationModel>()) }
    var filter by remember { mutableStateOf(SevFilter.ALL) }
    var selected by remember { mutableStateOf<NotificationModel?>(null) }
    var loading by remember { mutableStateOf(false) }
    var stale by remember { mutableStateOf(false) }
    var logoutDialogOpen by remember { mutableStateOf(false) }
    // For swipe-to-acknowledge: the row currently awaiting confirmation.
    var pendingSwipeAck by remember { mutableStateOf<NotificationModel?>(null) }

    fun refresh() {
        scope.launch {
            loading = true
            val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
            val res = withContext(Dispatchers.IO) { client.poll(0.0) }
            loading = false
            when (res) {
                is ApiResult.Ok      -> { rows = res.value; stale = false }
                is ApiResult.Http    -> snackbarHost.showSnackbar("Server: ${res.code} ${res.message}")
                is ApiResult.Network -> { stale = true; snackbarHost.showSnackbar("Offline: ${res.cause}") }
            }
        }
    }

    LaunchedEffect(Unit) { refresh() }
    // Honour deep links: jump straight to DetailPane for the requested alert.
    LaunchedEffect(pendingDeepLinkAlertId, rows) {
        val id = pendingDeepLinkAlertId ?: return@LaunchedEffect
        rows.firstOrNull { it.alert_id == id }?.let {
            selected = it
            pendingDeepLinkAlertId = null
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("APT THP") },
                actions = {
                    IconButton(onClick = { refresh() }) {
                        Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
                    }
                    IconButton(onClick = { logoutDialogOpen = true }) {
                        Icon(Icons.Outlined.Logout, contentDescription = "Log out")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHost) },
    ) { pad ->
        // ── Confirmation dialogs ────────────────────────────────────────────
        if (logoutDialogOpen) ConfirmDialog(
            title = "Log out and forget this device?",
            body  = "Your api_key will be cleared and notifications will stop. "
                    + "You'll need to re-enrol via a fresh QR.",
            confirmLabel = "Log out",
            danger = true,
            onConfirm = {
                logoutDialogOpen = false
                BiometricGate.gateSensitive(activity, "Log out", onPass = { onReset() })
            },
            onDismiss = { logoutDialogOpen = false },
        )
        pendingSwipeAck?.let { n ->
            ConfirmDialog(
                title = "Acknowledge alert?",
                body  = "[${n.severity.uppercase()}] ${n.title ?: n.alert_id}\n\nThis is audit-logged.",
                confirmLabel = "Acknowledge",
                onConfirm = {
                    pendingSwipeAck = null
                    BiometricGate.gateSensitive(activity, "Acknowledge", onPass = {
                        scope.launch {
                            val ok = withContext(Dispatchers.IO) {
                                ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
                                    .acknowledge(n.alert_id)
                            }
                            if (ok is ApiResult.Ok) {
                                prefs.markRead(n.id); prefs.bumpAckCount()
                                snackbarHost.showSnackbar("Acknowledged.")
                                refresh()
                            } else {
                                snackbarHost.showSnackbar("Ack failed.")
                            }
                        }
                    })
                },
                onDismiss = { pendingSwipeAck = null },
            )
        }

        if (selected != null) {
            DetailPane(
                activity = activity,
                notif = selected!!,
                onClose = { selected = null },
                onAcknowledged = {
                    scope.launch { snackbarHost.showSnackbar("Alert acknowledged.") }
                    refresh()
                },
                onNotePosted = {
                    scope.launch { snackbarHost.showSnackbar("Note posted.") }
                },
                onError = { msg ->
                    scope.launch { snackbarHost.showSnackbar(msg) }
                },
            )
            return@Scaffold
        }

        Column(modifier = Modifier.padding(pad).fillMaxSize()) {
            OnCallBadge(prefs)
            if (stale) StaleBanner(onReconnect = {
                NotificationListener.start(ctx)
                refresh()
            })

            // Filter chips
            Row(
                Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SevFilter.values().forEach { f ->
                    FilterChip(
                        selected = filter == f,
                        onClick = { filter = f },
                        label = { Text(f.label) },
                    )
                }
            }

            if (loading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

            val visible = rows.filter { filter.match(it.severity) }
            if (visible.isEmpty() && !loading) {
                Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Text(
                        if (rows.isEmpty()) "Listener idle — no detections yet."
                        else "No ${filter.label.lowercase()} detections in the current window.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                    visible.forEach { n ->
                        NotificationRow(
                            n = n,
                            read = prefs.isRead(n.id),
                            onOpen = { selected = n },
                            onSwipeAck = { pendingSwipeAck = n },
                        )
                        HorizontalDivider()
                    }
                }
            }

            // Personal weekly stat — small footer line.
            Text(
                "You've acknowledged ${prefs.ackCountThisWeek()} alerts this week.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(12.dp),
            )
        }
    }
}

// ── Rows + accessories ──────────────────────────────────────────────────────

@Composable
private fun NotificationRow(
    n: NotificationModel,
    read: Boolean,
    onOpen: () -> Unit,
    onSwipeAck: () -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    var offsetX by remember(n.id) { mutableFloatStateOf(0f) }

    // Pulse only when this is CRITICAL.
    val pulseColor = if (n.severity.equals("critical", true)) {
        val transition = rememberInfiniteTransition(label = "crit-pulse")
        val alpha by transition.animateFloat(
            0.35f, 1f,
            infiniteRepeatable(tween(900), repeatMode = RepeatMode.Reverse),
            label = "crit-alpha",
        )
        Brand.SevCritical.copy(alpha = alpha)
    } else severityColor(n.severity)

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (!read) MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                else Color.Transparent,
            )
            .pointerInput(n.id) {
                detectHorizontalDragGestures(
                    onDragEnd = {
                        if (offsetX > 240f) {
                            haptic.performHapticFeedback(androidx.compose.ui.hapticfeedback.HapticFeedbackType.LongPress)
                            onSwipeAck()
                        }
                        offsetX = 0f
                    },
                    onHorizontalDrag = { _, dx -> if (dx > 0) offsetX += dx },
                )
            }
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Box(modifier = Modifier
            .size(10.dp)
            .clip(CircleShape)
            .background(pulseColor))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                n.title ?: ("[" + n.severity.uppercase() + "]"),
                fontWeight = if (read) FontWeight.Normal else FontWeight.SemiBold,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
            n.body?.let {
                Text(it, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Text(
                relativeTime(n.created_at),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        TextButton(onClick = onOpen) { Text("Open") }
    }
}

@Composable
private fun StaleBanner(onReconnect: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.error.copy(alpha = 0.12f),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            Icon(Icons.Outlined.WifiTetheringErrorRounded,
                tint = MaterialTheme.colorScheme.error, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Reconnecting — alerts may be delayed.", modifier = Modifier.weight(1f))
            TextButton(onClick = onReconnect) { Text("Retry") }
        }
    }
}

@Composable
private fun OnCallBadge(prefs: Prefs) {
    val onCallUntil = prefs.onCallUntil()
    if (onCallUntil <= System.currentTimeMillis()) return
    val fmt = SimpleDateFormat("EEE HH:mm", Locale.getDefault())
    Surface(
        color = Brand.TealPrimary.copy(alpha = 0.15f),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            Icon(Icons.Outlined.Bolt, tint = Brand.TealPrimary, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("On call until ${fmt.format(Date(onCallUntil))}",
                color = MaterialTheme.colorScheme.onSurface)
        }
    }
}

// ── Detail pane ─────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetailPane(
    activity: FragmentActivity,
    notif: NotificationModel,
    onClose: () -> Unit,
    onAcknowledged: () -> Unit,
    onNotePosted: () -> Unit,
    onError: (String) -> Unit,
) {
    val ctx = LocalContext.current
    val prefs = remember { Prefs.get(ctx) }
    val scope = rememberCoroutineScope()
    var note by remember { mutableStateOf("") }
    var alert by remember { mutableStateOf<AlertSummary?>(null) }
    var notes by remember { mutableStateOf<List<AlertNote>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var ackDialogOpen by remember { mutableStateOf(false) }
    var pendingQuickReply by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(notif.alert_id) {
        val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
        loading = true
        val a = withContext(Dispatchers.IO) { client.getAlert(notif.alert_id) }
        if (a is ApiResult.Ok) alert = a.value
        val nlist = withContext(Dispatchers.IO) { client.listNotes(notif.alert_id) }
        if (nlist is ApiResult.Ok) notes = nlist.value
        loading = false
    }

    if (ackDialogOpen) ConfirmDialog(
        title = "Acknowledge alert?",
        body  = "[${notif.severity.uppercase()}] ${notif.title ?: notif.alert_id}\n\nThis is audit-logged.",
        confirmLabel = "Acknowledge",
        onConfirm = {
            ackDialogOpen = false
            BiometricGate.gateSensitive(activity, "Acknowledge", onPass = {
                scope.launch {
                    val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
                    val res = withContext(Dispatchers.IO) { client.acknowledge(notif.alert_id) }
                    when (res) {
                        is ApiResult.Ok -> {
                            prefs.markRead(notif.id); prefs.bumpAckCount()
                            onAcknowledged()
                        }
                        is ApiResult.Http    -> onError("Ack failed: ${res.code} ${res.message}")
                        is ApiResult.Network -> onError("Offline: ${res.cause}")
                    }
                }
            })
        },
        onDismiss = { ackDialogOpen = false },
    )

    pendingQuickReply?.let { preset ->
        ConfirmDialog(
            title = "Send quick reply?",
            body  = "Posts the note \"$preset\" and acknowledges the alert.\n\nBoth actions are audit-logged.",
            confirmLabel = "Send",
            onConfirm = {
                pendingQuickReply = null
                BiometricGate.gateSensitive(activity, preset, onPass = {
                    scope.launch {
                        val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
                        val ok = withContext(Dispatchers.IO) {
                            val r1 = client.postNote(notif.alert_id, preset)
                            val r2 = client.acknowledge(notif.alert_id)
                            r1 is ApiResult.Ok && r2 is ApiResult.Ok
                        }
                        if (ok) {
                            prefs.markRead(notif.id); prefs.bumpAckCount()
                            onAcknowledged()
                        } else onError("Quick-reply failed.")
                    }
                })
            },
            onDismiss = { pendingQuickReply = null },
        )
    }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text(notif.title ?: notif.severity.uppercase(), maxLines = 1) },
            navigationIcon = { TextButton(onClick = onClose) { Text("Back") } },
        )
    }) { pad ->
        Column(
            modifier = Modifier
                .padding(pad).padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SeverityBadge(notif.severity)
            notif.body?.let { Text(it) }
            alert?.let { a ->
                a.source_entity?.let { Text("Source: $it", style = MaterialTheme.typography.bodySmall) }
                if (a.mitre_techniques.isNotEmpty()) {
                    Text("MITRE: ${a.mitre_techniques.joinToString(", ")}",
                         style = MaterialTheme.typography.bodySmall)
                }
                a.status?.let { Text("Status: $it", style = MaterialTheme.typography.bodySmall) }
            }
            notif.url?.let {
                Text("Dashboard: $it", style = MaterialTheme.typography.bodySmall,
                     color = MaterialTheme.colorScheme.primary)
            }

            // Quick-reply chips: each posts a canned note + acknowledges,
            // gated by biometrics.
            Text("Quick reply", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                QuickReplyReceiver.PRESETS.forEach { preset ->
                    AssistChip(
                        label = { Text(preset) },
                        onClick = { pendingQuickReply = preset },
                    )
                }
            }

            Button(
                onClick = { ackDialogOpen = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Outlined.CheckCircle, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Acknowledge")
            }

            OutlinedTextField(
                value = note, onValueChange = { if (it.length <= 280) note = it },
                label = { Text("Investigation note (${note.length}/280)") },
                singleLine = false,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                enabled = note.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    BiometricGate.gateSensitive(activity, "Post note", onPass = {
                        scope.launch {
                            val client = ApiClient(prefs.serverUrl()!!, prefs.apiKey()!!)
                            val res = withContext(Dispatchers.IO) {
                                client.postNote(notif.alert_id, note.take(280))
                            }
                            when (res) {
                                is ApiResult.Ok -> {
                                    note = ""
                                    // Refresh the notes list.
                                    val nl = withContext(Dispatchers.IO) { client.listNotes(notif.alert_id) }
                                    if (nl is ApiResult.Ok) notes = nl.value
                                    onNotePosted()
                                }
                                is ApiResult.Http    -> onError("Server: ${res.code} ${res.message}")
                                is ApiResult.Network -> onError("Offline: ${res.cause}")
                            }
                        }
                    })
                },
            ) { Text("Post note") }

            HorizontalDivider()
            Text("Notes (${notes.size})", style = MaterialTheme.typography.labelLarge)
            if (loading) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            if (notes.isEmpty() && !loading) {
                Text("No notes yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            notes.forEach { n ->
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(10.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(n.actor, fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.weight(1f))
                            Icon(Icons.Outlined.AccessTime, contentDescription = null,
                                 modifier = Modifier.size(14.dp),
                                 tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.width(4.dp))
                            Text(relativeTime(n.at), style = MaterialTheme.typography.labelSmall)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(n.text)
                    }
                }
            }
        }
    }
}

@Composable
private fun SeverityBadge(sev: String) {
    Surface(
        color = severityColor(sev),
        shape = RoundedCornerShape(6.dp),
    ) {
        Text(
            sev.uppercase(),
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

private fun relativeTime(epochSeconds: Double?): String {
    if (epochSeconds == null || epochSeconds <= 0) return ""
    val deltaMs = System.currentTimeMillis() - (epochSeconds * 1000).toLong()
    val s = deltaMs / 1000
    return when {
        s < 60            -> "just now"
        s < 3600          -> "${s / 60}m ago"
        s < 86_400        -> "${s / 3600}h ago"
        s < 7 * 86_400    -> "${s / 86_400}d ago"
        else              -> SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
                                .format(Date((epochSeconds * 1000).toLong()))
    }
}
