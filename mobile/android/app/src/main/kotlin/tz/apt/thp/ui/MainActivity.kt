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
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.navigation.compose.rememberNavController
import tz.apt.thp.AppGraph
import tz.apt.thp.core.auth.SessionRefresher
import tz.apt.thp.core.design.AptTheme
import tz.apt.thp.core.design.ThemeController
import tz.apt.thp.core.rbac.LocalSession
import tz.apt.thp.core.rbac.Role
import tz.apt.thp.core.rbac.SessionStore
import tz.apt.thp.data.AuthEvents
import tz.apt.thp.feature.auth.EnrollRoute
import tz.apt.thp.feature.auth.LockRoute
import tz.apt.thp.navigation.AptBottomBar
import tz.apt.thp.navigation.AptNavHost
import tz.apt.thp.navigation.InboxRoutes
import tz.apt.thp.navigation.TabRoute
import tz.apt.thp.notif.NotifChannels
import tz.apt.thp.security.BiometricGate
import tz.apt.thp.service.NotificationListener

/**
 * Thin host. Responsibilities:
 *   - branded splash + biometric gate + post-notification permission
 *   - deep-link parsing (apt-thp://alert/<id>) → routes the NavHost to the
 *     investigation panel
 *   - process-lifecycle observer that resets biometric on background→foreground
 *   - top-level branching between Enroll / Lock / NavHost
 *
 * Screens themselves live under feature/. No business logic in here.
 */

// Cross-composable state. Held at file scope (not in the Activity) so the
// deep-link reader in MainActivity.handleIntent + the NavHost subtree both
// observe the same value. Kept private to ui/.
private var pendingDeepLinkAlertId by mutableStateOf<String?>(null)
private var authPassed by mutableStateOf(false)
private var splashReady by mutableStateOf(false)
private var unauthorizedReason by mutableStateOf<String?>(null)

class MainActivity : FragmentActivity() {

    private val askNotifPerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* ignored */ }

    @ExperimentalGetImage
    override fun onCreate(savedInstanceState: Bundle?) {
        val splash = installSplashScreen()
        super.onCreate(savedInstanceState)
        splash.setKeepOnScreenCondition { !splashReady }

        // Hide from recents thumbnail + screenshots (sensitive payloads).
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        NotifChannels.ensure(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
        ) {
            askNotifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        handleIntent(intent)

        AuthEvents.onUnauthorized = { reason ->
            runOnUiThread { unauthorizedReason = reason }
        }

        setContent { AppRoot(this) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private val processObserver = object : DefaultLifecycleObserver {
        override fun onStart(owner: LifecycleOwner) {
            if (AppGraph.from(this@MainActivity).prefs.isEnrolled()) {
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
        if (AppGraph.from(this).prefs.isEnrolled() && !authPassed) {
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
        BiometricGate.gateAppOpen(
            this,
            onPass = { authPassed = true },
            onFail = { authPassed = false },
        )
    }

    private fun handleIntent(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "apt-thp" && data.host == "alert") {
            val id = data.lastPathSegment
            if (!id.isNullOrBlank()) pendingDeepLinkAlertId = id
        }
    }
}

@ExperimentalGetImage
@Composable
private fun AppRoot(activity: FragmentActivity) {
    val ctx = LocalContext.current
    val themeMode by ThemeController.mode.collectAsState()
    val session by SessionStore.current.collectAsState()
    val appGraph = remember { AppGraph.from(ctx) }

    var enrolled by remember { mutableStateOf(appGraph.prefs.isEnrolled()) }

    // 401 from the server → drop creds + go back to enrolment.
    LaunchedEffect(unauthorizedReason) {
        if (unauthorizedReason != null && enrolled) {
            NotificationListener.stop(ctx)
            appGraph.prefs.clear()
            SessionStore.clear()
            BiometricGate.reset()
            authPassed = false
            enrolled = false
        }
    }

    AptTheme(mode = themeMode) {
        CompositionLocalProvider(LocalSession provides session) {
            when {
                !enrolled -> EnrollRoute(
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
                !authPassed -> LockRoute(onUnlock = { (activity as MainActivity).promptAppOpen() })
                else -> {
                    // Background-refresh the role on first composition after unlock.
                    SessionRefresher()
                    ShellWithNav(role = session?.role ?: Role.UNKNOWN)
                }
            }
        }
    }
}

@Composable
private fun ShellWithNav(role: Role) {
    val navController = rememberNavController()

    // Deep link → jump to the investigation panel.
    LaunchedEffect(pendingDeepLinkAlertId) {
        val id = pendingDeepLinkAlertId ?: return@LaunchedEffect
        navController.navigate(TabRoute.Inbox.path) {
            launchSingleTop = true
        }
        navController.navigate(InboxRoutes.detail(id))
        pendingDeepLinkAlertId = null
    }

    Scaffold(
        bottomBar = { AptBottomBar(navController = navController, role = role) },
    ) { padding ->
        AptNavHost(navController = navController, modifier = Modifier.padding(padding))
    }
}
