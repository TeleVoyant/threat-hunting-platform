package tz.apt.thp.core.design

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Process-wide theme mode source-of-truth. Persists the choice in
 * `EncryptedSharedPreferences` so it survives reboots and cannot be tampered
 * with by other apps.
 *
 * Reads happen SYNCHRONOUSLY in [boot] (called from [AptApplication.onCreate])
 * so the first composition uses the correct mode — eliminates the white-flash
 * the dashboard's first-paint script also defends against.
 *
 * Held as a singleton because Compose's CompositionLocal only carries the
 * resolved mode at draw time; the toggle UI needs a stable reference to write.
 */
object ThemeController {

    private const val PREFS_NAME = "apt-thp-theme"
    private const val KEY_MODE   = "theme_mode"

    private val _mode = MutableStateFlow(ThemeMode.Auto)
    val mode: StateFlow<ThemeMode> = _mode

    /** Synchronous read; call from Application.onCreate before setContent. */
    fun boot(ctx: Context) {
        val sp = openPrefs(ctx)
        val raw = sp.getString(KEY_MODE, ThemeMode.Auto.name) ?: ThemeMode.Auto.name
        _mode.value = runCatching { ThemeMode.valueOf(raw) }.getOrDefault(ThemeMode.Auto)
    }

    /** Cycle Auto → Light → Dark → Auto (matches the dashboard cycler). */
    fun cycle(ctx: Context) {
        val next = when (_mode.value) {
            ThemeMode.Auto  -> ThemeMode.Light
            ThemeMode.Light -> ThemeMode.Dark
            ThemeMode.Dark  -> ThemeMode.Auto
        }
        set(ctx, next)
    }

    fun set(ctx: Context, mode: ThemeMode) {
        if (_mode.value == mode) return
        _mode.value = mode
        openPrefs(ctx).edit().putString(KEY_MODE, mode.name).apply()
    }

    private fun openPrefs(ctx: Context) = EncryptedSharedPreferences.create(
        ctx,
        PREFS_NAME,
        MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}
