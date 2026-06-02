package tz.apt.thp.core.rbac

import androidx.compose.runtime.Composable

/**
 * Wraps `content` and only emits it if the active session has [perm].
 * Used liberally inside each feature's screens to hide UI a user can't
 * action. Defence-in-depth — the server still 403s the underlying call.
 *
 * Per the design decision in the plan addendum, unauthorized features are
 * HIDDEN entirely (not greyed). Calling site renders nothing.
 */
@Composable
fun RequirePermission(perm: String, content: @Composable () -> Unit) {
    val session = LocalSession.current ?: return
    if (PermissionMap.has(session.role, perm)) content()
}

/**
 * Same as [RequirePermission] but exposes an `else` slot so callers can
 * render a placeholder, locked badge, or a "request access" prompt. Useful
 * inside lists where preserving layout matters.
 */
@Composable
fun RequirePermissionOr(
    perm: String,
    fallback: @Composable () -> Unit,
    content: @Composable () -> Unit,
) {
    val session = LocalSession.current
    if (session != null && PermissionMap.has(session.role, perm)) content() else fallback()
}
