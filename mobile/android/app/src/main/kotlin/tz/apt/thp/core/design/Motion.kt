package tz.apt.thp.core.design

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.navigation.NavBackStackEntry

/**
 * Motion library — Compose mirrors of the dashboard's two named animations
 * (`heartbeat`, `crit-pulse`) plus shared-axis nav transitions.
 *
 * Motion specs (matched to the dashboard's `styles.css`):
 *   - heartbeat: 1.2s loop, scale 1.0↔1.05, used on live-listener dots.
 *   - critPulse: 900ms reverse tween on alpha, used on CRITICAL rows.
 *   - shared-axis horizontal: 280ms, FastOutSlowInEasing.
 *   - panel-right (sheet): 220ms slide-in + fade.
 */

/** Heartbeat: slow scale pulse to indicate a live, healthy upstream. */
@Composable
fun Modifier.heartbeat(enabled: Boolean = true): Modifier {
    if (!enabled) return this
    val transition = rememberInfiniteTransition(label = "heartbeat")
    val scale by transition.animateFloat(
        initialValue = 1.0f,
        targetValue = 1.06f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "heartbeat-scale",
    )
    return this.scale(scale)
}

/** Critical alpha pulse — drives attention to the most urgent row. */
@Composable
fun Modifier.critPulse(enabled: Boolean = true): Modifier {
    if (!enabled) return this
    val transition = rememberInfiniteTransition(label = "crit")
    val alphaValue by transition.animateFloat(
        initialValue = 0.35f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "crit-alpha",
    )
    return this.alpha(alphaValue)
}

/** Shared-axis horizontal — used for in-tab forward navigation. */
fun sharedAxisHorizontalEnter(
    scope: AnimatedContentTransitionScope<NavBackStackEntry>,
    forward: Boolean = true,
): EnterTransition {
    val sign = if (forward) 1 else -1
    return slideInHorizontally(
        animationSpec = tween(280, easing = FastOutSlowInEasing),
        initialOffsetX = { fullWidth -> sign * (fullWidth / 6) },
    ) + fadeIn(animationSpec = tween(180))
}

fun sharedAxisHorizontalExit(
    scope: AnimatedContentTransitionScope<NavBackStackEntry>,
    forward: Boolean = true,
): ExitTransition {
    val sign = if (forward) -1 else 1
    return slideOutHorizontally(
        animationSpec = tween(280, easing = FastOutSlowInEasing),
        targetOffsetX = { fullWidth -> sign * (fullWidth / 6) },
    ) + fadeOut(animationSpec = tween(180))
}

/** Panel-right slide-in — used for bottom sheets and the investigation panel. */
fun panelRightEnter(): EnterTransition =
    slideInHorizontally(
        animationSpec = tween(220, easing = FastOutSlowInEasing),
        initialOffsetX = { fullWidth -> fullWidth / 4 },
    ) + fadeIn(animationSpec = tween(160)) + scaleIn(initialScale = 0.97f, animationSpec = tween(220))

fun panelRightExit(): ExitTransition =
    slideOutHorizontally(
        animationSpec = tween(180, easing = FastOutSlowInEasing),
        targetOffsetX = { fullWidth -> fullWidth / 4 },
    ) + fadeOut(animationSpec = tween(140))
