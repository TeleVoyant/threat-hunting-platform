package tz.apt.thp.feature.more

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import tz.apt.thp.AppGraph
import tz.apt.thp.core.auth.rememberBiometricStepUp
import tz.apt.thp.core.design.AptType
import tz.apt.thp.core.design.Spacing
import tz.apt.thp.core.design.components.AptCard
import tz.apt.thp.core.design.components.Qr
import tz.apt.thp.core.design.components.StatusPill
import tz.apt.thp.data.InstallToken
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Operator-mode mint-token UI. Lets a field operator generate a fresh
 * install token (single- or multi-use), share the URL via the system
 * share-sheet, copy the one-liner, and revoke outstanding tokens.
 *
 * Distinct from EnrollRoute under feature/auth/ which pairs THIS device.
 */
@Composable
fun EnrollmentRoute(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val appGraph = remember { AppGraph.from(ctx) }
    val vm: EnrollmentViewModel = viewModel(factory = EnrollmentViewModel.Factory(appGraph))
    val state by vm.state.collectAsState()
    val snackbarHost = remember { SnackbarHostState() }

    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHost.showSnackbar(it)
            vm.clearMessage()
        }
    }

    var capacity by remember { mutableStateOf(10) }
    var unlimited by remember { mutableStateOf(false) }
    var ttlMin by remember { mutableStateOf(30) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(Spacing.lg)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(Spacing.md),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.Outlined.ArrowBack, contentDescription = "Back")
            }
            Text("Enrollment", style = AptType.titleLarge, color = MaterialTheme.colorScheme.onSurface)
        }

        // ─── Form ──────────────────────────────────────────────────────
        AptCard {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Mint a new install token", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    text = "Profile defaults to Full — required for the credential-lateral-movement and DNS-exfil detectors to perform at their trained accuracy.",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Spacer(Modifier.height(4.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Unlimited", style = AptType.labelMedium, modifier = Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurface)
                    Switch(checked = unlimited, onCheckedChange = { unlimited = it })
                }

                if (!unlimited) {
                    OutlinedTextField(
                        value = capacity.toString(),
                        onValueChange = { v -> v.toIntOrNull()?.takeIf { it in 1..1000 }?.let { capacity = it } },
                        label = { Text("Capacity (1–1000)") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                OutlinedTextField(
                    value = ttlMin.toString(),
                    onValueChange = { v -> v.toIntOrNull()?.takeIf { it in 5..240 }?.let { ttlMin = it } },
                    label = { Text("Expires in minutes (5–240)") },
                    modifier = Modifier.fillMaxWidth(),
                )
                val mintReason = "Mint ${if (unlimited) "unlimited" else capacity.toString() + "-use"} install token (${ttlMin} min)"
                // alwaysPrompt: minting a token is the credential-issuing
                // surface — fresh biometric every time, no grace bypass.
                val onMint = rememberBiometricStepUp(
                    actionLabel = mintReason,
                    alwaysPrompt = true,
                ) {
                    vm.create(
                        profile = "Full",
                        maxUses = if (unlimited) 0 else capacity,
                        ttlMinutes = ttlMin,
                    )
                }
                Button(
                    enabled = !state.creating,
                    onClick = onMint,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (state.creating) "Minting…" else "Generate token") }
            }
        }

        // ─── Result (last-minted token) ────────────────────────────────
        state.lastMinted?.let { token ->
            AptCard {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Share with the endpoint owner", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)

                    val url = token.url ?: ""
                    if (url.isNotBlank()) {
                        // Local QR — never round-tripped through public encoders.
                        Qr(text = url, size = 220.dp, modifier = Modifier)
                    }

                    val oneLiner = token.one_liner ?: ""
                    Text(oneLiner, style = AptType.mono, color = MaterialTheme.colorScheme.onSurface)

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { ctx.copyToClipboard("install one-liner", oneLiner) }) {
                            Icon(Icons.Outlined.ContentCopy, contentDescription = null)
                            Spacer(Modifier.width(6.dp))
                            Text("Copy")
                        }
                        TextButton(onClick = { ctx.shareText(oneLiner) }) {
                            Icon(Icons.Outlined.Share, contentDescription = null)
                            Spacer(Modifier.width(6.dp))
                            Text("Share")
                        }
                    }
                    Text(
                        text = "Capacity ${token.use_count} / ${if (token.max_uses == 0) "∞" else token.max_uses.toString()}",
                        style = AptType.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // ─── Active tokens list ────────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Active tokens", style = AptType.titleSmall, color = MaterialTheme.colorScheme.onSurface)
            IconButton(onClick = { vm.refresh() }) {
                Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
            }
        }

        if (state.active.isEmpty()) {
            AptCard {
                Text(
                    state.error ?: "No active tokens. Generate one above to onboard a laptop.",
                    style = AptType.bodyMedium,
                    color = if (state.error != null) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                state.active.forEach { t ->
                    // alwaysPrompt: revoking blocks any laptop still
                    // holding the URL from enrolling. Mirror the mint
                    // policy — credential-related actions never piggyback
                    // on stale grace.
                    val onRevoke = rememberBiometricStepUp(
                        actionLabel = "Revoke token #${t.id}",
                        alwaysPrompt = true,
                    ) { vm.revoke(t.id) }
                    ActiveTokenRow(t, onRevoke = onRevoke)
                }
            }
        }
    }

    SnackbarHost(snackbarHost)
}

@Composable
private fun ActiveTokenRow(token: InstallToken, onRevoke: () -> Unit) {
    val fmt = remember { SimpleDateFormat("HH:mm", Locale.US) }
    val expiresLabel = fmt.format(Date((token.expires_at * 1000).toLong()))
    AptCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "#${token.id} · ${token.profile}",
                    style = AptType.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    "Used ${token.use_count} / ${if (token.max_uses == 0) "∞" else token.max_uses.toString()} · expires $expiresLabel",
                    style = AptType.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            StatusPill(label = "ACTIVE", status = "ok")
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = onRevoke) { Text("Revoke") }
        }
    }
}

private fun Context.copyToClipboard(label: String, text: String) {
    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText(label, text))
}

private fun Context.shareText(text: String) {
    val sendIntent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val chooser = Intent.createChooser(sendIntent, "Share install URL")
    chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { startActivity(chooser) }
}

