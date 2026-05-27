# APT THP — Android Companion App

Kotlin + Jetpack Compose. Listens for new detections from the platform and
posts them as native phone notifications. A `ForegroundService` holds the SSE
connection alive so weekend pages don't go silent while the dashboard is
closed.

**No third-party push service.** Every byte travels between the phone and the
platform's own API. This satisfies the Tanzania data-sovereignty constraint
that forbids relaying detection content via FCM / APNs / Slack / etc.

## What it does

- Pulls notifications over Server-Sent Events from `GET /notifications/stream`.
- Falls back to `GET /notifications/poll` every 5 min when the socket drops.
- Posts native notifications with three action buttons:
  - **Acknowledge** — `POST /alerts/{id}/acknowledge` straight from the lock screen.
  - **Open** — deep-links straight into the detail screen for that alert.
  - **Investigating** — quick-reply: posts a canned note + acknowledges in one round-trip.
- Detail screen shows other analysts' notes, source entity, MITRE technique
  IDs, and lets you reply with one of three preset chips or a free-form note
  (≤280 chars).

## Security posture

| Defence | File | What it does |
|---|---|---|
| Biometric gate on app open + sensitive actions | `security/BiometricGate.kt` | Prompts on app launch when the unlocked session is older than 30s. Re-prompts for Acknowledge / Post-Note when the last unlock is older than 5 min. Falls back to device PIN/pattern when no biometric is enrolled. |
| `FLAG_SECURE` on `MainActivity` | `ui/MainActivity.kt` | Keeps the inbox and detail screen out of the recents thumbnail and any screenshot the user attempts. |
| Lock-screen redaction | `notif/NotifChannels.kt` | All detection channels are `VISIBILITY_PRIVATE`. The lock screen shows the channel name only ("Critical detection"); IOCs and hostnames require unlocking. |
| Network security policy | `res/xml/network_security_config.xml` | Production-ready SPKI pin block + custom-CA trust anchor slot (drop a PEM at `res/raw/server.crt`). Cleartext currently *permitted* because the reference deployment is local HTTP; flip the comment in the file once HTTPS lands. |
| `dataExtractionRules.xml` | `res/xml/data_extraction_rules.xml` | Android 12+ explicit no-backup, no-device-transfer policy for prefs / files / databases / external. |
| Encrypted credentials | `data/Prefs.kt` | `EncryptedSharedPreferences` (AES-256-GCM values, AES-256-SIV keys) backed by `MasterKey` in the AndroidKeyStore. |
| `BroadcastReceiver` lifecycle | `service/AckReceiver.kt`, `service/QuickReplyReceiver.kt` | `goAsync()` + `PendingResult.finish()` so the OS doesn't kill the process before the HTTP round-trip completes. |
| Single-use enrol token | `data/Enrol.kt` | Exchanges a 10-min JWT via `POST /auth/exchange-enroll`. Replay is rejected by the server (JTI tracked). |
| Tightened receivers | `AndroidManifest.xml` | `BootReceiver` is `exported="false"` (BOOT_COMPLETED is a protected broadcast). `AckReceiver` + `QuickReplyReceiver` are unexported. |
| Structured errors | `data/Models.kt::ApiResult` | Every network call returns `Ok / Http(code, message) / Network(cause)` so the UI shows a *specific* failure — never the silent `Toast("Ack failed")` of old. |

### Hardening to production (when HTTPS is in front of the API)

1. Stand up TLS — Caddy / nginx with Let's Encrypt or self-signed. Confirm
   `curl -v https://<host>/healthz`.
2. Compute the SPKI pin:
   ```bash
   openssl x509 -in server.pem -pubkey -noout |
     openssl pkey -pubin -outform der |
     openssl dgst -sha256 -binary | base64
   ```
   Repeat for a **backup keypair** you keep offline; without a second pin a
   key rotation locks every phone out.
3. In `res/xml/network_security_config.xml`:
   - Set `<base-config cleartextTrafficPermitted="false">`.
   - Uncomment the `<domain-config>` + `<pin-set>` block. Replace the
     placeholders and the `<domain>`.
   - If using a self-signed cert: drop the leaf PEM at
     `res/raw/server.crt` and uncomment the `@raw/server` line.
4. Bump `versionCode` in `app/build.gradle.kts` and redistribute the apk.

## UX features

| Feature | Where |
|---|---|
| QR camera scanner (CameraX + ML Kit) | `ui/QrScanner.kt`; opens from **Scan QR** on the Enrol screen. Paste-fallback retained for headless devices. |
| Deep-link routing | `ui/MainActivity.kt::handleIntent` — tapping a notification jumps straight to the detail pane for that alert id. |
| Severity filter chips | All / Critical / High / Other above the inbox. |
| Swipe-to-acknowledge | Drag a row right by ~240 dp; haptic confirms; ack fires. |
| Pull-to-refresh / manual refresh | Toolbar refresh icon. |
| STALE banner with **Retry** | Shown when the most recent poll returned a `Network` error. Restarts the foreground listener. |
| Snackbar feedback | All success / failure paths surface a snackbar — no silent fail. |
| Read / unread visual state | Background tint + bold title; tracked locally in `Prefs` so the UI updates instantly. |
| Relative timestamps | "2m ago", "3h ago", "1d ago"; ISO date past one week. |
| Brand theme | `ui/theme/Theme.kt` mirrors the dashboard palette (navy + teal) and respects `isSystemInDarkTheme()`. |

## Engagement

| Feature | Where |
|---|---|
| **Quick-reply chips** ("Investigating", "False positive", "Escalated") | Detail pane + notification action. One tap posts a canned note + acks. |
| **CRITICAL pulse** | Animated red dot on CRITICAL rows; matching haptic vibration pattern on the channel (`220-110-220-600-220-110-220 ms`). |
| **On-call badge** | Inbox header pill, pulled from `Prefs.onCallUntil()`. Set via the dashboard. |
| **Weekly stat** | Footer line: "You've acknowledged N alerts this week" — reset Sunday-to-Sunday inside `Prefs`. |
| Notification group | New detections collapse into one inbox-style stack in the shade. |

## Architecture

| Component | File | Role |
|---|---|---|
| `MainActivity` | `ui/MainActivity.kt` | Single-`FragmentActivity` Compose UI. Enrol → Inbox → Detail. Owns biometric gate + deep-link routing + `FLAG_SECURE`. |
| `AptThpTheme` | `ui/theme/Theme.kt` | Brand color tokens + system dark/light. |
| `QrScanner` | `ui/QrScanner.kt` | CameraX preview + ML Kit barcode (bundled, no Play Services dep). |
| `BiometricGate` | `security/BiometricGate.kt` | App-open + per-sensitive-action prompts with a freshness window. |
| `NotificationListener` | `service/NotificationListener.kt` | `ForegroundService` holding the OkHttp `EventSource`. Sticky notification: *LISTENING* / *STALE*. |
| `PollWorker` | `service/PollWorker.kt` | `WorkManager` worker with `NetworkType.CONNECTED` constraint that polls the platform when the SSE socket is down. |
| `AckReceiver` | `service/AckReceiver.kt` | `BroadcastReceiver` invoked by the **Acknowledge** action button. `goAsync()` until the HTTP call lands. |
| `QuickReplyReceiver` | `service/QuickReplyReceiver.kt` | Posts a canned investigation note + acks. |
| `BootReceiver` | `service/BootReceiver.kt` | Re-starts the listener after device reboot. Unexported. |
| `ApiClient` | `data/ApiClient.kt` | OkHttp wrapper. Every call returns `ApiResult`. Injects `X-API-Key`. |
| `Enrol` | `data/Enrol.kt` | Parses the QR payload and exchanges the enrol JWT for a persistent API key. |
| `Prefs` | `data/Prefs.kt` | `EncryptedSharedPreferences` for `{server_url, api_key, username, oncall_until, read_ids, ack_count}`. |
| `NotifBuilder` / `NotifChannels` | `notif/` | Notification rendering + channel setup (per-channel `VISIBILITY_PRIVATE` + CRITICAL vibration). |

## Build

Requires Android Studio Hedgehog (2023.1) or newer + JDK 17.

```bash
cd mobile/android
./gradlew :app:assembleRelease
```

The `.apk` lands at `app/build/outputs/apk/release/app-release-unsigned.apk`.
Sign it with your release keystore:

```bash
keytool -genkeypair -v -keystore apt-thp.keystore \
    -alias apt-thp -keyalg RSA -keysize 4096 -validity 3650
apksigner sign --ks apt-thp.keystore \
    --out apt-thp-companion.apk \
    app/build/outputs/apk/release/app-release-unsigned.apk
```

Then drop the signed `.apk` at `<platform-root>/data/downloads/companion.apk`
so the dashboard's *Settings → Companion app* page can serve it.

> **For the FYP demo**: the default `signingConfig = signingConfigs.findByName("debug")`
> in `app/build.gradle.kts` produces a debug-signed APK that installs fine on a
> personal device without setting up a release keystore.

## Sideload onto a phone

1. On the phone: Settings → Security → enable **Install unknown apps** for your
   browser or file manager.
2. Open the dashboard at *Settings → Companion app*. Tap **Download .apk**, or
   AirDrop / USB the signed `.apk` over.
3. Open the `.apk` — Android offers to install.
4. Launch *APT THP*. Grant the notifications permission (Android 13+) and the
   camera permission (for QR scanning).
5. From the dashboard's *Settings → Companion app* page, tap the **Scan QR**
   button in the app and aim the camera at the dashboard. The app exchanges
   the token, stores the api_key in `EncryptedSharedPreferences`, and starts
   the listener service.
6. The sticky *"APT THP — listening for detections"* notification appears in
   the shade. Don't swipe it away — that's the foreground service that keeps
   the SSE alive.

## Caveats

- **Local HTTP today.** The bundled `network_security_config.xml` permits
  cleartext because the reference deployment is plain HTTP on the LAN. Flip
  to HTTPS + SPKI pin (instructions above) before shipping outside the
  development network.
- **Android only.** iOS cannot hold a long-running foreground service for an
  SSE socket; production iOS would need a separate on-prem MQTT broker.
- **Custom HTTPS certs.** If the platform uses a self-signed cert, drop the
  PEM at `res/raw/server.crt` and uncomment the `@raw/server` line in
  `network_security_config.xml`.
- **English only.** UI strings are hardcoded English. Swahili localisation is
  a `res/values-sw/strings.xml` away if needed.

## Customise

- `applicationId` / branding → `app/build.gradle.kts` + `res/values/strings.xml`.
- Default API base URL → set per-user via the enrolment QR; no hard-coded URL
  in the source.
- Poll interval → `PollWorker.kt`'s `setInitialDelay(5, TimeUnit.MINUTES)`.
- Quick-reply chip presets → `QuickReplyReceiver.PRESETS`.
- Biometric freshness windows → `BiometricGate.APP_OPEN_GRACE_MS` (30s) and
  `BiometricGate.SENSITIVE_GRACE_MS` (5 min).
- Theme palette → `ui/theme/Theme.kt::Brand`.
