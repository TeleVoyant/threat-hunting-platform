plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "tz.apt.thp"
    compileSdk = 35

    defaultConfig {
        applicationId = "tz.apt.thp"
        minSdk = 24
        targetSdk = 34
        versionCode = 2
        versionName = "0.2.0"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Operators sign with their own keystore; see README for details.
            signingConfig = signingConfigs.findByName("debug")
        }
    }
    packaging {
        resources {
            excludes += setOf(
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
                "META-INF/DEPENDENCIES",
            )
        }
    }
}

dependencies {
    // Compose BOM
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-process:2.8.2")

    // HTTP + SSE
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:okhttp-sse:4.12.0")

    // JSON
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    // Encrypted prefs
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // WorkManager for poll fallback
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Biometric gate
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    // Branded splash screen (Android 12+ native; backported via this lib).
    implementation("androidx.core:core-splashscreen:1.0.1")
    // Force fragment >= 1.7 — biometric pulls 1.5.x transitively, which
    // still enforces the legacy 16-bit limit on requestPermissions codes
    // and crashes the new ActivityResultRegistry path with
    // "Can only use lower 16 bits for requestCode".
    implementation("androidx.fragment:fragment-ktx:1.8.2")

    // QR scanner — CameraX preview + ML Kit barcode (vision-only, no Google
    // Play Services required for the bundled variant).
    implementation("androidx.camera:camera-core:1.3.4")
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    // Explicit — barcode-scanning depends on this transitively but some
    // dependency-resolution paths drop the AAR's classes (only the native
    // .so lands), which crashes at app start with:
    //   ClassNotFoundException: com.google.mlkit.common.internal.MlKitInitProvider
    // Declaring it directly forces inclusion of the common AAR.
    implementation("com.google.mlkit:common:18.11.0")
    implementation("com.google.mlkit:vision-common:17.3.0")
}
