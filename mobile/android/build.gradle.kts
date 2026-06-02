// Top-level build script — minimal; everything lives in :app.
plugins {
    id("com.android.application")        version "8.5.0" apply false
    id("org.jetbrains.kotlin.android")    version "1.9.24" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.24" apply false
    // KSP — for Room annotation processing. Pin to a Kotlin-1.9.24 compatible version.
    id("com.google.devtools.ksp")         version "1.9.24-1.0.20" apply false
}
