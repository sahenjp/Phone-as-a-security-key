plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "site.sahen.phonefido"
    compileSdk = 35

    defaultConfig {
        applicationId = "site.sahen.phonefido"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            // No signing config on purpose: the release APK is built unsigned
            // (assembleRelease) and signed by whoever installs it, mirroring
            // the iOS unsigned-IPA flow.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // AndroidX only, per the project constraints. JSON is org.json (bundled
    // with Android), CBOR and HKDF are hand-rolled, ChaCha20-Poly1305 uses
    // javax.crypto on API 28+ with a hand-rolled fallback for API 26/27.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.biometric:biometric:1.1.0")
}
