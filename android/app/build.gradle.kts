plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.nkchat"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.nkchat"
        minSdk = 24            // ring / iroh comfortably support API 24+
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
        // The Rust .so is shipped per-ABI under src/main/jniLibs (staged by
        // ../stage.sh). Limit to the ABIs we build to keep the APK small.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    // UniFFI's generated Kotlin loads the cdylib through JNA — the `@aar`
    // classifier pulls the Android-native JNA build.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
