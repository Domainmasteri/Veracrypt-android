plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

val nativeSanitizersEnabled = providers.gradleProperty("veracryptSanitizers")
    .map { it.equals("true", ignoreCase = true) }
    .orElse(false)

android {
    namespace = "io.veracrypt.android.corenative"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-Wall")
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
                    "-DVERACRYPT_ENABLE_SANITIZERS=${if (nativeSanitizersEnabled.get()) "ON" else "OFF"}"
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    implementation(project(":core-api"))
    implementation(libs.androidx.core.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
