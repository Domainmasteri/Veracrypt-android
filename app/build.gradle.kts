plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

val keystorePath = System.getenv("VERACRYPT_KEYSTORE_PATH")
val keystorePassword = System.getenv("VERACRYPT_KEYSTORE_PASSWORD")
val releaseKeyAlias = System.getenv("VERACRYPT_KEY_ALIAS")
val releaseKeyPassword = System.getenv("VERACRYPT_KEY_PASSWORD")
val releaseSigningAvailable = !keystorePath.isNullOrBlank() &&
    !keystorePassword.isNullOrBlank() &&
    !releaseKeyAlias.isNullOrBlank() &&
    !releaseKeyPassword.isNullOrBlank()

android {
    namespace = "io.veracrypt.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.veracrypt.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            if (releaseSigningAvailable) {
                storeFile = file(requireNotNull(keystorePath))
                storePassword = requireNotNull(keystorePassword)
                keyAlias = requireNotNull(releaseKeyAlias)
                keyPassword = requireNotNull(releaseKeyPassword)
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (releaseSigningAvailable) {
                signingConfig = signingConfigs.getByName("release")
            }
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

    buildFeatures {
        viewBinding = true
    }

    sourceSets.getByName("androidTest").assets.srcDir(
        rootProject.file("core-native/src/androidTest/assets")
    )
}

gradle.taskGraph.whenReady {
    val appReleaseRequested = allTasks.any { task ->
        if (task.project != project) return@any false
        val taskName = task.name.lowercase()
        taskName == "assemblerelease" ||
            taskName.startsWith("bundlerelease") ||
            taskName.startsWith("packagerelease") ||
            taskName.startsWith("signrelease") ||
            taskName.startsWith("validatesigningrelease")
    }
    if (appReleaseRequested) {
        val requiredVariables = mapOf(
            "VERACRYPT_KEYSTORE_PATH" to keystorePath,
            "VERACRYPT_KEYSTORE_PASSWORD" to keystorePassword,
            "VERACRYPT_KEY_ALIAS" to releaseKeyAlias,
            "VERACRYPT_KEY_PASSWORD" to releaseKeyPassword
        )
        val missingVariables = requiredVariables
            .filterValues { it.isNullOrBlank() }
            .keys
            .sorted()
        if (missingVariables.isNotEmpty()) {
            throw GradleException(
                "Release signing requires environment variables: ${missingVariables.joinToString()}"
            )
        }

        val configuredKeystore = file(requireNotNull(keystorePath))
        if (!configuredKeystore.isFile || !configuredKeystore.canRead()) {
            throw GradleException(
                "VERACRYPT_KEYSTORE_PATH must point to a readable keystore file"
            )
        }
    }
}

dependencies {
    implementation(project(":core-api"))
    implementation(project(":core-native"))
    implementation(project(":provider-saf"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
