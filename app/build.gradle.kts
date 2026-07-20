import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

val signingProps = Properties().apply {
    val file = rootProject.file("signing.properties")
    if (file.exists()) {
        file.inputStream().use(::load)
    }
}

fun prop(name: String): String? =
    System.getenv(name) ?: signingProps.getProperty(name)

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

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfig
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

    signingConfigs {
        create("release") {
            val keystorePath = prop("KEYSTORE_PATH")
            val storePass = prop("KEYSTORE_PASSWORD")
            val keyAliasValue = prop("KEY_ALIAS")
            val keyPass = prop("KEY_PASSWORD")
            if (!keystorePath.isNullOrBlank() &&
                !storePass.isNullOrBlank() &&
                !keyAliasValue.isNullOrBlank() &&
                !keyPass.isNullOrBlank()
            ) {
                storeFile = file(keystorePath)
                storePassword = storePass
                keyAlias = keyAliasValue
                keyPassword = keyPass
            }
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
