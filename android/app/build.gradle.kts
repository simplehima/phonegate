import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

/** `PG_SIGNING_PROPERTIES`, else `~/.phonegate-signing/signing.properties`, else null. */
val releaseSigning: Properties? = run {
    val path = System.getenv("PG_SIGNING_PROPERTIES")
        ?: "${System.getProperty("user.home")}/.phonegate-signing/signing.properties"
    val f = file(path)
    if (!f.isFile) null else Properties().apply { f.inputStream().use { load(it) } }
}

tasks.configureEach {
    if (name == "assembleRelease" || name == "packageRelease" || name == "bundleRelease") {
        doFirst {
            if (releaseSigning == null) {
                throw GradleException(
                    "No release signing key. Run tools/android-release-key.ps1 once (it stores the key " +
                        "outside the repository), or set PG_SIGNING_PROPERTIES. Debug-signed builds are never shipped.",
                )
            }
        }
    }
}

android {
    namespace = "dev.phonegate"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.phonegate"
        minSdk = 30
        targetSdk = 36
        versionCode = 2
        versionName = "0.2.0"
    }

    // Release signing key lives OUTSIDE the repository (tools/android-release-key.ps1 creates it).
    // No key → no release build; we never fall back to the debug key (spec 003 FR-306).
    signingConfigs {
        if (releaseSigning != null) {
            create("release") {
                storeFile = file(releaseSigning.getProperty("storeFile"))
                storePassword = releaseSigning.getProperty("storePassword")
                keyAlias = releaseSigning.getProperty("keyAlias")
                keyPassword = releaseSigning.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (releaseSigning != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    lint {
        warningsAsErrors = false
        abortOnError = true
        checkDependencies = false
    }

    testOptions {
        unitTests.all { test ->
            // Shared vectors are read in place from the repository (never copied).
            val vectors = rootProject.file("../protocol/vectors/v1.json")
            test.systemProperty("pg.vectors", vectors.absolutePath)
            test.inputs.file(vectors)
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.service)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material3.adaptive.nav)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)
    implementation(libs.okhttp)
    implementation(libs.zxing.core)
    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.org.json)
}
