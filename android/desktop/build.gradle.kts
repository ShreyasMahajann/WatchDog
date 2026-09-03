import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.desktop)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core"))
    implementation(libs.jmdns)
    implementation(libs.sqlite.jdbc)

    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
}

compose.desktop {
    application {
        mainClass = "com.watchdog.desktop.MainKt"

        nativeDistributions {
            // Windows + Linux are the desktop targets (macOS not built/tested).
            // Exe = Windows installer (.exe), Deb = Linux package (.deb).
            targetFormats(TargetFormat.Exe, TargetFormat.Deb)
            packageName = "watchDog"
            // Version via env var (WATCHDOG_VERSION) to avoid cross-shell CLI arg
            // mangling on the Windows runner; falls back to a -P property, then 0.1.0.
            packageVersion = System.getenv("WATCHDOG_VERSION")?.takeIf { it.isNotBlank() }
                ?: (project.findProperty("versionName") as String?)?.takeIf { it.isNotBlank() }
                ?: "0.1.0"
            description = "watchDog network security assessment (desktop)"
            vendor = "Shreyas Mahajan"

            windows {
                // Stable identity so upgrades replace the prior install instead of
                // stacking. jpackage/WiX needs a fixed UUID for the installer.
                upgradeUuid = "5f2b9c1e-3a4d-4b6c-8e0f-1a2b3c4d5e6f"
                menuGroup = "watchDog"
            }
            linux {
                // Debian package names must be lowercase — jpackage rejects "watchDog".
                packageName = "watchdog"
            }
        }
    }
}

// Keep the headless CLI runnable alongside the GUI: `gradle :desktop:runHeadless`.
tasks.register<JavaExec>("runHeadless") {
    group = "application"
    description = "Run the headless scan runner instead of the GUI."
    mainClass.set("com.watchdog.desktop.HeadlessScanKt")
    classpath = sourceSets["main"].runtimeClasspath
}
