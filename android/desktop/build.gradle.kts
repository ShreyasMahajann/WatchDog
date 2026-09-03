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
            packageVersion = (project.findProperty("versionName") as String?) ?: "0.1.0"
            description = "watchDog network security assessment (desktop)"
            vendor = "Shreyas Mahajan"
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
