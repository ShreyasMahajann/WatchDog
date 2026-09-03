plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

application {
    // Headless scan runner for now; the Compose GUI entry point is added next.
    mainClass.set("com.watchdog.desktop.HeadlessScanKt")
}

dependencies {
    implementation(project(":core"))
    implementation(libs.jmdns)
}
