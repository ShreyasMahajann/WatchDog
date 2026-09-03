package com.watchdog.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import com.watchdog.desktop.ui.App

private val LightColors = lightColorScheme(
    primary = Color(0xFF111827),
    onPrimary = Color(0xFFFFFFFF),
    background = Color(0xFFFFFFFF),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF111827),
    onSurfaceVariant = Color(0xFF6B7280),
    surfaceVariant = Color(0xFFF3F4F6),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFE5E7EB),
    onPrimary = Color(0xFF0B1120),
    background = Color(0xFF0B1120),
    surface = Color(0xFF111827),
    onSurface = Color(0xFFE5E7EB),
    onSurfaceVariant = Color(0xFF9CA3AF),
    surfaceVariant = Color(0xFF161E2E),
)

@Composable
private fun WatchDogTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}

fun main() = application {
    val windowState = rememberWindowState(size = DpSize(1000.dp, 760.dp))
    Window(
        onCloseRequest = ::exitApplication,
        state = windowState,
        title = "watchDog",
    ) {
        WatchDogTheme {
            Surface(color = MaterialTheme.colorScheme.background) {
                App()
            }
        }
    }
}
