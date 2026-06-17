package com.watchdog.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Restrained, near-monochrome palette (ink primary), matching the original mock.

private val LightColors = lightColorScheme(
    primary = Color(0xFF111827),
    onPrimary = Color(0xFFFFFFFF),
    background = Color(0xFFFFFFFF),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF111827),
    onSurfaceVariant = Color(0xFF6B7280),
    outlineVariant = Color(0xFFEDEFF2),
    surfaceVariant = Color(0xFFF9FAFB),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFE5E7EB),
    onPrimary = Color(0xFF0B1120),
    background = Color(0xFF0B1120),
    surface = Color(0xFF111827),
    onSurface = Color(0xFFE5E7EB),
    onSurfaceVariant = Color(0xFF9CA3AF),
    outlineVariant = Color(0xFF1F2937),
    surfaceVariant = Color(0xFF161E2E),
)

// Severity colors, theme-independent.
object Severity {
    val Critical = Color(0xFFDC2626)
    val High = Color(0xFFD97706)
    val Medium = Color(0xFFCA8A04)
    val Low = Color(0xFF6B7280)
    val Verified = Color(0xFF059669)
}

@Composable
fun WatchDogTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
