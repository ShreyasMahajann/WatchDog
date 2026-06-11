package com.watchdog.app

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

// ---- Theme -----------------------------------------------------------------
// Restrained, near-monochrome palette (ink primary), matching the mockup.

private val WatchDogColors = lightColorScheme(
    primary = Color(0xFF111827),
    onPrimary = Color(0xFFFFFFFF),
    background = Color(0xFFFFFFFF),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF111827),
    onSurfaceVariant = Color(0xFF6B7280),
    outlineVariant = Color(0xFFEDEFF2),
)

@Composable
fun WatchDogTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = WatchDogColors, content = content)
}

// ---- Flow ------------------------------------------------------------------

private enum class Step { Start, Hosts, Services, Findings }

@Composable
fun WatchDogApp() {
    var step by remember { mutableStateOf(Step.Start) }

    BackHandler(enabled = step != Step.Start) {
        step = when (step) {
            Step.Findings -> Step.Services
            Step.Services -> Step.Hosts
            Step.Hosts -> Step.Start
            Step.Start -> Step.Start
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        when (step) {
            Step.Start -> StartScreen(onStart = { step = Step.Hosts })
            Step.Hosts -> HostsScreen(
                onBack = { step = Step.Start },
                onNext = { step = Step.Services },
            )
            Step.Services -> ServicesScreen(
                onBack = { step = Step.Hosts },
                onNext = { step = Step.Findings },
            )
            Step.Findings -> FindingsScreen(
                onBack = { step = Step.Services },
                onRestart = { step = Step.Start },
            )
        }
    }
}

// ---- Reusable chrome -------------------------------------------------------

@Composable
private fun ScreenChrome(
    title: String,
    subtitle: String?,
    onBack: (() -> Unit)?,
    primaryLabel: String,
    onPrimary: () -> Unit,
    content: @Composable () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 20.dp)) {
        if (onBack != null) {
            TextButton(onClick = onBack, contentPadding = PaddingValues(0.dp)) {
                Text("←  Back")
            }
            Spacer(Modifier.height(4.dp))
        }
        Text(
            text = title,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        if (subtitle != null) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(20.dp))
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
        ) {
            content()
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = onPrimary,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(primaryLabel, fontWeight = FontWeight.Medium)
        }
    }
}

// ---- Screens ---------------------------------------------------------------

@Composable
private fun StartScreen(onStart: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.weight(1f))
        Text(
            text = "watchDog",
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = "Portable network security assessment",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(28.dp))
        LabeledCard(label = "Network", value = "Home-Wi-Fi · 192.168.1.0/24")
        Spacer(Modifier.weight(1f))
        Button(
            onClick = onStart,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text("Start assessment", fontWeight = FontWeight.Medium)
        }
    }
}

private class Selectable(val primary: String, val secondary: String, selected: Boolean) {
    var selected by mutableStateOf(selected)
}

@Composable
private fun HostsScreen(onBack: () -> Unit, onNext: () -> Unit) {
    val hosts = remember {
        listOf(
            Selectable("192.168.1.1", "Router", false),
            Selectable("192.168.1.12", "Unknown", false),
            Selectable("192.168.1.20", "Linux", true),
            Selectable("192.168.1.42", "Windows", true),
        )
    }
    ScreenChrome(
        title = "Hosts",
        subtitle = "24 devices found",
        onBack = onBack,
        primaryLabel = "Enumerate selected",
        onPrimary = onNext,
    ) {
        hosts.forEachIndexed { i, host ->
            Row(
                modifier = Modifier.fillMaxWidth().height(52.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Checkbox(checked = host.selected, onCheckedChange = { host.selected = it })
                Spacer(Modifier.width(8.dp))
                Text(
                    text = host.primary,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyLarge,
                )
                Spacer(Modifier.weight(1f))
                Text(
                    text = host.secondary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (i < hosts.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}

@Composable
private fun ServicesScreen(onBack: () -> Unit, onNext: () -> Unit) {
    data class Svc(val port: String, val name: String, val version: String)
    val services = remember {
        listOf(
            Svc("22", "SSH", "OpenSSH 8.2p1"),
            Svc("80", "HTTP", "nginx 1.21"),
            Svc("443", "HTTPS", "TLS 1.3"),
            Svc("3000", "HTTP", "unknown"),
        )
    }
    ScreenChrome(
        title = "Services",
        subtitle = "192.168.1.20",
        onBack = onBack,
        primaryLabel = "Fingerprint services",
        onPrimary = onNext,
    ) {
        services.forEachIndexed { i, s ->
            Row(
                modifier = Modifier.fillMaxWidth().height(52.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = s.port,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(48.dp),
                )
                Text(text = s.name, style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.weight(1f))
                Text(
                    text = s.version,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (i < services.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}

@Composable
private fun FindingsScreen(onBack: () -> Unit, onRestart: () -> Unit) {
    ScreenChrome(
        title = "Findings",
        subtitle = "Sorted by priority",
        onBack = onBack,
        primaryLabel = "Start over",
        onPrimary = onRestart,
    ) {
        FindingRow(
            color = Color(0xFFDC2626),
            severity = "Critical",
            title = "Apache HTTP Server 2.4.49",
            cve = "CVE-2021-41773",
            note = "Verified · Known exploited",
        )
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        FindingRow(
            color = Color(0xFFD97706),
            severity = "High",
            title = "OpenSSH 8.2p1",
            cve = "CVE-2020-DEMO-SSH",
            note = "Likely vulnerable",
        )
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(12.dp))
        Text(
            text = "1 finding suppressed — patched by distro backport",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ---- Small building blocks -------------------------------------------------

@Composable
private fun FindingRow(color: Color, severity: String, title: String, cve: String, note: String) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(color))
            Spacer(Modifier.width(8.dp))
            Text(
                text = severity,
                color = color,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(text = title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(2.dp))
        Text(
            text = cve,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(2.dp))
        Text(
            text = note,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun LabeledCard(label: String, value: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFFF9FAFB))
            .padding(16.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = value,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyLarge,
        )
    }
}
