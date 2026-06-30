package com.watchdog.app.ui.common

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/** Shared screen scaffold: back link, title/subtitle, scrollable body, primary CTA. */
@Composable
fun ScreenChrome(
    title: String,
    subtitle: String?,
    onBack: (() -> Unit)?,
    primaryLabel: String?,
    primaryEnabled: Boolean = true,
    onPrimary: (() -> Unit)? = null,
    secondaryLabel: String? = null,
    onSecondary: (() -> Unit)? = null,
    body: @Composable () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 20.dp)) {
        if (onBack != null) {
            TextButton(onClick = onBack, contentPadding = PaddingValues(0.dp)) { Text("←  Back") }
            Spacer(Modifier.height(4.dp))
        }
        Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        if (subtitle != null) {
            Spacer(Modifier.height(4.dp))
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(16.dp))
        Column(modifier = Modifier.weight(1f).fillMaxWidth()) { body() }
        if (secondaryLabel != null && onSecondary != null) {
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onSecondary, modifier = Modifier.fillMaxWidth()) { Text(secondaryLabel) }
        }
        if (primaryLabel != null && onPrimary != null) {
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = onPrimary,
                enabled = primaryEnabled,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(12.dp),
            ) { Text(primaryLabel, fontWeight = FontWeight.Medium) }
        }
    }
}

@Composable
fun LabeledCard(label: String, value: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(16.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
        Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
    }
}

/** Shared "are you sure?" dialog for cancelling an in-progress scan/discovery. */
@Composable
fun CancelConfirmDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Cancel scan?") },
        text = { Text("This stops the current scan. Anything found so far is kept, but it won't continue.") },
        confirmButton = { TextButton(onClick = onConfirm) { Text("Cancel scan") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Keep scanning") } },
    )
}

@Composable
fun InfoBanner(text: String) {
    Row(
        modifier = Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(12.dp),
        horizontalArrangement = Arrangement.Start,
    ) {
        Text("ⓘ  $text", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
