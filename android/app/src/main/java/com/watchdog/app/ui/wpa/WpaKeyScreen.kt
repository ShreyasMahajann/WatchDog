package com.watchdog.app.ui.wpa

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome

/**
 * Configure the WPA-sec submission key. The key is stored encrypted (Android Keystore) and never
 * shown back in full or logged. This screen only reports whether one is set and lets you replace it.
 */
@Composable
fun WpaKeyScreen(
    configured: Boolean,
    onSave: (String) -> Unit,
    onClear: () -> Unit,
    onBack: () -> Unit,
) {
    var key by remember { mutableStateOf("") }
    var reveal by remember { mutableStateOf(false) }

    ScreenChrome(
        title = "WPA-sec key",
        subtitle = if (configured) "A key is configured ✓" else "No key configured",
        onBack = onBack,
        primaryLabel = "Save key",
        primaryEnabled = key.isNotBlank(),
        onPrimary = { onSave(key); key = "" },
        secondaryLabel = if (configured) "Remove stored key" else null,
        onSecondary = if (configured) onClear else null,
    ) {
        Column(Modifier.fillMaxWidth()) {
            InfoBanner("Get your own key at wpa-sec.stanev.org/?get_key (a 32-character hex token). It's stored encrypted on this device.")
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = key,
                onValueChange = { key = it.trim() },
                label = { Text(if (configured) "Replace key" else "Paste key") },
                singleLine = true,
                visualTransformation = if (reveal) VisualTransformation.None else PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            TextButton(onClick = { reveal = !reveal }) {
                Text(if (reveal) "Hide" else "Show")
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "The stored key is never displayed again or written to logs — it's only used to authenticate uploads and result checks.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
