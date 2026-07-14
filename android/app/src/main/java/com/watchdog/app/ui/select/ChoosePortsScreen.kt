package com.watchdog.app.ui.select

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun ChoosePortsScreen(
    selectedDepth: ScanDepth,
    onDepthChange: (ScanDepth) -> Unit,
    deviceCount: Int,
    onStart: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(
        title = "What ports to scan?",
        subtitle = "$deviceCount device${if (deviceCount == 1) "" else "s"} selected",
        onBack = onBack,
        primaryLabel = "Start scan",
        onPrimary = onStart,
    ) {
        Column(Modifier.fillMaxWidth()) {
            ScanDepth.entries.forEach { depth ->
                Row(
                    Modifier.fillMaxWidth().height(48.dp)
                        .selectable(selected = depth == selectedDepth, onClick = { onDepthChange(depth) }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = depth == selectedDepth, onClick = { onDepthChange(depth) })
                    Text(depth.label, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.weight(1f))
                    Text(depth.estimate, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
