package com.watchdog.app.ui.wpa

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.watchdog.app.wpa.data.SubmissionStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Shared display helpers for the WPA screens. */
internal object WpaFormat {

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())

    fun time(ms: Long?): String = if (ms == null || ms <= 0) "—" else dateFormat.format(Date(ms))

    fun size(bytes: Long): String = when {
        bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1_000_000.0)
        bytes >= 1_000 -> "%.1f KB".format(bytes / 1_000.0)
        else -> "$bytes B"
    }

    fun statusLabel(status: SubmissionStatus): String = when (status) {
        SubmissionStatus.NOT_SUBMITTED -> "Not submitted"
        SubmissionStatus.UPLOADING -> "Uploading…"
        SubmissionStatus.SUBMITTED -> "Submitted — awaiting result"
        SubmissionStatus.CRACKED -> "Password found"
        SubmissionStatus.FAILED -> "Failed"
    }
}

@Composable
internal fun statusColor(status: SubmissionStatus): Color = when (status) {
    SubmissionStatus.CRACKED -> Color(0xFF2E9E4F)
    SubmissionStatus.FAILED -> MaterialTheme.colorScheme.error
    SubmissionStatus.SUBMITTED, SubmissionStatus.UPLOADING -> Color(0xFFB8860B)
    SubmissionStatus.NOT_SUBMITTED -> MaterialTheme.colorScheme.onSurfaceVariant
}
