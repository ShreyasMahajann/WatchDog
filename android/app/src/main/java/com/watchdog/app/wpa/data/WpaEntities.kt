package com.watchdog.app.wpa.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Lifecycle of a capture's WPA-sec submission. wpa-sec exposes no per-file scan id or queue
 *  position, so there is no honest "queued"/"scanning" state — a submitted capture is either still
 *  awaiting a result or has been cracked. */
enum class SubmissionStatus {
    NOT_SUBMITTED,
    UPLOADING,
    SUBMITTED,   // uploaded; awaiting a cracked result (polled by BSSID)
    CRACKED,     // password recovered
    FAILED,      // upload failed
}

/** One captured/imported handshake plus its submission state. Denormalized on purpose — the history
 *  screen shows exactly these fields, and MD5 uniqueness is what prevents duplicate imports/uploads. */
@Entity(tableName = "captures", indices = [Index(value = ["md5"], unique = true)])
data class CaptureEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val md5: String,
    val ssid: String?,
    /** Bare lowercase hex (12 chars) — the key used to match WPA-sec potfile lines. */
    val bssid: String,
    /** Human-readable aa:bb:cc:dd:ee:ff. */
    val bssidDisplay: String,
    val channel: Int?,
    val security: String,
    val filePath: String,
    val fileName: String,
    val sizeBytes: Long,
    val hasValidHandshake: Boolean,
    val eapolCount: Int,
    val hasPmkid: Boolean,
    val capturedAt: Long,
    val source: String, // "IMPORT" or "CAPTURE"
    val status: String, // SubmissionStatus name
    val statusDetail: String?,
    val submittedAt: Long?,
    val lastCheckedAt: Long?,
    val password: String?,
) {
    val statusEnum: SubmissionStatus
        get() = runCatching { SubmissionStatus.valueOf(status) }.getOrDefault(SubmissionStatus.NOT_SUBMITTED)
}
