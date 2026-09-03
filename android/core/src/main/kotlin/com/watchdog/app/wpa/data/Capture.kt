package com.watchdog.app.wpa.data

/** Lifecycle of a capture's WPA-sec submission. wpa-sec exposes no per-file scan id or queue
 *  position, so there is no honest "queued"/"scanning" state — a submitted capture is either still
 *  awaiting a result or has been cracked. Shared by both apps. */
enum class SubmissionStatus {
    NOT_SUBMITTED,
    UPLOADING,
    SUBMITTED,   // uploaded; awaiting a cracked result (polled by BSSID)
    CRACKED,     // password recovered
    FAILED,      // upload failed
}

/**
 * Pure model of a captured/imported handshake plus its submission state. Each app maps its own
 * storage row (Android Room CaptureEntity, desktop sqlite row) to/from this.
 */
data class Capture(
    val id: Long = 0,
    val md5: String,
    val ssid: String?,
    /** Bare lowercase hex (12 chars) — the key matched against WPA-sec potfile lines. */
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
