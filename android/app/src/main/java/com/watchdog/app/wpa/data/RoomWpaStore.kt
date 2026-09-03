package com.watchdog.app.wpa.data

/**
 * Adapts the Room-backed [WpaRepository] to the shared [WpaStore] the core
 * submission service depends on, mapping [CaptureEntity] to the pure [Capture].
 */
class RoomWpaStore(private val repo: WpaRepository) : WpaStore {

    override suspend fun get(id: Long): Capture? = repo.get(id)?.toCapture()

    override suspend fun submittedCaptures(): List<Capture> = repo.submittedCaptures().map { it.toCapture() }

    override suspend fun updateStatus(
        id: Long,
        status: SubmissionStatus,
        detail: String?,
        submittedAt: Long?,
        lastCheckedAt: Long?,
        password: String?,
    ) = repo.updateStatus(id, status, detail, submittedAt, lastCheckedAt, password)
}

private fun CaptureEntity.toCapture() = Capture(
    id = id, md5 = md5, ssid = ssid, bssid = bssid, bssidDisplay = bssidDisplay, channel = channel,
    security = security, filePath = filePath, fileName = fileName, sizeBytes = sizeBytes,
    hasValidHandshake = hasValidHandshake, eapolCount = eapolCount, hasPmkid = hasPmkid,
    capturedAt = capturedAt, source = source, status = status, statusDetail = statusDetail,
    submittedAt = submittedAt, lastCheckedAt = lastCheckedAt, password = password,
)
