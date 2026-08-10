package com.watchdog.app.wpa.data

import com.watchdog.app.wpa.storage.CaptureStore
import com.watchdog.app.wpa.wpasec.WpaSecClient
import kotlinx.coroutines.flow.Flow

/** Persistence for captures + their submission state. */
class WpaRepository(private val dao: WpaDao) {

    fun observeAll(): Flow<List<CaptureEntity>> = dao.observeAll()
    fun observeById(id: Long): Flow<CaptureEntity?> = dao.observeById(id)
    suspend fun get(id: Long): CaptureEntity? = dao.getById(id)
    suspend fun submittedCaptures(): List<CaptureEntity> = dao.submittedCaptures()

    /**
     * Persist an imported/captured file. Deduplicated by MD5: importing the same handshake twice
     * returns the existing row (with its submission state intact) rather than creating a copy.
     */
    suspend fun saveCapture(imported: CaptureStore.Imported, source: String): CaptureEntity {
        dao.findByMd5(imported.md5)?.let { return it }
        val entity = imported.toEntity(source)
        val id = dao.insert(entity)
        return if (id >= 0) entity.copy(id = id) else dao.findByMd5(imported.md5)!!
    }

    suspend fun updateStatus(
        id: Long,
        status: SubmissionStatus,
        detail: String? = null,
        submittedAt: Long? = null,
        lastCheckedAt: Long? = null,
        password: String? = null,
    ) = dao.updateStatus(id, status.name, detail, submittedAt, lastCheckedAt, password)

    suspend fun delete(entity: CaptureEntity, store: CaptureStore) {
        dao.deleteById(entity.id)
        store.delete(entity.filePath)
    }

    private fun CaptureStore.Imported.toEntity(source: String): CaptureEntity {
        val net = analysis.primary
        val bssidDisplay = net?.bssid ?: ""
        return CaptureEntity(
            md5 = md5,
            ssid = net?.ssid,
            bssid = WpaSecClient.normalizeMac(bssidDisplay),
            bssidDisplay = bssidDisplay,
            channel = net?.channel,
            security = net?.security ?: "Unknown",
            filePath = filePath,
            fileName = fileName,
            sizeBytes = sizeBytes,
            hasValidHandshake = analysis.hasValidHandshake,
            eapolCount = analysis.eapolTotal,
            hasPmkid = net?.hasPmkid ?: false,
            capturedAt = nowMillis(),
            source = source,
            status = SubmissionStatus.NOT_SUBMITTED.name,
            statusDetail = null,
            submittedAt = null,
            lastCheckedAt = null,
            password = null,
        )
    }

    private fun nowMillis(): Long = System.currentTimeMillis()
}
