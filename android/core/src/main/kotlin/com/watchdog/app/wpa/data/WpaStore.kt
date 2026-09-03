package com.watchdog.app.wpa.data

/**
 * Persistence the shared [com.watchdog.app.wpa.tracking.WpaSubmissionService] needs.
 * Android backs it with Room, desktop with sqlite. Import/observe queries live on the
 * platform stores; this is only the submission/tracking path.
 */
interface WpaStore {
    suspend fun get(id: Long): Capture?
    suspend fun submittedCaptures(): List<Capture>
    suspend fun updateStatus(
        id: Long,
        status: SubmissionStatus,
        detail: String? = null,
        submittedAt: Long? = null,
        lastCheckedAt: Long? = null,
        password: String? = null,
    )
}
