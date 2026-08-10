package com.watchdog.app.wpa.tracking

import android.content.Context
import com.watchdog.app.wpa.creds.WpaSecCredentials
import com.watchdog.app.wpa.data.SubmissionStatus
import com.watchdog.app.wpa.data.WpaDatabase
import com.watchdog.app.wpa.data.WpaRepository
import com.watchdog.app.wpa.wpasec.ResultsResponse
import com.watchdog.app.wpa.wpasec.UploadResult
import com.watchdog.app.wpa.wpasec.WpaSecClient
import java.io.File

sealed interface SubmitOutcome {
    data object Submitted : SubmitOutcome
    data object NoKey : SubmitOutcome
    data object AlreadySubmitted : SubmitOutcome
    data object NotFound : SubmitOutcome
    data class Failed(val detail: String) : SubmitOutcome
}

sealed interface RefreshOutcome {
    data class Updated(val newlyCracked: Int, val checked: Int) : RefreshOutcome
    data object NoKey : RefreshOutcome
    data object InvalidKey : RefreshOutcome
    data class NetworkError(val detail: String) : RefreshOutcome
}

/**
 * Orchestrates upload and result-tracking. Enforces the rules the request calls for: never upload
 * without an explicit request, never re-upload an already-submitted capture, and associate remote
 * results to local captures by BSSID (wpa-sec exposes no per-file id). Refresh only reads results —
 * it never re-uploads.
 */
class SubmissionTracker(
    context: Context,
    private val client: WpaSecClient = WpaSecClient(),
) {
    private val repo = WpaRepository(WpaDatabase.get(context).dao())
    private val creds = WpaSecCredentials(context)

    suspend fun submit(id: Long): SubmitOutcome {
        val key = creds.getKey() ?: return SubmitOutcome.NoKey
        val cap = repo.get(id) ?: return SubmitOutcome.NotFound
        when (cap.statusEnum) {
            SubmissionStatus.UPLOADING, SubmissionStatus.SUBMITTED, SubmissionStatus.CRACKED ->
                return SubmitOutcome.AlreadySubmitted
            else -> Unit
        }

        val file = File(cap.filePath)
        if (!file.exists()) {
            repo.updateStatus(id, SubmissionStatus.FAILED, detail = "Capture file missing.")
            return SubmitOutcome.Failed("Capture file missing.")
        }

        repo.updateStatus(id, SubmissionStatus.UPLOADING)
        return when (val res = client.upload(file, key)) {
            UploadResult.Success -> {
                repo.updateStatus(id, SubmissionStatus.SUBMITTED, detail = null, submittedAt = now())
                SubmitOutcome.Submitted
            }
            is UploadResult.Rejected -> {
                repo.updateStatus(id, SubmissionStatus.FAILED, detail = res.detail)
                SubmitOutcome.Failed(res.detail)
            }
            is UploadResult.NetworkError -> {
                repo.updateStatus(id, SubmissionStatus.NOT_SUBMITTED, detail = "Upload failed: ${res.detail}")
                SubmitOutcome.Failed(res.detail)
            }
        }
    }

    /** Poll WPA-sec once and reconcile all outstanding submissions by BSSID. No re-upload happens. */
    suspend fun refresh(): RefreshOutcome {
        val key = creds.getKey() ?: return RefreshOutcome.NoKey
        val submitted = repo.submittedCaptures()
        return when (val res = client.fetchResults(key)) {
            is ResultsResponse.NetworkError -> RefreshOutcome.NetworkError(res.detail)
            ResultsResponse.InvalidKey -> RefreshOutcome.InvalidKey
            is ResultsResponse.Success -> {
                val byBssid = res.entries.associateBy { it.bssidHex }
                var cracked = 0
                for (cap in submitted) {
                    val hit = byBssid[cap.bssid]
                    if (hit != null) {
                        repo.updateStatus(
                            cap.id,
                            SubmissionStatus.CRACKED,
                            detail = null,
                            lastCheckedAt = now(),
                            password = hit.password,
                        )
                        cracked++
                    } else {
                        // Still outstanding — record that we checked, keep status as-is.
                        repo.updateStatus(cap.id, cap.statusEnum, detail = cap.statusDetail, lastCheckedAt = now())
                    }
                }
                RefreshOutcome.Updated(newlyCracked = cracked, checked = submitted.size)
            }
        }
    }

    private fun now(): Long = System.currentTimeMillis()
}
