package com.watchdog.app.wpa.tracking

import android.content.Context
import com.watchdog.app.wpa.creds.WpaSecCredentials
import com.watchdog.app.wpa.data.RoomWpaStore
import com.watchdog.app.wpa.data.WpaDatabase
import com.watchdog.app.wpa.data.WpaRepository
import com.watchdog.app.wpa.wpasec.WpaSecClient

/**
 * Android wiring for the shared [WpaSubmissionService]: supplies a Room-backed
 * [RoomWpaStore] and the encrypted [WpaSecCredentials]. All submission/tracking
 * logic (and [SubmitOutcome]/[RefreshOutcome]) now lives in :core so it is shared
 * with the desktop app.
 */
class SubmissionTracker(
    context: Context,
    client: WpaSecClient = WpaSecClient(),
) {
    private val repo = WpaRepository(WpaDatabase.get(context).dao())
    private val service = WpaSubmissionService(
        store = RoomWpaStore(repo),
        secrets = WpaSecCredentials(context),
        client = client,
    )

    suspend fun submit(id: Long): SubmitOutcome = service.submit(id)

    suspend fun refresh(): RefreshOutcome = service.refresh()
}
