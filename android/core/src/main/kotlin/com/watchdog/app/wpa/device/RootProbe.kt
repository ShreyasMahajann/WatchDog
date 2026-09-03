package com.watchdog.app.wpa.device

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** How much root access the device actually grants us. */
enum class RootStatus { NONE, PRESENT_UNGRANTED, GRANTED, UNKNOWN }

data class RootResult(
    val status: RootStatus,
    val suPath: String?,
    val detail: String,
)

/**
 * Detects root without pretending. Passive detection only looks for an `su` binary
 * (never prompts). An explicit active check actually opens a `su` shell to confirm a
 * real uid=0 — that may raise the superuser app's grant dialog, so it's only run when
 * the user asks for it via the diagnostics screen.
 */
object RootProbe {

    private val SU_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/su/bin/su", "/sbin/su",
        "/system/sbin/su", "/vendor/bin/su", "/data/local/xbin/su", "/data/local/bin/su",
    )

    suspend fun detect(activeCheck: Boolean): RootResult = withContext(Dispatchers.IO) {
        val suPath = SU_PATHS.firstOrNull { runCatching { File(it).exists() }.getOrDefault(false) }
            ?: Shell.which("su")

        if (suPath == null) {
            return@withContext RootResult(
                status = RootStatus.NONE,
                suPath = null,
                detail = "No su binary on the standard paths or PATH. On-device capture (monitor mode) is not possible without root.",
            )
        }

        if (!activeCheck) {
            return@withContext RootResult(
                status = RootStatus.PRESENT_UNGRANTED,
                suPath = suPath,
                detail = "su binary present at $suPath. Tap “Test root access” to confirm a root shell is actually granted.",
            )
        }

        // Active check: really try to get a uid=0 shell. May prompt the superuser app.
        val out = Shell.run(listOf("su", "-c", "id"))
        val granted = out.text.contains("uid=0")
        when {
            granted -> RootResult(RootStatus.GRANTED, suPath, "Root shell granted — confirmed uid=0.")
            out.timedOut -> RootResult(RootStatus.UNKNOWN, suPath, "Root request timed out (no response from the superuser app).")
            else -> RootResult(RootStatus.PRESENT_UNGRANTED, suPath, "su present but a root shell was denied or not granted.")
        }
    }
}
