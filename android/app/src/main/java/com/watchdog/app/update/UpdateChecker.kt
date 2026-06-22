package com.watchdog.app.update

import com.watchdog.app.correlate.direct.OsvClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request

/** Result of comparing the installed build against the latest GitHub release. */
sealed interface UpdateStatus {
    /** Not checked yet, offline, or the check failed — surface nothing to the user. */
    data object Unknown : UpdateStatus

    /** Installed build is the latest published release (or newer, for local dev builds). */
    data object UpToDate : UpdateStatus

    /** A newer release exists; [releaseUrl] is where to download it. */
    data class Available(val latestVersion: String, val releaseUrl: String) : UpdateStatus
}

/**
 * Checks the latest GitHub release for newer builds. Read-only, keyless call to the
 * public GitHub API; any failure degrades to [UpdateStatus.Unknown] rather than
 * bothering the user. The phone never auto-installs — it only points at the release
 * page so the user downloads it themselves.
 */
class UpdateChecker(
    private val currentVersion: String,
    private val client: OkHttpClient = OsvClient.defaultClient(),
    private val json: Json = OsvClient.LENIENT_JSON,
    private val url: String = LATEST_RELEASE_API,
) {
    @Serializable
    private data class GithubRelease(
        @SerialName("tag_name") val tagName: String? = null,
        @SerialName("html_url") val htmlUrl: String? = null,
        val draft: Boolean = false,
        val prerelease: Boolean = false,
    )

    suspend fun check(): UpdateStatus = withContext(Dispatchers.IO) {
        try {
            val req = Request.Builder()
                .url(url)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "watchDog-android") // GitHub rejects requests without one
                .get()
                .build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use UpdateStatus.Unknown
                val body = resp.body?.string() ?: return@use UpdateStatus.Unknown
                val release = json.decodeFromString(GithubRelease.serializer(), body)
                val tag = release.tagName?.takeIf { it.isNotBlank() } ?: return@use UpdateStatus.Unknown
                if (release.draft) return@use UpdateStatus.Unknown
                val target = release.htmlUrl?.takeIf { it.isNotBlank() } ?: RELEASES_PAGE
                if (isNewer(tag, currentVersion)) UpdateStatus.Available(tag, target) else UpdateStatus.UpToDate
            }
        } catch (e: Exception) {
            UpdateStatus.Unknown
        }
    }

    companion object {
        const val REPO = "ShreyasMahajann/WatchDog"
        const val LATEST_RELEASE_API = "https://api.github.com/repos/$REPO/releases/latest"
        const val RELEASES_PAGE = "https://github.com/$REPO/releases/latest"

        /** True if the release [tag] is a strictly higher semantic version than [current]. */
        internal fun isNewer(tag: String, current: String): Boolean {
            val a = parse(tag)
            val b = parse(current)
            for (i in 0 until maxOf(a.size, b.size)) {
                val x = a.getOrElse(i) { 0 }
                val y = b.getOrElse(i) { 0 }
                if (x != y) return x > y
            }
            return false
        }

        /** "v1.2.3", "1.2.3-rc1", "1.2" → [1, 2, 3] / [1, 2, 3] / [1, 2]; non-numeric parts → 0. */
        private fun parse(version: String): List<Int> =
            version.trim()
                .removePrefix("v").removePrefix("V")
                .substringBefore('-').substringBefore('+')
                .split('.')
                .map { it.trim().toIntOrNull() ?: 0 }
    }
}
