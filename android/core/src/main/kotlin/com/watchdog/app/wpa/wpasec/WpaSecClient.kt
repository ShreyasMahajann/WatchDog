package com.watchdog.app.wpa.wpasec

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import java.io.File
import java.util.concurrent.TimeUnit

/** One cracked network as returned by the WPA-sec results API. MACs are normalized to bare hex. */
data class CrackedEntry(
    val bssidHex: String,
    val stationHex: String,
    val ssid: String,
    val password: String,
)

sealed interface UploadResult {
    data object Success : UploadResult
    data class Rejected(val detail: String) : UploadResult
    data class NetworkError(val detail: String) : UploadResult
}

sealed interface ResultsResponse {
    data class Success(val entries: List<CrackedEntry>) : ResultsResponse
    data object InvalidKey : ResultsResponse
    data class NetworkError(val detail: String) : ResultsResponse
}

/**
 * Client for wpa-sec.stanev.org. Upload: POST the pcap as multipart field `file` with the key
 * carried in a `key` cookie. Results: GET `?api&dl=1` with the same cookie, returning colon-
 * separated `bssid:station:ssid:password` lines. The key is passed in per call and never held,
 * logged, or stored here — [com.watchdog.app.wpa.creds.WpaSecCredentials] owns it.
 */
class WpaSecClient(
    private val client: OkHttpClient = defaultClient(),
    private val baseUrl: String = "https://wpa-sec.stanev.org/",
) {

    suspend fun upload(file: File, key: String): UploadResult = withContext(Dispatchers.IO) {
        val body = MultipartBody.Builder().setType(MultipartBody.FORM)
            .addFormDataPart("file", file.name, file.asRequestBody(OCTET_STREAM))
            .build()
        val req = Request.Builder()
            .url(baseUrl)
            .header("Cookie", "key=$key")
            .post(body)
            .build()
        try {
            client.newCall(req).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                when {
                    resp.isSuccessful -> UploadResult.Success
                    else -> UploadResult.Rejected("HTTP ${resp.code}: ${text.take(160).trim()}")
                }
            }
        } catch (e: Exception) {
            UploadResult.NetworkError(e.message ?: e.javaClass.simpleName)
        }
    }

    suspend fun fetchResults(key: String): ResultsResponse = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url("${baseUrl}?api&dl=1")
            .header("Cookie", "key=$key")
            .get()
            .build()
        try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use ResultsResponse.NetworkError("HTTP ${resp.code}")
                val text = resp.body?.string().orEmpty()
                // An invalid key gets the HTML site rather than a potfile; a valid key with nothing
                // cracked returns an empty body (a legitimate "no results yet").
                if (text.contains("<html", ignoreCase = true) || text.contains("<!doctype", ignoreCase = true)) {
                    return@use ResultsResponse.InvalidKey
                }
                ResultsResponse.Success(text.lineSequence().mapNotNull(::parseLine).toList())
            }
        } catch (e: Exception) {
            ResultsResponse.NetworkError(e.message ?: e.javaClass.simpleName)
        }
    }

    /** Parse `bssid:station:ssid:password`. bssid/station are the first two fields; password is the last;
     *  anything between is the SSID (so an SSID containing ':' survives). */
    private fun parseLine(line: String): CrackedEntry? {
        val parts = line.trim().split(':')
        if (parts.size < 4) return null
        val bssid = parts[0].lowercase()
        if (!bssid.matches(HEX12)) return null
        return CrackedEntry(
            bssidHex = bssid,
            stationHex = parts[1].lowercase(),
            ssid = parts.subList(2, parts.size - 1).joinToString(":"),
            password = parts.last(),
        )
    }

    companion object {
        private val OCTET_STREAM = "application/octet-stream".toMediaType()
        private val HEX12 = Regex("[0-9a-f]{12}")

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS) // uploads
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        /** Normalize a MAC (any separators, any case) to bare lowercase hex for matching. */
        fun normalizeMac(mac: String): String = mac.filter { it.isLetterOrDigit() }.lowercase()
    }
}
