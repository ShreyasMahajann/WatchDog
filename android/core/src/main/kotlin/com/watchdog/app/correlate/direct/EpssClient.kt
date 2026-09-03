package com.watchdog.app.correlate.direct

import com.watchdog.app.scan.model.Epss
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request

@Serializable
private data class EpssResponse(val data: List<EpssItem> = emptyList())

@Serializable
private data class EpssItem(
    val cve: String,
    val epss: String? = null,
    val percentile: String? = null,
)

/**
 * Looks up EPSS (exploitation-probability) scores for a set of CVE IDs via
 * FIRST's public API (keyless). Batches IDs into the query string; ids not in
 * the response simply have no EPSS overlay.
 */
class EpssClient(
    private val client: OkHttpClient = OsvClient.defaultClient(),
    private val json: Json = OsvClient.LENIENT_JSON,
    private val baseUrl: String = "https://api.first.org/data/v1/epss",
) {
    suspend fun fetch(cveIds: Collection<String>): Map<String, Epss> {
        val ids = cveIds.filter { it.startsWith("CVE-") }.distinct()
        if (ids.isEmpty()) return emptyMap()
        val out = mutableMapOf<String, Epss>()
        // Keep URLs well under length limits.
        for (chunk in ids.chunked(100)) {
            out.putAll(fetchChunk(chunk))
        }
        return out
    }

    private suspend fun fetchChunk(ids: List<String>): Map<String, Epss> =
        withContext(Dispatchers.IO) {
            try {
                val url = "$baseUrl?cve=${ids.joinToString(",")}"
                val req = Request.Builder().url(url).get().build()
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@use emptyMap()
                    val body = resp.body?.string() ?: return@use emptyMap()
                    json.decodeFromString(EpssResponse.serializer(), body).data.mapNotNull { item ->
                        val score = item.epss?.toDoubleOrNull() ?: return@mapNotNull null
                        val pct = item.percentile?.toDoubleOrNull() ?: 0.0
                        item.cve to Epss(score = score, percentile = pct)
                    }.toMap()
                }
            } catch (e: Exception) {
                emptyMap()
            }
        }
}
