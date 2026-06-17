package com.watchdog.app.correlate.direct

import com.watchdog.app.scan.model.Kev
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request

@Serializable
private data class KevFeed(val vulnerabilities: List<KevItem> = emptyList())

@Serializable
private data class KevItem(
    val cveID: String,
    val dateAdded: String? = null,
    @SerialName("knownRansomwareCampaignUse") val ransomware: String? = null,
)

/**
 * Fetches the CISA KEV catalog (CC0 JSON) and indexes it by CVE ID. The catalog
 * is ~1–2 MB; a caller should fetch once per scan (or cache) and reuse the map.
 * Mirrors backend/src/ingest/kev.ts.
 */
class KevClient(
    private val client: OkHttpClient = OsvClient.defaultClient(),
    private val json: Json = OsvClient.LENIENT_JSON,
    private val url: String = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
) {
    suspend fun fetch(): Map<String, Kev> = withContext(Dispatchers.IO) {
        try {
            val req = Request.Builder().url(url).get().build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use emptyMap()
                val body = resp.body?.string() ?: return@use emptyMap()
                val feed = json.decodeFromString(KevFeed.serializer(), body)
                feed.vulnerabilities.associate { item ->
                    item.cveID to Kev(
                        dateAdded = item.dateAdded ?: "",
                        ransomware = item.ransomware?.equals("Known", ignoreCase = true) ?: false,
                    )
                }
            }
        } catch (e: Exception) {
            emptyMap()
        }
    }
}
