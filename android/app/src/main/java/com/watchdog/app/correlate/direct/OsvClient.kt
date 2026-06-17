package com.watchdog.app.correlate.direct

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

/**
 * Queries OSV.dev's public /v1/query endpoint (keyless). One call per product
 * query returns the full vuln objects, so no separate hydrate step is needed.
 * Network failures return an empty list — correlation degrades, never crashes.
 */
class OsvClient(
    private val client: OkHttpClient = defaultClient(),
    private val json: Json = LENIENT_JSON,
    private val baseUrl: String = "https://api.osv.dev",
) {
    private val jsonMedia = "application/json".toMediaType()

    suspend fun query(pkg: OsvPackage, version: String?): List<OsvVuln> =
        withContext(Dispatchers.IO) {
            val payload = json.encodeToString(OsvQuery.serializer(), OsvQuery(version = version, pkg = pkg))
            val req = Request.Builder()
                .url("$baseUrl/v1/query")
                .post(payload.toRequestBody(jsonMedia))
                .build()
            try {
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@use emptyList()
                    val body = resp.body?.string() ?: return@use emptyList()
                    json.decodeFromString(OsvQueryResponse.serializer(), body).vulns
                }
            } catch (e: Exception) {
                emptyList()
            }
        }

    companion object {
        val LENIENT_JSON = Json {
            ignoreUnknownKeys = true
            isLenient = true
            explicitNulls = false
        }

        fun defaultClient(): OkHttpClient =
            OkHttpClient.Builder()
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(12, TimeUnit.SECONDS)
                .build()
    }
}
