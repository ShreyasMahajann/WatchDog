package com.watchdog.app.correlate.remote

import com.watchdog.app.correlate.Correlator
import com.watchdog.app.correlate.direct.OsvClient
import com.watchdog.app.scan.model.CorrelateRequest
import com.watchdog.app.scan.model.CorrelateResponse
import com.watchdog.app.scan.model.ServiceObservation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

/**
 * Own-server mode: POST the frozen CorrelateRequest to the user's backend
 * (the deployed TypeScript engine) and return its CorrelateResponse verbatim.
 * The phone still did all the network I/O; this only ships evidence to the brain.
 */
class RemoteCorrelator(
    private val baseUrl: String,
    private val token: String? = null,
    private val client: OkHttpClient = defaultClient(),
    private val json: Json = OsvClient.LENIENT_JSON,
) : Correlator {
    private val jsonMedia = "application/json".toMediaType()

    override suspend fun correlate(observations: List<ServiceObservation>): CorrelateResponse =
        withContext(Dispatchers.IO) {
            val url = baseUrl.trimEnd('/') + "/api/v1/correlate"
            val payload = json.encodeToString(
                CorrelateRequest.serializer(),
                CorrelateRequest(observations),
            )
            val builder = Request.Builder()
                .url(url)
                .post(payload.toRequestBody(jsonMedia))
            if (!token.isNullOrBlank()) builder.header("Authorization", "Bearer $token")

            client.newCall(builder.build()).execute().use { resp ->
                val body = resp.body?.string()
                    ?: error("empty response from $url (${resp.code})")
                if (!resp.isSuccessful) error("backend returned ${resp.code}: ${body.take(300)}")
                json.decodeFromString(CorrelateResponse.serializer(), body)
            }
        }

    companion object {
        fun defaultClient(): OkHttpClient =
            OkHttpClient.Builder()
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(20, TimeUnit.SECONDS)
                .build()
    }
}
