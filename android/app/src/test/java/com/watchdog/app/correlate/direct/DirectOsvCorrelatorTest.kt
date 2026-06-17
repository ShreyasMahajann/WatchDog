package com.watchdog.app.correlate.direct

import com.watchdog.app.scan.model.Exposure
import com.watchdog.app.scan.model.FindingState
import com.watchdog.app.scan.model.MatchBasis
import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.scan.model.Severity
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class DirectOsvCorrelatorTest {

    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `distro-tagged service maps OSV vuln to an exact finding with CVSS`() = runBlocking {
        // OSV /v1/query, then KEV, then EPSS — served in enqueue order.
        server.enqueue(
            MockResponse().setBody(
                """
                {"vulns":[{"id":"DSA-9999","aliases":["CVE-2022-1234"],
                "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "summary":"demo"}]}
                """.trimIndent(),
            ),
        )
        server.enqueue(MockResponse().setBody("""{"vulnerabilities":[]}"""))
        server.enqueue(MockResponse().setBody("""{"data":[]}"""))

        val base = server.url("/").toString().trimEnd('/')
        val correlator = DirectOsvCorrelator(
            osv = OsvClient(baseUrl = base),
            kev = KevClient(url = "$base/kev"),
            epss = EpssClient(baseUrl = "$base/epss"),
            now = { "2026-08-10T00:00:00Z" },
        )

        val obs = ServiceObservation(
            host = "192.168.1.50", port = 443, serviceName = "https",
            product = ProductIdentity(
                product = "nginx", version = "1.22.1",
                distro = "debian", distroRelease = "12", distroPackage = "nginx",
                distroPkgVersion = "1.22.1-9",
            ),
            exposure = Exposure(reachable = true),
        )

        val res = correlator.correlate(listOf(obs))
        val f = res.findings.single { it.cveId == "CVE-2022-1234" }
        assertEquals(MatchBasis.EXACT, f.matchBasis)
        assertEquals(FindingState.LIKELY_VULNERABLE, f.state)
        assertEquals(Severity.CRITICAL, f.severity)
        assertTrue(f.cvssScore!! >= 9.0)
    }

    @Test
    fun `bare upstream service surfaces low-confidence DETECTED`() = runBlocking {
        server.enqueue(
            MockResponse().setBody("""{"vulns":[{"id":"GHSA-x","aliases":["CVE-2021-9"],"summary":"y"}]}"""),
        )
        server.enqueue(MockResponse().setBody("""{"vulnerabilities":[]}"""))
        server.enqueue(MockResponse().setBody("""{"data":[]}"""))

        val base = server.url("/").toString().trimEnd('/')
        val correlator = DirectOsvCorrelator(
            osv = OsvClient(baseUrl = base),
            kev = KevClient(url = "$base/kev"),
            epss = EpssClient(baseUrl = "$base/epss"),
            now = { "2026-08-10T00:00:00Z" },
        )

        val obs = ServiceObservation(
            host = "192.168.1.60", port = 8080, serviceName = "http",
            product = ProductIdentity(product = "nginx", version = "1.21.0"),
            exposure = Exposure(reachable = true),
        )

        val res = correlator.correlate(listOf(obs))
        val f = res.findings.single { it.cveId == "CVE-2021-9" }
        assertEquals(FindingState.DETECTED, f.state)
        assertEquals(MatchBasis.PRODUCT_ONLY, f.matchBasis)
    }
}
