package com.watchdog.app.correlate.engine

import com.watchdog.app.scan.model.CorrelateRequest
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.FindingState
import com.watchdog.app.scan.model.MatchBasis
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.scan.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Mirrors backend/test/correlation.test.ts against the same golden set.
class CorrelateEngineTest {

    private val source = Fixtures.source()
    private val now = "2026-08-10T00:00:00.000Z"

    private fun run(vararg obs: ServiceObservation) =
        CorrelateEngine.correlate(CorrelateRequest(obs.toList()), source, now)

    private fun only(findings: List<Finding>, cveId: String): Finding {
        val m = findings.filter { it.cveId == cveId }
        assertEquals("expected exactly one $cveId, got ${m.size}", 1, m.size)
        return m.first()
    }

    @Test
    fun `upstream version in range is LIKELY_VULNERABLE bounded`() {
        val res = run(Fixtures.OBS_SSH_UPSTREAM)
        assertEquals(0, res.suppressed.size)
        val f = only(res.findings, "CVE-2020-DEMO-SSH")
        assertEquals(FindingState.LIKELY_VULNERABLE, f.state)
        assertEquals(MatchBasis.BOUNDED_RANGE, f.matchBasis)
        assertEquals(false, f.suppressed)
        assertEquals(Severity.HIGH, f.severity)
    }

    @Test
    fun `distro backport patched is suppressed`() {
        val res = run(Fixtures.OBS_SSH_FOCAL_PATCHED)
        assertEquals(0, res.findings.size)
        val f = only(res.suppressed, "CVE-2020-DEMO-SSH")
        assertTrue(f.suppressed)
        assertEquals(0, f.priority)
        assertTrue((f.suppressionReason ?: "").contains("backported") || (f.suppressionReason ?: "").contains(">="))
    }

    @Test
    fun `distro package below fixed revision is VERIFIED`() {
        val res = run(Fixtures.OBS_SSH_FOCAL_VULN)
        val f = only(res.findings, "CVE-2020-DEMO-SSH")
        assertEquals(FindingState.VERIFIED, f.state)
        assertEquals(false, f.suppressed)
        assertTrue("confidence ${f.confidence} should be high", f.confidence >= 90)
    }

    @Test
    fun `known-exploited exact match ranks highest and flags KEV`() {
        val res = run(Fixtures.OBS_APACHE_VULN)
        val f = only(res.findings, "CVE-2021-41773")
        assertEquals(true, f.knownExploited)
        assertEquals(com.watchdog.app.scan.model.ExploitMaturity.KEV, f.exploitMaturity)
        assertEquals(MatchBasis.EXACT, f.matchBasis)
        assertEquals(Severity.CRITICAL, f.severity) // CNA CRITICAL beats NVD HIGH
        assertEquals(9.8, f.cvssScore!!, 0.0001)
        assertTrue(f.why.any { it.contains("KEV") })
    }

    @Test
    fun `version above fixed yields no finding`() {
        val res = run(Fixtures.OBS_NGINX_PATCHED)
        assertEquals(0, res.findings.size)
        assertEquals(0, res.suppressed.size)
    }

    @Test
    fun `nginx in bounded range is medium LIKELY`() {
        val res = run(Fixtures.OBS_NGINX_VULN)
        val f = only(res.findings, "CVE-2021-DEMO-NGINX")
        assertEquals(FindingState.LIKELY_VULNERABLE, f.state)
        assertEquals(Severity.MEDIUM, f.severity)
    }

    @Test
    fun `prioritization KEV critical outranks verified high and medium`() {
        val res = run(Fixtures.OBS_APACHE_VULN, Fixtures.OBS_SSH_FOCAL_VULN, Fixtures.OBS_NGINX_VULN)
        val order = res.findings.map { it.cveId }
        assertEquals("KEV critical should be first, got $order", "CVE-2021-41773", order.first())
        assertEquals("CVE-2021-DEMO-NGINX", order.last())
    }

    @Test
    fun `response envelope shape`() {
        val res = run(Fixtures.OBS_APACHE_VULN)
        assertEquals("0.1.0", res.engineVersion)
        assertEquals(now, res.generatedAt)
    }
}
