package com.watchdog.app.correlate.direct

import com.watchdog.app.scan.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CvssV3Test {

    @Test
    fun `apache path traversal scores 9_8 critical`() {
        val s = CvssV3.fromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "osv")!!
        assertEquals(9.8, s.baseScore, 0.0001)
        assertEquals(Severity.CRITICAL, s.severity)
    }

    @Test
    fun `info leak scores 5_3 medium`() {
        val s = CvssV3.fromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "osv")!!
        assertEquals(5.3, s.baseScore, 0.0001)
        assertEquals(Severity.MEDIUM, s.severity)
    }

    @Test
    fun `none vector scores 0`() {
        val s = CvssV3.fromVector("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", "osv")!!
        assertEquals(0.0, s.baseScore, 0.0001)
        assertEquals(Severity.NONE, s.severity)
    }

    @Test
    fun `v4 vector is not computed here`() {
        assertNull(CvssV3.fromVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "osv"))
    }
}
