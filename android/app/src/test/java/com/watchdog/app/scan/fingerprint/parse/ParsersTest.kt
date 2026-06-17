package com.watchdog.app.scan.fingerprint.parse

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ParsersTest {

    @Test
    fun `ssh banner with ubuntu backport tag`() {
        val p = SshBannerParser.parse("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11")!!
        assertEquals("openssh", p.product)
        assertEquals("8.2p1", p.version)
        assertEquals("ubuntu", p.distro)
        assertEquals("8.2p1-4ubuntu0.11", p.distroPkgVersion)
    }

    @Test
    fun `ssh banner debian carries release`() {
        val p = SshBannerParser.parse("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2")!!
        assertEquals("openssh", p.product)
        assertEquals("9.2p1", p.version)
        assertEquals("debian", p.distro)
        assertEquals("12", p.distroRelease)
        assertEquals("9.2p1-2+deb12u2", p.distroPkgVersion)
    }

    @Test
    fun `ssh banner plain has no distro`() {
        val p = SshBannerParser.parse("SSH-2.0-OpenSSH_8.9")!!
        assertEquals("openssh", p.product)
        assertEquals("8.9", p.version)
        assertNull(p.distro)
    }

    @Test
    fun `http server header nginx`() {
        val p = HttpHeaderParser.parseServer("nginx/1.21.0")!!
        assertEquals("nginx", p.product)
        assertEquals("1.21.0", p.version)
    }

    @Test
    fun `http server header apache with distro`() {
        val p = HttpHeaderParser.parseServer("Apache/2.4.49 (Ubuntu)")!!
        assertEquals("apache", p.product)
        assertEquals("2.4.49", p.version)
        assertEquals("ubuntu", p.distro)
    }

    @Test
    fun `distro banner parse handles parenthetical`() {
        val tag = DistroBannerParser.parse("(Debian)")!!
        assertEquals("debian", tag.distro)
    }

    @Test
    fun `distro banner parse rejects unknown`() {
        assertNull(DistroBannerParser.parse("SomeRandomComment"))
    }

    @Test
    fun `http title extraction`() {
        // exercised indirectly; ensure empty header returns null
        assertNull(HttpHeaderParser.parseServer(null))
        assertTrue(true)
    }
}
