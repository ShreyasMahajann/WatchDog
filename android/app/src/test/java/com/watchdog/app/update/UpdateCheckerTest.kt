package com.watchdog.app.update

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckerTest {

    @Test
    fun `higher release tag is newer`() {
        assertTrue(UpdateChecker.isNewer("0.2.0", "0.1.0"))
        assertTrue(UpdateChecker.isNewer("v1.0.0", "0.9.9"))
        assertTrue(UpdateChecker.isNewer("1.2.3", "1.2.2"))
        assertTrue(UpdateChecker.isNewer("1.3.0", "1.2.9"))
    }

    @Test
    fun `equal or lower tag is not newer`() {
        assertFalse(UpdateChecker.isNewer("0.1.0", "0.1.0"))
        assertFalse(UpdateChecker.isNewer("v0.1.0", "0.1.0"))
        assertFalse(UpdateChecker.isNewer("1.0.0", "1.0.1")) // local dev build ahead of release
        assertFalse(UpdateChecker.isNewer("1.2.0", "1.2.0"))
    }

    @Test
    fun `v prefix and differing component counts are handled`() {
        assertTrue(UpdateChecker.isNewer("v2", "1.9.9"))
        assertFalse(UpdateChecker.isNewer("1.2", "1.2.0"))
        assertTrue(UpdateChecker.isNewer("1.2.1", "1.2"))
    }

    @Test
    fun `pre-release and build suffixes are stripped`() {
        assertTrue(UpdateChecker.isNewer("1.4.0-rc1", "1.3.0"))
        assertFalse(UpdateChecker.isNewer("1.3.0-rc1", "1.3.0")) // rc of same version is not "newer"
        assertTrue(UpdateChecker.isNewer("2.0.0+build7", "1.9.0"))
    }

    @Test
    fun `non-numeric components degrade to zero rather than throwing`() {
        assertFalse(UpdateChecker.isNewer("nightly", "0.1.0"))
        assertTrue(UpdateChecker.isNewer("0.1.0", "garbage"))
    }
}
