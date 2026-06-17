package com.watchdog.app.correlate.engine

import org.junit.Assert.assertEquals
import org.junit.Test

// Mirrors backend/test/version.test.ts — the Kotlin port must agree with the
// TypeScript comparator on every case.
class VersionTest {

    @Test
    fun `compareUpstream service point and patch releases`() {
        assertEquals(-1, compareUpstream("8.2p1", "8.3"))
        assertEquals(1, compareUpstream("8.2p1", "8.2")) // p1 is newer than plain 8.2
        assertEquals(-1, compareUpstream("2.4.49", "2.4.50"))
        assertEquals(0, compareUpstream("1.20.2", "1.20.2"))
    }

    @Test
    fun `compareUpstream numeric segments are not lexical`() {
        assertEquals(1, compareUpstream("1.21.0", "1.9.0")) // 21 > 9
        assertEquals(1, compareUpstream("1.20.0", "1.20")) // extra segment sorts higher
    }

    @Test
    fun `compareDebian revision ordering`() {
        assertEquals(1, compareDebian("1:8.2p1-4ubuntu0.11", "1:8.2p1-4"))
        assertEquals(0, compareDebian("1:8.2p1-4ubuntu0.11", "1:8.2p1-4ubuntu0.11"))
        assertEquals(-1, compareDebian("1:8.2p1-4ubuntu0.2", "1:8.2p1-4ubuntu0.11"))
    }

    @Test
    fun `compareDebian epoch dominates`() {
        assertEquals(-1, compareDebian("2.0", "1:1.0"))
        assertEquals(1, compareDebian("1:1.0", "2.0"))
    }

    @Test
    fun `compareDebian tilde sorts before everything`() {
        assertEquals(-1, compareDebian("1.0~rc1", "1.0"))
        assertEquals(-1, compareDebian("1.0~~", "1.0~"))
        assertEquals(-1, compareDebian("1.0", "1.0.1"))
    }
}
