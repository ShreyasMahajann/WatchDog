package com.watchdog.app.wpa.creds

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedPrefsRecoveryTest {

    @Test
    fun returnsValueAndDoesNotWipeWhenOpenSucceeds() {
        var wiped = false
        val result = openWithRecovery(opener = { "prefs" }, wiper = { wiped = true })
        assertEquals("prefs", result)
        assertFalse(wiped)
    }

    @Test
    fun wipesAndRetriesWhenFirstOpenThrows() {
        var wiped = false
        var attempts = 0
        val result = openWithRecovery(
            opener = {
                attempts++
                if (attempts == 1) throw javax.crypto.AEADBadTagException("corrupt")
                "recovered"
            },
            wiper = { wiped = true },
        )
        assertEquals("recovered", result)
        assertTrue(wiped)
        assertEquals(2, attempts)
    }

    @Test
    fun returnsNullWithoutThrowingWhenRecoveryAlsoFails() {
        var wipes = 0
        val result = openWithRecovery<String>(
            opener = { throw javax.crypto.AEADBadTagException("still corrupt") },
            wiper = { wipes++ },
        )
        assertNull(result)
        assertEquals(1, wipes)
    }

    @Test
    fun swallowsWiperFailureAndStillRetries() {
        var attempts = 0
        val result = openWithRecovery(
            opener = {
                attempts++
                if (attempts == 1) throw IllegalStateException("bad keyset")
                "ok"
            },
            wiper = { throw RuntimeException("could not delete file") },
        )
        assertEquals("ok", result)
    }
}
