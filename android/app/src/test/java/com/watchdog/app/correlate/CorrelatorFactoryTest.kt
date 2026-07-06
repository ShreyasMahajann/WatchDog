package com.watchdog.app.correlate

import com.watchdog.app.settings.Settings
import org.junit.Assert.assertEquals
import org.junit.Test

class CorrelatorFactoryTest {
    @Test
    fun `own server available only when base url set`() {
        assertEquals(
            listOf(CorrelationTarget.OSV),
            CorrelatorFactory.targetsFor(Settings(serverBaseUrl = "")),
        )
        assertEquals(
            listOf(CorrelationTarget.OSV, CorrelationTarget.OWN_SERVER),
            CorrelatorFactory.targetsFor(Settings(serverBaseUrl = "https://x.example")),
        )
    }
}
