package com.watchdog.app.wpa.device

/**
 * A single capability verdict. Every value here is derived from a real probe of the
 * device's current state — nothing is ever hardcoded to [Supported]. When we genuinely
 * cannot tell (e.g. a driver's presence can't be confirmed without attempting to load
 * it), we say [Unknown] with the reason rather than guessing.
 */
sealed interface Capability {
    /** The short word shown in the UI badge. */
    val label: String

    /** Hardware/OS genuinely supports this, confirmed by a probe. */
    data object Supported : Capability {
        override val label = "Supported"
    }

    /** Confirmed not possible on this device, with the concrete blocking reason. */
    data class Unsupported(val reason: String) : Capability {
        override val label = "Unsupported"
    }

    /** Cannot be determined from the app alone (e.g. needs an enable attempt). */
    data class Unknown(val reason: String) : Capability {
        override val label = "Unknown"
    }

    /** Reason text for [Unsupported]/[Unknown]; null for [Supported]. */
    val reasonOrNull: String?
        get() = when (this) {
            is Unsupported -> reason
            is Unknown -> reason
            Supported -> null
        }
}
