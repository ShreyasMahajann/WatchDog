package com.watchdog.app.wpa.device

/** The four capability verdicts that gate the on-device capture path. */
data class CapabilityAssessment(
    val monitorModeSupported: Capability,
    val monitorModeEnactable: Capability,
    val packetCapturePossible: Capability,
    val handshakeCapturePossible: Capability,
)

/** Inputs the assessment reasons about — all sourced from real probes. */
data class CapabilityInputs(
    val rootStatus: RootStatus,
    val adapter: IdentifiedAdapter?,
    val hasUsbHost: Boolean,
    val monitorInterfacePresent: Boolean,
    val captureToolPresent: Boolean,
)

/**
 * Pure, Android-free reasoning that turns probe facts into honest capability verdicts.
 *
 * The chain is: does some hardware support monitor mode → can *this* device actually enact it
 * (needs root + the driver) → can it capture packets (needs a capture tool) → can it capture a
 * handshake. Each step is [Capability.Supported] only when the facts prove it, [Unsupported]
 * with the blocking reason when they rule it out, and [Capability.Unknown] when the app
 * genuinely cannot tell without attempting an enable.
 */
object CapabilityModel {

    fun assess(inputs: CapabilityInputs): CapabilityAssessment {
        val supported = monitorModeSupported(inputs)
        val enactable = monitorModeEnactable(inputs, supported)
        val capture = packetCapturePossible(inputs, enactable)
        val handshake = handshakeCapturePossible(capture)
        return CapabilityAssessment(supported, enactable, capture, handshake)
    }

    private fun monitorModeSupported(inputs: CapabilityInputs): Capability {
        val adapter = inputs.adapter
        return when {
            adapter?.profile?.monitorMode == true ->
                Capability.Supported
            adapter != null && adapter.profile == null ->
                Capability.Unknown(
                    "Adapter ${adapter.device.idString} is not in the known-chipset list, so its monitor-mode " +
                        "support can't be confirmed.",
                )
            adapter?.profile != null -> // recognized but chipset can't do monitor mode
                Capability.Unsupported("The ${adapter.profile.name} chipset does not support monitor mode.")
            else ->
                Capability.Unknown(
                    "No external adapter connected. The internal Wi-Fi chipset's monitor-mode support " +
                        "can't be verified from the app (it would require a Nexmon-patched firmware).",
                )
        }
    }

    private fun monitorModeEnactable(inputs: CapabilityInputs, supported: Capability): Capability {
        if (inputs.rootStatus != RootStatus.GRANTED) {
            return Capability.Unsupported(
                "Enabling monitor mode requires a granted root shell (current root status: " +
                    "${inputs.rootStatus.name.lowercase()}).",
            )
        }
        when (supported) {
            is Capability.Unsupported -> return supported
            is Capability.Unknown -> return supported
            Capability.Supported -> Unit
        }
        // Root granted + chipset supports monitor mode. Whether THIS kernel actually carries the
        // driver can only be confirmed by trying to bring the interface up.
        return if (inputs.monitorInterfacePresent) {
            Capability.Supported
        } else {
            Capability.Unknown(
                "The chipset supports monitor mode and root is granted, but whether this kernel has the " +
                    "required driver can only be confirmed by attempting to enable it.",
            )
        }
    }

    private fun packetCapturePossible(inputs: CapabilityInputs, enactable: Capability): Capability {
        when (enactable) {
            is Capability.Unsupported -> return enactable
            is Capability.Unknown -> {
                if (!inputs.captureToolPresent) {
                    return Capability.Unsupported(
                        "No capture tool (tcpdump/airodump-ng) is available; the app would need to bundle one.",
                    )
                }
                return enactable
            }
            Capability.Supported -> Unit
        }
        return if (inputs.captureToolPresent) {
            Capability.Supported
        } else {
            Capability.Unsupported(
                "No capture tool (tcpdump/airodump-ng) is available; the app would need to bundle one.",
            )
        }
    }

    private fun handshakeCapturePossible(capture: Capability): Capability = when (capture) {
        Capability.Supported -> Capability.Supported
        // If raw packets can (or might) be captured in monitor mode, EAPOL handshake frames are
        // capturable too, so this verdict simply mirrors packet capture.
        is Capability.Unknown -> capture
        is Capability.Unsupported -> capture
    }
}
