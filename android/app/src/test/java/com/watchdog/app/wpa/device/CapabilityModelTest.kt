package com.watchdog.app.wpa.device

import org.junit.Assert.assertTrue
import org.junit.Test

class CapabilityModelTest {

    private fun ar9271() = ChipsetProfiles.identify(
        UsbDeviceInfo(0x0cf3, 0x9271, null, null, "dev", emptyList()),
    )

    private fun unknownAdapter() = ChipsetProfiles.identify(
        UsbDeviceInfo(0x1234, 0x5678, null, null, "dev", emptyList()),
    )

    private fun assess(
        root: RootStatus = RootStatus.NONE,
        adapter: IdentifiedAdapter? = null,
        monitorIface: Boolean = false,
        captureTool: Boolean = false,
    ) = CapabilityModel.assess(
        CapabilityInputs(
            rootStatus = root,
            adapter = adapter,
            hasUsbHost = true,
            monitorInterfacePresent = monitorIface,
            captureToolPresent = captureTool,
        ),
    )

    @Test
    fun `no adapter leaves monitor support unknown`() {
        val r = assess()
        assertTrue(r.monitorModeSupported is Capability.Unknown)
    }

    @Test
    fun `AR9271 makes monitor mode supported at the hardware level`() {
        val r = assess(adapter = ar9271())
        assertTrue(r.monitorModeSupported is Capability.Supported)
    }

    @Test
    fun `unrecognized adapter leaves monitor support unknown`() {
        val r = assess(adapter = unknownAdapter())
        assertTrue(r.monitorModeSupported is Capability.Unknown)
    }

    @Test
    fun `without root monitor mode is not enactable even with a supported adapter`() {
        val r = assess(root = RootStatus.NONE, adapter = ar9271())
        val enactable = r.monitorModeEnactable
        assertTrue(enactable is Capability.Unsupported)
        assertTrue((enactable as Capability.Unsupported).reason.contains("root", ignoreCase = true))
    }

    @Test
    fun `root plus supported adapter plus live monitor iface plus tool is fully capturable`() {
        val r = assess(
            root = RootStatus.GRANTED,
            adapter = ar9271(),
            monitorIface = true,
            captureTool = true,
        )
        assertTrue(r.monitorModeEnactable is Capability.Supported)
        assertTrue(r.packetCapturePossible is Capability.Supported)
        assertTrue(r.handshakeCapturePossible is Capability.Supported)
    }

    @Test
    fun `root plus supported adapter but no live monitor iface is unknown until enable attempt`() {
        val r = assess(root = RootStatus.GRANTED, adapter = ar9271(), monitorIface = false, captureTool = true)
        assertTrue(r.monitorModeEnactable is Capability.Unknown)
    }

    @Test
    fun `missing capture tool blocks packet capture even when monitor is enactable`() {
        val r = assess(root = RootStatus.GRANTED, adapter = ar9271(), monitorIface = true, captureTool = false)
        assertTrue(r.monitorModeEnactable is Capability.Supported)
        assertTrue(r.packetCapturePossible is Capability.Unsupported)
    }
}
