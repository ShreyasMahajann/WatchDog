package com.watchdog.app.wpa.device

/**
 * Capability profile for a known Wi-Fi adapter chipset. These describe what the *chipset*
 * is capable of on Linux/Android with the right driver — not whether this particular phone's
 * kernel actually ships that driver (that's decided later by [CapabilityModel] plus a real
 * enable attempt).
 */
data class ChipsetProfile(
    val name: String,
    val driver: String,
    val monitorMode: Boolean,
    val packetInjection: Boolean,
    val handshakeCapture: Boolean,
    val firmware: String?,
    val notes: String,
)

/** A connected USB device paired with its recognized chipset profile (null = unrecognized). */
data class IdentifiedAdapter(
    val device: UsbDeviceInfo,
    val profile: ChipsetProfile?,
) {
    val isRecognized: Boolean get() = profile != null
}

/**
 * VID/PID → chipset lookup.
 *
 * Only the **Atheros AR9271** is shipped today (the adapter this feature is being built and
 * tested against). Support for other chipsets — Ralink RT3070/RT5370, MediaTek MT76xx,
 * Realtek RTL8812AU — is intentionally left as open-source contribution tasks; adding one is
 * a single [ChipsetProfile] entry here plus a VID/PID mapping.
 */
object ChipsetProfiles {

    val AR9271 = ChipsetProfile(
        name = "Atheros AR9271",
        driver = "ath9k_htc",
        monitorMode = true,
        packetInjection = true,
        handshakeCapture = true,
        firmware = "htc_9271.fw",
        notes = "Single-band 2.4GHz USB. Reference chipset for monitor mode + injection on Linux " +
            "(ath9k_htc). Needs the htc_9271 firmware loaded and the ath9k_htc driver present in the " +
            "running kernel — on stock Android that requires a custom (e.g. NetHunter) kernel + root.",
    )

    val MT7612U = ChipsetProfile(
        name = "MediaTek MT7612U / MT7610U",
        driver = "mt76",
        monitorMode = true,
        packetInjection = true,
        handshakeCapture = true,
        firmware = null,
        notes = "mt76 is modern and in-tree upstream but absent from stock Android kernels; on-device capture needs root + a kernel carrying the driver.",
    )

    val MT7601U = ChipsetProfile(
        name = "MediaTek MT7601U",
        driver = "mt7601u",
        monitorMode = false,
        packetInjection = false,
        handshakeCapture = false,
        firmware = null,
        notes = "2.4 GHz only. Monitor mode and packet injection are weak/unreliable.",
    )

    // AR9271 enumerates under Atheros VID 0x0cf3. 0x9271 is the common id (e.g. TP-Link
    // TL-WN722N v1, Alfa AWUS036NHA); 0x7015 appears on some AR7010+AR9271 combos.
    private val byId: Map<Pair<Int, Int>, ChipsetProfile> = mapOf(
        (0x0cf3 to 0x9271) to AR9271,
        (0x0cf3 to 0x7015) to AR9271,
        (0x0e8d to 0x7612) to MT7612U,
        (0x0e8d to 0x7610) to MT7612U,
        (0x0e8d to 0x7601) to MT7601U,
    )

    /** The chipset profile for a given USB vendor/product id, or null if unrecognized. */
    fun lookup(vendorId: Int, productId: Int): ChipsetProfile? = byId[vendorId to productId]

    /** Pair a probed USB device with its profile. */
    fun identify(device: UsbDeviceInfo): IdentifiedAdapter =
        IdentifiedAdapter(device, lookup(device.vendorId, device.productId))
}
