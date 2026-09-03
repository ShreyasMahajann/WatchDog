package com.watchdog.app.wpa.device

/** A connected USB device, as the platform reports it. Pure model — no Android types. */
data class UsbDeviceInfo(
    val vendorId: Int,
    val productId: Int,
    val productName: String?,
    val manufacturerName: String?,
    val deviceName: String,
    val interfaceClasses: List<Int>,
) {
    val vendorHex: String get() = "%04x".format(vendorId)
    val productHex: String get() = "%04x".format(productId)
    val idString: String get() = "$vendorHex:$productHex"

    /** True if any interface advertises the USB "Wireless Controller" class (0xE0). */
    val looksLikeWireless: Boolean get() = interfaceClasses.contains(USB_CLASS_WIRELESS_CONTROLLER)

    private companion object {
        // Value of android.hardware.usb.UsbConstants.USB_CLASS_WIRELESS_CONTROLLER.
        const val USB_CLASS_WIRELESS_CONTROLLER = 0xE0
    }
}
