package com.watchdog.app.wpa.device

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager

/** A connected USB device, as Android reports it. */
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
    val looksLikeWireless: Boolean get() = interfaceClasses.contains(UsbConstants.USB_CLASS_WIRELESS_CONTROLLER)
}

/**
 * Reads USB host state and enumerates connected devices. Enumeration needs no permission;
 * we only need per-device permission if/when we later open a device for I/O (a later milestone).
 */
class UsbDetector(private val context: Context) {

    private val usbManager: UsbManager? = context.getSystemService(Context.USB_SERVICE) as? UsbManager

    /** Whether this device supports USB host mode (OTG) at all. */
    fun hasUsbHost(): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)

    /** Currently connected USB devices. Empty when nothing is plugged in or host mode is unavailable. */
    fun listDevices(): List<UsbDeviceInfo> =
        usbManager?.deviceList?.values.orEmpty().map { it.toInfo() }

    private fun UsbDevice.toInfo(): UsbDeviceInfo {
        val classes = (0 until interfaceCount).map { getInterface(it).interfaceClass }
        return UsbDeviceInfo(
            vendorId = vendorId,
            productId = productId,
            productName = runCatching { productName }.getOrNull(),
            manufacturerName = runCatching { manufacturerName }.getOrNull(),
            deviceName = deviceName,
            interfaceClasses = classes,
        )
    }
}
