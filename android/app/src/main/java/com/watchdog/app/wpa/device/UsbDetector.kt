package com.watchdog.app.wpa.device

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager

/**
 * Reads USB host state and enumerates connected devices. Enumeration needs no permission;
 * we only need per-device permission if/when we later open a device for I/O (a later milestone).
 * Maps Android's [UsbDevice] onto the platform-neutral [UsbDeviceInfo] model in :core.
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
