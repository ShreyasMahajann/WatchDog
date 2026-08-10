package com.watchdog.app.wpa.diagnostics

import android.content.Context
import android.os.Build
import com.watchdog.app.wpa.device.CapabilityInputs
import com.watchdog.app.wpa.device.CapabilityModel
import com.watchdog.app.wpa.device.ChipsetProfiles
import com.watchdog.app.wpa.device.IdentifiedAdapter
import com.watchdog.app.wpa.device.InterfaceProbe
import com.watchdog.app.wpa.device.RootProbe
import com.watchdog.app.wpa.device.ToolProbe
import com.watchdog.app.wpa.device.UsbDetector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Runs every device probe and assembles a [DiagnosticsReport]. Each probe is wrapped so one
 * failure records an error string instead of aborting the whole report.
 */
class DiagnosticsCollector(context: Context) {

    private val appContext = context.applicationContext
    private val usbDetector = UsbDetector(appContext)

    suspend fun collect(activeRootCheck: Boolean): DiagnosticsReport = withContext(Dispatchers.IO) {
        val errors = mutableListOf<String>()

        val root = runOrError(errors, "root") { RootProbe.detect(activeRootCheck) }
            ?: RootProbe.detect(activeCheck = false)

        val hasUsbHost = runOrError(errors, "usb-host") { usbDetector.hasUsbHost() } ?: false
        val usbDevices: List<IdentifiedAdapter> =
            runOrError(errors, "usb-devices") { usbDetector.listDevices().map { ChipsetProfiles.identify(it) } }
                ?: emptyList()

        val interfaces = runOrError(errors, "interfaces") { InterfaceProbe.list() } ?: emptyList()
        val tools = runOrError(errors, "tools") { ToolProbe.probe() } ?: emptyList()

        val capability = CapabilityModel.assess(
            CapabilityInputs(
                rootStatus = root.status,
                adapter = usbDevices.firstOrNull { it.isRecognized } ?: usbDevices.firstOrNull(),
                hasUsbHost = hasUsbHost,
                monitorInterfacePresent = interfaces.any { it.looksMonitor },
                captureToolPresent = tools.any { it.present },
            ),
        )

        DiagnosticsReport(
            androidRelease = Build.VERSION.RELEASE ?: "unknown",
            apiLevel = Build.VERSION.SDK_INT,
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
            internalWifiChipset = internalWifiChipset(),
            root = root,
            hasUsbHost = hasUsbHost,
            usbDevices = usbDevices,
            interfaces = interfaces,
            tools = tools,
            capability = capability,
            errors = errors,
        )
    }

    /** Best-effort read of the built-in Wi-Fi chipset from vendor system properties. */
    private fun internalWifiChipset(): String {
        val keys = listOf("ro.hardware.wlan", "ro.boot.wifi.chip", "ro.vendor.wifi.chip", "wlan.driver.status")
        val value = keys.asSequence().map { systemProperty(it) }.firstOrNull { it.isNotBlank() }
        return value?.takeIf { it.isNotBlank() }
            ?: "Not exposed by this device (OEMs rarely publish the internal Wi-Fi chipset)."
    }

    private fun systemProperty(key: String): String = runCatching {
        val clazz = Class.forName("android.os.SystemProperties")
        val get = clazz.getMethod("get", String::class.java, String::class.java)
        get.invoke(null, key, "") as String
    }.getOrDefault("")

    private inline fun <T> runOrError(errors: MutableList<String>, tag: String, block: () -> T): T? =
        runCatching { block() }.getOrElse {
            errors.add("$tag probe failed: ${it.message ?: it.javaClass.simpleName}")
            null
        }
}
