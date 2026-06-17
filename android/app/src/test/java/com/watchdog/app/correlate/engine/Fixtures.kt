package com.watchdog.app.correlate.engine

import com.watchdog.app.scan.model.CvssScore
import com.watchdog.app.scan.model.CvssVersion
import com.watchdog.app.scan.model.DistroFix
import com.watchdog.app.scan.model.DistroStatus
import com.watchdog.app.scan.model.Epss
import com.watchdog.app.scan.model.Exposure
import com.watchdog.app.scan.model.ExploitMaturity
import com.watchdog.app.scan.model.Kev
import com.watchdog.app.scan.model.ProductIdentity
import com.watchdog.app.scan.model.ServiceEvidence
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.scan.model.Severity
import com.watchdog.app.scan.model.VersionRange
import com.watchdog.app.scan.model.VulnRecord

// Kotlin mirror of backend/test/fixtures.ts. Kept identical so the ported engine
// is validated against the same golden set as the TypeScript engine.

object Fixtures {

    val VULNS = listOf(
        VulnRecord(
            cveId = "CVE-2020-DEMO-SSH",
            ranges = listOf(VersionRange(vendor = "openbsd", product = "openssh", introduced = "0", fixed = "8.3")),
            distroFixes = listOf(
                DistroFix("ubuntu", "focal", "openssh", DistroStatus.FIXED, "1:8.2p1-4ubuntu0.11"),
            ),
            cvss = listOf(CvssScore(CvssVersion.V3_1, 7.5, Severity.HIGH, source = "nvd")),
            summary = "Demo OpenSSH issue fixed in 8.3.",
            remediation = "Upgrade OpenSSH to 8.3+ or apply distro update.",
        ),
        VulnRecord(
            cveId = "CVE-2021-41773",
            ranges = listOf(VersionRange(vendor = "apache", product = "http_server", exactVersion = "2.4.49")),
            cvss = listOf(
                CvssScore(CvssVersion.V3_1, 9.8, Severity.CRITICAL, source = "cna:apache"),
                CvssScore(CvssVersion.V3_1, 7.5, Severity.HIGH, source = "nvd"),
            ),
            kev = Kev("2021-11-03", false),
            epss = Epss(0.94, 0.99),
            exploitMaturity = ExploitMaturity.WEAPONIZED,
            summary = "Path traversal and file disclosure in Apache HTTP Server 2.4.49.",
            remediation = "Upgrade to 2.4.51+.",
        ),
        VulnRecord(
            cveId = "CVE-2021-DEMO-NGINX",
            ranges = listOf(VersionRange(vendor = "nginx", product = "nginx", introduced = "1.20.0", fixed = "1.20.2")),
            cvss = listOf(CvssScore(CvssVersion.V3_1, 5.3, Severity.MEDIUM, source = "nvd")),
            summary = "Demo nginx issue fixed in 1.20.2.",
        ),
    )

    fun source(vulns: List<VulnRecord> = VULNS): VulnSource {
        val index = mutableMapOf<String, MutableList<VulnRecord>>()
        for (v in vulns) {
            for (r in v.ranges) {
                val key = normalizeProduct(r.product)
                val list = index.getOrPut(key) { mutableListOf() }
                if (v !in list) list.add(v)
            }
        }
        return VulnSource { np -> index[np] ?: emptyList() }
    }

    val OBS_SSH_UPSTREAM = ServiceObservation(
        host = "192.168.1.20", port = 22, serviceName = "ssh",
        product = ProductIdentity(vendor = "openbsd", product = "openssh", version = "8.2p1"),
        evidence = ServiceEvidence(banner = "SSH-2.0-OpenSSH_8.2p1"),
        exposure = Exposure(reachable = true),
    )

    val OBS_SSH_FOCAL_PATCHED = ServiceObservation(
        host = "192.168.1.21", port = 22, serviceName = "ssh",
        product = ProductIdentity(
            vendor = "openbsd", product = "openssh", version = "8.2p1",
            distro = "ubuntu", distroRelease = "focal", distroPackage = "openssh",
            distroPkgVersion = "1:8.2p1-4ubuntu0.11",
        ),
        evidence = ServiceEvidence(banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"),
        exposure = Exposure(reachable = true),
    )

    val OBS_SSH_FOCAL_VULN = ServiceObservation(
        host = "192.168.1.22", port = 22, serviceName = "ssh",
        product = ProductIdentity(
            vendor = "openbsd", product = "openssh", version = "8.2p1",
            distro = "ubuntu", distroRelease = "focal", distroPackage = "openssh",
            distroPkgVersion = "1:8.2p1-4ubuntu0.2",
        ),
        evidence = ServiceEvidence(banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2"),
        exposure = Exposure(reachable = true),
    )

    val OBS_APACHE_VULN = ServiceObservation(
        host = "192.168.1.42", port = 80, serviceName = "http",
        product = ProductIdentity(product = "Apache", version = "2.4.49"),
        evidence = ServiceEvidence(httpServer = "Apache/2.4.49 (Unix)"),
        exposure = Exposure(reachable = true, authless = true),
    )

    val OBS_NGINX_PATCHED = ServiceObservation(
        host = "192.168.1.30", port = 443, serviceName = "https",
        product = ProductIdentity(product = "nginx", version = "1.20.5"),
        exposure = Exposure(reachable = true),
    )

    val OBS_NGINX_VULN = ServiceObservation(
        host = "192.168.1.31", port = 443, serviceName = "https",
        product = ProductIdentity(product = "nginx", version = "1.20.1"),
        exposure = Exposure(reachable = true),
    )
}
