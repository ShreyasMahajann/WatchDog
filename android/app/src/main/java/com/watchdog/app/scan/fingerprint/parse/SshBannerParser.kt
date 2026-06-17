package com.watchdog.app.scan.fingerprint.parse

import com.watchdog.app.scan.model.ProductIdentity

// Pure parser for SSH identification strings (RFC 4253 §4.2), e.g.
//   "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"
//   "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"
//   "SSH-2.0-dropbear_2020.81"

object SshBannerParser {

    fun parse(banner: String?): ProductIdentity? {
        if (banner == null) return null
        val line = banner.trim().lineSequence().firstOrNull { it.startsWith("SSH-") } ?: return null

        // Strip "SSH-<protoversion>-" -> software + optional space-separated comment.
        val firstDash = line.indexOf('-')
        val secondDash = line.indexOf('-', firstDash + 1)
        if (secondDash < 0) return null
        val software = line.substring(secondDash + 1)

        val spaceIdx = software.indexOf(' ')
        val idPart = if (spaceIdx >= 0) software.substring(0, spaceIdx) else software
        val comment = if (spaceIdx >= 0) software.substring(spaceIdx + 1).trim() else null

        // idPart like "OpenSSH_8.2p1" or "dropbear_2020.81".
        val us = idPart.indexOf('_')
        if (us < 0) return null
        val product = idPart.substring(0, us).lowercase()
        val version = idPart.substring(us + 1).ifBlank { null }

        val tag = DistroBannerParser.parse(comment)
        val distroPkgVersion = if (tag?.packageRevision != null && version != null) {
            "$version-${tag.packageRevision}"
        } else {
            null
        }

        return ProductIdentity(
            product = product,
            version = version,
            distro = tag?.distro,
            distroRelease = tag?.release,
            distroPkgVersion = distroPkgVersion,
        )
    }
}
