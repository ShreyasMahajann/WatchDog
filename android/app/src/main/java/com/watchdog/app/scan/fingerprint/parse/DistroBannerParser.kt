package com.watchdog.app.scan.fingerprint.parse

// Pure parser: pull distro context out of a banner comment. This is the signal
// that later suppresses backport false-positives — an OpenSSH banner of
// "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11" is patched even though upstream 8.2p1 looks
// vulnerable, because the distro package revision carries the fix.

data class DistroTag(
    val distro: String, // "ubuntu" | "debian" | ...
    val release: String? = null, // "focal" | "12" | ...
    val packageRevision: String? = null, // "4ubuntu0.11" | "2+deb12u2"
)

object DistroBannerParser {

    private val KNOWN = mapOf(
        "ubuntu" to "ubuntu",
        "debian" to "debian",
        "raspbian" to "debian",
        "freebsd" to "freebsd",
        "centos" to "redhat",
        "rhel" to "redhat",
        "red hat" to "redhat",
        "redhat" to "redhat",
        "fedora" to "fedora",
        "alpine" to "alpine",
    )

    // Map a Debian revision like "2+deb12u2" to its release number ("12").
    private val DEB_RELEASE = Regex("""\+deb(\d+)u\d+""")

    /**
     * Parse comment fragments such as "Ubuntu-4ubuntu0.11", "Debian-2+deb12u2",
     * or a parenthetical "(Ubuntu)". Returns null if no known distro is present.
     */
    fun parse(comment: String?): DistroTag? {
        if (comment.isNullOrBlank()) return null
        val cleaned = comment.trim().trim('(', ')').trim()
        val lower = cleaned.lowercase()

        val distroKey = KNOWN.entries.firstOrNull { lower.contains(it.key) } ?: return null
        val distro = distroKey.value

        // Revision follows the first '-' after the distro label, e.g.
        // "Ubuntu-4ubuntu0.11" -> "4ubuntu0.11".
        var revision: String? = null
        val dash = cleaned.indexOf('-')
        if (dash in 0 until cleaned.length - 1) {
            val tail = cleaned.substring(dash + 1).trim()
            if (tail.isNotEmpty() && tail.any { it.isDigit() }) revision = tail
        }

        val release = revision?.let { rev ->
            DEB_RELEASE.find(rev)?.groupValues?.getOrNull(1)
        }

        return DistroTag(distro = distro, release = release, packageRevision = revision)
    }
}
