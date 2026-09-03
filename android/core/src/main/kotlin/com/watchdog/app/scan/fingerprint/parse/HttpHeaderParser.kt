package com.watchdog.app.scan.fingerprint.parse

import com.watchdog.app.scan.model.ProductIdentity

// Pure parser for HTTP Server / X-Powered-By headers, e.g.
//   "nginx/1.21.0"
//   "Apache/2.4.49 (Ubuntu)"
//   "Microsoft-IIS/10.0"
//   "openresty/1.19.3.1"

object HttpHeaderParser {

    fun parseServer(server: String?): ProductIdentity? {
        if (server.isNullOrBlank()) return null
        val value = server.trim()

        // First whitespace-delimited token holds product[/version].
        val firstToken = value.substringBefore(' ')
        val slash = firstToken.indexOf('/')
        val product: String
        val version: String?
        if (slash >= 0) {
            product = firstToken.substring(0, slash).lowercase()
            version = firstToken.substring(slash + 1).ifBlank { null }
        } else {
            product = firstToken.lowercase()
            version = null
        }
        if (product.isBlank()) return null

        // A parenthetical often names the distro, e.g. "(Ubuntu)".
        val paren = Regex("""\(([^)]*)\)""").find(value)?.groupValues?.getOrNull(1)
        val tag = DistroBannerParser.parse(paren)

        return ProductIdentity(
            product = product,
            version = version,
            distro = tag?.distro,
            distroRelease = tag?.release,
        )
    }
}
