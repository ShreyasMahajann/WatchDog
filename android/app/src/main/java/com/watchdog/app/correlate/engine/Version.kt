package com.watchdog.app.correlate.engine

// Semantics-preserving port of backend/src/version.ts. Verified against the
// backend's own version.test.ts fixtures (see VersionTest).
//
// Two comparators, because network-service versions come in two flavours:
//   - upstream versions from banners:   "8.2p1", "2.4.49", "1.20.0"
//   - distro package revisions:         "1:8.2p1-4ubuntu0.11"
// compareDebian implements dpkg's verrevcmp (epoch, upstream, revision, with
// '~' sorting before end-of-string and letters before non-letters). RPM/EVR is
// a follow-up.

private fun sign(n: Int): Int = if (n < 0) -1 else if (n > 0) 1 else 0

private fun charOrNull(s: String, i: Int): Char? = if (i < s.length) s[i] else null

private fun isDigit(ch: Char?): Boolean = ch != null && ch in '0'..'9'

// --- Debian dpkg comparison -------------------------------------------------

// Order value for a single character per dpkg: '~' before anything (including
// end-of-string), then letters (by ASCII), then everything else (shifted above
// letters so non-letters sort after letters).
private fun debOrder(ch: Char?): Int {
    if (ch == null) return 0 // end of string
    if (ch == '~') return -1
    val c = ch.code
    val isLetter = (c in 65..90) || (c in 97..122)
    if (isLetter) return c
    return c + 256 // non-letters sort after letters
}

private fun verrevcmp(a: String, b: String): Int {
    var i = 0
    var j = 0
    while (i < a.length || j < b.length) {
        // Non-digit prefix, compared by debOrder char-by-char (including '~').
        while (
            (i < a.length && !isDigit(a[i])) ||
            (j < b.length && !isDigit(b[j]))
        ) {
            val oa = debOrder(if (i < a.length && !isDigit(a[i])) a[i] else null)
            val ob = debOrder(if (j < b.length && !isDigit(b[j])) b[j] else null)
            if (oa != ob) return sign(oa - ob)
            if (i < a.length && !isDigit(a[i])) i++
            if (j < b.length && !isDigit(b[j])) j++
        }

        // Skip leading zeros then compare digit runs numerically.
        while (charOrNull(a, i) == '0') i++
        while (charOrNull(b, j) == '0') j++
        var firstDiff = 0
        while (isDigit(charOrNull(a, i)) && isDigit(charOrNull(b, j))) {
            if (firstDiff == 0) firstDiff = a[i].code - b[j].code
            i++
            j++
        }
        if (isDigit(charOrNull(a, i))) return 1 // a has a longer number => larger
        if (isDigit(charOrNull(b, j))) return -1
        if (firstDiff != 0) return sign(firstDiff)
    }
    return 0
}

private data class DebParts(val epoch: Int, val upstream: String, val revision: String)

private fun parseDeb(v: String): DebParts {
    var epoch = 0
    var rest = v.trim()
    val colon = rest.indexOf(':')
    if (colon >= 0) {
        val e = rest.substring(0, colon).toIntOrNull()
        if (e != null) {
            epoch = e
            rest = rest.substring(colon + 1)
        }
    }
    var upstream = rest
    var revision = ""
    val dash = rest.lastIndexOf('-')
    if (dash >= 0) {
        upstream = rest.substring(0, dash)
        revision = rest.substring(dash + 1)
    }
    return DebParts(epoch, upstream, revision)
}

fun compareDebian(a: String, b: String): Int {
    val pa = parseDeb(a)
    val pb = parseDeb(b)
    if (pa.epoch != pb.epoch) return sign(pa.epoch - pb.epoch)
    val up = verrevcmp(pa.upstream, pb.upstream)
    if (up != 0) return up
    return verrevcmp(pa.revision, pb.revision)
}

// --- General upstream comparison --------------------------------------------

// Tokenize into alternating numeric and alpha runs; numbers compared
// numerically, alpha lexically. A version with an extra trailing segment sorts
// higher ("8.2p1" > "8.2", "1.20.0" > "1.20").
private sealed interface Token {
    data class Num(val value: Long) : Token
    data class Alpha(val value: String) : Token
}

private val TOKEN_RE = Regex("(\\d+)|([A-Za-z]+)")

private fun tokenize(v: String): List<Token> =
    TOKEN_RE.findAll(v).map { m ->
        val num = m.groups[1]?.value
        if (num != null) Token.Num(num.toLong()) else Token.Alpha(m.groups[2]!!.value.lowercase())
    }.toList()

fun compareUpstream(a: String, b: String): Int {
    val ta = tokenize(a)
    val tb = tokenize(b)
    val n = maxOf(ta.size, tb.size)
    for (i in 0 until n) {
        val x = ta.getOrNull(i)
        val y = tb.getOrNull(i)
        if (x == null) return -1 // a ran out => a is smaller
        if (y == null) return 1
        if (x is Token.Num && y is Token.Num) {
            if (x.value != y.value) return sign(if (x.value < y.value) -1 else 1)
        } else if (x is Token.Alpha && y is Token.Alpha) {
            if (x.value != y.value) return if (x.value < y.value) -1 else 1
        } else {
            // Mixed: a numeric token outranks an alpha token at the same position.
            return if (x is Token.Num) 1 else -1
        }
    }
    return 0
}
