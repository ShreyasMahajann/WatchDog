package com.watchdog.app.correlate.direct

import com.watchdog.app.scan.model.CvssScore
import com.watchdog.app.scan.model.CvssVersion
import com.watchdog.app.scan.model.Severity
import kotlin.math.ceil
import kotlin.math.pow

/**
 * Pure CVSS v3.0/v3.1 base-score calculator. OSV records carry the vector string
 * but not always the numeric base score, and priority ranking needs the number.
 * Implements the official v3.1 spec formula (Roundup via ceil to one decimal).
 *
 * CVSS v4.0 uses a MacroVector lookup and is not computed here; a v4-only record
 * is returned with a null base score (a documented gap — most current CVEs still
 * publish v3.1).
 */
object CvssV3 {

    private val AV = mapOf("N" to 0.85, "A" to 0.62, "L" to 0.55, "P" to 0.20)
    private val AC = mapOf("L" to 0.77, "H" to 0.44)
    private val UI = mapOf("N" to 0.85, "R" to 0.62)
    private val CIA = mapOf("H" to 0.56, "L" to 0.22, "N" to 0.0)
    private val PR_UNCHANGED = mapOf("N" to 0.85, "L" to 0.62, "H" to 0.27)
    private val PR_CHANGED = mapOf("N" to 0.85, "L" to 0.68, "H" to 0.50)

    /** Parse a CVSS vector like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". */
    fun fromVector(vector: String, source: String): CvssScore? {
        val v = vector.trim()
        val version = when {
            v.startsWith("CVSS:3.1") -> CvssVersion.V3_1
            v.startsWith("CVSS:3.0") -> CvssVersion.V3_0
            else -> return null
        }
        val metrics = v.split('/')
            .mapNotNull { part ->
                val kv = part.split(':')
                if (kv.size == 2) kv[0] to kv[1] else null
            }.toMap()

        val av = AV[metrics["AV"]] ?: return null
        val ac = AC[metrics["AC"]] ?: return null
        val ui = UI[metrics["UI"]] ?: return null
        val c = CIA[metrics["C"]] ?: return null
        val i = CIA[metrics["I"]] ?: return null
        val a = CIA[metrics["A"]] ?: return null
        val scopeChanged = metrics["S"] == "C"
        val pr = (if (scopeChanged) PR_CHANGED else PR_UNCHANGED)[metrics["PR"]] ?: return null

        val iscBase = 1 - ((1 - c) * (1 - i) * (1 - a))
        val impact = if (scopeChanged) {
            7.52 * (iscBase - 0.029) - 3.25 * (iscBase - 0.02).pow(15)
        } else {
            6.42 * iscBase
        }
        val exploitability = 8.22 * av * ac * pr * ui

        val base = if (impact <= 0) {
            0.0
        } else if (scopeChanged) {
            roundUp(minOf(1.08 * (impact + exploitability), 10.0))
        } else {
            roundUp(minOf(impact + exploitability, 10.0))
        }

        return CvssScore(
            version = version,
            baseScore = base,
            severity = severityOf(base),
            vector = v,
            source = source,
        )
    }

    fun severityOf(score: Double): Severity = when {
        score <= 0.0 -> Severity.NONE
        score < 4.0 -> Severity.LOW
        score < 7.0 -> Severity.MEDIUM
        score < 9.0 -> Severity.HIGH
        else -> Severity.CRITICAL
    }

    // CVSS Roundup: smallest one-decimal number >= x (with float tolerance).
    private fun roundUp(x: Double): Double {
        val scaled = Math.round(x * 100_000.0)
        return if (scaled % 10_000 == 0L) {
            scaled / 100_000.0
        } else {
            (Math.floor(scaled / 10_000.0) + 1) / 10.0
        }
    }
}
