package com.watchdog.app.ui.results

import com.watchdog.app.scan.model.ServiceObservation

/** One open port/service seen across the scan, plus the hosts that expose it. */
data class ServiceGroup(
    val port: Int,
    val proto: String,
    val serviceName: String?,
    val hosts: List<String>,
) {
    val label: String = "$port/$proto${serviceName?.let { " $it" } ?: ""}"
}

/**
 * Pure, Android-free filtering/grouping for the results screen so it can be
 * unit-tested. A blank query matches everything; all matching is
 * case-insensitive substring.
 */
object ResultsFilter {

    fun serviceMatches(obs: ServiceObservation, query: String): Boolean {
        val q = query.trim()
        if (q.isEmpty()) return true
        val haystack = buildList {
            add(obs.port.toString())
            add(obs.proto)
            obs.serviceName?.let { add(it) }
            obs.product?.let { p ->
                p.vendor?.let { add(it) }
                add(p.product)
                p.version?.let { add(it) }
                p.cpe?.let { add(it) }
            }
            obs.evidence?.let { e ->
                e.banner?.let { add(it) }
                e.httpServer?.let { add(it) }
                e.httpPoweredBy?.let { add(it) }
                e.httpTitle?.let { add(it) }
                e.tlsSubject?.let { add(it) }
            }
        }
        return haystack.any { it.contains(q, ignoreCase = true) }
    }

    fun hostMatches(ip: String, hostname: String?, query: String): Boolean {
        val q = query.trim()
        if (q.isEmpty()) return true
        return ip.contains(q, ignoreCase = true) ||
            (hostname?.contains(q, ignoreCase = true) == true)
    }

    /** All services collapsed to per-port groups, most-widespread first. */
    fun groupByService(observations: List<ServiceObservation>): List<ServiceGroup> =
        observations
            .groupBy { Triple(it.port, it.proto, it.serviceName) }
            .map { (key, obs) ->
                ServiceGroup(
                    port = key.first,
                    proto = key.second,
                    serviceName = key.third,
                    hosts = obs.map { it.host }.distinct()
                        .sortedBy { runCatching { com.watchdog.app.net.Cidr.ipToLong(it) }.getOrDefault(Long.MAX_VALUE) },
                )
            }
            .sortedWith(compareByDescending<ServiceGroup> { it.hosts.size }.thenBy { it.port })

    fun serviceGroupMatches(group: ServiceGroup, query: String): Boolean {
        val q = query.trim()
        if (q.isEmpty()) return true
        if (group.port.toString().contains(q, ignoreCase = true)) return true
        if (group.proto.contains(q, ignoreCase = true)) return true
        if (group.serviceName?.contains(q, ignoreCase = true) == true) return true
        return group.hosts.any { it.contains(q, ignoreCase = true) }
    }
}
