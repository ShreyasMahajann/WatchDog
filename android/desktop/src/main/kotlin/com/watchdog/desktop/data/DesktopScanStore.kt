package com.watchdog.desktop.data

import com.watchdog.app.net.NetworkInfo
import com.watchdog.app.net.Cidr
import com.watchdog.app.scan.ScanConfig
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.sql.Connection
import java.sql.DriverManager

/** A small serializable host record for history (the core DiscoveredHost is enough but kept explicit). */
@Serializable
data class HostRec(val ip: String, val hostname: String? = null, val source: String = "scan")

/** One row of the history list. */
data class ScanSummary(
    val id: Long,
    val networkId: String,
    val ssid: String?,
    val cidr: String?,
    val scope: String,
    val depth: String,
    val startedAt: Long,
    val finishedAt: Long?,
    val status: String,
    val name: String?,
) {
    val label: String get() = name ?: "${ssid ?: cidr ?: networkId} · $status"
}

/** A full stored scan, for reopening from history. */
data class ScanRecord(
    val summary: ScanSummary,
    val hosts: List<HostRec>,
    val services: List<ServiceObservation>,
    val findings: List<Finding>,
)

/**
 * Desktop scan persistence via sqlite-jdbc. Stores one row per scan with hosts,
 * services, and findings as JSON columns (the core models are @Serializable).
 * Simple and durable — the desktop analogue of the Android Room store.
 */
class DesktopScanStore(
    dbFile: java.io.File = java.io.File(AppDirs.dataDir(), "watchdog.db"),
) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }
    private val url = "jdbc:sqlite:${dbFile.absolutePath}"

    init {
        // Ensure the driver is registered (some classloaders need this explicitly).
        runCatching { Class.forName("org.sqlite.JDBC") }
        conn().use { c ->
            c.createStatement().use { st ->
                st.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      networkId TEXT, ssid TEXT, cidr TEXT, scope TEXT, depth TEXT,
                      startedAt INTEGER, finishedAt INTEGER, status TEXT, name TEXT,
                      hostsJson TEXT NOT NULL DEFAULT '[]',
                      servicesJson TEXT NOT NULL DEFAULT '[]',
                      findingsJson TEXT NOT NULL DEFAULT '[]'
                    )
                    """.trimIndent(),
                )
            }
        }
    }

    private fun conn(): Connection = DriverManager.getConnection(url)

    fun startScan(net: NetworkInfo, config: ScanConfig): Long {
        val now = System.currentTimeMillis()
        val netId = net.cidr?.let { "${net.ssid ?: "net"}|${Cidr.longToIp(it.networkAddr)}/${it.prefixLength}" } ?: "unknown"
        val cidrStr = net.cidr?.let { "${Cidr.longToIp(it.networkAddr)}/${it.prefixLength}" }
        conn().use { c ->
            c.prepareStatement(
                "INSERT INTO scans(networkId, ssid, cidr, scope, depth, startedAt, status) VALUES(?,?,?,?,?,?,?)",
                java.sql.Statement.RETURN_GENERATED_KEYS,
            ).use { ps ->
                ps.setString(1, netId)
                ps.setString(2, net.ssid)
                ps.setString(3, cidrStr)
                ps.setString(4, config.scope.name)
                ps.setString(5, config.depth.name)
                ps.setLong(6, now)
                ps.setString(7, "RUNNING")
                ps.executeUpdate()
                ps.generatedKeys.use { rs -> return if (rs.next()) rs.getLong(1) else -1L }
            }
        }
    }

    fun finishScan(
        id: Long,
        status: String,
        hosts: List<HostRec>,
        services: List<ServiceObservation>,
    ) {
        conn().use { c ->
            c.prepareStatement(
                "UPDATE scans SET status=?, finishedAt=?, hostsJson=?, servicesJson=? WHERE id=?",
            ).use { ps ->
                ps.setString(1, status)
                ps.setLong(2, System.currentTimeMillis())
                ps.setString(3, json.encodeToString(ListSerializer(HostRec.serializer()), hosts))
                ps.setString(4, json.encodeToString(ListSerializer(ServiceObservation.serializer()), services))
                ps.setLong(5, id)
                ps.executeUpdate()
            }
        }
    }

    fun saveFindings(id: Long, findings: List<Finding>) {
        conn().use { c ->
            c.prepareStatement("UPDATE scans SET findingsJson=? WHERE id=?").use { ps ->
                ps.setString(1, json.encodeToString(ListSerializer(Finding.serializer()), findings))
                ps.setLong(2, id)
                ps.executeUpdate()
            }
        }
    }

    fun rename(id: Long, name: String?) = conn().use { c ->
        c.prepareStatement("UPDATE scans SET name=? WHERE id=?").use { ps ->
            ps.setString(1, name); ps.setLong(2, id); ps.executeUpdate()
        }
    }

    fun delete(id: Long) = conn().use { c ->
        c.prepareStatement("DELETE FROM scans WHERE id=?").use { ps -> ps.setLong(1, id); ps.executeUpdate() }
    }

    fun listScans(limit: Int = 100): List<ScanSummary> {
        conn().use { c ->
            c.prepareStatement("SELECT * FROM scans ORDER BY startedAt DESC LIMIT ?").use { ps ->
                ps.setInt(1, limit)
                ps.executeQuery().use { rs ->
                    val out = mutableListOf<ScanSummary>()
                    while (rs.next()) out.add(rs.toSummary())
                    return out
                }
            }
        }
    }

    fun getScan(id: Long): ScanRecord? {
        conn().use { c ->
            c.prepareStatement("SELECT * FROM scans WHERE id=?").use { ps ->
                ps.setLong(1, id)
                ps.executeQuery().use { rs ->
                    if (!rs.next()) return null
                    val summary = rs.toSummary()
                    val hosts = decode(rs.getString("hostsJson"), ListSerializer(HostRec.serializer()))
                    val services = decode(rs.getString("servicesJson"), ListSerializer(ServiceObservation.serializer()))
                    val findings = decode(rs.getString("findingsJson"), ListSerializer(Finding.serializer()))
                    return ScanRecord(summary, hosts, services, findings)
                }
            }
        }
    }

    private fun <T> decode(s: String?, ser: kotlinx.serialization.KSerializer<List<T>>): List<T> =
        if (s.isNullOrBlank()) emptyList() else runCatching { json.decodeFromString(ser, s) }.getOrDefault(emptyList())

    private fun java.sql.ResultSet.toSummary() = ScanSummary(
        id = getLong("id"),
        networkId = getString("networkId") ?: "",
        ssid = getString("ssid"),
        cidr = getString("cidr"),
        scope = getString("scope") ?: "",
        depth = getString("depth") ?: "",
        startedAt = getLong("startedAt"),
        finishedAt = getLong("finishedAt").let { if (wasNull()) null else it },
        status = getString("status") ?: "",
        name = getString("name"),
    )
}
