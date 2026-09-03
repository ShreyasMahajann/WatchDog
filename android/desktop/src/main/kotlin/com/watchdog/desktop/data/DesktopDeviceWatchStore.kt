package com.watchdog.desktop.data

import com.watchdog.app.devicewatch.DeviceWatchStore
import com.watchdog.app.devicewatch.WatchedDevice
import java.sql.Connection
import java.sql.DriverManager

/**
 * Desktop Device Watch persistence via sqlite-jdbc. Implements the shared
 * [DeviceWatchStore] (scanner write-path) and adds UI queries.
 */
class DesktopDeviceWatchStore(
    dbFile: java.io.File = java.io.File(AppDirs.dataDir(), "watchdog.db"),
) : DeviceWatchStore {

    private val url = "jdbc:sqlite:${dbFile.absolutePath}"

    init {
        runCatching { Class.forName("org.sqlite.JDBC") }
        conn().use { c ->
            c.createStatement().use { st ->
                st.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS watched_devices (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scopeKey TEXT NOT NULL, networkLabel TEXT NOT NULL, ip TEXT NOT NULL,
                      hostname TEXT, serviceHints TEXT NOT NULL DEFAULT '', label TEXT,
                      trusted INTEGER NOT NULL DEFAULT 0, firstSeen INTEGER NOT NULL,
                      lastSeen INTEGER NOT NULL, present INTEGER NOT NULL DEFAULT 1,
                      UNIQUE(scopeKey, ip)
                    )
                    """.trimIndent(),
                )
            }
        }
    }

    private fun conn(): Connection = DriverManager.getConnection(url)

    override suspend fun devicesInScope(scopeKey: String): List<WatchedDevice> = query(scopeKey)

    /** UI query: present-first, then trusted, then newest. */
    fun listScope(scopeKey: String): List<WatchedDevice> =
        query(scopeKey).sortedWith(
            compareByDescending<WatchedDevice> { it.present }
                .thenBy { it.trusted }
                .thenByDescending { it.firstSeen },
        )

    override suspend fun applyScan(
        toInsert: List<WatchedDevice>,
        toUpdate: List<WatchedDevice>,
        scopeKey: String,
        seenIps: Collection<String>,
    ) {
        conn().use { c ->
            c.autoCommit = false
            try {
                for (d in toInsert) {
                    c.prepareStatement(
                        "INSERT OR IGNORE INTO watched_devices(scopeKey, networkLabel, ip, hostname, serviceHints, label, trusted, firstSeen, lastSeen, present) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    ).use { it.bindDevice(d); it.executeUpdate() }
                }
                for (d in toUpdate) {
                    c.prepareStatement(
                        "UPDATE watched_devices SET networkLabel=?, hostname=?, serviceHints=?, lastSeen=?, present=1 WHERE id=?",
                    ).use { ps ->
                        ps.setString(1, d.networkLabel); ps.setString(2, d.hostname)
                        ps.setString(3, d.serviceHints); ps.setLong(4, d.lastSeen); ps.setLong(5, d.id)
                        ps.executeUpdate()
                    }
                }
                if (seenIps.isEmpty()) {
                    c.prepareStatement("UPDATE watched_devices SET present=0 WHERE scopeKey=?").use { ps ->
                        ps.setString(1, scopeKey); ps.executeUpdate()
                    }
                } else {
                    val placeholders = seenIps.joinToString(",") { "?" }
                    c.prepareStatement("UPDATE watched_devices SET present=0 WHERE scopeKey=? AND ip NOT IN ($placeholders)").use { ps ->
                        ps.setString(1, scopeKey)
                        seenIps.forEachIndexed { i, ip -> ps.setString(i + 2, ip) }
                        ps.executeUpdate()
                    }
                }
                c.commit()
            } catch (e: Exception) {
                c.rollback(); throw e
            }
        }
    }

    fun setTrusted(id: Long, trusted: Boolean) = exec("UPDATE watched_devices SET trusted=? WHERE id=?") {
        it.setInt(1, if (trusted) 1 else 0); it.setLong(2, id)
    }

    fun rename(id: Long, label: String?) = exec("UPDATE watched_devices SET label=? WHERE id=?") {
        it.setString(1, label?.trim()?.ifBlank { null }); it.setLong(2, id)
    }

    fun forget(id: Long) = exec("DELETE FROM watched_devices WHERE id=?") { it.setLong(1, id) }

    private fun query(scopeKey: String): List<WatchedDevice> {
        conn().use { c ->
            c.prepareStatement("SELECT * FROM watched_devices WHERE scopeKey=?").use { ps ->
                ps.setString(1, scopeKey)
                ps.executeQuery().use { rs ->
                    val out = mutableListOf<WatchedDevice>()
                    while (rs.next()) out.add(
                        WatchedDevice(
                            id = rs.getLong("id"), scopeKey = rs.getString("scopeKey"),
                            networkLabel = rs.getString("networkLabel"), ip = rs.getString("ip"),
                            hostname = rs.getString("hostname"), serviceHints = rs.getString("serviceHints") ?: "",
                            label = rs.getString("label"), trusted = rs.getInt("trusted") == 1,
                            firstSeen = rs.getLong("firstSeen"), lastSeen = rs.getLong("lastSeen"),
                            present = rs.getInt("present") == 1,
                        ),
                    )
                    return out
                }
            }
        }
    }

    private inline fun exec(sql: String, bind: (java.sql.PreparedStatement) -> Unit) {
        conn().use { c -> c.prepareStatement(sql).use { ps -> bind(ps); ps.executeUpdate() } }
    }

    private fun java.sql.PreparedStatement.bindDevice(d: WatchedDevice) {
        setString(1, d.scopeKey); setString(2, d.networkLabel); setString(3, d.ip)
        setString(4, d.hostname); setString(5, d.serviceHints); setString(6, d.label)
        setInt(7, if (d.trusted) 1 else 0); setLong(8, d.firstSeen); setLong(9, d.lastSeen)
        setInt(10, if (d.present) 1 else 0)
    }
}
