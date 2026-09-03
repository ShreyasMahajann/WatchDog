package com.watchdog.desktop.data

import com.watchdog.app.wpa.data.Capture
import com.watchdog.app.wpa.data.SubmissionStatus
import com.watchdog.app.wpa.data.WpaStore
import com.watchdog.app.wpa.handshake.HandshakeAnalyzer
import com.watchdog.app.wpa.wpasec.WpaSecClient
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager

/**
 * Desktop WPA capture persistence via sqlite-jdbc. Implements the shared [WpaStore]
 * (submission path) and adds import/list/delete. Files are stored under the app data
 * dir, named by MD5 so re-importing the same handshake dedupes.
 */
class DesktopWpaStore(
    dbFile: java.io.File = java.io.File(AppDirs.dataDir(), "watchdog.db"),
) : WpaStore {

    private val url = "jdbc:sqlite:${dbFile.absolutePath}"

    init {
        runCatching { Class.forName("org.sqlite.JDBC") }
        conn().use { c ->
            c.createStatement().use { st ->
                st.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS captures (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      md5 TEXT NOT NULL UNIQUE, ssid TEXT, bssid TEXT NOT NULL, bssidDisplay TEXT NOT NULL,
                      channel INTEGER, security TEXT NOT NULL, filePath TEXT NOT NULL, fileName TEXT NOT NULL,
                      sizeBytes INTEGER NOT NULL, hasValidHandshake INTEGER NOT NULL, eapolCount INTEGER NOT NULL,
                      hasPmkid INTEGER NOT NULL, capturedAt INTEGER NOT NULL, source TEXT NOT NULL,
                      status TEXT NOT NULL, statusDetail TEXT, submittedAt INTEGER, lastCheckedAt INTEGER, password TEXT
                    )
                    """.trimIndent(),
                )
            }
        }
    }

    private fun conn(): Connection = DriverManager.getConnection(url)

    /** Result of an import attempt. */
    sealed interface ImportResult {
        data class Ok(val capture: Capture, val alreadyExisted: Boolean) : ImportResult
        data class Failed(val reason: String) : ImportResult
    }

    /** Validate + store a pcap file's bytes. Dedupes by MD5. Throws nothing — returns [ImportResult]. */
    fun importBytes(bytes: ByteArray, originalName: String): ImportResult {
        val analysis = try {
            HandshakeAnalyzer.analyze(bytes)
        } catch (e: Exception) {
            return ImportResult.Failed(e.message ?: "Not a valid capture file")
        }
        val md5 = md5(bytes)
        existingByMd5(md5)?.let { return ImportResult.Ok(it, alreadyExisted = true) }

        val ext = originalName.substringAfterLast('.', "").lowercase().filter { it.isLetterOrDigit() }.take(8).ifBlank { "pcap" }
        val file = java.io.File(AppDirs.capturesDir(), "$md5.$ext")
        if (!file.exists()) file.writeBytes(bytes)

        val net = analysis.primary
        val bssidDisplay = net?.bssid ?: ""
        val capture = Capture(
            md5 = md5, ssid = net?.ssid, bssid = WpaSecClient.normalizeMac(bssidDisplay), bssidDisplay = bssidDisplay,
            channel = net?.channel, security = net?.security ?: "Unknown", filePath = file.absolutePath, fileName = originalName,
            sizeBytes = bytes.size.toLong(), hasValidHandshake = analysis.hasValidHandshake, eapolCount = analysis.eapolTotal,
            hasPmkid = net?.hasPmkid ?: false, capturedAt = System.currentTimeMillis(), source = "IMPORT",
            status = SubmissionStatus.NOT_SUBMITTED.name, statusDetail = null, submittedAt = null, lastCheckedAt = null, password = null,
        )
        val id = insert(capture)
        return ImportResult.Ok(capture.copy(id = id), alreadyExisted = false)
    }

    fun listAll(): List<Capture> = queryAll("SELECT * FROM captures ORDER BY capturedAt DESC")

    fun delete(capture: Capture) {
        conn().use { c -> c.prepareStatement("DELETE FROM captures WHERE id=?").use { it.setLong(1, capture.id); it.executeUpdate() } }
        runCatching { java.io.File(capture.filePath).takeIf { it.parentFile == AppDirs.capturesDir() }?.delete() }
    }

    override suspend fun get(id: Long): Capture? =
        queryAll("SELECT * FROM captures WHERE id=$id").firstOrNull()

    override suspend fun submittedCaptures(): List<Capture> =
        queryAll("SELECT * FROM captures WHERE status IN ('UPLOADING','SUBMITTED')")

    override suspend fun updateStatus(
        id: Long,
        status: SubmissionStatus,
        detail: String?,
        submittedAt: Long?,
        lastCheckedAt: Long?,
        password: String?,
    ) {
        conn().use { c ->
            c.prepareStatement(
                """UPDATE captures SET status=?, statusDetail=?,
                   submittedAt=COALESCE(?, submittedAt), lastCheckedAt=COALESCE(?, lastCheckedAt),
                   password=COALESCE(?, password) WHERE id=?""",
            ).use { ps ->
                ps.setString(1, status.name); ps.setString(2, detail)
                if (submittedAt != null) ps.setLong(3, submittedAt) else ps.setNull(3, java.sql.Types.INTEGER)
                if (lastCheckedAt != null) ps.setLong(4, lastCheckedAt) else ps.setNull(4, java.sql.Types.INTEGER)
                ps.setString(5, password); ps.setLong(6, id)
                ps.executeUpdate()
            }
        }
    }

    private fun existingByMd5(md5: String): Capture? =
        queryAll("SELECT * FROM captures WHERE md5='$md5' LIMIT 1").firstOrNull()

    private fun insert(cap: Capture): Long {
        conn().use { c ->
            c.prepareStatement(
                """INSERT OR IGNORE INTO captures(md5, ssid, bssid, bssidDisplay, channel, security, filePath, fileName,
                   sizeBytes, hasValidHandshake, eapolCount, hasPmkid, capturedAt, source, status, statusDetail,
                   submittedAt, lastCheckedAt, password) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                java.sql.Statement.RETURN_GENERATED_KEYS,
            ).use { ps ->
                ps.setString(1, cap.md5); ps.setString(2, cap.ssid); ps.setString(3, cap.bssid); ps.setString(4, cap.bssidDisplay)
                val ch = cap.channel
                if (ch != null) ps.setInt(5, ch) else ps.setNull(5, java.sql.Types.INTEGER)
                ps.setString(6, cap.security); ps.setString(7, cap.filePath); ps.setString(8, cap.fileName)
                ps.setLong(9, cap.sizeBytes); ps.setInt(10, if (cap.hasValidHandshake) 1 else 0); ps.setInt(11, cap.eapolCount)
                ps.setInt(12, if (cap.hasPmkid) 1 else 0); ps.setLong(13, cap.capturedAt); ps.setString(14, cap.source)
                ps.setString(15, cap.status); ps.setString(16, cap.statusDetail)
                ps.setNull(17, java.sql.Types.INTEGER); ps.setNull(18, java.sql.Types.INTEGER); ps.setString(19, cap.password)
                ps.executeUpdate()
                ps.generatedKeys.use { rs -> return if (rs.next()) rs.getLong(1) else (existingByMd5(cap.md5)?.id ?: -1L) }
            }
        }
    }

    private fun queryAll(sql: String): List<Capture> {
        conn().use { c ->
            c.createStatement().use { st ->
                st.executeQuery(sql).use { rs ->
                    val out = mutableListOf<Capture>()
                    while (rs.next()) out.add(
                        Capture(
                            id = rs.getLong("id"), md5 = rs.getString("md5"), ssid = rs.getString("ssid"),
                            bssid = rs.getString("bssid"), bssidDisplay = rs.getString("bssidDisplay"),
                            channel = rs.getInt("channel").let { if (rs.wasNull()) null else it },
                            security = rs.getString("security"), filePath = rs.getString("filePath"),
                            fileName = rs.getString("fileName"), sizeBytes = rs.getLong("sizeBytes"),
                            hasValidHandshake = rs.getInt("hasValidHandshake") == 1, eapolCount = rs.getInt("eapolCount"),
                            hasPmkid = rs.getInt("hasPmkid") == 1, capturedAt = rs.getLong("capturedAt"),
                            source = rs.getString("source"), status = rs.getString("status"), statusDetail = rs.getString("statusDetail"),
                            submittedAt = rs.getLong("submittedAt").let { if (rs.wasNull()) null else it },
                            lastCheckedAt = rs.getLong("lastCheckedAt").let { if (rs.wasNull()) null else it },
                            password = rs.getString("password"),
                        ),
                    )
                    return out
                }
            }
        }
    }

    private fun md5(bytes: ByteArray): String =
        MessageDigest.getInstance("MD5").digest(bytes).joinToString("") { "%02x".format(it) }
}
